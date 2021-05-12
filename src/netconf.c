/**
 * @file netconf.c
 * @author Michal Vasko <mvasko@cesnet.cz>
 * @brief ietf-netconf callbacks
 *
 * Copyright (c) 2019 CESNET, z.s.p.o.
 *
 * This source code is licensed under BSD 3-Clause License (the "License").
 * You may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://opensource.org/licenses/BSD-3-Clause
 */

#define _GNU_SOURCE
#define _DEFAULT_SOURCE

#include <stdio.h>
#include <assert.h>
#include <inttypes.h>
#include <unistd.h>
#include <string.h>
#include <pthread.h>
#include <errno.h>
#include <ctype.h>

#include <sysrepo.h>
#include <libyang/libyang.h>

#include "common.h"
#include "log.h"
#include "netconf_acm.h"
#include "mpra.h"

#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <signal.h>

#define PRINT_LOG 1
int CURR_LOG_LEVEL = DEBUG_LOG;

#define __FILENAME__ (strrchr(__FILE__, '/') ? strrchr(__FILE__, '/') + 1 : __FILE__)
#define LOG(LEVEL, fmt, ...)                                               \
            if(PRINT_LOG)                                                  \
            do {                                                           \
                if(LEVEL >= CURR_LOG_LEVEL)                                \
                    fprintf(stderr, "[NETOPEER2] <%s, %s:%d> " fmt "\n",   \
                        __func__, __FILENAME__, __LINE__,  ##__VA_ARGS__); \
            } while(0)

#define MAX_INPUT_SIZE 1024
#define DELIMETER ' '

static int
np2srv_get_first_ns(const char *expr, const char **start, int *len)
{
    int i;

    if (expr[0] != '/') {
        return -1;
    }
    if (expr[1] == '/') {
        expr += 2;
    } else {
        ++expr;
    }

    if (!isalpha(expr[0]) && (expr[0] != '_')) {
        return -1;
    }
    for (i = 1; expr[i] && (isalnum(expr[i]) || (expr[i] == '_') || (expr[i] == '-') || (expr[i] == '.')); ++i);
    if (expr[i] != ':') {
        return -1;
    }

    *start = expr;
    *len = i;
    return 0;
}

/**
 * @brief Get generic filters in the form of "/module:*" from exact xpath filters.
 */
static int
np2srv_get_rpc_module_filters(const struct np2_filter *filter, struct np2_filter *mod_filter)
{
    int i, j, len, selection;
    const char *start;
    char *str;

    for (i = 0; i < filter->count; ++i) {
        if (np2srv_get_first_ns(filter->filters[i].str, &start, &len)) {
            /* not the simple format, use it as it is */
            str = strdup(filter->filters[i].str);
            selection = filter->filters[i].selection;
        } else {
            /* get all the data of a module */
            if (asprintf(&str, "/%.*s:*", len, start) == -1) {
                str = NULL;
            }
            selection = 1;
        }

        if (!str) {
            EMEM;
            return SR_ERR_NOMEM;
        }

        /* check for a duplicity */
        for (j = 0; j < mod_filter->count; ++j) {
            if (!strcmp(str, mod_filter->filters[j].str)) {
                break;
            }
        }
        if (j < mod_filter->count) {
            free(str);
            continue;
        }

        /* add a new module filter */
        mod_filter->filters = realloc(mod_filter->filters, (mod_filter->count + 1) * sizeof *mod_filter->filters);
        mod_filter->filters[mod_filter->count].str = str;
        mod_filter->filters[mod_filter->count].selection = selection;
        ++mod_filter->count;
    }

    return SR_ERR_OK;
}

/**
 * @brief Get data for a get RPC.
 */
static int
np2srv_get_rpc_data(sr_session_ctx_t *session, const struct np2_filter *filter, sr_session_ctx_t *ev_sess,
        struct lyd_node **data)
{
    struct lyd_node *all_data = NULL;
    sr_datastore_t ds;
    sr_get_oper_options_t get_opts = 0;
    struct np2_filter mod_filter = {0};
    int rc = SR_ERR_OK;
    struct ly_set *set = NULL;

    /* get generic filters to allow retrieving all possibly needed data first, which are then filtered again
     * (once we have merged config and state data) */
    rc = np2srv_get_rpc_module_filters(filter, &mod_filter);
    if (rc) {
        goto cleanup;
    }

    /* get data from running first */
    ds = SR_DS_RUNNING;

get_sr_data:
    sr_session_switch_ds(session, ds);

    if ((rc = op_filter_data_get(session, 0, get_opts, &mod_filter, ev_sess, &all_data))) {
        goto cleanup;
    }

    if (ds == SR_DS_RUNNING) {
        /* we have running data, now append state data */
        ds = SR_DS_OPERATIONAL;
        get_opts = SR_OPER_NO_CONFIG;
        goto get_sr_data;
    }

    /* now filter only the requested data from the created running data + state data */
    if ((rc = op_filter_data_filter(&all_data, filter, 1, data))) {
        goto cleanup;
    }

cleanup:
    ly_set_free(set);
    lyd_free_withsiblings(all_data);
    op_filter_erase(&mod_filter);
    return rc;
}

/**
 * @brief get data for a get-config RPC.
 */
static int
np2srv_getconfig_rpc_data(sr_session_ctx_t *session, const struct np2_filter *filter, sr_datastore_t ds,
        sr_session_ctx_t *ev_sess, struct lyd_node **data)
{
    struct lyd_node *select_data = NULL;
    int rc = SR_ERR_OK;

    /* update sysrepo session datastore */
    sr_session_switch_ds(session, ds);

    /*
     * create the data tree for the data reply
     */
    if ((rc = op_filter_data_get(session, 0, 0, filter, ev_sess, &select_data))) {
        goto cleanup;
    }

    if ((rc = op_filter_data_filter(&select_data, filter, 0, data))) {
        goto cleanup;
    }

cleanup:
    lyd_free_withsiblings(select_data);
    return rc;
}

void mplane_append_in_command_buff(const sr_val_t *value, char *command_buff)
{
    if (NULL == value) {
        return;
    }
    char *p = NULL;
    char *dup_str = NULL;
    p = strrchr(value->xpath, '/');
    const char *field = ++p;
    command_buff += strlen(command_buff);
    sprintf(command_buff, "%s%c", field, DELIMETER);
    command_buff += strlen(command_buff);
    if(!strcmp(field, "xpath") && value->data.string_val[0] != '/')
    {
        sprintf(command_buff, "%s", "/");
        command_buff += strlen(command_buff);
    }

    switch (value->type) {
    case SR_CONTAINER_T:
    case SR_CONTAINER_PRESENCE_T:
        LOG(DEBUG_LOG, "(container)");
        break;
    case SR_LIST_T:
        LOG(DEBUG_LOG, "(list instance)");
        break;
    case SR_STRING_T:
        LOG(DEBUG_LOG, "%s = %s", value->xpath, value->data.string_val);
        sprintf(command_buff, "%s%c", value->data.string_val, DELIMETER);
        break;
    case SR_BOOL_T:
        LOG(DEBUG_LOG, "%s = %s", value->xpath, value->data.bool_val ? "true" : "false");
        sprintf(command_buff, "%s%c", value->data.bool_val ? "true" : "false", DELIMETER);
        break;
    case SR_DECIMAL64_T:
        LOG(DEBUG_LOG, "%s = %g", value->xpath, value->data.decimal64_val);
        sprintf(command_buff, "%g%c", value->data.decimal64_val, DELIMETER);
        break;
    case SR_INT8_T:
        LOG(DEBUG_LOG, "%s = %" PRId8, value->xpath, value->data.int8_val);
        sprintf(command_buff, "%" PRId8, value->data.int8_val);
        command_buff += strlen(command_buff);
        sprintf(command_buff, "%c", DELIMETER);
        break;
    case SR_INT32_T:
        LOG(DEBUG_LOG, "%s = %" PRId32, value->xpath, value->data.int32_val);
        sprintf(command_buff, "%" PRId32, value->data.int32_val);
        command_buff += strlen(command_buff);
        sprintf(command_buff, "%c", DELIMETER);
        break;
    case SR_INT64_T:
        LOG(DEBUG_LOG, "%s = %" PRId64, value->xpath, value->data.int64_val);
        sprintf(command_buff, "%" PRId64, value->data.int64_val);
        command_buff += strlen(command_buff);
        sprintf(command_buff, "%c", DELIMETER);
        break;
    case SR_UINT8_T:
        LOG(DEBUG_LOG, "%s = %" PRIu8, value->xpath, value->data.uint8_val);
        sprintf(command_buff, "%" PRIu8, value->data.uint8_val);
        command_buff += strlen(command_buff);
        sprintf(command_buff, "%c", DELIMETER);
        break;
    case SR_UINT32_T:
        LOG(DEBUG_LOG, "%s = %" PRIu32, value->xpath, value->data.uint32_val);
        sprintf(command_buff, " %" PRIu32, value->data.uint32_val);
        command_buff += strlen(command_buff);
        sprintf(command_buff, " %c", DELIMETER);
        break;
    case SR_UINT64_T:
        LOG(DEBUG_LOG, "%s = %" PRIu64, value->xpath, value->data.uint64_val);
        sprintf(command_buff, " %" PRIu64, value->data.uint64_val);
        command_buff += strlen(command_buff);
        sprintf(command_buff, "%c", DELIMETER);
        break;
    case SR_ENUM_T:
        LOG(DEBUG_LOG, "%s = %s", value->xpath, value->data.enum_val);
        sprintf(command_buff, "%s%c", value->data.enum_val, DELIMETER);
        break;
    default:
        LOG(DEBUG_LOG, "(unprintable)");
        break;
    }
}

input_t*
mplane_parse_rpc_input(const sr_val_t *input, const size_t input_cnt)
{
    size_t i;
    input_t *cmd_buff = NULL;
    char buff[MAX_INPUT_SIZE];

    cmd_buff = (input_t*) malloc(sizeof(input_t)+sizeof(char));
    if(!cmd_buff)
    {
        LOG(CRIT_LOG, "malloc() failed");
        return NULL;
    }

    memset(cmd_buff, 0, (sizeof(input_t)+sizeof(char)) * sizeof(char));
    cmd_buff->size = sizeof(input_t) + sizeof(char);
    cmd_buff->buff[0] = '\0';

    for (i = 0; i < input_cnt; ++i) {
        memset(buff, 0, MAX_INPUT_SIZE * sizeof(char));
        mplane_append_in_command_buff(&input[i], buff);
        cmd_buff = (input_t *) realloc(cmd_buff, cmd_buff->size + strlen(buff));
        if(!cmd_buff)
        {
            LOG(CRIT_LOG, "realloc() failed");
            return NULL;
        }
        strcat(cmd_buff->buff, buff);
        cmd_buff->size += strlen(buff);
    }
    LOG(DEBUG_LOG, "length: %ld", cmd_buff->size);
    LOG(DEBUG_LOG, "buff: %s", cmd_buff->buff);
    return cmd_buff;
}

void msg_snd(void *buff, size_t size)
{
    LOG(DEBUG_LOG, "Writing on fifo: %ld bytes", size);
    int fd;
    char * FIFO = "/tmp/mplane";

    mkfifo(FIFO, 0777);
    fd = open(FIFO, O_WRONLY);
    write(fd, buff, size);
    LOG(DEBUG_LOG, "Write successful");
    close(fd);
    usleep(1);
}
void msg_rcv(void **buff, size_t size)
{
    LOG(DEBUG_LOG, "Reading from the fifo: %ld bytes", size);
    int fd;
    size_t retbyte = 0;
    char * FIFO = "/tmp/mplane";
    void *out = (void*) malloc(size);
    memset(out, 0, size);

    mkfifo(FIFO, 0777);
retry:
    fd = open(FIFO, O_RDONLY);
    retbyte = read(fd, out, size);
    if(retbyte == 0)
    {
        LOG(DEBUG_LOG, "Received fifo closed response, retry read");
        close(fd);
        goto retry;
    }
    if(retbyte == -1)
    {
        LOG(DEBUG_LOG, "read() failed");
        close(fd);
        *buff = NULL;
        return;
    }

    ((char*)out)[retbyte] = '\0';
    LOG(DEBUG_LOG, "Read successful");
    close(fd);
    *buff = out;
}

void send_ack()
{
    LOG(DEBUG_LOG, "Sending ACK");
    int ack = 1;
    msg_snd(&ack, sizeof(int));
    LOG(DEBUG_LOG, "Send ACK successful");
}

void recv_ack()
{
    LOG(DEBUG_LOG, "Waiting ACK");
    int *ack = NULL;
    msg_rcv((void**)&ack, sizeof(int));
    LOG(DEBUG_LOG, "Receive ACK successful: %d", *ack);
}

void mplane_send_buffer(void *input_buff)
{
    size_t i = 0;
    size_t size = ((msg_t*)input_buff)->size;
    printf("Netopeer Send Buffer \n");
    for(i = 0; i < size; i++)
    {
        printf("'%c' ", ((char*)input_buff)[i]);
    }
    printf("\n"); fflush(stdout);

    LOG(DEBUG_LOG, "Sending message length: %ld", ((msg_t*)input_buff)->size);
    msg_snd(&((msg_t*)input_buff)->size, sizeof(size_t));
    LOG(DEBUG_LOG, "Sent successful");
    //recv_ack();
    LOG(DEBUG_LOG, "Sending message content");
    msg_snd(input_buff, ((msg_t*)input_buff)->size);
    LOG(DEBUG_LOG, "Sent successful");
    //recv_ack();
}

void mplane_recv_buffer(void **output_buff)
{
    size_t *size = NULL;
    LOG(DEBUG_LOG, "Reading message length");
    msg_rcv((void**)&size, sizeof(size_t));
    LOG(DEBUG_LOG, "Read successful, length: %ld", *size);
    //send_ack();
    LOG(DEBUG_LOG, "Reading message content");
    msg_rcv(output_buff, *size);
    LOG(DEBUG_LOG, "Read successful");
    //send_ack();
    size_t i = 0;
    printf("Netopeer Recv Buffer \n");
    for(i = 0; i < *size; i++)
    {
        printf("'%c' ", ((char*)output_buff)[i]);
    }
    printf("\n"); fflush(stdout);
}

void mplane_snd_rcv(input_t *input_buff ,output_t **output_buff, snd_rcv_t snd_rcv)
{
    switch(snd_rcv)
    {
        case SND:
        mplane_send_buffer((void*)input_buff);
        break;
        case RCV:
        mplane_recv_buffer((void**)output_buff);
        break;
    }
}

void release_in_out_buff(void *in_buff, void *out_buff)
{
    if(in_buff)
        free(in_buff);
    if(out_buff)
        free(out_buff);
}

int
mplane_rpc_start_mpra_cb(sr_session_ctx_t *session, const char *path, const sr_val_t *input, const size_t input_cnt,
        sr_event_t event, uint32_t request_id, sr_val_t **output, size_t *output_cnt, void *private_data)
{
    (void)session;
    (void)event;
    (void)request_id;
    (void)private_data;
    input_t *mpra_input;
    output_t *mpra_output = NULL;
    char *cmd = "request START";
    int cmd_len = strlen(cmd);
    int retcode = 0;

    LOG(INFO_LOG, "=============== RPC \"%s\" RECEIVED: ===============", path);

    LOG(INFO_LOG, "Processing rpc input");
    mpra_input = mplane_parse_rpc_input(input, input_cnt);

    LOG(INFO_LOG, "Adding start command");
    mpra_input = (input_t *) realloc(mpra_input, mpra_input->size + cmd_len);
    if(!mpra_input)
    {
        LOG(CRIT_LOG, "malloc() failed");
        return SR_ERR_INTERNAL;
    }
    strcat(mpra_input->buff, cmd);
    mpra_input->size += cmd_len;
    LOG(INFO_LOG, "Rrepared cmd buff from rpc input: %s", mpra_input->buff);

    LOG(INFO_LOG, "Sending cmd buff to MPRA");
    mplane_snd_rcv(mpra_input, NULL, SND);
    LOG(INFO_LOG, "Sent cmd buff to MPRA");

    LOG(INFO_LOG, "Waiting for cmd response from MPRA");
    mplane_snd_rcv(NULL, &mpra_output, RCV);
    LOG(INFO_LOG, "Received response from MPRA");
    LOG(INFO_LOG, "Received content: %s", mpra_output->buff);
    LOG(INFO_LOG, "=============== FINISHED PROCESSING RPC ===============");

    retcode = mpra_output->retcode;
    release_in_out_buff(mpra_input, mpra_output);
    return retcode;

}

int
mplane_rpc_stop_mpra_cb(sr_session_ctx_t *session, const char *path, const sr_val_t *input, const size_t input_cnt,
        sr_event_t event, uint32_t request_id, sr_val_t **output, size_t *output_cnt, void *private_data)
{
    (void)session;
    (void)event;
    (void)request_id;
    (void)private_data;
    input_t *mpra_input;
    output_t *mpra_output = NULL;
    char *cmd = "request STOP";
    int cmd_len = strlen(cmd);
    int retcode = 0;

    LOG(INFO_LOG, "=============== RPC \"%s\" RECEIVED: ===============", path);

    LOG(INFO_LOG, "Processing rpc input");
    mpra_input = mplane_parse_rpc_input(input, input_cnt);

    LOG(INFO_LOG, "Adding stop command");
    mpra_input = (input_t *) realloc(mpra_input, mpra_input->size + cmd_len);
    if(!mpra_input)
    {
        LOG(CRIT_LOG, "malloc() failed");
        return SR_ERR_INTERNAL;
    }
    strcat(mpra_input->buff, cmd);
    mpra_input->size += cmd_len;
    LOG(INFO_LOG, "Rrepared cmd buff from rpc input: %s", mpra_input->buff);

    LOG(INFO_LOG, "Sending cmd buff to MPRA");
    mplane_snd_rcv(mpra_input, NULL, SND);
    LOG(INFO_LOG, "Sent cmd buff to MPRA");

    LOG(INFO_LOG, "Waiting for cmd response from MPRA");
    mplane_snd_rcv(NULL, &mpra_output, RCV);
    LOG(INFO_LOG, "Received response from MPRA");
    LOG(INFO_LOG, "Received content: %s", mpra_output->buff);
    LOG(INFO_LOG, "=============== FINISHED PROCESSING RPC ===============");

    retcode = mpra_output->retcode;
    release_in_out_buff(mpra_input, mpra_output);
    return retcode;
}

int
mplane_rpc_set_temperature_cb(sr_session_ctx_t *session, const char *path, const sr_val_t *input, const size_t input_cnt,
        sr_event_t event, uint32_t request_id, sr_val_t **output, size_t *output_cnt, void *private_data)
{
    (void)session;
    (void)event;
    (void)request_id;
    (void)private_data;
    int retcode = 0;
    input_t *mpra_input;
    output_t *mpra_output = NULL;
    LOG(INFO_LOG, "=============== RPC \"%s\" RECEIVED: ===============", path);

    LOG(INFO_LOG, "Processing rpc input");
    mpra_input = mplane_parse_rpc_input(input, input_cnt);
    LOG(INFO_LOG, "Rrepared cmd buff from rpc input: %s", mpra_input->buff);

    LOG(INFO_LOG, "Sending cmd buff to MPRA");
    mplane_snd_rcv(mpra_input, NULL, SND);
    LOG(INFO_LOG, "Sent cmd buff to MPRA");

    LOG(INFO_LOG, "Waiting for cmd response from MPRA");
    mplane_snd_rcv(NULL, &mpra_output, RCV);
    LOG(INFO_LOG, "Received response from MPRA");
    LOG(INFO_LOG, "Received content: %s", mpra_output->buff);
    LOG(INFO_LOG, "=============== FINISHED PROCESSING RPC ===============");

    retcode = mpra_output->retcode;
    release_in_out_buff(mpra_input, mpra_output);
    return retcode;
}

int
mplane_rpc_get_antenna_cb(sr_session_ctx_t *session, const char *path, const sr_val_t *input, const size_t input_cnt,
        sr_event_t event, uint32_t request_id, sr_val_t **output, size_t *output_cnt, void *private_data)
{
    (void)session;
    (void)event;
    (void)request_id;
    (void)private_data;
    int retcode = 0;
    input_t *mpra_input;
    output_t *mpra_output = NULL;
    LOG(INFO_LOG, "=============== RPC \"%s\" RECEIVED: ===============", path);
    mpra_input = mplane_parse_rpc_input(input, input_cnt);
    LOG(INFO_LOG, "Rrepared cmd buff from rpc input: %s", mpra_input->buff);

    LOG(INFO_LOG, "Sending cmd buff to MPRA");
    mplane_snd_rcv(mpra_input, NULL, SND);
    LOG(INFO_LOG, "Sent cmd buff to MPRA");

    LOG(INFO_LOG, "Waiting for cmd response from MPRA");
    mplane_snd_rcv(NULL, &mpra_output, RCV);
    LOG(INFO_LOG, "Received response from MPRA");
    LOG(INFO_LOG, "Received content: %s", mpra_output->buff);

    /* generate some output */
    if(mpra_output->retcode != SR_ERR_OK)
        goto cleanup;
    *output = malloc((sizeof **output)*2);
    *output_cnt = 2;

    (*output)[0].xpath = strdup("/mplane-rpcs:get-antenna-cfg/msg");
    (*output)[0].type = SR_STRING_T;
    (*output)[0].dflt = 0;
    (*output)[0].data.string_val = strdup("Returned temperature");

    (*output)[1].xpath = strdup("/mplane-rpcs:get-antenna-cfg/ret");
    (*output)[1].type = SR_STRING_T;
    (*output)[1].dflt = 0;
    (*output)[1].data.string_val = strdup(mpra_output->buff);

    LOG(INFO_LOG, "=============== FINISHED PROCESSING RPC ===============");

cleanup:
    retcode = mpra_output->retcode;
    release_in_out_buff(mpra_input, mpra_output);
    return retcode;
}

int
mplane_rpc_edit_antenna_cb(sr_session_ctx_t *session, const char *path, const sr_val_t *input, const size_t input_cnt,
        sr_event_t event, uint32_t request_id, sr_val_t **output, size_t *output_cnt, void *private_data)
{
    (void)session;
    (void)event;
    (void)request_id;
    (void)private_data;
    int retcode = 0;
    input_t *mpra_input;
    output_t *mpra_output = NULL;
    LOG(INFO_LOG, "=============== RPC \"%s\" RECEIVED: ===============", path);

    LOG(INFO_LOG, "Processing rpc input");
    mpra_input = mplane_parse_rpc_input(input, input_cnt);
    LOG(INFO_LOG, "Rrepared cmd buff from rpc input: %s", mpra_input->buff);

    LOG(INFO_LOG, "Sending cmd buff to MPRA");
    mplane_snd_rcv(mpra_input, NULL, SND);
    LOG(INFO_LOG, "Sent cmd buff to MPRA");

    LOG(INFO_LOG, "Waiting for cmd response from MPRA");
    mplane_snd_rcv(NULL, &mpra_output, RCV);
    LOG(INFO_LOG, "Received response from MPRA");
    LOG(INFO_LOG, "Received content: %s", mpra_output->buff);
    LOG(INFO_LOG, "=============== FINISHED PROCESSING RPC ===============");

    retcode = mpra_output->retcode;
    release_in_out_buff(mpra_input, mpra_output);
    return retcode;
}

int
mplane_rpc_show_temperature_cb(sr_session_ctx_t *session, const char *path, const sr_val_t *input, const size_t input_cnt,
        sr_event_t event, uint32_t request_id, sr_val_t **output, size_t *output_cnt, void *private_data)
{
    (void)session;
    (void)event;
    (void)request_id;
    (void)private_data;
    int retcode = 0;
    input_t *mpra_input;
    output_t *mpra_output = NULL;
    LOG(INFO_LOG, "=============== RPC \"%s\" RECEIVED: ===============", path);
    mpra_input = mplane_parse_rpc_input(input, input_cnt);
    LOG(INFO_LOG, "Rrepared cmd buff from rpc input: %s", mpra_input->buff);

    LOG(INFO_LOG, "Sending cmd buff to MPRA");
    mplane_snd_rcv(mpra_input, NULL, SND);
    LOG(INFO_LOG, "Sent cmd buff to MPRA");

    LOG(INFO_LOG, "Waiting for cmd response from MPRA");
    mplane_snd_rcv(NULL, &mpra_output, RCV);
    LOG(INFO_LOG, "Received response from MPRA");
    LOG(INFO_LOG, "Received content: %s", mpra_output->buff);

    /* generate some output */
    if(mpra_output->retcode != SR_ERR_OK)
        goto cleanup;
    *output = malloc((sizeof **output)*2);
    *output_cnt = 2;

    (*output)[0].xpath = strdup("/mplane-rpcs:show-temperature/msg");
    (*output)[0].type = SR_STRING_T;
    (*output)[0].dflt = 0;
    (*output)[0].data.string_val = strdup("Returned temperature");

    (*output)[1].xpath = strdup("/mplane-rpcs:show-temperature/ret");
    (*output)[1].type = SR_STRING_T;
    (*output)[1].dflt = 0;
    (*output)[1].data.string_val = strdup(mpra_output->buff);

    LOG(INFO_LOG, "=============== FINISHED PROCESSING RPC ===============");

cleanup:
    retcode = mpra_output->retcode;
    release_in_out_buff(mpra_input, mpra_output);
    return retcode;
}

int
np2srv_rpc_get_cb(sr_session_ctx_t *session, const char *op_path, const struct lyd_node *input, sr_event_t event,
        uint32_t UNUSED(request_id), struct lyd_node *output, void *UNUSED(private_data))
{
    struct lyd_node *node, *data_get = NULL;
    struct np2_filter filter = {0};
    int rc = SR_ERR_OK;
    sr_session_ctx_t *user_sess;
    struct ly_set *nodeset;
    sr_datastore_t ds = 0;
    char *username = NULL;

    if (event == SR_EV_ABORT) {
        /* ignore in this case */
        return SR_ERR_OK;
    }

    /* Get username. It is assumed that right now the NETCONF session cannot end
     * due to the RPC lock held while np2srv_rpc_cb() is executing (which called this callback).
     */
    if ((username = (char *)np_get_nc_sess_user(session))) {
        if (!(username = strdup(username))) {
            EMEM;
            rc = SR_ERR_NOMEM;
            goto cleanup;
        }
    } else {
        EINT;
        rc = SR_ERR_INTERNAL;
        goto cleanup;
    }

    /* get know which datastore is being affected for get-config */
    if (!strcmp(op_path, "/ietf-netconf:get-config")) {
        nodeset = lyd_find_path(input, "source/*");
        if (!strcmp(nodeset->set.d[0]->schema->name, "running")) {
            ds = SR_DS_RUNNING;
        } else if (!strcmp(nodeset->set.d[0]->schema->name, "startup")) {
            ds = SR_DS_STARTUP;
        } else {
            assert(!strcmp(nodeset->set.d[0]->schema->name, "candidate"));
            ds = SR_DS_CANDIDATE;
        }

        ly_set_free(nodeset);
    }

    /* create filters */
    nodeset = lyd_find_path(input, "filter");
    if (nodeset->number) {
        node = nodeset->set.d[0];
        ly_set_free(nodeset);
        if (op_filter_create(node, &filter)) {
            rc = SR_ERR_INTERNAL;
            goto cleanup;
        }
    } else {
        ly_set_free(nodeset);

        filter.filters = malloc(sizeof *filter.filters);
        if (!filter.filters) {
            EMEM;
            rc = SR_ERR_NOMEM;
            goto cleanup;
        }
        filter.count = 1;
        filter.filters[0].str = strdup("/*");
        filter.filters[0].selection = 1;
        if (!filter.filters[0].str) {
            EMEM;
            rc = SR_ERR_NOMEM;
            goto cleanup;
        }
    }

    /* we do not care here about with-defaults mode, it does not change anything */

    /* get the user session */
    user_sess = np_get_user_sess(session);
    if (!user_sess) {
        EINT;
        rc = SR_ERR_INTERNAL;
        goto cleanup;
    }

    /* get filtered data */
    if (!strcmp(op_path, "/ietf-netconf:get-config")) {
        rc = np2srv_getconfig_rpc_data(user_sess, &filter, ds, session, &data_get);
    } else {
        rc = np2srv_get_rpc_data(user_sess, &filter, session, &data_get);
    }
    if (rc) {
        goto cleanup;
    }

    /* perform correct NACM filtering */
    ncac_check_data_read_filter(&data_get, username);

    /* add output */
    node = lyd_new_output_anydata(output, NULL, "data", data_get, LYD_ANYDATA_DATATREE);
    if (!node) {
        goto cleanup;
    }
    data_get = NULL;

    /* success */

cleanup:
    op_filter_erase(&filter);
    lyd_free_withsiblings(data_get);
    free(username);
    return rc;
}

int
np2srv_rpc_editconfig_cb(sr_session_ctx_t *session, const char *UNUSED(op_path), const struct lyd_node *input,
        sr_event_t event, uint32_t UNUSED(request_id), struct lyd_node *UNUSED(output), void *UNUSED(private_data))
{
    sr_datastore_t ds = 0;
    struct ly_set *nodeset;
    struct lyd_node *config = NULL;
    const sr_error_info_t *err_info;
    sr_session_ctx_t *user_sess = NULL;
    const char *str, *defop = "merge", *testop = "test-then-set";
    int rc = SR_ERR_OK;

    if (event == SR_EV_ABORT) {
        /* ignore in this case */
        return SR_ERR_OK;
    }

    /* get know which datastore is being affected */
    nodeset = lyd_find_path(input, "target/*");
    if (!strcmp(nodeset->set.d[0]->schema->name, "running")) {
        ds = SR_DS_RUNNING;
    } else {
        assert(!strcmp(nodeset->set.d[0]->schema->name, "candidate"));
        ds = SR_DS_CANDIDATE;
    }
    ly_set_free(nodeset);

    /* default-operation */
    nodeset = lyd_find_path(input, "default-operation");
    if (nodeset->number) {
        defop = ((struct lyd_node_leaf_list *)nodeset->set.d[0])->value_str;
    }
    ly_set_free(nodeset);

    /* test-option */
    nodeset = lyd_find_path(input, "test-option");
    if (nodeset->number) {
        testop = ((struct lyd_node_leaf_list *)nodeset->set.d[0])->value_str;
        if (!strcmp(testop, "set")) {
            VRB("edit-config test-option \"set\" not supported, validation will be performed.");
            testop = "test-then-set";
        }
    }
    ly_set_free(nodeset);

    /* error-option */
    nodeset = lyd_find_path(input, "error-option");
    if (nodeset->number) {
        str = ((struct lyd_node_leaf_list *)nodeset->set.d[0])->value_str;
        if (strcmp(str, "rollback-on-error")) {
            VRB("edit-config error-option \"%s\" not supported, rollback-on-error will be performed.", str);
        }
    }
    ly_set_free(nodeset);

    /* config */
    nodeset = lyd_find_path(input, "config | url");
    if (!strcmp(nodeset->set.d[0]->schema->name, "config")) {
        config = op_parse_config((struct lyd_node_anydata *)nodeset->set.d[0], LYD_OPT_EDIT | LYD_OPT_STRICT, &rc, session);
        if (rc) {
            ly_set_free(nodeset);
            goto cleanup;
        }
    } else {
        assert(!strcmp(nodeset->set.d[0]->schema->name, "url"));
#ifdef NP2SRV_URL_CAPAB
        config = op_parse_url(((struct lyd_node_leaf_list *)nodeset->set.d[0])->value_str,
                LYD_OPT_EDIT | LYD_OPT_STRICT | LYD_OPT_TRUSTED, &rc, session);
        if (rc) {
            ly_set_free(nodeset);
            goto cleanup;
        }
#else
        ly_set_free(nodeset);
        rc = SR_ERR_UNSUPPORTED;
        sr_set_error(session, NULL, "URL not supported.");
        goto cleanup;
#endif
    }
    ly_set_free(nodeset);

    /* get the user session */
    user_sess = np_get_user_sess(session);
    if (!user_sess) {
        EINT;
        rc = SR_ERR_INTERNAL;
        goto cleanup;
    }

    /* update sysrepo session datastore */
    sr_session_switch_ds(user_sess, ds);

    /* sysrepo API */
    if (config) {
        rc = sr_edit_batch(user_sess, config, defop);
        if (rc != SR_ERR_OK) {
            goto cleanup;
        }
    }

    if (!strcmp(testop, "test-then-set")) {
        rc = sr_apply_changes(user_sess, np2srv.sr_timeout, 1);
    } else {
        assert(!strcmp(testop, "test-only"));
        rc = sr_validate(user_sess, NULL, 0);
    }
    if (rc != SR_ERR_OK) {
        sr_get_error(user_sess, &err_info);
        sr_set_error(session, err_info->err[0].xpath, err_info->err[0].message);
        goto cleanup;
    }

    /* success */

cleanup:
    if (user_sess) {
        /* discard any changes that possibly failed to be applied */
        sr_discard_changes(user_sess);
    }
    lyd_free_withsiblings(config);
    return rc;
}

int
np2srv_rpc_copyconfig_cb(sr_session_ctx_t *session, const char *UNUSED(op_path), const struct lyd_node *input,
        sr_event_t event, uint32_t UNUSED(request_id), struct lyd_node *UNUSED(output), void *UNUSED(private_data))
{
    sr_datastore_t ds = SR_DS_OPERATIONAL, sds = SR_DS_OPERATIONAL;
    struct ly_set *nodeset;
    const sr_error_info_t *err_info;
    struct lyd_node *config = NULL;
    int rc = SR_ERR_OK, run_to_start = 0;
    sr_session_ctx_t *user_sess;
    char *username = NULL;
#ifdef NP2SRV_URL_CAPAB
    struct lyd_node_leaf_list *leaf;
    const char *trg_url = NULL;
    int lyp_wd_flag;
#endif

    if (event == SR_EV_ABORT) {
        /* ignore in this case */
        return SR_ERR_OK;
    }

    /* Get username. It is assumed that right now the NETCONF session cannot end
     * due to the RPC lock held while np2srv_rpc_cb() is executing (which called this callback).
     */
    if ((username = (char *)np_get_nc_sess_user(session))) {
        if (!(username = strdup(username))) {
            EMEM;
            rc = SR_ERR_NOMEM;
            goto cleanup;
        }
    } else {
        EINT;
        rc = SR_ERR_INTERNAL;
        goto cleanup;
    }


    /* get know which datastores are affected */
    nodeset = lyd_find_path(input, "target/*");
    if (!strcmp(nodeset->set.d[0]->schema->name, "running")) {
        ds = SR_DS_RUNNING;
    } else if (!strcmp(nodeset->set.d[0]->schema->name, "startup")) {
        ds = SR_DS_STARTUP;
    } else if (!strcmp(nodeset->set.d[0]->schema->name, "candidate")) {
        ds = SR_DS_CANDIDATE;
    } else {
        assert(!strcmp(nodeset->set.d[0]->schema->name, "url"));
#ifdef NP2SRV_URL_CAPAB
        trg_url = ((struct lyd_node_leaf_list *)nodeset->set.d[0])->value_str;
#else
        ly_set_free(nodeset);
        rc = SR_ERR_UNSUPPORTED;
        sr_set_error(session, NULL, "URL not supported.");
        goto cleanup;
#endif
    }
    ly_set_free(nodeset);

    nodeset = lyd_find_path(input, "source/*");
    if (!strcmp(nodeset->set.d[0]->schema->name, "running")) {
        sds = SR_DS_RUNNING;
        if (ds == SR_DS_STARTUP) {
            /* special copy-config from running to startup that bypasses NACM */
            run_to_start = 1;
        }
    } else if (!strcmp(nodeset->set.d[0]->schema->name, "startup")) {
        sds = SR_DS_STARTUP;
    } else if (!strcmp(nodeset->set.d[0]->schema->name, "candidate")) {
        sds = SR_DS_CANDIDATE;
    } else if (!strcmp(nodeset->set.d[0]->schema->name, "config")) {
        config = op_parse_config((struct lyd_node_anydata *)nodeset->set.d[0], LYD_OPT_CONFIG | LYD_OPT_STRICT, &rc, session);
        if (rc) {
            ly_set_free(nodeset);
            goto cleanup;
        }
    } else {
        assert(!strcmp(nodeset->set.d[0]->schema->name, "url"));
#ifdef NP2SRV_URL_CAPAB
        if (trg_url && !strcmp(trg_url, ((struct lyd_node_leaf_list *)nodeset->set.d[0])->value_str)) {
            rc = SR_ERR_INVAL_ARG;
            sr_set_error(session, NULL, "Source and target URLs are the same.");
            goto cleanup;
        }

        config = op_parse_url(((struct lyd_node_leaf_list *)nodeset->set.d[0])->value_str,
                LYD_OPT_CONFIG | LYD_OPT_STRICT | LYD_OPT_TRUSTED, &rc, session);
        if (rc) {
            ly_set_free(nodeset);
            goto cleanup;
        }
#else
        ly_set_free(nodeset);
        rc = SR_ERR_UNSUPPORTED;
        sr_set_error(session, NULL, "URL not supported.");
        goto cleanup;
#endif
    }
    ly_set_free(nodeset);

    if (ds == sds) {
        rc = SR_ERR_INVAL_ARG;
        sr_set_error(session, NULL, "Source and target datastores are the same.");
        goto cleanup;
    }

    /* NACM checks */
    if (!config && !run_to_start) {
        /* get source datastore data and filter them */
        sr_session_switch_ds(session, sds);
        rc = sr_get_data(session, "/*", 0, np2srv.sr_timeout, 0, &config);
        if (rc != SR_ERR_OK) {
            goto cleanup;
        }

        ncac_check_data_read_filter(&config, username);
    }

    /* get the user session */
    user_sess = np_get_user_sess(session);
    if (!user_sess) {
        EINT;
        rc = SR_ERR_INTERNAL;
        goto cleanup;
    }

    /* update sysrepo session datastore */
    sr_session_switch_ds(user_sess, ds);

    /* sysrepo API/URL handling */
#ifdef NP2SRV_URL_CAPAB
    if (trg_url) {
        /* we need with-defaults flag in this case */
        nodeset = lyd_find_path(input, "ietf-netconf-with-defaults:with-defaults");
        lyp_wd_flag = 0;
        if (nodeset->number) {
            leaf = (struct lyd_node_leaf_list *)nodeset->set.d[0];
            if (!strcmp(leaf->value_str, "report-all")) {
                lyp_wd_flag = LYP_WD_ALL;
            } else if (!strcmp(leaf->value_str, "report-all-tagged")) {
                lyp_wd_flag = LYP_WD_ALL_TAG;
            } else if (!strcmp(leaf->value_str, "trim")) {
                lyp_wd_flag = LYP_WD_TRIM;
            } else {
                assert(!strcmp(leaf->value_str, "explicit"));
                lyp_wd_flag = LYP_WD_EXPLICIT;
            }
        }
        ly_set_free(nodeset);

        if (op_export_url(trg_url, config, LYP_FORMAT | LYP_WITHSIBLINGS | lyp_wd_flag, &rc, session)) {
            goto cleanup;
        }
    } else
#endif
    {
        if (config) {
            /* config is spent */
            rc = sr_replace_config(user_sess, NULL, config, np2srv.sr_timeout, 1);
            config = NULL;
        } else {
            assert(run_to_start);

            /* set SID to skip NACM check, only one copy-config can be executed at once */
            ATOMIC_STORE_RELAXED(skip_nacm_sr_sid, sr_session_get_id(user_sess));
            rc = sr_copy_config(user_sess, NULL, sds, np2srv.sr_timeout, 1);
            ATOMIC_STORE_RELAXED(skip_nacm_sr_sid, 0);
        }
        if (rc != SR_ERR_OK) {
            sr_get_error(user_sess, &err_info);
            sr_set_error(session, err_info->err[0].xpath, err_info->err[0].message);
            goto cleanup;
        }
    }

    /* success */

cleanup:
    lyd_free_withsiblings(config);
    free(username);
    return rc;
}

int
np2srv_rpc_deleteconfig_cb(sr_session_ctx_t *session, const char *UNUSED(op_path), const struct lyd_node *input,
        sr_event_t event, uint32_t UNUSED(request_id), struct lyd_node *UNUSED(output), void *UNUSED(private_data))
{
    sr_datastore_t ds = 0;
    struct ly_set *nodeset;
    int rc = SR_ERR_OK;
    sr_session_ctx_t *user_sess;
    const sr_error_info_t *err_info;
#ifdef NP2SRV_URL_CAPAB
    struct lyd_node *config;
    const char *trg_url = NULL;
#endif

    if (event == SR_EV_ABORT) {
        /* ignore in this case */
        return SR_ERR_OK;
    }

    /* get know which datastore is affected */
    nodeset = lyd_find_path(input, "target/*");
    if (!strcmp(nodeset->set.d[0]->schema->name, "startup")) {
        ds = SR_DS_STARTUP;
    } else {
        assert(!strcmp(nodeset->set.d[0]->schema->name, "url"));
#ifdef NP2SRV_URL_CAPAB
        trg_url = ((struct lyd_node_leaf_list *)nodeset->set.d[0])->value_str;
#else
        ly_set_free(nodeset);
        rc = SR_ERR_UNSUPPORTED;
        sr_set_error(session, NULL, "URL not supported.");
        goto cleanup;
#endif
    }
    ly_set_free(nodeset);

    /* get the user session */
    user_sess = np_get_user_sess(session);
    if (!user_sess) {
        EINT;
        rc = SR_ERR_INTERNAL;
        goto cleanup;
    }

    /* update sysrepo session datastore */
    sr_session_switch_ds(user_sess, ds);

    /* sysrepo API/URL handling */
#ifdef NP2SRV_URL_CAPAB
    if (trg_url) {
        /* import URL to check its validity */
        config = op_parse_url(trg_url, LYD_OPT_CONFIG | LYD_OPT_STRICT | LYD_OPT_TRUSTED, &rc, session);
        if (rc) {
            goto cleanup;
        }
        lyd_free_withsiblings(config);

        /* upload empty config */
        if (op_export_url(trg_url, NULL, 0, &rc, session)) {
            goto cleanup;
        }
    } else
#endif
    {
        rc = sr_replace_config(user_sess, NULL, NULL, np2srv.sr_timeout, 1);
        if (rc != SR_ERR_OK) {
            sr_get_error(user_sess, &err_info);
            sr_set_error(session, err_info->err[0].xpath, err_info->err[0].message);
            goto cleanup;
        }
    }

    /* success */

cleanup:
    return rc;
}

int
np2srv_rpc_un_lock_cb(sr_session_ctx_t *session, const char *UNUSED(op_path), const struct lyd_node *input,
        sr_event_t event, uint32_t UNUSED(request_id), struct lyd_node *UNUSED(output), void *UNUSED(private_data))
{
    sr_datastore_t ds = 0;
    struct ly_set *nodeset;
    sr_session_ctx_t *user_sess;
    const sr_error_info_t *err_info;
    int rc = SR_ERR_OK;

    if (event == SR_EV_ABORT) {
        /* ignore in this case */
        return SR_ERR_OK;
    }

    /* get know which datastore is being affected */
    nodeset = lyd_find_path(input, "target/*");
    if (!strcmp(nodeset->set.d[0]->schema->name, "running")) {
        ds = SR_DS_RUNNING;
    } else if (!strcmp(nodeset->set.d[0]->schema->name, "startup")) {
        ds = SR_DS_STARTUP;
    } else {
        assert(!strcmp(nodeset->set.d[0]->schema->name, "candidate"));
        ds = SR_DS_CANDIDATE;
    }
    ly_set_free(nodeset);

    /* get the user session */
    user_sess = np_get_user_sess(session);
    if (!user_sess) {
        EINT;
        rc = SR_ERR_INTERNAL;
        goto cleanup;
    }

    /* update sysrepo session datastore */
    sr_session_switch_ds(user_sess, ds);

    /* sysrepo API */
    if (!strcmp(input->schema->name, "lock")) {
        rc = sr_lock(user_sess, NULL);
    } else if (!strcmp(input->schema->name, "unlock")) {
        rc = sr_unlock(user_sess, NULL);
    }
    if (rc != SR_ERR_OK) {
        sr_get_error(user_sess, &err_info);
        sr_set_error(session, err_info->err[0].xpath, err_info->err[0].message);
        goto cleanup;
    }

    /* success */

cleanup:
    return rc;
}

int
np2srv_rpc_kill_cb(sr_session_ctx_t *session, const char *UNUSED(op_path), const struct lyd_node *input,
        sr_event_t event, uint32_t UNUSED(request_id), struct lyd_node *UNUSED(output), void *UNUSED(private_data))
{
    struct nc_session *kill_sess;
    struct ly_set *nodeset;
    uint32_t kill_sid, i;
    int rc = SR_ERR_OK;

    if (event == SR_EV_ABORT) {
        /* ignore in this case */
        return SR_ERR_OK;
    }

    nodeset = lyd_find_path(input, "session-id");
    kill_sid = ((struct lyd_node_leaf_list *)nodeset->set.d[0])->value.uint32;
    ly_set_free(nodeset);

    if (kill_sid == sr_session_get_event_nc_id(session)) {
        rc = SR_ERR_INVAL_ARG;
        sr_set_error(session, NULL, "It is forbidden to kill own session.");
        goto cleanup;
    }

    for (i = 0; (kill_sess = nc_ps_get_session(np2srv.nc_ps, i)); ++i) {
        if (nc_session_get_id(kill_sess) == kill_sid) {
            break;
        }
    }
    if (!kill_sess) {
        rc = SR_ERR_INVAL_ARG;
        sr_set_error(session, NULL, "Session with the specified \"session-id\" not found.");
        goto cleanup;
    }

    /* kill the session */
    nc_session_set_status(kill_sess, NC_STATUS_INVALID);
    nc_session_set_term_reason(kill_sess, NC_SESSION_TERM_KILLED);
    nc_session_set_killed_by(kill_sess, kill_sid);

    /* success */

cleanup:
    return rc;
}

int
np2srv_rpc_commit_cb(sr_session_ctx_t *session, const char *UNUSED(op_path), const struct lyd_node *UNUSED(input),
        sr_event_t event, uint32_t UNUSED(request_id), struct lyd_node *UNUSED(output), void *UNUSED(private_data))
{
    int rc = SR_ERR_OK;
    sr_session_ctx_t *user_sess;
    const sr_error_info_t *err_info;

    if (event == SR_EV_ABORT) {
        /* ignore in this case */
        return SR_ERR_OK;
    }

    /* get the user session */
    user_sess = np_get_user_sess(session);
    if (!user_sess) {
        EINT;
        rc = SR_ERR_INTERNAL;
        goto cleanup;
    }

    /* update sysrepo session datastore */
    sr_session_switch_ds(user_sess, SR_DS_RUNNING);

    /* sysrepo API */
    rc = sr_copy_config(user_sess, NULL, SR_DS_CANDIDATE, np2srv.sr_timeout, 1);
    if (rc != SR_ERR_OK) {
        sr_get_error(user_sess, &err_info);
        sr_set_error(session, err_info->err[0].xpath, err_info->err[0].message);
        goto cleanup;
    }

    /* success */

cleanup:
    return rc;
}

int
np2srv_rpc_discard_cb(sr_session_ctx_t *session, const char *UNUSED(op_path), const struct lyd_node *UNUSED(input),
        sr_event_t event, uint32_t UNUSED(request_id), struct lyd_node *UNUSED(output), void *UNUSED(private_data))
{
    int rc = SR_ERR_OK;
    sr_session_ctx_t *user_sess;
    const sr_error_info_t *err_info;

    if (event == SR_EV_ABORT) {
        /* ignore in this case */
        return SR_ERR_OK;
    }

    /* get the user session */
    user_sess = np_get_user_sess(session);
    if (!user_sess) {
        EINT;
        rc = SR_ERR_INTERNAL;
        goto cleanup;
    }

    /* update sysrepo session datastore */
    sr_session_switch_ds(user_sess, SR_DS_CANDIDATE);

    /* sysrepo API */
    rc = sr_copy_config(user_sess, NULL, SR_DS_RUNNING, np2srv.sr_timeout, 1);
    if (rc != SR_ERR_OK) {
        sr_get_error(user_sess, &err_info);
        sr_set_error(session, err_info->err[0].xpath, err_info->err[0].message);
        goto cleanup;
    }

    /* success */

cleanup:
    return rc;
}

int
np2srv_rpc_validate_cb(sr_session_ctx_t *session, const char *UNUSED(op_path), const struct lyd_node *input,
        sr_event_t event, uint32_t UNUSED(request_id), struct lyd_node *UNUSED(output), void *UNUSED(private_data))
{
    sr_datastore_t ds;
    struct lyd_node *config = NULL;
    struct ly_set *nodeset;
    sr_session_ctx_t *user_sess;
    int rc = SR_ERR_OK;
    const sr_error_info_t *err_info;

    if (event == SR_EV_ABORT) {
        /* ignore in this case */
        return SR_ERR_OK;
    }

    /* get know which datastore is affected */
    nodeset = lyd_find_path(input, "source/*");
    if (nodeset->number) {
        if (!strcmp(nodeset->set.d[0]->schema->name, "running")) {
            ds = SR_DS_RUNNING;
        } else if (!strcmp(nodeset->set.d[0]->schema->name, "startup")) {
            ds = SR_DS_STARTUP;
        } else if (!strcmp(nodeset->set.d[0]->schema->name, "candidate")) {
            ds = SR_DS_CANDIDATE;
        } else if (!strcmp(nodeset->set.d[0]->schema->name, "config")) {
            /* config is also validated now */
            config = op_parse_config((struct lyd_node_anydata *)nodeset->set.d[0], LYD_OPT_CONFIG | LYD_OPT_STRICT, &rc, session);
            if (rc) {
                ly_set_free(nodeset);
                goto cleanup;
            }
        } else {
            assert(!strcmp(nodeset->set.d[0]->schema->name, "url"));
#ifdef NP2SRV_URL_CAPAB
            config = op_parse_url(((struct lyd_node_leaf_list *)nodeset->set.d[0])->value_str,
                    LYD_OPT_CONFIG | LYD_OPT_STRICT | LYD_OPT_TRUSTED, &rc, session);
            if (rc) {
                ly_set_free(nodeset);
                goto cleanup;
            }
#else
            ly_set_free(nodeset);
            rc = SR_ERR_UNSUPPORTED;
            sr_set_error(session, NULL, "URL not supported.");
            goto cleanup;
#endif
        }
    }
    ly_set_free(nodeset);

    if (!config) {
        /* get the user session */
        user_sess = np_get_user_sess(session);
        if (!user_sess) {
            EINT;
            rc = SR_ERR_INTERNAL;
            goto cleanup;
        }

        /* update sysrepo session datastore */
        sr_session_switch_ds(user_sess, ds);

        /* sysrepo API */
        rc = sr_validate(user_sess, NULL, 0);
        if (rc != SR_ERR_OK) {
            sr_get_error(user_sess, &err_info);
            sr_set_error(session, err_info->err[0].xpath, err_info->err[0].message);
            goto cleanup;
        }
    }

    /* success */

cleanup:
    lyd_free_withsiblings(config);
    return rc;
}

static int
np2srv_rpc_subscribe_append_str(const char *str, char **ret)
{
    void *mem;
    int len;

    if (!*ret) {
        *ret = strdup(str);
        if (!*ret) {
            EMEM;
            return SR_ERR_NOMEM;
        }
    } else {
        len = strlen(*ret);
        mem = realloc(*ret, len + strlen(str) + 1);
        if (!mem) {
            EMEM;
            return SR_ERR_NOMEM;
        }
        *ret = mem;
        strcat(*ret + len, str);
    }

    return SR_ERR_OK;
}

int
np2srv_rpc_subscribe_cb(sr_session_ctx_t *session, const char *UNUSED(op_path), const struct lyd_node *input,
        sr_event_t event, uint32_t UNUSED(request_id), struct lyd_node *UNUSED(output), void *UNUSED(private_data))
{
    struct ly_set *nodeset;
    const struct lys_module *ly_mod;
    struct lys_node *root, *next, *elem, *parent;
    struct nc_session *ncs;
    const char *stream;
    struct np2_filter filter = {0};
    char *xp = NULL;
    time_t start = 0, stop = 0;
    int rc = SR_ERR_OK, i;
    uint32_t idx;

    if (event == SR_EV_ABORT) {
        /* ignore in this case (not supported) */
        return SR_ERR_OK;
    }

    /* find this NETCONF session */
    for (i = 0; (ncs = nc_ps_get_session(np2srv.nc_ps, i)); ++i) {
        if (nc_session_get_id(ncs) == sr_session_get_event_nc_id(session)) {
            break;
        }
    }
    if (!ncs) {
        ERR("Failed to find NETCONF session SID %u.", sr_session_get_event_nc_id(session));
        rc = SR_ERR_INTERNAL;
        goto cleanup;
    }

    /* RFC 5277 section 6.5 */
    if (nc_session_get_notif_status(ncs)) {
        sr_set_error(session, NULL, "Session already subscribed.");
        return SR_ERR_EXISTS;
    }

    /* learn stream */
    nodeset = lyd_find_path(input, "stream");
    stream = ((struct lyd_node_leaf_list *)nodeset->set.d[0])->value_str;
    ly_set_free(nodeset);

    /* filter, join all into one xpath */
    nodeset = lyd_find_path(input, "filter");
    if (nodeset->number) {
        if (op_filter_create(nodeset->set.d[0], &filter)) {
            rc = SR_ERR_INTERNAL;
            goto cleanup;
        }

        /* all selection filters first */
        for (i = 0; i < filter.count; ++i) {
            if (!filter.filters[i].selection) {
                continue;
            }

            /* put all selection filters into parentheses */
            if (!xp) {
                if ((rc = np2srv_rpc_subscribe_append_str("(", &xp))) {
                    goto cleanup;
                }

                if ((rc = np2srv_rpc_subscribe_append_str(filter.filters[i].str, &xp))) {
                    goto cleanup;
                }
            } else {
                if ((rc = np2srv_rpc_subscribe_append_str(" or ", &xp))) {
                    goto cleanup;
                }

                if ((rc = np2srv_rpc_subscribe_append_str(filter.filters[i].str, &xp))) {
                    goto cleanup;
                }
            }
        }

        if (xp) {
            /* finish parentheses */
            if ((rc = np2srv_rpc_subscribe_append_str(")", &xp))) {
                goto cleanup;
            }
        }

        /* now append all content filters */
        for (i = 0; i < filter.count; ++i) {
            if (filter.filters[i].selection) {
                continue;
            }

            if (xp) {
                if ((rc = np2srv_rpc_subscribe_append_str(" and ", &xp))) {
                    goto cleanup;
                }
            }

            if ((rc = np2srv_rpc_subscribe_append_str(filter.filters[i].str, &xp))) {
                goto cleanup;
            }
        }
    }
    ly_set_free(nodeset);

    /* start time */
    nodeset = lyd_find_path(input, "startTime");
    if (nodeset->number) {
        start = nc_datetime2time(((struct lyd_node_leaf_list *)nodeset->set.d[0])->value_str);
    }
    ly_set_free(nodeset);

    /* stop time */
    nodeset = lyd_find_path(input, "stopTime");
    if (nodeset->number) {
        stop = nc_datetime2time(((struct lyd_node_leaf_list *)nodeset->set.d[0])->value_str);
    }
    ly_set_free(nodeset);

    /* set ongoing notifications flag */
    nc_session_set_notif_status(ncs, 1);

    /* sysrepo API */
    if (!strcmp(stream, "NETCONF")) {
        /* subscribe to all modules with notifications */
        idx = 0;
        while ((ly_mod = ly_ctx_get_module_iter(lyd_node_module(input)->ctx, &idx))) {
            rc = SR_ERR_OK;
            LY_TREE_FOR(ly_mod->data, root) {
                LY_TREE_DFS_BEGIN(root, next, elem) {
                    if (elem->nodetype == LYS_NOTIF) {
                        /* check that we are not in a grouping */
                        parent = lys_parent(elem);
                        while (parent && (parent->nodetype != LYS_GROUPING)) {
                            parent = lys_parent(parent);
                        }
                        if (!parent) {
                            rc = sr_event_notif_subscribe_tree(nc_session_get_data(ncs), ly_mod->name, xp, start, stop,
                                    np2srv_ntf_new_cb, ncs, np2srv.sr_notif_sub ? SR_SUBSCR_CTX_REUSE : 0, &np2srv.sr_notif_sub);
                            break;
                        }
                    }
                    LY_TREE_DFS_END(root, next, elem);
                }
                if (elem && (elem->nodetype == LYS_NOTIF)) {
                   break;
                }
            }
            if (rc != SR_ERR_OK) {
                goto cleanup;
            }
        }
    } else {
        rc = sr_event_notif_subscribe_tree(nc_session_get_data(ncs), stream, xp, start, stop, np2srv_ntf_new_cb, ncs,
                np2srv.sr_notif_sub ? SR_SUBSCR_CTX_REUSE : 0, &np2srv.sr_notif_sub);
    }
    if (rc != SR_ERR_OK) {
        goto cleanup;
    }

    /* success */

cleanup:
    op_filter_erase(&filter);
    free(xp);
    if (ncs && rc) {
        nc_session_set_notif_status(ncs, 0);
    }
    return rc;
}
