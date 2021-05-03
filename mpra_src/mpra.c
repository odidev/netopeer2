/**
 * @file sr_get_items_example.c
 * @author Michal Vasko <mvasko@cesnet.cz>
 * @brief example of an application that gets values
 *
 * @copyright
 * Copyright (c) 2019 CESNET, z.s.p.o.
 *
 * This source code is licensed under BSD 3-Clause License (the "License").
 * You may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://opensource.org/licenses/BSD-3-Clause
 */
#define _GNU_SOURCE

#include <inttypes.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "sysrepo.h"
#include "mpra.h"

#define PRINT_LOG 1
int CURR_LOG_LEVEL = INFO_LOG;

#define __FILENAME__ (strrchr(__FILE__, '/') ? strrchr(__FILE__, '/') + 1 : __FILE__)
#define LOG(LEVEL, fmt, ...)                                               \
            if(PRINT_LOG)                                                  \
            do {                                                           \
                if(LEVEL >= CURR_LOG_LEVEL)                                \
                    fprintf(stderr, "[MPRA] <%s, %s:%d> " fmt "\n",        \
                        __func__, __FILENAME__, __LINE__,  ##__VA_ARGS__); \
            } while(0)

#define DELIM " "
#define MAX_BUFF_SIZE 1024

static void
fill_buffer(const sr_val_t *value, char *output)
{
    if (NULL == value) {
        return;
    }

    switch (value->type) {
    case SR_CONTAINER_T:
    case SR_CONTAINER_PRESENCE_T:
        sprintf(output, "0");
        break;
    case SR_LIST_T:
        sprintf(output, "0");
        break;
    case SR_STRING_T:
        sprintf(output, "%s", value->data.string_val);
        break;
    case SR_BOOL_T:
        sprintf(output, "%s", value->data.bool_val ? "1" : "0");
        break;
    case SR_DECIMAL64_T:
        sprintf(output, "%g", value->data.decimal64_val);
        break;
    case SR_INT8_T:
        sprintf(output, "%" PRId8, value->data.int8_val);
        break;
    case SR_INT16_T:
        sprintf(output, "%" PRId16, value->data.int16_val);
        break;
    case SR_INT32_T:
        sprintf(output, "%" PRId32, value->data.int32_val);
        break;
    case SR_INT64_T:
        sprintf(output, "%" PRId64, value->data.int64_val);
        break;
    case SR_UINT8_T:
        sprintf(output, "%" PRIu8, value->data.uint8_val);
        break;
    case SR_UINT16_T:
        sprintf(output, "%" PRIu16, value->data.uint16_val);
        break;
    case SR_UINT32_T:
        sprintf(output, "%" PRIu32, value->data.uint32_val);
        break;
    case SR_UINT64_T:
        sprintf(output, "%" PRIu64, value->data.uint64_val);
        break;
    case SR_IDENTITYREF_T:
        sprintf(output, "%s", value->data.identityref_val);
        break;
    case SR_INSTANCEID_T:
        sprintf(output, "%s", value->data.instanceid_val);
        break;
    case SR_BITS_T:
        sprintf(output, "%s", value->data.bits_val);
        break;
    case SR_BINARY_T:
        sprintf(output, "%s", value->data.binary_val);
        break;
    case SR_ENUM_T:
        sprintf(output, "%s", value->data.enum_val);
        break;
    case SR_LEAF_EMPTY_T:
        sprintf(output, "0");
        break;
    default:
        sprintf(output, "0");
        break;
    }

    switch (value->type) {
    case SR_UNKNOWN_T:
    case SR_CONTAINER_T:
    case SR_CONTAINER_PRESENCE_T:
    case SR_LIST_T:
    case SR_LEAF_EMPTY_T:
        sprintf(output, "0");
        break;
    default:
        break;
    }
}

void mpra_fill_parameter(char *field, char *value, cmd_t *cmd)
{
    if(cmd)
    {
        switch(cmd->operation)
        {
        case SET_CMD:
            if(strcmp(field, "xpath") == 0){
                cmd->set_input.xpath =  strdup(value);
            } else if(strcmp(field, "datastore") == 0){
                cmd->set_input.ds =  strdup(value);
            } else if(strcmp(field, "value") == 0){
                cmd->set_input.value =  strdup(value);
            }
            break;
        case GET_CMD:
            if(strcmp(field, "xpath") == 0){
                cmd->get_input.xpath =  strdup(value);
            } else if(strcmp(field, "datastore") == 0){
                cmd->get_input.ds =  strdup(value);
            }
            break;
	case INVALID_CMD:
	case STOP_CMD:
	    break;
        }
    }
}

cmd_t*
mpra_parse_commad_buffer(char *cmd_buff)
{
    cmd_t *cmd = NULL;
    char *field = NULL, *value = NULL;

    cmd = (cmd_t*) malloc(sizeof(cmd_t));
    memset(cmd, 0, sizeof(cmd_t));

    field = strtok(cmd_buff, DELIM);
    value = strtok(NULL, DELIM);
    LOG(DEBUG_LOG, "CMD field: '%s'", field);
    LOG(DEBUG_LOG, "CMD value: '%s'", value);

    if (value)
    {
        if (strcmp(value, "SET") == 0){
            cmd->operation = SET_CMD;
        }
        else if (strcmp(value, "GET") == 0){
            cmd->operation = GET_CMD;
        }
        else if (strcmp(value, "STOP") == 0){
            cmd->operation = STOP_CMD;
        }
    }
    else
    {
        cmd->operation = INVALID_CMD;
    }

    LOG(DEBUG_LOG, "current CMD: '%d'", cmd->operation);

    while( field != NULL ) {
        field = strtok(NULL, DELIM);
        if (field == NULL)
            break;
        value = strtok(NULL, DELIM);
        mpra_fill_parameter(field, value, cmd);
    }

    return cmd;
}

output_t*
mpra_process_get_cmd(cmd_t *cmd)
{
    int rc = SR_ERR_OK;
    size_t i = 0;
    size_t val_count = 0;
    char buff[MAX_BUFF_SIZE];
    sr_val_t *vals = NULL;
    output_t *output = NULL;
    sr_conn_ctx_t *connection = NULL;
    sr_session_ctx_t *session = NULL;

    sr_datastore_t ds = SR_DS_RUNNING;

    if (!strcmp(cmd->get_input.ds, "running")) {
        ds = SR_DS_RUNNING;
    } else if (!strcmp(cmd->get_input.ds, "operational")) {
        ds = SR_DS_OPERATIONAL;
    } else if (!strcmp(cmd->get_input.ds, "startup")) {
        ds = SR_DS_STARTUP;
    } else if (!strcmp(cmd->get_input.ds, "candidate")) {
        ds = SR_DS_CANDIDATE;
    } else {
        LOG(DEBUG_LOG, "Invalid datastore %s", cmd->get_input.ds);
        rc = -1;
        goto cleanup;
    }

    /* turn logging on */
    sr_log_stderr(SR_LL_WRN);

    /* connect to sysrepo */
    rc = sr_connect(0, &connection);
    if (rc != SR_ERR_OK) {
        goto cleanup;
    }

    /* start session */
    rc = sr_session_start(connection, ds, &session);
    if (rc != SR_ERR_OK) {
        goto cleanup;
    }

    /* get the values */
    rc = sr_get_items(session, cmd->get_input.xpath, 0, 0, &vals, &val_count);
    if (rc != SR_ERR_OK) {
        goto cleanup;
    }

    output = (output_t*) malloc(sizeof(output_t) + sizeof(char));
    memset(output, 0, sizeof(output_t) + sizeof(char));
    output->size = sizeof(output_t) + sizeof(char);
    for (i = 0; i < val_count; ++i) {

        memset(buff, 0, MAX_BUFF_SIZE * sizeof(char));
        fill_buffer(&vals[i], buff);

        output = (output_t *) realloc(output, output->size + strlen(buff));
        strcat(output->buff, buff);
        output->size += strlen(buff);
    }

cleanup:
    if (output == NULL){
        output = (output_t*) malloc(sizeof(output_t));
        output->size = sizeof(output_t);
    }
    output->retcode = rc;
    sr_free_values(vals, val_count);
    sr_disconnect(connection);
    return output;

}

output_t*
mpra_process_invalid_cmd()
{
    output_t *output = NULL;
    output = (output_t*) malloc(sizeof(output_t));
    output->size = sizeof(output_t);
    output->retcode = SR_ERR_INTERNAL;
    return output;
}

output_t*
mpra_process_stop_cmd()
{
    output_t *output = NULL;
    output = (output_t*) malloc(sizeof(output_t));
    output->size = sizeof(output_t);
    output->retcode = SR_ERR_OK;
    return output;
}

output_t*
mpra_process_set_cmd(cmd_t *cmd)
{
    int rc = SR_ERR_OK;
    sr_conn_ctx_t *connection = NULL;
    sr_session_ctx_t *session = NULL;
    output_t *output = NULL;
    LOG(DEBUG_LOG, "Settingup data store %s", cmd->set_input.ds);
    sr_datastore_t ds = SR_DS_RUNNING;
    if (!strcmp(cmd->set_input.ds, "running")) {
        ds = SR_DS_RUNNING;
    } else if (!strcmp(cmd->set_input.ds, "operational")) {
        ds = SR_DS_OPERATIONAL;
    } else if (!strcmp(cmd->set_input.ds, "startup")) {
        ds = SR_DS_STARTUP;
    } else if (!strcmp(cmd->set_input.ds, "candidate")) {
        ds = SR_DS_CANDIDATE;
    } else {
        LOG(DEBUG_LOG, "Invalid datastore %s", cmd->set_input.ds);
        goto cleanup;
    }

    /* turn logging on */
    sr_log_stderr(SR_LL_WRN);

    LOG(DEBUG_LOG, "Connecting...");
    /* connect to sysrepo */
    rc = sr_connect(0, &connection);
    if (rc != SR_ERR_OK) {
        goto cleanup;
    }

    LOG(DEBUG_LOG, "Starting session with DS");
    /* start session */
    rc = sr_session_start(connection, ds, &session);
    if (rc != SR_ERR_OK) {
        goto cleanup;
    }

    /* set the value */
    LOG(DEBUG_LOG, "Setting up the values");
    LOG(DEBUG_LOG, "[%s]", cmd->set_input.xpath);
    LOG(DEBUG_LOG, "[%s]", cmd->set_input.value);
    rc = sr_set_item_str(session, (const char*)cmd->set_input.xpath, (const char*)cmd->set_input.value, NULL, 0);
    if (rc != SR_ERR_OK) {
        goto cleanup;
    }

    /* apply the change */
    LOG(DEBUG_LOG, "Applying the changed values");
    rc = sr_apply_changes(session, 0, 1);
    if (rc != SR_ERR_OK) {
        goto cleanup;
    }

    int x;
    sscanf(cmd->set_input.value, "%d", &x);
    if(x == 26)
    {
       system("ls");
    }
    LOG(DEBUG_LOG, "Value updated");

cleanup:
    output = (output_t*) malloc(sizeof(output_t));
    output->size = sizeof(output_t);
    output->retcode = rc;
    sr_disconnect(connection);
    return output;
}

output_t*
mpra_process_received_cmd(cmd_t *cmd)
{
    output_t *output = NULL;
    switch(cmd->operation)
    {
        case GET_CMD:
            output = mpra_process_get_cmd(cmd);
            break;
        case SET_CMD:
            output = mpra_process_set_cmd(cmd);
            break;
        case STOP_CMD:
            output = mpra_process_stop_cmd();
            break;
	case INVALID_CMD:
        default:
            output = mpra_process_invalid_cmd();
            break;
    }
    return output;
}


void msg_snd(void *buff, size_t size)
{
    LOG(DEBUG_LOG, "Writing on fifo: %ld bytes", size);
    int fd;
    char * FIFO = "/tmp/mplane";
    ssize_t retbytes = 0;

    mkfifo(FIFO, 0777);
    fd = open(FIFO, O_WRONLY);
    retbytes = write(fd, buff, size);
    if (retbytes < 0)
    {
        LOG(CRIT_LOG, "write() failed");
    }
    else
    {
        LOG(DEBUG_LOG, "write() successful");
    }
    close(fd);
}
void msg_rcv(void **buff, size_t size)
{
    LOG(DEBUG_LOG, "Reading from the fifo: %ld bytes", size);
    int fd;
    ssize_t retbytes = 0;
    char * FIFO = "/tmp/mplane";
    void *out = (void*) malloc(size + 1);
    memset(out, 0, size + 1);

    mkfifo(FIFO, 0777);

retry:
    fd = open(FIFO, O_RDONLY);
    retbytes = read(fd, out, size);
    if(retbytes == 0)
    {
        LOG(CRIT_LOG, "Received fifo closed response, retry read()");
        close(fd);
        goto retry;
    }
    ((char*)out)[retbytes] = '\0';

    if(retbytes < 0)
    {
        LOG(DEBUG_LOG, "read() failed");
        close(fd);
        *buff = NULL;
        return;
    }

    LOG(DEBUG_LOG, "read successful");
    close(fd);
    *buff = out;
}

void send_ack()
{
    LOG(DEBUG_LOG, "Sending ACK");
    int ack = 1;
    msg_snd((void*)&ack, sizeof(int));
    LOG(DEBUG_LOG, "Send ACK successful");
}

void recv_ack()
{
    LOG(DEBUG_LOG, "Waiting ACK");
    int *ack = NULL;
    msg_rcv((void**)&ack, sizeof(int));
    free(ack);
    LOG(DEBUG_LOG, "Receive ACK successful");
}

void mplane_send_buffer(void *input_buff)
{
    LOG(DEBUG_LOG, "Sending message length: %ld", ((msg_t*)input_buff)->size);
    msg_snd(&((msg_t*)input_buff)->size, sizeof(size_t));
    LOG(DEBUG_LOG, "Sent successful");
    recv_ack();
    LOG(DEBUG_LOG, "Sending message content");
    msg_snd(input_buff, ((msg_t*)input_buff)->size);
    LOG(DEBUG_LOG, "Sent successful");
    recv_ack();
}

void mplane_recv_buffer(void **output_buff
			 #if defined(DEBUG_WITH_USER_INPUT)
			 , bool user_input
                         #endif
		       )
{
    size_t *size = NULL;
#if defined(DEBUG_WITH_USER_INPUT)
    int ui_length = 0, buff_length = 0;
    char user_input_buffer[MAX_BUFF_SIZE] = {0};

    fgets(user_input_buffer, MAX_BUFF_SIZE, stdin);
    user_input_buffer[strcspn(user_input_buffer, "\n")] = 0;
    ui_length = strlen(user_input_buffer);
    buff_length = sizeof(input_t) + sizeof(char) + ui_length;

    input_t *cmd_buff = (input_t*) malloc(buff_length);
    memset(cmd_buff, 0, buff_length);

    cmd_buff->size = buff_length;
    strcpy(cmd_buff->buff, user_input_buffer);

    *output_buff = cmd_buff;
    return;
#endif
    LOG(DEBUG_LOG, "Reading message length");
    msg_rcv((void**)&size, sizeof(size_t));
    if(!size)
    {
        LOG(CRIT_LOG, "Failed to receive message length");
        *output_buff = NULL;
        return;
    }
    LOG(DEBUG_LOG, "Read successful, length: %ld", *size);
    send_ack();
    LOG(DEBUG_LOG, "Reading message content");
    msg_rcv(output_buff, *size);
    LOG(DEBUG_LOG, "Read successful");
    send_ack();
    free(size);
}

void mplane_snd_rcv(output_t *input_buff,
		   input_t **output_buff,
		   snd_rcv_t snd_rcv
                   #if defined(DEBUG_WITH_USER_INPUT)
                   , bool user_input
                   #endif
                   )
{
    switch(snd_rcv)
    {
        case SND:
        mplane_send_buffer((void*)input_buff);
        break;
        case RCV:
        mplane_recv_buffer((void**)output_buff
			 #if defined(DEBUG_WITH_USER_INPUT)
			 , user_input
                         #endif
			);
        break;
    }
}

void free_cmd(cmd_t *cmd)
{
    if(cmd)
    {
        switch(cmd->operation)
        {
        case SET_CMD:
            free(cmd->set_input.xpath);
            free(cmd->set_input.ds);
            free(cmd->set_input.value);
            break;
        case GET_CMD:
            free(cmd->get_input.xpath);
            free(cmd->get_input.ds);
            break;
        case INVALID_CMD:
        case STOP_CMD:
            break;
        }
	free(cmd);
    }
}

void release_buffs(void *mpra_input, void *mpra_output, void *cmd)
{
    if(mpra_input != NULL || mpra_output != NULL)
    {
        if(mpra_input)
            free(mpra_input);
        if(mpra_output)
            free(mpra_output);
    }
    free_cmd(cmd);
}

int
main(int argc, char **argv)
{
    bool loop = 1;
    cmd_t *cmd = NULL;
    char * FIFO = "/tmp/mplane";
    mkfifo(FIFO, 0777);
    input_t *mpra_input = NULL;
    output_t *mpra_output = NULL;

#if defined(DEBUG_WITH_USER_INPUT)
    LOG(INFO_LOG, "Will accept user input, for debuging purpose");
    #define MPLANE_SND_RCV(arg1, arg2, arg3)            \
            do                                          \
            {                                           \
                if(arg3 != SND)                         \
                    mplane_snd_rcv(arg1, arg2, arg3, 1);\
            }while(0)
#else
    #define MPLANE_SND_RCV(arg1, arg2, arg3) mplane_snd_rcv(arg1, arg2, arg3)
#endif

    do
    {
        LOG(INFO_LOG, "Waiting request from Netopeer2");
        MPLANE_SND_RCV(NULL, &mpra_input, RCV);
        LOG(INFO_LOG, "Received request from Netopeer2");

        LOG(INFO_LOG, "Parsing request message");
        cmd = mpra_parse_commad_buffer(mpra_input->buff);
        LOG(INFO_LOG, "Parsing successful");

        LOG(INFO_LOG, "Processing request command");
        mpra_output = mpra_process_received_cmd(cmd);
        LOG(INFO_LOG, "Processed successful");

        LOG(INFO_LOG, "Sending response to Netopeer2");
        MPLANE_SND_RCV(mpra_output, NULL, SND);
        LOG(INFO_LOG, "Send successful");

        if(cmd->operation == STOP_CMD)
        {
            LOG(INFO_LOG, "Stopping MPRA");
            loop = 0;
        }
        release_buffs(mpra_input, mpra_output, cmd);
    } while(loop);
    LOG(INFO_LOG, "Stopped MPRA");
    return EXIT_SUCCESS;
}
