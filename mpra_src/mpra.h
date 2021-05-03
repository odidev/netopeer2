typedef enum
{
    DEBUG_LOG,
    INFO_LOG,
    CRIT_LOG
} logleve_t;

typedef enum
{
    SET_CMD,
    GET_CMD,
    STOP_CMD,
    INVALID_CMD
} operation_t;

typedef enum
{
    SND,
    RCV
} snd_rcv_t;

typedef enum
{
    MSG_01,
    MSG_02
} msg_type;

typedef struct
{
    char *value;
    char *ds;
    char *xpath;
} set_input_t;

typedef struct
{
    char *ds;
    char *xpath;
} get_input_t;

typedef struct
{
    operation_t operation;
    union
    {
        set_input_t set_input;
        get_input_t get_input;
    };
} cmd_t;

typedef struct
{
    size_t size;
    size_t retcode;
    char buff[0];
} output_t;

typedef struct
{
    size_t size;
    char buff[0];
} input_t;
typedef struct
{
    size_t size;
    union
    {
        output_t output;
	input_t input;
    };
} msg_t;
