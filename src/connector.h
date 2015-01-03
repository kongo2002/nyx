#ifndef __NYX_CONNECTOR_H__
#define __NYX_CONNECTOR_H__

typedef enum
{
    CMD_PING,
    CMD_VERSION,
    CMD_TERMINATE,
    CMD_SIZE
} connector_command_e;

const char *
connector_call(connector_command_e cmd);

int
parse_command(const char *input, connector_command_e *cmd);

void
connector_close();

void *
connector_start(void *nyx);

#endif

/* vim: set et sw=4 sts=4 tw=80: */
