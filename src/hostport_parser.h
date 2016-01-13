/*
 * Copyright (c) 2016, CodeWard.org
 */
#ifndef _HOSTFORMAT_H
#define _HOSTFORMAT_H

#define PORT_MAX_LEN 6

extern int hostport_parse (const char *str, char *hostname, char *port);

#endif

