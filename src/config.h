/*
 * Copyright (c) 2016, CodeWard.org
 */
#ifndef _CONFIG_H
#define _CONFIG_H

#include <stdlib.h>
#include <stdint.h>

#define CONF_FILTER_NAME_MAXLEN 128
#define CONF_FILTER_MAXCNT 512

#define CONF_ERRBUF_SIZE 256

struct config_filter
{
	char *name;
	char *iface;
	char *match;
	char *link_type;
	uint32_t session_timeout;
	uint8_t rfmon;
	struct config_filter *next;
};

struct config
{
	struct config_filter *head;
	struct config_filter *tail;
};

extern int config_load (struct config *conf, const char *filename, char *errbuf);

extern void config_unload (struct config *conf);

#endif

