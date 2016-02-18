/*
 * Copyright (c) 2016, CodeWard.org
 */
#ifndef _CONFIG_H
#define _CONFIG_H

#define CONF_DEVNAME_MAXLEN 64
#define CONF_ERRBUF_SIZE 1024

enum
{
	CONF_IF_PROMISC = 1,
	CONF_IF_MONITOR = 2
};

struct config_dev
{
	char *name;
	char *match;
	unsigned long int timeout;
	struct config_dev *next;
};

struct config_iface
{
	char *name;
	char *link_type;
	int mode;
	int enabled;
	struct config_dev *dev;
	struct config_iface *next;
};

struct config
{
	struct config_iface *head;
	struct config_iface *tail;
};

extern int config_load (struct config *conf, const char *filename);

extern void config_unload (struct config *conf);

#endif

