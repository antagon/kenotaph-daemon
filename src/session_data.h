/*
 * Copyright (c) 2016, CodeWard.org
 */
#ifndef _SESSION_DATA_H
#define _SESSION_DATA_H

#include <pcap.h>

#include "session_event.h"

struct session_data
{
	int fd;
	pcap_t *handle;
	char *iface;
	char *dev;
	struct session_event evt;
	unsigned long int timeout;
};

extern void session_data_init (struct session_data *session_data);

extern void session_data_free (struct session_data *session_data);

#endif

