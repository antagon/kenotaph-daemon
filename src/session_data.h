/*
 * Copyright (c) 2013 - 2016, CodeWard.org
 */
#ifndef _SESSION_DATA_H
#define _SESSION_DATA_H

#include <stdint.h>
#include <pcap.h>
#include <wordexp.h>

#include "session_event.h"

struct session_data
{
	int fd;
	pcap_t *handle;
	char *filter_name;
	struct session_event evt;
	uint32_t timeout;
};

extern void session_data_init (struct session_data *session_data);

extern void session_data_free (struct session_data *session_data);

#endif

