/*
 * Copyright (c) 2016, CodeWard.org
 */
#include <stdlib.h>
#include <string.h>
#include <pcap.h>

#include "session_data.h"

void
session_data_init (struct session_data *session_data)
{
	memset (session_data, 0, sizeof (struct session_data));
	session_data->fd = -1;
}

void
session_data_free (struct session_data *session_data)
{
	if ( session_data->handle != NULL )
		pcap_close (session_data->handle);

	if ( session_data->iface != NULL )
		free (session_data->iface);

	if ( session_data->dev != NULL )
		free (session_data->dev);
}

