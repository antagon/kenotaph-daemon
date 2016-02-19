/*
 * kenotaphd - detect a presence of a network device
 * Copyright (C) 2016  CodeWard.org
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
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

