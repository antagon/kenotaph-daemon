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
#include <string.h>
#include <limits.h>

#include "hostport_parser.h"

int
hostport_parse (const char *str, char *hostname, char *port)
{
	char *semicolon_pos;
	size_t cpy_cnt;

	semicolon_pos = strrchr (str, ':');

	if ( semicolon_pos == NULL )
		return -1;

	cpy_cnt = semicolon_pos - str;

	if ( cpy_cnt > HOST_NAME_MAX )
		cpy_cnt = HOST_NAME_MAX - 1;

	strncpy (hostname, str, cpy_cnt);
	hostname[cpy_cnt] = '\0';

	strncpy (port, (semicolon_pos + 1), PORT_MAX_LEN);
	port[PORT_MAX_LEN - 1] = '\0';

	return 0;
}

