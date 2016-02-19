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
#include <libgen.h>

#include "pathname.h"

int
path_split (const char *path, struct pathname *pathname)
{
	pathname->bak = strdup (path);

	if ( pathname->bak == NULL )
		return 1;

	pathname->base = basename (pathname->bak);
	pathname->dir = dirname (pathname->bak);

	return 0;
}

void
path_free (struct pathname *pathname)
{
	if ( pathname->bak != NULL )
		free (pathname->bak);

	pathname->bak = NULL;
	pathname->base = NULL;
	pathname->dir = NULL;
}

