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
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include "pidfile.h"

pid_t
pidfile_read (const char *filename)
{
	FILE *file;
	pid_t pid;
	int rval;

	file = fopen (filename, "r");

	// Pid file does not exists
	if ( file == NULL )
		return 0;

	rval = fscanf (file, "%d", &pid);

	if ( rval < 1 || rval == EOF )
		pid = -1;

	fclose (file);

	return pid;
}

int
pidfile_write (const char *filename)
{
	char buff[8];
	int fd, exitno;

	exitno = 0;

	fd = open (filename, O_WRONLY | O_CREAT, S_IWUSR | S_IRUSR);

	if ( fd == -1 )
		return -1;

	snprintf (buff, sizeof (buff), "%d", getpid ());

	if ( write (fd, buff, strlen (buff)) == -1 )
		exitno = -1;

	close (fd);

	return exitno;
}

