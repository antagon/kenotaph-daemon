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
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <confuse.h>
#include <unistd.h>

#include "config.h"
#include "pathname.h"

int
main (int argc, char *argv[])
{
	struct config conf;
	struct pathname path_config;
	struct config_iface *confif_iter;
	int rval, exitno;

	exitno = EXIT_SUCCESS;

	memset (&conf, 0, sizeof (struct config));
	memset (&path_config, 0, sizeof (struct pathname));

	if ( argc < 2 ){
		fprintf (stdout, "Usage: %s <config-file>\n\nList all interfaces set in a monitor mode with a channel defined.\n", argv[0]);
		exitno = EXIT_FAILURE;
		goto cleanup;
	}

	// Change working directory to match the dirname of the config file.
	rval = path_split (argv[1], &path_config);

	if ( rval != 0 ){
		fprintf (stderr, "%s: cannot split path to a configuration file.\n", argv[0]);
		exitno = EXIT_FAILURE;
		goto cleanup;
	}

	rval = chdir (path_config.dir);

	if ( rval == -1 ){
		fprintf (stderr, "%s: cannot change directory to '%s': %s\n", argv[0], path_config.dir, strerror (errno));
		exitno = EXIT_FAILURE;
		goto cleanup;
	}

	rval = config_load (&conf, path_config.base, NULL);

	switch ( rval ){
		case CFG_FILE_ERROR:
			fprintf (stderr, "%s: cannot load a configuration file '%s': %s\n", argv[0], argv[optind], strerror (errno));
			exitno = EXIT_FAILURE;
			goto cleanup;

		case CFG_PARSE_ERROR:
			exitno = EXIT_FAILURE;
			goto cleanup;
	}

	for ( confif_iter = conf.head; confif_iter != NULL; confif_iter = confif_iter->next ){
		if ( !(confif_iter->mode & CONF_IF_MONITOR) || (confif_iter->channel == 0) )
			continue;

		fprintf (stdout, "%s %lu\n", confif_iter->name, confif_iter->channel);
	}

cleanup:
	config_unload (&conf);
	path_free (&path_config);

	return exitno;
}

