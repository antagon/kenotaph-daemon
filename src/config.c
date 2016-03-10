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
#include <string.h>
#include <errno.h>
#include <confuse.h>

#include "config.h"

static cfg_opt_t dev_opts[] = {
	CFG_STR ("match", NULL, CFGF_NODEFAULT),
	CFG_INT ("timeout", 0, CFGF_NODEFAULT),
	CFG_END ()
};

static cfg_opt_t iface_opts[] = {
	CFG_BOOL ("monitor_mode", cfg_false, CFGF_NONE),
	CFG_BOOL ("promisc_mode", cfg_true, CFGF_NONE),
	CFG_BOOL ("enabled", cfg_true, CFGF_NONE),
	CFG_STR ("link_type", NULL, CFGF_NODEFAULT),
	CFG_SEC ("device", dev_opts, CFGF_TITLE | CFGF_MULTI | CFGF_NO_TITLE_DUPES),
	CFG_FUNC ("include", cfg_include),
	// This option is ignored by kenotaph-daemon but it allows external tools
	// get an information about a wireless channel on which we want to listen.
	CFG_INT ("channel", 0, CFGF_NONE),
	CFG_END ()
};

static cfg_opt_t conf_opts[] = {
	CFG_SEC ("interface", iface_opts, CFGF_TITLE | CFGF_MULTI | CFGF_NO_TITLE_DUPES),
	CFG_FUNC ("include", cfg_include),
	CFG_END ()
};

static int
cfg_validate_device (cfg_t *cfg, cfg_opt_t *opt)
{
	cfg_t *dev;

	dev = cfg_opt_getnsec (opt, cfg_opt_size (opt) - 1);

	if ( strlen (cfg_title (dev)) > CONF_DEVNAME_MAXLEN ){
		cfg_error (cfg, "device name too long (max %d)", CONF_DEVNAME_MAXLEN);
		return -1;
	}

	if ( cfg_size (dev, "match") == 0 ){
		cfg_error (cfg, "missing mandatory option 'match'");
		return -1;
	}

	if ( cfg_size (dev, "timeout") == 0 ){
		cfg_error (cfg, "missing mandatory option 'timeout'");
		return -1;
	}

	return 0;
}

static int
cfg_validate_device_timeout (cfg_t *cfg, cfg_opt_t *opt)
{
	long int val;

	val = cfg_opt_getnint (opt, 0);

	if ( val <= 0 ){
		cfg_error (cfg, "option 'timeout' must be >0");
		return -1;
	}

	return 0;
}

static void
config_dev_free (struct config_dev *conf_dev)
{
	if ( conf_dev->name != NULL )
		free (conf_dev->name);

	if ( conf_dev->match != NULL )
		free (conf_dev->match);
}

static void
config_iface_free (struct config_iface *conf_iface)
{
	struct config_dev *dev_iter, *dev_iter_next;

	if ( conf_iface->name != NULL )
		free (conf_iface->name);

	if ( conf_iface->link_type != NULL )
		free (conf_iface->link_type);

	for ( dev_iter = conf_iface->dev; dev_iter != NULL; ){
		dev_iter_next = dev_iter->next;
		config_dev_free (dev_iter);
		free (dev_iter);
		dev_iter = dev_iter_next;
	}
}

int
config_load (struct config *conf, const char *filename, unsigned long *dev_cnt)
{
	cfg_t *cfg, *cfg_iface, *cfg_dev;
	struct config_iface *conf_iface;
	struct config_dev *conf_dev, **conf_dev_tail;
	int i, j, exitno, sec_enabled;
	char *str_val;

	if ( dev_cnt != NULL )
		*dev_cnt = 0;

	cfg = cfg_init (conf_opts, CFGF_NONE);

	cfg_set_validate_func (cfg, "interface|device", cfg_validate_device);
	cfg_set_validate_func (cfg, "interface|device|timeout", cfg_validate_device_timeout);

	exitno = cfg_parse (cfg, filename);

	switch ( exitno ){
		case CFG_FILE_ERROR:
			goto cleanup;

		case CFG_PARSE_ERROR:
			goto cleanup;
	}

	for ( i = 0; i < cfg_size (cfg, "interface"); i++ ){
		cfg_iface = cfg_getnsec (cfg, "interface", i);

		// Check if this section is enabled and if there is at least one device
		// defined, if not skip this interface.
		if ( cfg_getbool (cfg_iface, "enabled") == cfg_true )
			sec_enabled = 1;
		else
			sec_enabled = 0;

		if ( cfg_size (cfg_iface, "device") == 0 )
			sec_enabled = 0;

		if ( ! sec_enabled )
			continue;

		conf_iface = (struct config_iface*) calloc (1, sizeof (struct config_iface));

		if ( conf_iface == NULL ){
			exitno = CFG_FILE_ERROR;
			goto cleanup;
		}

		// If we've got here, it means the section is enabled.
		conf_iface->enabled = 1;

		conf_iface->name = strdup (cfg_title (cfg_iface));

		if ( conf_iface->name == NULL ){
			free (conf_iface);
			exitno = CFG_FILE_ERROR;
			goto cleanup;
		}

		str_val = cfg_getstr (cfg_iface, "link_type");

		if ( str_val != NULL ){
			conf_iface->link_type = strdup (str_val);

			if ( conf_iface->link_type == NULL ){
				config_iface_free (conf_iface);
				free (conf_iface);
				exitno = CFG_FILE_ERROR;
				goto cleanup;
			}
		}

		if ( cfg_getbool (cfg_iface, "promisc_mode") == cfg_true )
			conf_iface->mode |= CONF_IF_PROMISC;

		if ( cfg_getbool (cfg_iface, "monitor_mode") == cfg_true )
			conf_iface->mode |= CONF_IF_MONITOR;

		conf_iface->channel = cfg_getint (cfg_iface, "channel");

		conf_dev_tail = &(conf_iface->dev);

		// Parse device sections
		for ( j = 0; j < cfg_size (cfg_iface, "device"); j++ ){
			cfg_dev = cfg_getnsec (cfg_iface, "device", j);

			conf_dev = (struct config_dev*) calloc (1, sizeof (struct config_dev));

			if ( conf_dev == NULL ){
				config_iface_free (conf_iface);
				free (conf_iface);
				exitno = CFG_FILE_ERROR;
				goto cleanup;
			}

			conf_dev->name = strdup (cfg_title (cfg_dev));

			if ( conf_dev->name == NULL ){
				free (conf_dev);
				config_iface_free (conf_iface);
				free (conf_iface);
				exitno = CFG_FILE_ERROR;
				goto cleanup;
			}

			conf_dev->match = strdup (cfg_getstr (cfg_dev, "match"));

			if ( conf_dev->match == NULL ){
				config_dev_free (conf_dev);
				free (conf_dev);
				config_iface_free (conf_iface);
				free (conf_iface);
				exitno = CFG_FILE_ERROR;
				goto cleanup;
			}

			conf_dev->timeout = cfg_getint (cfg_dev, "timeout");

			*conf_dev_tail = conf_dev;
			conf_dev_tail = &((*conf_dev_tail)->next);
		}

		if ( dev_cnt != NULL )
			(*dev_cnt)++;

		if ( conf->head == NULL ){
			conf->head = conf_iface;
			conf->tail = conf->head;
		} else {
			conf->tail->next = conf_iface;
			conf->tail = conf_iface;
		}
	}

cleanup:
	cfg_free (cfg);

	return exitno;
}

void
config_unload (struct config *conf)
{
	struct config_iface *iface_iter, *iface_iter_next;

	for ( iface_iter = conf->head; iface_iter != NULL; ){
		iface_iter_next = iface_iter->next;
		config_iface_free (iface_iter);
		free (iface_iter);
		iface_iter = iface_iter_next;
	}

	conf->head = NULL;
	conf->tail = NULL;
}

