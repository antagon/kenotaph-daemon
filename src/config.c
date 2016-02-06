/*
 * Copyright (c) 2016, CodeWard.org
 */
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <libconfig.h>

#include "config.h"

static int
filter_set_name (struct config_filter *filter, const char *name)
{
	if ( filter->name != NULL )
		free (filter->name);

	if ( name == NULL ){
		filter->name = NULL;
		return 0;
	}

	filter->name = strdup (name);
	
	if ( filter->name == NULL )
		return 1;
	
	return 0;
}

static int
filter_set_matchrule (struct config_filter *filter, const char *rule)
{
	if ( filter->match != NULL )
		free (filter->match);

	if ( rule == NULL ){
		filter->match = NULL;
		return 0;
	}

	filter->match = strdup (rule);

	if ( filter->match == NULL )
		return 1;
	
	return 0;
}

static int
filter_set_interface (struct config_filter *filter, const char *interface)
{
	if ( filter->iface != NULL )
		free (filter->iface);

	if ( interface == NULL ){
		filter->iface = NULL;
		return 0;
	}

	filter->iface = strdup (interface);

	if ( filter->iface == NULL )
		return 1;
	
	return 0;
}

static inline void
filter_set_timeout (struct config_filter *filter, uint32_t timeout)
{
	filter->timeout = timeout;
}

static inline void
filter_set_monitor_mode (struct config_filter *filter, uint8_t monitor_mode)
{
	filter->rfmon = monitor_mode;
}

static inline void
filter_set_promisc_mode (struct config_filter *filter, uint8_t promisc_mode)
{
	filter->promisc = promisc_mode;
}

static int
filter_set_link_type (struct config_filter *filter, const char *link_type)
{
	if ( filter->link_type != NULL )
		free (filter->link_type);

	if ( link_type == NULL ){
		filter->link_type = NULL;
		return 1;
	}

	filter->link_type = strdup (link_type);

	if ( filter->link_type == NULL )
		return 1;

	return 0;
}

static void
filter_destroy (struct config_filter *filter)
{
	if ( filter->name != NULL )
		free (filter->name);
	if ( filter->match != NULL )
		free (filter->match);
	if ( filter->iface != NULL )
		free (filter->iface);
	if ( filter->link_type != NULL )
		free (filter->link_type);
}

int
config_load (struct config *conf, const char *filename, char *errbuf)
{
	config_t libconfig;
	config_setting_t *root_setting;
	config_setting_t *filter_setting;
	struct config_filter *filter;
	struct stat fstat;
	const char *str_val;
	int i, filter_cnt, num;

	config_init (&libconfig);

	if ( stat (filename, &fstat) == -1 ){
		snprintf (errbuf, CONF_ERRBUF_SIZE, "%s", strerror (errno));
		config_destroy (&libconfig);
		return -1;
	}

	if ( S_ISDIR (fstat.st_mode) ){
		snprintf (errbuf, CONF_ERRBUF_SIZE, "is a directory");
		config_destroy (&libconfig);
		return -1;
	}

	if ( config_read_file (&libconfig, filename) == CONFIG_FALSE ){
		snprintf (errbuf, CONF_ERRBUF_SIZE, "%s on line %d", config_error_text (&libconfig), config_error_line (&libconfig));
		config_destroy (&libconfig);
		return -1;
	}

	root_setting = config_root_setting (&libconfig);
	filter_cnt = config_setting_length (root_setting);

	if ( filter_cnt > CONF_FILTER_MAXCNT ){
		snprintf (errbuf, CONF_ERRBUF_SIZE, "too many device rules defined (max %d)", CONF_FILTER_MAXCNT);
		config_destroy (&libconfig);
		return -1;
	}

	memset (errbuf, 0, sizeof (CONF_ERRBUF_SIZE));

	for ( i = 0; i < filter_cnt; i++ ){
		filter = (struct config_filter*) calloc (1, sizeof (struct config_filter));

		if ( filter == NULL ){
			snprintf (errbuf, CONF_ERRBUF_SIZE, "cannot allocate memory");
			config_destroy (&libconfig);
			return -1;
		}

		filter_setting = config_setting_get_elem (root_setting, i);

		if ( filter_setting == NULL ){
			snprintf (errbuf, CONF_ERRBUF_SIZE, "cannot get a device rule");
			free (filter);
			config_destroy (&libconfig);
			return -1;
		}

		str_val = config_setting_name (filter_setting);

		if ( str_val == NULL ){
			snprintf (errbuf, CONF_ERRBUF_SIZE, "device rule %d, has no name id", i + 1);
			free (filter);
			config_unload (conf);
			config_destroy (&libconfig);
			return -1;
		}

		if ( strlen (str_val) > CONF_FILTER_NAME_MAXLEN ){
			snprintf (errbuf, CONF_ERRBUF_SIZE, "device rule %d, name too long", i + 1);
			free (filter);
			config_destroy (&libconfig);
			return -1;
		}

		filter_set_name (filter, str_val);

		if ( config_setting_lookup_string (filter_setting, "match", &str_val) == CONFIG_FALSE ){
			str_val = NULL;
		}

		filter_set_matchrule (filter, str_val);

		if ( config_setting_lookup_int (filter_setting, "timeout", &num) == CONFIG_FALSE ){
			snprintf (errbuf, CONF_ERRBUF_SIZE, "device rule '%s', missing option 'timeout'", filter->name);
			filter_destroy (filter);
			free (filter);
			config_unload (conf);
			config_destroy (&libconfig);
			return -1;
		}

		if ( num == 0 ){
			snprintf (errbuf, CONF_ERRBUF_SIZE, "device rule '%s', 'timeout' must be >0", filter->name);
			filter_destroy (filter);
			free (filter);
			config_unload (conf);
			config_destroy (&libconfig);
			return -1;
		}
	
		filter_set_timeout (filter, ((num < 0)? (num * -1):num));

		if ( config_setting_lookup_bool (filter_setting, "monitor_mode", &num) == CONFIG_FALSE ){
			num = 0;
		}

		filter_set_monitor_mode (filter, num);

		if ( config_setting_lookup_bool (filter_setting, "promisc_mode", &num) == CONFIG_FALSE ){
			num = 1;
		}

		filter_set_promisc_mode (filter, num);

		if ( config_setting_lookup_string (filter_setting, "interface", &str_val) == CONFIG_FALSE ){
			snprintf (errbuf, CONF_ERRBUF_SIZE, "device rule '%s', missing option 'interface'", filter->name);
			filter_destroy (filter);
			free (filter);
			config_unload (conf);
			config_destroy (&libconfig);
			return -1;
		}

		if ( strlen (str_val) == 0 ){
			snprintf (errbuf, CONF_ERRBUF_SIZE, "device rule '%s', empty option 'interface'", filter->name);
			filter_destroy (filter);
			free (filter);
			config_unload (conf);
			config_destroy (&libconfig);
			return -1;
		}

		filter_set_interface (filter, str_val);

		if ( config_setting_lookup_string (filter_setting, "link_type", &str_val) == CONFIG_FALSE ){
			str_val = NULL;
		}

		filter_set_link_type (filter, str_val);

		if ( conf->head == NULL ){
			conf->head = filter;
			conf->tail = conf->head;
		} else {
			conf->tail->next = filter;
			conf->tail = filter;
		}
	}

	config_destroy (&libconfig); // destroy libconfig object

	return filter_cnt;
}

void
config_unload (struct config *conf)
{
	struct config_filter *filter, *filter_next;

	filter = conf->head;

	while ( filter != NULL ){
		filter_next = filter->next;
		filter_destroy (filter);
		free (filter);
		filter = filter_next;
	}

	conf->head = NULL;
	conf->tail = conf->head;
}

