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
#ifndef _CONFIG_H
#define _CONFIG_H

#define CONF_DEVNAME_MAXLEN 64
#define CONF_ERRBUF_SIZE 1024

enum
{
	CONF_IF_PROMISC = 1,
	CONF_IF_MONITOR = 2
};

struct config_dev
{
	char *name;
	char *match;
	unsigned long int timeout;
	struct config_dev *next;
};

struct config_iface
{
	char *name;
	char *link_type;
	int mode;
	unsigned long int channel;
	struct config_dev *dev;
	struct config_iface *next;
};

struct config
{
	struct config_iface *head;
	struct config_iface *tail;
};

extern int config_load (struct config *conf, const char *filename, unsigned long *dev_cnt);

extern void config_unload (struct config *conf);

#endif

