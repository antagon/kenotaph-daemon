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

#include "nmsg_queue.h"

struct nmsg_node*
nmsg_node_new (const struct nmsg_text *msg_text)
{
	struct nmsg_node *node;

	node = (struct nmsg_node*) malloc (sizeof (struct nmsg_node));

	if ( node == NULL )
		return NULL;

	memset (node, 0, sizeof (struct nmsg_node));

	node->len = snprintf (node->msg, sizeof (node->msg), "%s%c%s%c%s%c",
							msg_text->type, NMSG_FLDDELIM,
							msg_text->id, NMSG_FLDDELIM,
							msg_text->iface, NMSG_MSGDELIM);

	return node;
}

int
nmsg_node_text (const struct nmsg_node *node, struct nmsg_text *msg_text)
{
	char *node_buff;
	size_t i, len, maxlen;
	int state, syntax;

	len = 0;
	maxlen = NMSG_ID_MAXLEN;
	node_buff = msg_text->id;

	state = NMSG_ECON;
	syntax = NMSG_ESYN;

	memset (msg_text, 0, sizeof (struct nmsg_text));

	for ( i = 0; i < node->len; i++ ){

		if ( node->msg[i] == NMSG_FLDDELIM ){
			len = 0;
			maxlen = NMSG_TYPE_MAXLEN;
			node_buff = msg_text->type;
			syntax = NMSG_ESYN;
			continue;
		} else if ( node->msg[i] == NMSG_MSGDELIM ){
			state = (syntax == NMSG_EOK)? NMSG_EOK:NMSG_ESYN;
			break;
		}

		if ( len > maxlen )
			continue;

		syntax = NMSG_EOK;

		node_buff[len++] = node->msg[i];
	}

	return state;
}

void
nmsg_queue_push (struct nmsg_queue *res, struct nmsg_node *node)
{
	if ( res->head == NULL ){
		node->prev = res->head;
		res->head = node;
		res->tail = res->head;
	} else {
		node->prev = res->tail;
		res->tail->next = node;
		res->tail = node;
	}

	res->len += node->len;
}

ssize_t
nmsg_queue_serialize (struct nmsg_queue *res, char **buff)
{
	struct nmsg_node *node;
	size_t bcp;

	if ( res->len < 1 )
		return 0;

	*buff = (char*) malloc (res->len + 1);

	if ( *buff == NULL )
		return -1;

	bcp = 0;

	for ( node = res->head; node != NULL; node = node->next ){
		bcp += snprintf ((char*) (*buff + bcp), (res->len + 1) - bcp, "%s", node->msg);
	}

	return bcp;
}

ssize_t
nmsg_queue_unserialize (struct nmsg_queue *res, const char *buff, size_t buff_len)
{
	struct nmsg_node **node;
	size_t i;

	node = &(res->st_node);

	for ( i = 0; i < buff_len; i++ ){

		if ( *node == NULL ){
			*node = (struct nmsg_node*) malloc (sizeof (struct nmsg_node));

			if ( *node == NULL )
				return -1;

			memset (*node, 0, sizeof (struct nmsg_node));

			nmsg_queue_push (res, *node);
		}

		// Check if we have reached end of nmsg message buffer, if so,
		// terminate the message with newline character and exit.
		if ( (*node)->len == NMSG_MAXLEN ){
			(*node)->msg[(*node)->len - 1] = NMSG_MSGDELIM;
			break;
		}

		(*node)->msg[(*node)->len++] = buff[i];

		if ( buff[i] == NMSG_MSGDELIM ){
			*node = NULL;
			continue;
		}
	}

	return i;
}

void
nmsg_queue_delete (struct nmsg_queue *res, struct nmsg_node **node)
{
	struct nmsg_node *prev_node, *next_node;

	prev_node = (*node)->prev;
	next_node = (*node)->next;

	free (*node);

	if ( prev_node == NULL )
		res->head = next_node;
	else
		prev_node->next = next_node;

	if ( next_node == NULL )
		res->tail = prev_node;
	else
		next_node->prev = prev_node;

	if ( *node == res->st_node )
		res->st_node = NULL;

	*node = next_node;
}

void
nmsg_queue_free (struct nmsg_queue *res)
{
	struct nmsg_node *node, *node_next;

	node = res->head;

	while ( node != NULL ){
		node_next = node->next;
		free (node);
		node = node_next;
	}

	memset (res, 0, sizeof (struct nmsg_queue));
}

