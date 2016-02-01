/*
 * Copyright (c) 2016, CodeWard.org
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

	snprintf (node->msg, sizeof (node->msg), "%s:%s\n", msg_text->id, msg_text->type);

	node->len = strlen (msg_text->id) + 1 + strlen (msg_text->type) + 1;

	return node;
}

int
nmsg_node_text (const struct nmsg_node *node, struct nmsg_text *msg_text)
{
	char *node_buff;
	size_t i, len, maxlen;
	int state;

	len = 0;
	maxlen = NMSG_ID_MAXLEN;
	node_buff = msg_text->id;
	state = NMSG_ECON;

	memset (msg_text, 0, sizeof (struct nmsg_text));

	for ( i = 0; i < node->len; i++ ){

		if ( node->msg[i] == ':' ){
			len = 0;
			maxlen = NMSG_TYPE_MAXLEN;
			node_buff = msg_text->type;
			continue;
		} else if ( node->msg[i] == '\n' ){
			state = NMSG_OK;
			break;
		}

		if ( len > maxlen )
			continue;

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
	static struct nmsg_node *node = NULL;
	size_t i;

	//node = NULL;

	for ( i = 0; i < buff_len; i++ ){

		if ( node == NULL ){
			node = (struct nmsg_node*) malloc (sizeof (struct nmsg_node));

			if ( node == NULL )
				return -1;

			memset (node, 0, sizeof (struct nmsg_node));

			nmsg_queue_push (res, node);
		}

		if ( node->len > NMSG_MAXLEN )
			continue;

		node->msg[node->len++] = buff[i];

		if ( buff[i] == '\n' ){
			node = NULL;
			continue;
		}
	}

	return i;
}

void
nmsg_queue_delete (struct nmsg_queue *res, struct nmsg_node *node)
{
	struct nmsg_node *prev_node, *next_node;

	prev_node = node->prev;
	next_node = node->next;

	free (node);

	if ( prev_node == NULL )
		res->head = next_node;
	else
		prev_node->next = next_node;

	if ( next_node == NULL )
		res->tail = prev_node;
	else
		next_node->prev = prev_node;

	return;
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

