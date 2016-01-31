/*
 * Copyright (c) 2016, CodeWard.org
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "nmsg_queue.h"

struct nmsg_node*
nmsg_node_new (const char *id, const char *event)
{
	struct nmsg_node *node;

	node = (struct nmsg_node*) malloc (sizeof (struct nmsg_node));

	if ( node == NULL )
		return NULL;

	memset (node, 0, sizeof (struct nmsg_node));

	snprintf (node->msg, sizeof (node->msg), "%s:%s%c", id, event, '\n');

	return node;
}

int
nmsg_node_extract (const struct nmsg_node *node, char *id, char *event)
{
	return 0;
}

void
nmsg_queue_init (struct nmsg_queue *res)
{
	memset (res, 0, sizeof (struct nmsg_queue));
}

void
nmsg_queue_push (struct nmsg_queue *res, struct nmsg_node *node)
{
	if ( res->head == NULL ){
		res->head = node;
		res->tail = res->head;
	} else {
		res->tail->next = node;
		res->tail = node;
	}

	res->len += strlen (node->msg);
}

char*
nmsg_queue_serialize (struct nmsg_queue *res)
{
	struct nmsg_node *node;
	char *buff;
	size_t bcp;

	buff = (char*) malloc (res->len + 1);

	if ( buff == NULL )
		return NULL;

	bcp = 0;

	for ( node = res->head; node != NULL; node = node->next ){
		strncpy ((char*) (buff + bcp), node->msg, res->len - bcp);
		bcp += strlen (node->msg);
	}

	buff[res->len] = '\0';

	return buff;
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

