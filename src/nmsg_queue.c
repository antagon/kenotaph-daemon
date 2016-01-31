/*
 * Copyright (c) 2016, CodeWard.org
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "nmsg_queue.h"

struct nmsg_node*
nmsg_node_new (const char *id, const char *type)
{
	struct nmsg_node *node;

	node = (struct nmsg_node*) malloc (sizeof (struct nmsg_node));

	if ( node == NULL )
		return NULL;

	// Length: id + semicolon + type + newline
	node->len = strlen (id) + 1 + strlen (type) + 1;

	strncpy (node->id, id, NMSG_ID_MAXLEN);
	node->id[NMSG_ID_MAXLEN] = '\0';

	strncpy (node->type, type, NMSG_TYPE_MAXLEN);
	node->type[NMSG_TYPE_MAXLEN] = '\0';

	node->next = NULL;

	return node;
}

int
nmsg_node_extract (const struct nmsg_node *node, char *id, char *event)
{
	return 0;
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
		bcp += snprintf ((char*) (*buff + bcp), res->len - bcp, "%s:%s%c", node->id, node->type, '\n');
	}

	return bcp;
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

