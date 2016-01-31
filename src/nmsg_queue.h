/*
 * Copyright (c) 2016, CodeWard.org
 */
#ifndef _NMSG_QUEUE_H
#define _NMSG_QUEUE_H

#define NMSG_ID_MAXLEN 127
#define NMSG_TYPE_MAXLEN 8

struct nmsg_node
{
	size_t len;
	char id[NMSG_ID_MAXLEN + 1];
	char type[NMSG_TYPE_MAXLEN + 1];
	struct nmsg_node *next;
};

struct nmsg_queue
{
	struct nmsg_node *head;
	struct nmsg_node *tail;
	size_t len;
};

extern struct nmsg_node* nmsg_node_new (const char *id, const char *event);

extern int nmsg_node_extract (const struct nmsg_node *node, char *id, char *type);


extern void nmsg_queue_push (struct nmsg_queue *res, struct nmsg_node *node);

extern ssize_t nmsg_queue_serialize (struct nmsg_queue *res, char **buff);

extern void nmsg_queue_free (struct nmsg_queue *res);

#endif

