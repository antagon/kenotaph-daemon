/*
 * Copyright (c) 2016, CodeWard.org
 */
#ifndef _NMSG_QUEUE_H
#define _NMSG_QUEUE_H

#define NMSG_MAXLEN 255

struct nmsg_node
{
	char msg[NMSG_MAXLEN + 1];
	struct nmsg_node *next;
};

struct nmsg_queue
{
	struct nmsg_node *head;
	struct nmsg_node *tail;
	size_t len;
};

extern struct nmsg_node* nmsg_node_new (const char *id, const char *event);

extern int nmsg_node_extract (const struct nmsg_node *node, char *id, char *event);


extern void nmsg_queue_init (struct nmsg_queue *res);

extern void nmsg_queue_push (struct nmsg_queue *res, struct nmsg_node *node);

extern char* nmsg_queue_serialize (struct nmsg_queue *res);

extern void nmsg_queue_free (struct nmsg_queue *res);

#endif

