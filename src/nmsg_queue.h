/*
 * Copyright (c) 2016, CodeWard.org
 */
#ifndef _NMSG_QUEUE_H
#define _NMSG_QUEUE_H

#define NMSG_FLDDELIM	' '
#define NMSG_MSGDELIM	'\n'

enum
{
	NMSG_IF_MAXLEN = 127,
	NMSG_ID_MAXLEN = 127,
	NMSG_TYPE_MAXLEN = 8,
	NMSG_MAXLEN = NMSG_IF_MAXLEN + NMSG_ID_MAXLEN + NMSG_TYPE_MAXLEN
};

enum
{
	NMSG_EOK = 0,
	NMSG_ECON = 1,
	NMSG_ESYN = 2,
	NMSG_ECHR = 3
};

struct nmsg_text
{
	char iface[NMSG_IF_MAXLEN + 1];
	char id[NMSG_ID_MAXLEN + 1];
	char type[NMSG_TYPE_MAXLEN + 1];
};

struct nmsg_node
{
	char msg[NMSG_MAXLEN + 1];
	size_t len;
	struct nmsg_node *prev;
	struct nmsg_node *next;
};

struct nmsg_queue
{
	struct nmsg_node *st_node;
	struct nmsg_node *head;
	struct nmsg_node *tail;
	size_t len;
};

extern struct nmsg_node* nmsg_node_new (const struct nmsg_text *msg_text);

extern int nmsg_node_text (const struct nmsg_node *node, struct nmsg_text *msg_text);

extern void nmsg_queue_push (struct nmsg_queue *res, struct nmsg_node *node);

extern ssize_t nmsg_queue_serialize (struct nmsg_queue *res, char **buff);

extern ssize_t nmsg_queue_unserialize (struct nmsg_queue *res, const char *buff, size_t buff_len);

extern void nmsg_queue_delete (struct nmsg_queue *res, struct nmsg_node **node);

extern void nmsg_queue_free (struct nmsg_queue *res);

#endif

