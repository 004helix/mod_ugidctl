/*
 * This file is released under the GPL.
 */

#ifndef _UGIDCTL_H
#define _UGIDCTL_H
#include <linux/types.h>
#ifndef __KERNEL__
#include <sys/types.h>
#endif

struct ugidctl_key_rq {
	__u8 key[32];
};

struct ugidctl_add_rq {
	__u32 count;
	union {
		uid_t uid_list[0];
		gid_t gid_list[0];
	};
};

struct ugidctl_setid_rq {
	__u8 key[32];
	union {
		uid_t uid;
		gid_t gid;
	};
};

struct ugidctl_setgroups_rq {
	__u8 key[32];
	__u32 count;
	gid_t list[0];
};

/* limits */
#define UGIDCTL_UIDSMAX		1048576
#define UGIDCTL_GIDSMAX		1048576

/* pid check type */
#define UGIDCTL_PIDTYPE_PID	0
#define UGIDCTL_PIDTYPE_PGID	1
#define UGIDCTL_PIDTYPE_SID	2

/* ioctl interface */
#define UGIDCTLIO_GETKEY	_IOR ('S', 0x01, struct ugidctl_key_rq)
#define UGIDCTLIO_GETPIDCHKTYPE	_IO  ('S', 0x02)
#define UGIDCTLIO_SETPIDCHKTYPE	_IOW ('S', 0x03, unsigned long)
#define UGIDCTLIO_ADDUIDLIST	_IOW ('S', 0x04, struct ugidctl_add_rq)
#define UGIDCTLIO_ADDGIDLIST	_IOW ('S', 0x05, struct ugidctl_add_rq)
#define UGIDCTLIO_SETUID	_IOW ('S', 0x06, struct ugidctl_setid_rq)
#define UGIDCTLIO_SETGID	_IOW ('S', 0x07, struct ugidctl_setid_rq)
#define UGIDCTLIO_SETGROUPS	_IOWR('S', 0x08, struct ugidctl_setgroups_rq)

/* kernel-only API declarations */
#ifdef __KERNEL__

#ifdef CONFIG_COMPAT
#define UGIDCTLIO_SETPIDCHKTYPE_32 _IOW ('S', 0x03, unsigned int)
#endif

#define UGIDCTL_BULKSIZE	512

extern struct kmem_cache *uid_cache;
extern struct kmem_cache *gid_cache;

struct ugidctl_uid_node {
	struct rb_node node;
	uid_t uid;
};

struct ugidctl_gid_node {
	struct rb_node node;
	gid_t gid;
};

struct ugidctl_context {
	struct mutex	lock;
	pid_t		pid;
	enum pid_type	ptype;
	struct rb_root	uids;
	struct rb_root	gids;
	unsigned	uids_total;
	unsigned	gids_total;
	__u8		key[32];
};

extern int ugidctl_add_uid(struct ugidctl_context *ctx, uid_t uid);
extern int ugidctl_add_gid(struct ugidctl_context *ctx, gid_t gid);
extern int ugidctl_find_uid(struct ugidctl_context *ctx, uid_t uid);
extern int ugidctl_find_gid(struct ugidctl_context *ctx, gid_t gid);
extern void ugidctl_flush_uids(struct ugidctl_context *ctx);
extern void ugidctl_flush_gids(struct ugidctl_context *ctx);

#endif
#endif
