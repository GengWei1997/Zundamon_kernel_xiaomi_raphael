/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Filesystem context support
 *
 * Backport of the filesystem context API from Linux 5.2, as far as it is
 * needed by the new mount API (fsopen/fsconfig/fsmount/fspick).
 *
 * Only the "legacy" backend is provided: filesystems that have not been
 * converted keep their old mount()/mount2() callback, and the parameters
 * collected by fsconfig() are handed to it as a single option string.  No
 * filesystem in this tree has been converted to the new API upstream, so the
 * legacy path is the only one that can be reached.
 */

#ifndef _LINUX_FS_CONTEXT_H
#define _LINUX_FS_CONTEXT_H

#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/mutex.h>
#include <linux/fs_parser.h>

struct cred;
struct dentry;
struct file_system_type;
struct net;
struct super_block;
struct user_namespace;
struct vfsmount;

enum fs_context_purpose {
	FS_CONTEXT_FOR_MOUNT,		/* New superblock for explicit mount */
	FS_CONTEXT_FOR_SUBMOUNT,	/* New superblock for automatic submount */
	FS_CONTEXT_FOR_RECONFIGURE,	/* Superblock reconfiguration (remount) */
};

/*
 * The phases a context goes through, mirroring upstream.  fsconfig() and
 * fsmount() check these so that a context cannot be configured and consumed
 * out of order.
 */
enum fs_context_phase {
	FS_CONTEXT_CREATE_PARAMS,	/* Still receiving new-superblock params */
	FS_CONTEXT_CREATING,		/* Called ->get_tree() to create the sb */
	FS_CONTEXT_AWAITING_MOUNT,	/* get_tree() done, waiting for fsmount() */
	FS_CONTEXT_AWAITING_RECONF,	/* Clean, ready for reconfiguration */
	FS_CONTEXT_RECONF_PARAMS,	/* Receiving reconfiguration params */
	FS_CONTEXT_RECONFIGURING,	/* Called ->reconfigure() */
	FS_CONTEXT_FAILED,		/* Should be discarded */
};

struct fs_context_operations;

/*
 * The filesystem context holds the parameters collected by fsconfig() and
 * hands them to the filesystem when the superblock is created.
 */
struct fs_context {
	const struct fs_context_operations *ops;
	struct mutex		uapi_mutex;	/* Userspace access mutex */
	struct file_system_type	*fs_type;
	void			*fs_private;	/* The filesystem's context */
	void			*sget_key;
	struct dentry		*root;		/* The root of the new superblock */
	struct vfsmount		*mnt;		/* The mount instance, once built */
	struct user_namespace	*user_ns;	/* The user namespace for this mount */
	struct net		*net_ns;	/* The network namespace for this mount */
	const struct cred	*cred;		/* The mounter's credentials */
	char			*source;	/* The source name (eg. dev path) */
	void			*security;	/* LSM options */
	unsigned int		sb_flags;	/* Superblock flags */
	unsigned int		sb_flags_mask;	/* Superblock flags that were changed */
	unsigned int		s_iflags;	/* Internal SB_I_* flags */
	unsigned int		lsm_flags;	/* Information flags from the fs to the LSM */
	enum fs_context_purpose	purpose:8;
	enum fs_context_phase	phase:8;	/* The phase the context is in */
	bool			need_free:1;	/* Need to call ops->free() */
	bool			global:1;	/* Goes into &init_user_ns */
	bool			oldapi:1;	/* Coming from the old mount API */
};

struct fs_context_operations {
	void (*free)(struct fs_context *fc);
	int (*dup)(struct fs_context *fc, struct fs_context *src_fc);
	int (*parse_param)(struct fs_context *fc, struct fs_parameter *param);
	int (*parse_monolithic)(struct fs_context *fc, void *data);
	int (*get_tree)(struct fs_context *fc);
	int (*reconfigure)(struct fs_context *fc);
};

/*
 * fs_context manipulation functions.
 */
extern struct fs_context *fs_context_for_mount(struct file_system_type *fs_type,
					      unsigned int sb_flags);
extern struct fs_context *fs_context_for_reconfigure(struct dentry *dentry,
					      unsigned int sb_flags,
					      unsigned int sb_flags_mask);
extern struct fs_context *vfs_dup_fs_context(struct fs_context *fc);
extern void put_fs_context(struct fs_context *fc);
extern int vfs_parse_fs_param(struct fs_context *fc,
			      struct fs_parameter *param);
extern int vfs_parse_fs_string(struct fs_context *fc, const char *key,
			       const char *value, size_t v_size);
extern int generic_parse_monolithic(struct fs_context *fc, void *data);
extern int vfs_get_tree(struct fs_context *fc);
extern int reconfigure_super(struct fs_context *fc);

extern int get_tree_nodev(struct fs_context *fc,
			  int (*fill_super)(struct super_block *,
					    struct fs_context *));
extern struct vfsmount *vfs_mount_from_super(struct file_system_type *type,
					     struct super_block *sb,
					     const char *name);

extern const struct fs_context_operations legacy_fs_context_ops;
extern int legacy_init_fs_context(struct fs_context *fc);

#endif /* _LINUX_FS_CONTEXT_H */
