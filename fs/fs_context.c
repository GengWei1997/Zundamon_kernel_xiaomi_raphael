// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Filesystem context support.
 *
 * Backport of fs/fs_context.c from Linux 5.2, reduced to what the new mount
 * API needs on this tree.  The legacy backend converts the parameters
 * gathered by fsconfig() into a single option string and calls the
 * filesystem's old mount()/mount2() callback, so unmodified filesystems keep
 * working without touching their mount code.
 *
 * Original copyright:
 *   Copyright (C) 2017 Red Hat, Inc. All Rights Reserved.
 *   Written by David Howells (dhowells@redhat.com)
 */

#include <linux/fs_context.h>
#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/security.h>
#include <linux/mount.h>
#include <linux/nsproxy.h>
#include <linux/user_namespace.h>
#include <linux/cred.h>
#include <linux/namei.h>
#include <net/net_namespace.h>

/* Private data for the legacy (unconverted) filesystem backend. */
struct legacy_fs_context {
	char		*data;		/* Accumulated option string */
	size_t		size;		/* Allocated size of @data */
	size_t		used;		/* Used bytes, excluding NUL */
};

enum legacy_fs_param {
	LEGACY_FS_UNSET = 0,
	LEGACY_FS_MONOLITHIC_PARAMS,
	LEGACY_FS_INDIVIDUAL_PARAMS,
};

static void legacy_fs_context_free(struct fs_context *fc);
static int legacy_parse_param(struct fs_context *fc, struct fs_parameter *param);
static int legacy_parse_monolithic(struct fs_context *fc, void *data);
static int legacy_get_tree(struct fs_context *fc);
static int legacy_reconfigure(struct fs_context *fc);

const struct fs_context_operations legacy_fs_context_ops = {
	.free			= legacy_fs_context_free,
	.dup			= NULL,
	.parse_param		= legacy_parse_param,
	.parse_monolithic	= legacy_parse_monolithic,
	.get_tree		= legacy_get_tree,
	.reconfigure		= legacy_reconfigure,
};

/**
 * legacy_init_fs_context - Initialise a legacy filesystem context
 * @fc: The context to initialise
 *
 * Set up a context for a filesystem that has not been converted to the new
 * mount API.  The option string is accumulated here and handed to the old
 * mount()/mount2() callback when the tree is finally created.
 */
int legacy_init_fs_context(struct fs_context *fc)
{
	fc->fs_private = kzalloc(sizeof(struct legacy_fs_context), GFP_KERNEL);
	if (!fc->fs_private)
		return -ENOMEM;
	fc->ops = &legacy_fs_context_ops;
	return 0;
}
EXPORT_SYMBOL(legacy_init_fs_context);

/*
 * Allocate a filesystem context.
 */
static struct fs_context *alloc_fs_context(struct file_system_type *fs_type,
					   unsigned int sb_flags)
{
	struct fs_context *fc;
	int ret;

	fc = kzalloc(sizeof(struct fs_context), GFP_KERNEL);
	if (!fc)
		return ERR_PTR(-ENOMEM);

	mutex_init(&fc->uapi_mutex);

	fc->fs_type	= get_filesystem(fs_type);
	fc->cred	= get_current_cred();
	fc->net_ns	= get_net(current->nsproxy->net_ns);
	fc->user_ns	= get_user_ns(current_user_ns());
	fc->sb_flags	= sb_flags;
	fc->purpose	= FS_CONTEXT_FOR_MOUNT;

	if (fs_type->init_fs_context) {
		ret = fs_type->init_fs_context(fc);
	} else {
		ret = legacy_init_fs_context(fc);
	}

	if (ret < 0) {
		put_fs_context(fc);
		return ERR_PTR(ret);
	}

	fc->need_free = true;
	return fc;
}

/**
 * fs_context_for_mount - Allocate a filesystem context
 * @fs_type: The filesystem type.
 * @sb_flags: The initial set of superblock flags.
 *
 * Allocate a filesystem context for the purpose of creating a mount.
 */
struct fs_context *fs_context_for_mount(struct file_system_type *fs_type,
					unsigned int sb_flags)
{
	return alloc_fs_context(fs_type, sb_flags);
}
EXPORT_SYMBOL(fs_context_for_mount);

/**
 * fs_context_for_reconfigure - Create a filesystem context for reconfiguration
 * @dentry: The dentry to be reconfigurable
 * @sb_flags: Updated SB_* flags
 * @sb_flags_mask: Mask of SB_* flags to update
 *
 * Allocate a filesystem context for the purpose of reconfiguring an already
 * mounted superblock (the fspick()+fsconfig() path).
 */
struct fs_context *fs_context_for_reconfigure(struct dentry *dentry,
					      unsigned int sb_flags,
					      unsigned int sb_flags_mask)
{
	struct fs_context *fc;

	fc = alloc_fs_context(dentry->d_sb->s_type, sb_flags);
	if (IS_ERR(fc))
		return fc;

	fc->purpose	 = FS_CONTEXT_FOR_RECONFIGURE;
	fc->sb_flags	 = sb_flags;
	fc->sb_flags_mask = sb_flags_mask;

	/*
	 * Keep a reference to the root dentry of the superblock being
	 * reconfigured: reconfigure_super() and the legacy backend reach the
	 * superblock through fc->root, and vfs_clean_context() drops it again
	 * once the reconfiguration is done.  The dentry alone is not enough
	 * to keep the superblock alive, so pin s_active alongside it -- the
	 * matching deactivate_super() is in put_fs_context().
	 */
	fc->root = dget(dentry);
	atomic_inc(&dentry->d_sb->s_active);

	return fc;
}
EXPORT_SYMBOL(fs_context_for_reconfigure);

/**
 * vfs_dup_fs_context - Duplicate a filesystem context
 * @src_fc: The context to duplicate
 */
struct fs_context *vfs_dup_fs_context(struct fs_context *src_fc)
{
	struct fs_context *fc;
	struct legacy_fs_context *src, *dst;
	int ret;

	fc = kzalloc(sizeof(struct fs_context), GFP_KERNEL);
	if (!fc)
		return ERR_PTR(-ENOMEM);

	mutex_init(&fc->uapi_mutex);

	fc->ops		 = src_fc->ops;
	fc->fs_type	 = get_filesystem(src_fc->fs_type);
	fc->cred	 = get_current_cred();
	fc->net_ns	 = get_net(src_fc->net_ns);
	fc->user_ns	 = get_user_ns(src_fc->user_ns);
	fc->sb_flags	 = src_fc->sb_flags;
	fc->sb_flags_mask = src_fc->sb_flags_mask;
	fc->s_iflags	 = src_fc->s_iflags;
	fc->purpose	 = src_fc->purpose;
	fc->global	 = src_fc->global;

	if (src_fc->source) {
		fc->source = kstrdup(src_fc->source, GFP_KERNEL);
		if (!fc->source) {
			put_fs_context(fc);
			return ERR_PTR(-ENOMEM);
		}
	}

	/*
	 * Duplicate the accumulated legacy option string so both contexts can
	 * be freed independently.
	 */
	if (src_fc->fs_private && src_fc->ops == &legacy_fs_context_ops) {
		src = src_fc->fs_private;
		dst = kzalloc(sizeof(*dst), GFP_KERNEL);
		if (!dst) {
			put_fs_context(fc);
			return ERR_PTR(-ENOMEM);
		}
		if (src->data) {
			dst->data = kmemdup(src->data, src->size, GFP_KERNEL);
			if (!dst->data) {
				kfree(dst);
				put_fs_context(fc);
				return ERR_PTR(-ENOMEM);
			}
			dst->size = src->size;
			dst->used = src->used;
		}
		fc->fs_private = dst;
		fc->need_free = true;
	}

	if (fc->ops->dup) {
		ret = fc->ops->dup(fc, src_fc);
		if (ret < 0) {
			put_fs_context(fc);
			return ERR_PTR(ret);
		}
	}

	return fc;
}
EXPORT_SYMBOL(vfs_dup_fs_context);

/**
 * put_fs_context - Dispose of a filesystem context
 * @fc: The context to dispose of
 */
void put_fs_context(struct fs_context *fc)
{
	if (!fc)
		return;

	/*
	 * @fc->root carries its own s_active reference (taken by get_tree from
	 * the freshly built superblock), so releasing the dentry has to drop
	 * that reference too.  The mount, if any is still held here, has a
	 * separate one of its own.
	 */
	if (fc->root) {
		struct super_block *sb = fc->root->d_sb;

		dput(fc->root);
		fc->root = NULL;
		deactivate_super(sb);
	}
	if (fc->mnt) {
		mntput(fc->mnt);
		fc->mnt = NULL;
	}

	if (fc->need_free && fc->ops && fc->ops->free)
		fc->ops->free(fc);

	put_net(fc->net_ns);
	put_user_ns(fc->user_ns);
	put_cred(fc->cred);
	kfree(fc->source);
	kfree(fc);
}
EXPORT_SYMBOL(put_fs_context);

/*
 * Append one parameter to the accumulated legacy option string.
 */
static int legacy_parse_param(struct fs_context *fc, struct fs_parameter *param)
{
	struct legacy_fs_context *ctx = fc->fs_private;
	size_t need, used;
	char *new;

	if (!ctx)
		return -EINVAL;

	/*
	 * "source" and "subtype" are not options: they identify the device
	 * and select a filesystem subtype, and must be kept separate from the
	 * option string passed to mount().
	 */
	if (strcmp(param->key, "source") == 0) {
		if (param->type != fs_param_is_string)
			return -EINVAL;
		if (fc->source)
			return -EBUSY;
		fc->source = kstrndup(param->string, param->size, GFP_KERNEL);
		if (!fc->source)
			return -ENOMEM;
		return 0;
	}

	switch (param->type) {
	case fs_param_is_string:
		/* "key=value" plus a possible separator. */
		need = strlen(param->key) + 1 + param->size + 2;
		break;
	case fs_param_is_flag:
		/* Just the key. */
		need = strlen(param->key) + 2;
		break;
	default:
		/*
		 * Binary/fd parameters cannot be represented in the legacy
		 * option string; the caller gets a clear error rather than a
		 * silently mangled mount request.
		 */
		return -EOPNOTSUPP;
	}

	/*
	 * A comma inside a key or value would be re-interpreted as a
	 * separator by the filesystem's own option parser.
	 */
	if (strchr(param->key, ','))
		return -EINVAL;
	if (param->type == fs_param_is_string &&
	    memchr(param->string, ',', param->size))
		return -EINVAL;

	used = ctx->used;

	if (!ctx->data || used + need > ctx->size) {
		size_t newsize = max(used + need, max(ctx->size * 2, 256UL));

		new = krealloc(ctx->data, newsize, GFP_KERNEL);
		if (!new)
			return -ENOMEM;
		ctx->data = new;
		ctx->size = newsize;
	}

	if (used > 0)
		ctx->data[used++] = ',';

	if (param->type == fs_param_is_string) {
		used += sprintf(ctx->data + used, "%s=", param->key);
		memcpy(ctx->data + used, param->string, param->size);
		used += param->size;
	} else {
		used += sprintf(ctx->data + used, "%s", param->key);
	}
	ctx->data[used] = 0;
	ctx->used = used;

	return 0;
}

/*
 * Parse a monolithic option blob (the old mount data page).
 */
static int legacy_parse_monolithic(struct fs_context *fc, void *data)
{
	struct legacy_fs_context *ctx = fc->fs_private;
	char *options = data, *key;
	int ret = 0;

	if (!options)
		return 0;
	if (!ctx)
		return -EINVAL;

	/*
	 * A monolithic blob replaces whatever individual parameters have been
	 * collected so far; the two forms cannot be mixed.
	 */
	if (ctx->used)
		return -EBUSY;

	while ((key = strsep(&options, ",")) != NULL) {
		size_t v_len = 0;
		char *value;

		if (!*key)
			continue;

		value = strchr(key, '=');
		if (value) {
			if (value == key)
				continue;
			*value++ = 0;
			v_len = strlen(value);
		}
		ret = vfs_parse_fs_string(fc, key, value, v_len);
		if (ret < 0)
			break;
	}

	return ret;
}

/*
 * Create the superblock for a legacy filesystem.
 *
 * This only builds the superblock and its root dentry; no mount object is
 * created here.  fsmount() constructs the mount itself and takes its own
 * s_active reference, so the context and the mount each hold an independent
 * reference on the superblock.  Sharing a single reference between the two
 * is what makes the dentry outlive the superblock when the mount is
 * dissolved before the context is released.
 */
static int legacy_get_tree(struct fs_context *fc)
{
	struct legacy_fs_context *ctx = fc->fs_private;
	struct vfsmount *mnt;
	const char *name;

	name = fc->source ? fc->source : fc->fs_type->name;

	mnt = vfs_kern_mount(fc->fs_type, fc->sb_flags, name,
			     ctx ? ctx->data : NULL);
	if (IS_ERR(mnt))
		return PTR_ERR(mnt);

	/*
	 * vfs_kern_mount() returns a fully formed mount holding one s_active
	 * reference; that one goes to fsmount()'s mount object.  The context
	 * also needs a reference of its own: it keeps @fc->root across
	 * fsmount() so that a later fsconfig(FSCONFIG_CMD_RECONFIGURE) can
	 * still reach the superblock, exactly as fspick() would.  Two
	 * independent references are required -- sharing a single one is what
	 * lets the root dentry outlive its superblock.
	 */
	fc->root = dget(mnt->mnt_root);
	fc->mnt = mnt;
	atomic_inc(&mnt->mnt_sb->s_active);

	return 0;
}

/*
 * Reconfigure an already mounted superblock through the old remount_fs
 * callback.  Filesystems that do not implement remount_fs simply accept the
 * new superblock flags, which is what the old MS_REMOUNT path does as well.
 */
static int legacy_reconfigure(struct fs_context *fc)
{
	struct legacy_fs_context *ctx = fc->fs_private;
	struct super_block *sb = fc->root->d_sb;

	if (!sb->s_op->remount_fs)
		return 0;

	return sb->s_op->remount_fs(sb, &fc->sb_flags,
				    ctx ? ctx->data : NULL);
}

static void legacy_fs_context_free(struct fs_context *fc)
{
	struct legacy_fs_context *ctx = fc->fs_private;

	if (ctx) {
		kfree(ctx->data);
		kfree(ctx);
	}
	fc->fs_private = NULL;
}

/*
 * Superblock flags that may be set through the new mount API.  These are
 * handled by the VFS rather than by the filesystem, exactly as the old
 * mount() code did.
 */
static const struct constant_table common_set_sb_flag[] = {
	{ "dirsync",	SB_DIRSYNC },
	{ "lazytime",	SB_LAZYTIME },
	{ "mand",	SB_MANDLOCK },
	{ "posixacl",	SB_POSIXACL },
	{ "ro",		SB_RDONLY },
	{ "sync",	SB_SYNCHRONOUS },
	{ }
};

static const struct constant_table common_clear_sb_flag[] = {
	{ "async",	SB_SYNCHRONOUS },
	{ "nolazytime",	SB_LAZYTIME },
	{ "nomand",	SB_MANDLOCK },
	{ "rw",		SB_RDONLY },
	{ "silent",	SB_SILENT },
	{ }
};

static const char *const forbidden_sb_flag[] = {
	"bind",
	"dev",
	"exec",
	"move",
	"noatime",
	"nodev",
	"nodiratime",
	"noexec",
	"norelatime",
	"nostrictatime",
	"nosuid",
	"private",
	"rec",
	"relatime",
	"remount",
	"shared",
	"slave",
	"strictatime",
	"suid",
	"unbindable",
};

static int vfs_parse_sb_flag(struct fs_context *fc, const char *key)
{
	unsigned int token;
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(forbidden_sb_flag); i++)
		if (strcmp(key, forbidden_sb_flag[i]) == 0)
			return -EINVAL;

	token = lookup_constant(common_set_sb_flag, key, 0);
	if (token) {
		fc->sb_flags |= token;
		fc->sb_flags_mask |= token;
		return 0;
	}

	token = lookup_constant(common_clear_sb_flag, key, 0);
	if (token) {
		fc->sb_flags &= ~token;
		fc->sb_flags_mask |= token;
		return 0;
	}

	return -ENOPARAM;
}

/**
 * vfs_parse_fs_param - Add a parameter to a filesystem context
 * @fc: The filesystem context.
 * @param: The parameter.
 */
int vfs_parse_fs_param(struct fs_context *fc, struct fs_parameter *param)
{
	int ret;

	if (!param->key)
		return -EINVAL;

	ret = vfs_parse_sb_flag(fc, param->key);
	if (ret != -ENOPARAM)
		return ret;

	if (fc->ops->parse_param) {
		ret = fc->ops->parse_param(fc, param);
		if (ret != -ENOPARAM)
			return ret;
	}

	/*
	 * Filesystems that take no options get the default treatment of
	 * "source", so that the device can always be supplied.
	 */
	if (strcmp(param->key, "source") == 0) {
		if (param->type != fs_param_is_string)
			return -EINVAL;
		if (fc->source)
			return -EBUSY;
		fc->source = kstrndup(param->string, param->size, GFP_KERNEL);
		if (!fc->source)
			return -ENOMEM;
		return 0;
	}

	return -EINVAL;
}
EXPORT_SYMBOL(vfs_parse_fs_param);

/**
 * vfs_parse_fs_string - Convenience function to just specify a key/value pair
 * @fc: The filesystem context.
 * @key: Parameter name
 * @value: Value string
 * @v_size: Size of value
 */
int vfs_parse_fs_string(struct fs_context *fc, const char *key,
			const char *value, size_t v_size)
{
	struct fs_parameter param = {
		.key	= key,
		.type	= (value || v_size) ? fs_param_is_string : fs_param_is_flag,
		.string	= value,
		.size	= v_size,
	};

	return vfs_parse_fs_param(fc, &param);
}
EXPORT_SYMBOL(vfs_parse_fs_string);

/**
 * generic_parse_monolithic - Parse key[=val][,key[=val]]* mount data
 * @fc: The superblock configuration to fill in.
 * @data: The data to parse
 */
int generic_parse_monolithic(struct fs_context *fc, void *data)
{
	if (!data)
		return 0;
	if (!fc->ops->parse_monolithic)
		return -EINVAL;
	return fc->ops->parse_monolithic(fc, data);
}
EXPORT_SYMBOL(generic_parse_monolithic);

/**
 * vfs_get_tree - Get the mountable root
 * @fc: The superblock configuration context.
 *
 * Ask the filesystem to build (or find) its superblock and stow the resulting
 * mount instance in @fc->mnt.  Calling this twice on the same context is an
 * error: the caller owns the mount from then on.
 */
int vfs_get_tree(struct fs_context *fc)
{
	int ret;

	if (!fc->ops || !fc->ops->get_tree)
		return -EINVAL;

	if (fc->mnt)
		return -EBUSY;

	ret = fc->ops->get_tree(fc);
	if (ret < 0)
		return ret;

	if (!fc->mnt)
		return -EINVAL;

	return 0;
}
EXPORT_SYMBOL(vfs_get_tree);
