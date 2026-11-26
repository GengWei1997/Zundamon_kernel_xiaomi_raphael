// SPDX-License-Identifier: GPL-2.0-or-later
/* Filesystem parameter parser.
 *
 * Backport of fs/fs_parser.c from Linux 5.4, adapted to the fs_parameter
 * representation used by this tree.  tmpfs needs it so that fsconfig() calls
 * from systemd succeed rather than being reported as "not converted to the
 * new mount API".
 *
 * Copyright (C) 2018 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 */

#include <linux/export.h>
#include <linux/fs_context.h>
#include <linux/fs_parser.h>
#include <linux/slab.h>
#include <linux/security.h>
#include <linux/namei.h>

static const struct constant_table bool_names[] = {
	{ "0",		false },
	{ "1",		true },
	{ "false",	false },
	{ "no",		false },
	{ "true",	true },
	{ "yes",	true },
};

/**
 * __lookup_constant - Look up a constant by name in an ordered table
 * @tbl: The table of constants to search.
 * @tbl_size: The size of the table.
 * @name: The name to look up.
 * @not_found: The value to return if the name is not found.
 */
int __lookup_constant(const struct constant_table *tbl, size_t tbl_size,
		      const char *name, int not_found)
{
	unsigned int i;

	for (i = 0; i < tbl_size; i++)
		if (strcmp(name, tbl[i].name) == 0)
			return tbl[i].value;

	return not_found;
}
EXPORT_SYMBOL(__lookup_constant);

static const struct fs_parameter_spec *fs_lookup_key(
	const struct fs_parameter_description *desc,
	const char *name)
{
	const struct fs_parameter_spec *p;

	if (!desc->specs)
		return NULL;

	for (p = desc->specs; p->name; p++)
		if (strcmp(p->name, name) == 0)
			return p;

	return NULL;
}

/*
 * fs_parse - Parse a filesystem configuration parameter
 * @fc: The filesystem context to log errors through.
 * @desc: The parameter description to use.
 * @param: The parameter.
 * @result: Where to place the result of the parse
 *
 * Parse a filesystem configuration parameter and attempt a conversion for a
 * simple parameter for which this is requested.  If successful, the determined
 * parameter ID is returned, the desired type is indicated in @result->t and
 * any converted value is placed into an appropriate member of the union in
 * @result.
 *
 * The function returns the parameter number if the parameter was matched,
 * -ENOPARAM if it wasn't matched and -EINVAL if there was a conversion issue.
 */
int fs_parse(struct fs_context *fc,
	     const struct fs_parameter_description *desc,
	     struct fs_parameter *param,
	     struct fs_parse_result *result)
{
	const struct fs_parameter_spec *p;
	const struct fs_parameter_enum *e;
	int ret = -ENOPARAM, b;

	result->has_value = !!param->string;
	result->negated = false;
	result->uint_64 = 0;

	p = fs_lookup_key(desc, param->key);
	if (!p) {
		/*
		 * If we didn't find something that looks like "noxxx", see if
		 * "xxx" takes the "no"-form negative - but only if there
		 * wasn't a value.
		 */
		if (result->has_value)
			goto unknown_parameter;
		if (param->key[0] != 'n' || param->key[1] != 'o' || !param->key[2])
			goto unknown_parameter;

		p = fs_lookup_key(desc, param->key + 2);
		if (!p)
			goto unknown_parameter;
		if (!(p->flags & fs_param_neg_with_no))
			goto unknown_parameter;
		result->boolean = false;
		result->negated = true;
	}

	if (p->flags & fs_param_deprecated)
		pr_warn("%s: Deprecated parameter '%s'\n",
			desc->name, param->key);

	if (result->negated)
		goto okay;

	/* Certain parameter types only take a string and convert it. */
	switch (p->type) {
	case __fs_param_wasnt_defined:
		return -EINVAL;
	case fs_param_is_u32:
	case fs_param_is_u32_octal:
	case fs_param_is_u32_hex:
	case fs_param_is_s32:
	case fs_param_is_u64:
	case fs_param_is_enum:
	case fs_param_is_string:
		if (param->type != fs_param_is_string)
			goto bad_value;
		if (!result->has_value) {
			if (p->flags & fs_param_v_optional)
				goto okay;
			goto bad_value;
		}
		/* Fall through */
	default:
		break;
	}

	/* Try to turn the type we were given into the type desired by the
	 * parameter and give an error if we can't.
	 */
	switch (p->type) {
	case fs_param_is_flag:
		if (param->type != fs_param_is_flag &&
		    (param->type != fs_param_is_string || result->has_value))
			goto bad_value;
		result->boolean = true;
		goto okay;

	case fs_param_is_bool:
		switch (param->type) {
		case fs_param_is_flag:
			result->boolean = true;
			goto okay;
		case fs_param_is_string:
			if (param->size == 0) {
				result->boolean = true;
				goto okay;
			}
			b = lookup_constant(bool_names, param->string, -1);
			if (b == -1)
				goto bad_value;
			result->boolean = b;
			goto okay;
		default:
			goto bad_value;
		}

	case fs_param_is_u32:
		ret = kstrtouint(param->string, 0, &result->uint_32);
		goto maybe_okay;
	case fs_param_is_u32_octal:
		ret = kstrtouint(param->string, 8, &result->uint_32);
		goto maybe_okay;
	case fs_param_is_u32_hex:
		ret = kstrtouint(param->string, 16, &result->uint_32);
		goto maybe_okay;
	case fs_param_is_s32:
		ret = kstrtoint(param->string, 0, &result->int_32);
		goto maybe_okay;
	case fs_param_is_u64:
		ret = kstrtoull(param->string, 0, &result->uint_64);
		goto maybe_okay;

	case fs_param_is_enum:
		for (e = desc->enums; e && e->name[0]; e++) {
			if (e->opt == p->opt &&
			    strcmp(e->name, param->string) == 0) {
				result->uint_32 = e->value;
				goto okay;
			}
		}
		goto bad_value;

	case fs_param_is_string:
		goto okay;
	case fs_param_is_blob:
		if (param->type != fs_param_is_blob)
			goto bad_value;
		goto okay;

	case fs_param_is_fd: {
		switch (param->type) {
		case fs_param_is_string:
			if (!result->has_value)
				goto bad_value;

			ret = kstrtouint(param->string, 0, &result->uint_32);
			break;
		case fs_param_is_fd:
			result->uint_32 = param->_fd;
			ret = 0;
			break;
		default:
			goto bad_value;
		}

		if (result->uint_32 > INT_MAX)
			goto bad_value;
		goto maybe_okay;
	}

	case fs_param_is_blockdev:
	case fs_param_is_path:
		goto okay;
	default:
		BUG();
	}

maybe_okay:
	if (ret < 0)
		goto bad_value;
okay:
	return p->opt;

bad_value:
	pr_warn("%s: Bad value for '%s'\n", desc->name, param->key);
	return -EINVAL;
unknown_parameter:
	return -ENOPARAM;
}
EXPORT_SYMBOL(fs_parse);

/**
 * fs_lookup_param - Look up a path referred to by a parameter
 * @fc: The filesystem context to log errors through.
 * @param: The parameter.
 * @want_bdev: T if want a blockdev
 * @_path: The result of the lookup
 */
/*
 * fs_lookup_param - Look up a path referred to by a parameter
 * @fc: The filesystem context to log errors through.
 * @param: The parameter.
 * @want_bdev: T if want a blockdev
 * @_path: The result of the lookup
 *
 * tmpfs does not use this; it exists so that filesystems converted later can.
 */
int fs_lookup_param(struct fs_context *fc,
		    struct fs_parameter *param,
		    bool want_bdev,
		    struct path *_path)
{
	char *buf;
	int ret;

	if (param->type != fs_param_is_string)
		return -EINVAL;

	buf = kstrdup(param->string, GFP_KERNEL);
	if (!buf)
		return -ENOMEM;

	ret = kern_path(buf, 0, _path);
	kfree(buf);
	return ret;
}
EXPORT_SYMBOL(fs_lookup_param);
