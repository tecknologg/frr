
#include "zebra.h"

#include "zlog.h"
#include "command.h"

static int zdf_cmp(const struct zlog_debugflag *a,
		   const struct zlog_debugflag *b)
{
	return strcmp(a->cli_name, b->cli_name);
}

DECLARE_RBTREE_UNIQ(zlog_debugflags, struct zlog_debugflag, zdf_item, zdf_cmp)

static struct zlog_debugflags_head zlog_debugflags;

void zlog_debugflag_register(struct zlog_debugflag *zdf)
{
	zlog_debugflags_add(&zlog_debugflags, zdf);
}

int zlog_debugflag_cli(struct zlog_debugflag *zdf, struct vty *vty,
			int argc, struct cmd_token *argv[])
{
	bool no;
	uint32_t bit;

	assert(argc > 0);

	no = !strcmp(argv[0]->text, "no");
	bit = (vty->node == ENABLE_NODE) ? ZDF_EPHEMERAL : ZDF_CONFIG;

	if (no)
		atomic_fetch_and_explicit(&zdf->enable, ~bit,
					  memory_order_relaxed);
	else
		atomic_fetch_or_explicit(&zdf->enable, bit,
					 memory_order_relaxed);

	return CMD_SUCCESS;
}
