#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <getopt.h>
#include <xtables.h>
#include "xt_dpi.h"

#define DPI_VERSION         "0.01"

#define MAX_FN_LEN 256
#define PACKET_TO_CHECK_DEFAULT 10

static void
DPI_help(void)
{
    printf("DPI v%s .\n", DPI_VERSION);
}

static void
DPI_init(struct xt_entry_target *t)
{	
    ;
}

static struct option DPI_opts[] = {
	{ .name = NULL }
};

static int
DPI_parse(int c, char **argv, int invert, unsigned int *flags,
      const void *entry, struct xt_entry_target **target)
{
    printf("DPI: %s\n", __FUNCTION__);
	return 1;
}

static void 
DPI_print(const void *ip, const struct xt_entry_target *target, int numeric)
{
    printf("DPI: %s\n", __FUNCTION__);
    return;
}

static void 
DPI_save(const void *ip, const struct xt_entry_target *target)
{
    printf("DPI: %s\n", __FUNCTION__);
}

static struct xtables_target dpi_target_reg = { 
	.name           = "DPI",
	.version        = XTABLES_VERSION,
    .family         = NFPROTO_IPV4,
    .size           = XT_ALIGN(sizeof(struct ipt_dpi_info)),
    .userspacesize  = XT_ALIGN(sizeof(struct ipt_dpi_info)),
    .help           = DPI_help,
	.init			= DPI_init,
    .parse          = DPI_parse,
    .print          = DPI_print,
    .save           = DPI_save,
    .extra_opts     = DPI_opts
};

void _init(void)
{
    xtables_register_target(&dpi_target_reg);
}
