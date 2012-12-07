#if defined(MODVERSIONS)
#include <linux/modversions.h>
#endif
#include <linux/module.h>
#include <linux/version.h>

#include <linux/types.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/skbuff.h>

#include <linux/proc_fs.h>
#include <linux/seq_file.h>

#include <linux/spinlock.h>
#include <linux/vmalloc.h>
#include <linux/slab.h>

#include <linux/netfilter/x_tables.h>

#include <linux/ip.h>
#include <net/tcp.h>
#include <net/udp.h>

#include "xt_dpi.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("DPI TEAM @ Opzoon, Inc.");
MODULE_DESCRIPTION("Deep Packet Inspection For layer 7 payload");

static uint8_t mod_ref = 0;

static struct ipt_dpi_info g_stDpiInfo;

static unsigned int 
DPI_Process(struct sk_buff *pskb, const struct xt_target_param *para)
{
    printk("DPI: %s\n", __FUNCTION__);

	return XT_CONTINUE;
}

static bool 
checkentry(const struct xt_tgchk_param *para)
{
    struct ipt_dpi_info *info = (struct ipt_dpi_info *)para->targetinfo; 
	printk(KERN_INFO "nf_dpi: %s\n", __FUNCTION__);

	if (strcmp(para->table, "mangle") != 0)
	{
		printk(KERN_WARNING "DPI: can only be called from \"mangle\" table, not \"%s\"\n", para->table);
		return 0;
	}

    if(NULL == info) {
        return 0;     
    } else {
        strcpy(&g_dpi_info, info, sizeof(struct ipt_dpi_info));
    }

    if( 0 != check_info(&g_dpi_info)) {
        return 0;
    }

    if(DPI_SUCESS != DPI_load_conf()) {
       goto ERROR;    
    }

    DPI_load_lib();

    DPI_init_inner_dev();

	mod_ref++;

    if(mod_ref > 1) {
        return 0; 
    }

	printk(KERN_INFO "DPI: checkentry : mod_ref = %hu.\n", mod_ref);

	return 1;
}

static void 
destroy(const struct xt_tgdtor_param *para)
{
	printk(KERN_INFO "DPI: %s\n", __FUNCTION__);

	printk(KERN_INFO "DPI: destroy : mod_ref = %hu.\n", mod_ref);

	mod_ref--;
}

static struct xt_target nf_dpi_target = { 
	.name		= "DPI",
	.target		= DPI_Process,  /* handle function */
	.checkentry	= checkentry,   /* when add iptables rules */
	.destroy	= destroy,      /* when remove iptables rules */
	.me			= THIS_MODULE
};

static int __init init(void)
{
	printk(KERN_INFO "nf_dpi v%s is loading...\n", DPI_VERSION);

	//need_ip_conntrack();

	return xt_register_target(&nf_dpi_target);
}

static void __exit fini(void)
{
	xt_unregister_target(&nf_dpi_target);
	printk(KERN_INFO "nf_dpi v%s has been unloaded.\n", DPI_VERSION);
}

module_init(init);
module_exit(fini);
