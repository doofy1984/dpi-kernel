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

#include <linux/mutex.h>

//#include <linux/netfilter_ipv4/ip_tables.h>
//#include <linux/netfilter_ipv4/ip_conntrack.h>
//#include <linux/netfilter_ipv4/ip_conntrack_core.h>
#include <linux/netfilter/x_tables.h>
#include <linux/list.h>
//#include <linux/netfilter_ipv4/lockhelp.h>


#include <linux/ip.h>
#include <net/tcp.h>
#include <net/udp.h>

#include "ipt_NSC.h"
#include "ip_nsc_common.h"
#include "ns_pkttype.h"

/* We have two lists to protect, so 
 * we must set these macros to NULL */
#define ASSERT_READ_LOCK(x)
#define ASSERT_WRITE_LOCK(x)

#if 0
#define DEBUGP printk
#else
#define DEBUGP(format, args...)
#endif

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Daniel Chou Netentsec, Inc.");
#include "ipt_nsc_build_info.h"
MODULE_DESCRIPTION("An netfilter hook to classify packets according to application layer payload." NSC_BUILD_INFO);

/* global list */
static struct list_head tcp_dissector_list;
static struct list_head udp_dissector_list;

static struct ipt_nsc_target_info nsc_info;
static uint8_t mod_ref = 0;
static DECLARE_MUTEX(nsc_mutex);

/* all individual dissector(type: tuple-match) */
static struct ns_dissector **tm_nds_list;
static uint32_t tm_nds_idx = 0;
static uint32_t tm_nds_max = MTUPLE_MAX;

/* in 2.6.9, still use DECLARE rather than DEFINE */
static rwlock_t tcp_dissector_lock = RW_LOCK_UNLOCKED;
static rwlock_t udp_dissector_lock = RW_LOCK_UNLOCKED;
/* defined in ip_conntrack_core.c
 * we need this to protect ip_conntrack */
extern rwlock_t ip_conntrack_lock;


/* emule hooks */
int (*ns_check_emule_peer)(const struct pkt_tuple *ptuple, int be_hm) = NULL; /* when we found new handshaking */
//int (*ns_update_emule_peer)(const struct pkt_tuple *ptuple) = NULL; /* when we found new handshaking */
int (*ns_check_emule_hm)(const struct pkt_tuple *ptuple) = NULL; /* when we trying to match the hm_len */


static inline int
nds_id_equal(const struct ns_dissector *ds, const uint32_t id2)
{
	return (ds->id == id2);
}

static inline
struct list_head *get_list_byproto(const uint8_t proto)
{
	return (proto == IPPROTO_TCP) ? &tcp_dissector_list : &udp_dissector_list;
}

static inline
rwlock_t *get_rwlock_byproto(const uint8_t proto)
{
	return (proto == IPPROTO_TCP) ? &tcp_dissector_lock : &udp_dissector_lock;
}

static inline struct ns_dissector *
find_nds_byid(const uint32_t id, const uint8_t proto)
{
	struct list_head *ds_list = get_list_byproto(proto);

	return LIST_FIND(ds_list, nds_id_equal, struct ns_dissector *, id);
}

#define PKT_DIR_I2O 1
#define PKT_DIR_O2I	2

static uint8_t
check_indev(const struct pkt_tuple *ptuple)
{
	int i;
	if (strncmp(ptuple->indev, "local", 5) == 0)
		return PKT_DIR_I2O;
	for (i = 0; i < nsc_info.indev_count; i++)
	{
		/* FIXME: eth1: eth1.n(vlan) and eth10(non-vlan) eth100 match! */
		if (strncmp(ptuple->indev, nsc_info.indev[i], strlen(nsc_info.indev[i])) == 0)
			return PKT_DIR_I2O;
	}
	//DEBUGP(KERN_INFO "NSC: input device not matched : #%s# and #%s# .\n", ptuple->indev, nsc_info.indev[0]);
	return PKT_DIR_O2I;
}

/* pay attention to byte-order */
static int
tuple_match(const struct pkt_tuple *my_tuple, const struct match_tuple *mtuple)
{
	uint16_t match_result = 0;
	/* tuple_mask != 0 */
	if ((32 & mtuple->tuple_mask) == 32) {
		if(mtuple->src_ip != my_tuple->src_ip) goto nomatch;
		match_result |= 32;
	}
	if ((16 & mtuple->tuple_mask) == 16) {
		//if(my_tuple->dir == PKT_DIR_O2I) goto nomatch;
		if(mtuple->dst_ip != my_tuple->dst_ip) goto nomatch;
		match_result |= 16;
	}
	if ((8 & mtuple->tuple_mask) == 8) {
		if(mtuple->src_port != my_tuple->src_port) goto nomatch;
		match_result |= 8;
	}
	if ((4 & mtuple->tuple_mask) == 4) {
		//if(my_tuple->dir == PKT_DIR_O2I) goto nomatch;
		if(mtuple->dst_port != my_tuple->dst_port) goto nomatch;
		match_result |= 4;
	}
	if ((2 & mtuple->tuple_mask) == 2) {
		if(my_tuple->plen < mtuple->plen_min) goto nomatch;
		match_result |= 2;
	}
	if ((1 & mtuple->tuple_mask) == 1) {
		if(my_tuple->plen > mtuple->plen_max) goto nomatch;
		match_result |= 1;
	}
	/* 2006.8.28 */
	/* tuple_mask highest bit: user-defined protocols */
	if((mtuple->tuple_mask & 0x7fff) == match_result) return 1;
   nomatch:
	return 0;
}

static inline int check_single_plen(const uint16_t plen, const uint8_t offset, const struct single_plen *sp)
{
	//printk(KERN_INFO "NSC: %s plen = %hu; sp->plen = %hu\n", __FUNCTION__, plen, sp->plen);
	return ((plen >= (sp->plen - sp->bias) && plen <= (sp->plen + sp->bias)) &&
			(sp->max_offset == 0 ? 1 : (offset <= sp->max_offset)));
}

static int check_plen(const struct pkt_tuple *my_tuple,
			const struct plen_pattern *pp,
			struct ns_conninfo *cinfo)
{
	int i;
	int idx = pp->id - 1;
	struct pm_status *pms = &cinfo->pmstatus[idx];
	if (idx == 2 && pms->match_count >= 1 && /* must match the one of 1,2 packet */
		(my_tuple->offset > 5 && my_tuple->offset < (5 + 5)) &&
		ns_check_emule_hm)
	{
		if (ns_check_emule_hm(my_tuple))
		{
			pms->match_count += 4;
			goto check_threshold;
		}
	}
	for (i = 0; i < pp->pkt_num; i++)
	{
		if (!(pms->match_pos & (1 << i)) && (pms->match_count >= pp->splen[i].bench) &&
			check_single_plen(my_tuple->plen, my_tuple->offset, &pp->splen[i]))
		{
			DEBUGP(KERN_INFO "NSC: Found a single plen match, "
				"patt_id:%u; pkt_plen:%hu; patt_plen:%hu; pkt_offset:%hu; patt_offset:%hu; patt_pos:0x%04x; match_count:%hu\n",
				pp->id, my_tuple->plen, pp->splen[i].plen, my_tuple->offset, pp->splen[i].max_offset, pms->match_pos, pms->match_count);
			pms->match_pos |= (1 << i);
			pms->match_count += pp->splen[i].weight;
			DEBUGP(KERN_INFO "NSC: now match_count:%hu(weight:%hu)\n", pms->match_count, pp->splen[i].weight);
			break;
		}
	}
 check_threshold:
	if (pms->match_count >= pp->threshold)
	{
		DEBUGP(KERN_INFO "NSC: Found a plen_pattern-match, "
			"pattern id: %u\n", pp->id);
		return 1;
	}
	return 0;
}

/* commands when dissecting */
#define NDS_CMD_SKIPTM		1 /* skip all tuple matches */
#define NDS_CMD_SKIPBIS		2 /* skip all bistouries */
#define NDS_CMD_SKIPPATT	4 /* skip all plen pattern matches */

/* match result when returning from dissecting */
#define NDS_RES_TUPLE		1 /* matched by tuple */
#define NDS_RES_BISTOURY	2 /* matched by bistoury */
#define NDS_RES_USRDEF		4 /* matched by user-defined tuples */
#define NDS_RES_PATTERN		8 /* matched by plen patterns */

int
dissect_packet(const unsigned char		*payload,
				struct ip_conntrack *conntrack,
				const struct pkt_tuple	*my_tuple,
				const uint16_t			command,
				uint16_t				*result,
				const uint32_t			exception)
{
	struct ns_dissector *nds;
	rwlock_t *list_lock;
	struct list_head *my_list;

	int pkt_type;
	int res = APP_UNCLASSIFIED; //XXX: added for rule.ko

	list_lock = get_rwlock_byproto(my_tuple->proto);
	my_list = get_list_byproto(my_tuple->proto);

	read_lock_bh(list_lock);
	/* priority works here */
	list_for_each_entry(nds, my_list, list)
	{
		/* if nds->app_code == exception we specify, ignore it */
		if (nds->app_code == exception)
		{
			DEBUGP(KERN_INFO "NSC: [dissect_packet]skip exception: 0x%02x\n", exception);
			continue;
		}
		if (my_tuple->plen < nds->plen_min || my_tuple->plen > nds->plen_max)
			continue;
		switch (nds->type) {
		case NDS_TUPLEMATCH:
			if (command & NDS_CMD_SKIPTM)
			{
				//DEBUGP(KERN_INFO "NSC: NSC_SKIP_TMATCH set, skip tuple match 0x%04x.\n", nds->app_code);
				break;
			}
			if(tuple_match(my_tuple, nds->action.mtuple))
			{
				DEBUGP(KERN_INFO "NSC: [dissect_packet]Found a tuple-match!\n");
				DEBUGP(KERN_INFO "NSC: mtuple=(%hu,%hu,%u.%u.%u.%u,%u.%u.%u.%u,%hu,%hu,%hu,%hu,%u)\n",
					nds->action.mtuple->proto,
					nds->action.mtuple->tuple_mask,
					NIPQUAD(nds->action.mtuple->src_ip),
					NIPQUAD(nds->action.mtuple->dst_ip),
					nds->action.mtuple->src_port,
					nds->action.mtuple->dst_port,
					nds->action.mtuple->plen_min,
					nds->action.mtuple->plen_max,
					nds->action.mtuple->app_code);
				DEBUGP(KERN_INFO "     ptuple=(%hu,%s,%u.%u.%u.%u,%u.%u.%u.%u,%hu,%hu,%hu)\n",
					my_tuple->proto,
					my_tuple->indev,
					NIPQUAD(my_tuple->src_ip),
					NIPQUAD(my_tuple->dst_ip),
					my_tuple->src_port,
					my_tuple->dst_port,
					my_tuple->plen);
				/* user-defined tuple match */
				if ((nds->action.mtuple->tuple_mask & 0x8000) == 0x8000)
				{
					DEBUGP(KERN_INFO "NSC: [dissect_packet]user-defined tuple-match!\n");
					*result |= NDS_RES_USRDEF;
				}
				*result |= NDS_RES_TUPLE;
				DEBUGP(KERN_INFO "NSC: [dissect_packet]result flags set: 0x%04x.\n", *result);
				goto done;
			}
			break;
		case NDS_BISTOURY:
			if ((pkt_type = nds->action.bistoury(payload, my_tuple)))
			{
				DEBUGP(KERN_INFO "NSC: [dissect_packet]Found a bistoury-match, code: 0x%04x\n", nds->app_code);
				*result |= NDS_RES_BISTOURY;
				if (my_tuple->dir == PKT_DIR_O2I)
				{
					DEBUGP(KERN_INFO "NSC: [dissect_packet]dir=%hu;src_ip=%u.%u.%u.%u;dst_ip=%u.%u.%u.%u\n",
						my_tuple->dir, HIPQUAD(my_tuple->src_ip), HIPQUAD(my_tuple->dst_ip));
					goto done;
				}
				/* found a emule TCP connection, search the list */
				if (pkt_type == EMULE_HELLO_MSG) {
					if (ns_check_emule_peer)
					{
						ns_check_emule_peer(my_tuple, 1);
					}
				} else if (pkt_type == EMULE_UDP_PKT)//nds->app_code == APP_P2P_ED2K)
				{
					if (ns_check_emule_peer)
					{
						ns_check_emule_peer(my_tuple, 0);
					}
				}
				goto done;
			}
			break;
		case NDS_PLENPATT:
			if (check_plen(my_tuple, nds->action.ppattern, &conntrack->cinfo))
			{
				DEBUGP(KERN_INFO "NSC: [dissect_packet]Found a plen_pattern-match,"
					"code: 0x%04x; pattern id: %u\n", nds->app_code, nds->action.ppattern->id);
				*result |= NDS_RES_PATTERN;
				/* handle the ALL-ENCRYPTED case */
				/*
				if (nds->app_code == APP_P2P_ED2K + 1)
				{
					check_emule_hm(my_tuple);
				}
				*/
				goto done;
			}
			break;
		default:
			break;
		}
	}
	read_unlock_bh(list_lock);
	return APP_UNCLASSIFIED;
   done:
   	res = nds->app_code; //XXX: to avoid race condition caused by rule.ko
	read_unlock_bh(list_lock);
	return res;
}

/* check if udp/tcp/icmp */
static int pre_check(const struct sk_buff *skb)
{
	/* SHOULD not happen */
	if(!skb->nh.iph) 
		return 0;
	/* not tcp/udp/icmp */
	if(skb->nh.iph->protocol != IPPROTO_TCP &&
	   skb->nh.iph->protocol != IPPROTO_UDP &&
	   skb->nh.iph->protocol != IPPROTO_ICMP)
		return 0;
	return 1;
}

/* compute socks data pointer */
unsigned char *get_socks_datapt(const unsigned char *orig_pt, struct pkt_tuple *ptuple)
{
	unsigned char *socks_datapt = (unsigned char *)orig_pt;
	switch (ptuple->proto){
	case IPPROTO_TCP:
		/* tcp socks handler */
		return socks_datapt;
	case IPPROTO_UDP:
		/* udp socks handler */
		if(orig_pt[3] == 0x01) // ip
		{
			DEBUGP(KERN_INFO "NSC: [get_socks_datapt]found udp socks ip address.\n");
			socks_datapt = (unsigned char *)&orig_pt[10];
			ptuple->plen -= 10;
		}
		else if(orig_pt[3] == 0x03) //domain
		{
			uint8_t sk_hlen = orig_pt[4];
			DEBUGP(KERN_INFO "NSC: [get_socks_datapt]found udp socks domain name %hhu bytes.\n", sk_hlen);
			socks_datapt = (unsigned char *)&orig_pt[7 + sk_hlen]; // 7 = 2 + 1 + 1 + 1 + sk_len + 2
			ptuple->plen -= sk_hlen;
		}
		DEBUGP(KERN_INFO "NSC: the first byte of new payload: 0x%02x\n", socks_datapt[0]);
		return socks_datapt;
	default:
		return NULL;
	}
}

static void
set_connmark(struct ip_conntrack *ct, const u_int32_t mark_vaule)
{
	DEBUGP(KERN_INFO "NSC: Set conntrack mark : 0x%x -> 0x%x\n", ct->mark, mark_vaule);
	ct->mark = mark_vaule;
}

/* copied from ip_conntrack.h::is_confirmed */
static inline int is_classified_bytuple(struct ip_conntrack *ct)
{
	return test_bit(IPS_BYTUPLE_BIT, &ct->status);
}
/*
static inline int is_socks(struct ip_conntrack *ct)
{
	return test_bit(IPS_SOCKS_BIT, &ct->status);
}
*/

static unsigned int
target(struct sk_buff **pskb,
       unsigned int hooknum,
       const struct net_device *in,
       const struct net_device *out,
       const void *targinfo,
       void *userinfo)
{
	struct ip_conntrack *conntrack;
	enum ip_conntrack_info ctinfo;
	struct nf_bridge_info *nf_bridge;
	/* tuple of this packet */
	struct pkt_tuple ptuple;
	int dissect_result = 0;
	int dissect_result_tmp = 0;

	/* number of packets of this connection */
	u_int64_t conn_pkt;
	u_int64_t conn_bytes;

	u_int16_t dst_port;

	uint16_t ds_res = 0;
	uint16_t ds_cmd = 0;

	unsigned char *haystack; 	// transport layer data pointer
	unsigned char *payload;		// application layer data pointer
	struct iphdr *ip;

	int hlen; //haystack length

	int classified_bytuple = 0;

	struct tcphdr *tcph;
	struct udphdr *udph;

	/* new payload pointer when computing socks data */
	unsigned char *new_payload;

	if (!(conntrack = ip_conntrack_get(*pskb, &ctinfo))) {
		DEBUGP(KERN_INFO "NSC: packet is not from a known connection, giving up.\n");
		goto pass;
	}

	write_lock_bh(&ip_conntrack_lock);

	/* compute number of packets on this connection */
	conn_pkt = conntrack->counters[IP_CT_DIR_ORIGINAL].packets +
				conntrack->counters[IP_CT_DIR_REPLY].packets;
	conn_bytes = conntrack->counters[IP_CT_DIR_ORIGINAL].bytes +
				conntrack->counters[IP_CT_DIR_REPLY].bytes;

	/* connection need no more classification */
	if (test_bit(IPS_CLASSIFIED_BIT, &conntrack->status)) {
		if (conntrack->mark == APP_UNKNOWN && 
			conn_pkt == 40) {
			if (conn_bytes > 15000) {
				set_connmark(conntrack, APP_DATATRANS);
			}
		}
		DEBUGP(KERN_INFO "NSC: [test_bit]IPS_CLASSIFIED_BIT set. code: 0x%04x\n", conntrack->mark);
		(*pskb)->nfmark = conntrack->mark;
		goto unlock;
	}

	/* ignore ![tcp,udp,icmp] traffic */
	if (!pre_check(*pskb)) {
		DEBUGP(KERN_INFO "NSC: packet ignored\n");
		set_connmark(conntrack, APP_IGNORED);
		set_bit(IPS_CLASSIFIED_BIT, &conntrack->status);
		(*pskb)->nfmark = APP_IGNORED;
		goto unlock;
	}
	/* handle ICMP */
	if ((*pskb)->nh.iph->protocol == IPPROTO_ICMP) {
		if (ctinfo == IP_CT_NEW) {
			DEBUGP(KERN_INFO "NSC: new icmp packet: %u.%u.%u.%u\n",
				NIPQUAD((*pskb)->nh.iph->daddr));
			set_connmark(conntrack, APP_ICMP);
			set_bit(IPS_CLASSIFIED_BIT, &conntrack->status);
			(*pskb)->nfmark = APP_ICMP;
		}
		/* let related ICMP packets go:
		   - if we dont, NSC will mark the entire connection
		   - as 0!! it's sad. */
		goto unlock;
	}
	/* handle abnormal traffic */
	if (conntrack->mark == APP_ABNORMAL_TRAFFIC) {
		DEBUGP(KERN_INFO "NSC: abnormal traffic\n");
		set_bit(IPS_CLASSIFIED_BIT, &conntrack->status);
		(*pskb)->nfmark = APP_ABNORMAL_TRAFFIC;
		goto unlock;
	}

	dst_port =
		ntohs(conntrack->tuplehash[IP_CT_DIR_ORIGINAL].tuple.dst.u.all);
	DEBUGP(KERN_INFO "dst_port = %hu\n", dst_port);

	/* BELOW: this packet is unclassified */
	if (conn_pkt > nsc_info.pkt2check)
	{
		DEBUGP(KERN_INFO "NSC: seen more than %d packets. giving up.\n", nsc_info.pkt2check);
		set_bit(IPS_CLASSIFIED_BIT, &conntrack->status);

		if (conntrack->mark != 0) {
			(*pskb)->nfmark = conntrack->mark;
			goto unlock;
		} else {  /* unknown */
			if (dst_port <= 1024)
				dissect_result = APP_UNKNOWN_SERVICES;
			else
				dissect_result = APP_UNKNOWN;
			set_connmark(conntrack, dissect_result);
			(*pskb)->nfmark = dissect_result;
			goto unlock;
		}
	}
	if (conntrack->mark == APP_MISC_SOCKS_PROXY)
	{
		DEBUGP(KERN_INFO "NSC: this packet belongs to a socks connection.\n");
		dissect_result = APP_MISC_SOCKS_PROXY;
	}
	if (is_classified_bytuple(conntrack) && conntrack->mark != 0)
	{
		DEBUGP(KERN_INFO "NSC: this packet belongs to a connection classified by tuple-match: 0x%04x\n", conntrack->mark);
		dissect_result = conntrack->mark;
		classified_bytuple = 1;
		//ds_flags |= NSC_MATCH_BYTUPLE;
	}
	write_unlock_bh(&ip_conntrack_lock);

	/* now begin to handle the application layer data */

	ip = (*pskb)->nh.iph;

	ptuple.src_ip = ntohl(ip->saddr);
	ptuple.dst_ip = ntohl(ip->daddr);
	ptuple.offset = conn_pkt; /* appended 2007.1.3 and happy new year */

	/* FIXME: vlan interface wildcard eth3.1 eth3.2 ... */
	if ((*pskb)->dev == NULL) /* from LOCAL_OUT */
	{
		DEBUGP(KERN_INFO "NSC: skb->dev is NULL. set to \"local\".\n");
		strncpy(ptuple.indev, "local", IFNAMSIZ);
		ptuple.indev[IFNAMSIZ - 1] = '\0';
	}
	else
	{
		/* we are in bridge mode */
		if ((nf_bridge = (*pskb)->nf_bridge))
		{
			if (nf_bridge->physindev)
			{
				strncpy(ptuple.indev, nf_bridge->physindev->name, IFNAMSIZ);
				ptuple.indev[IFNAMSIZ - 1] = '\0';
			}
			else
				ptuple.indev[0] = '\0';
		}
		else
		{
			/* in == bri0 when bridge-OUTPUT
			   in == skb->dev when FORWARD and INPUT
			   see netfilter.c ip_forward.c ip_output.c ip_input.c
			*/
			strncpy(ptuple.indev, (*pskb)->dev->name, IFNAMSIZ);
			ptuple.indev[IFNAMSIZ - 1] = '\0';
		}
	}
	
	ptuple.dir = check_indev(&ptuple);
	// haystack length in bytes
	hlen = ntohs(ip->tot_len)-(ip->ihl*4);
	haystack = (char *)ip + (ip->ihl*4);

	switch (ip->protocol)
	{
	case IPPROTO_TCP:
	{
		tcph = (void *) ip + ip->ihl * 4;
		ptuple.src_port = ntohs(tcph->source);
		ptuple.dst_port = ntohs(tcph->dest);
		ptuple.proto = IPPROTO_TCP;
		payload = haystack + tcph->doff * 4;
		ptuple.plen = hlen - tcph->doff * 4;
		/* We must mark syn/ack packets per tuple */
		//if (ptuple.plen == 0)
			//goto pass;
		/* this connection has already been classified by tuple */
		if (classified_bytuple)
		{
			if (ptuple.plen > 0)
			{
				ds_cmd |= NDS_CMD_SKIPTM;
				dissect_result_tmp = dissect_packet(payload, conntrack, &ptuple, ds_cmd, &ds_res, 0);
				if (dissect_result_tmp != APP_UNCLASSIFIED) /* ds_res & NDS_RES_BISTOURY */
				{
					DEBUGP(KERN_INFO "NSC: Found a tunneled connection: 0x%04x=>0x%04x\n",
						dissect_result, dissect_result_tmp);
					dissect_result = dissect_result_tmp;
				}
				else
				{
					(*pskb)->nfmark = dissect_result;
					goto pass;
				}
			}
			else /* skip packets with 0-length payload */
			{
				(*pskb)->nfmark = dissect_result;
				goto pass;
			}
			break;
		}

		/* play with TCP_SOCKS 
		   and classified_bytuple != 1 */
		if (dissect_result == APP_MISC_SOCKS_PROXY)
		{
			ds_cmd |= NDS_CMD_SKIPTM;
			DEBUGP(KERN_INFO "NSC: packet from a TCP SOCKS connection, reclassify!\n");
			dissect_result_tmp = dissect_packet(payload, conntrack, &ptuple, ds_cmd, &ds_res, APP_MISC_SOCKS_PROXY);
			if (dissect_result_tmp != APP_UNCLASSIFIED) /* ds_res & NDS_RES_BISTOURY */
			{
				DEBUGP(KERN_INFO "NSC: Found a tunneled socks connection: 0x%04x=>0x%04x\n",
					dissect_result, dissect_result_tmp);
				dissect_result = dissect_result_tmp;
			}
			else /* */
			{
				(*pskb)->nfmark = APP_MISC_SOCKS_PROXY;
				goto pass;
			}
			break;
		}

		dissect_result = dissect_packet(payload, conntrack, &ptuple, ds_cmd, &ds_res, 0);
		break;
	}
	case IPPROTO_UDP:
	{
		udph = (void *) ip + ip->ihl * 4;
		ptuple.src_port = ntohs(udph->source);
		ptuple.dst_port = ntohs(udph->dest);
		ptuple.proto = IPPROTO_UDP;

		payload = haystack + 8;
		ptuple.plen = hlen - 8;
		//if (ptuple.plen == 0)
			//goto pass;
		if (classified_bytuple) /* this connection has already been classified by tuple */
		{
			ds_cmd |= NDS_CMD_SKIPTM;
			dissect_result_tmp = dissect_packet(payload, conntrack, &ptuple, ds_cmd, &ds_res, 0);
			if (dissect_result_tmp != APP_UNCLASSIFIED)
			{
				DEBUGP(KERN_INFO "NSC: Found a tunneled connection: 0x%04x=>0x%04x\n", dissect_result, dissect_result_tmp);
				dissect_result = dissect_result_tmp;
			}
			else
			{
				(*pskb)->nfmark = dissect_result;
				goto pass;
			}
			break;
		}
		/* play with UDP_SOCKS */
		if (dissect_result == APP_MISC_SOCKS_PROXY)
		{
			//set_bit(IPS_SOCKS_BIT, &conntrack->status);
			DEBUGP(KERN_INFO "NSC: packet from an UDP SOCKS connection, reclassify!\n");
			new_payload = get_socks_datapt(payload, &ptuple);
			ds_cmd |= NDS_CMD_SKIPTM;
			dissect_result_tmp = dissect_packet(new_payload, conntrack, &ptuple, ds_cmd, &ds_res, APP_MISC_SOCKS_PROXY);
			if (dissect_result_tmp != APP_UNCLASSIFIED) /* ds_res & NDS_RES_BISTOURY */
			{
				DEBUGP(KERN_INFO "NSC: Found a tunneled UDP socks connection from nth packet: 0x%04x=>0x%04x\n", dissect_result, dissect_result_tmp);
				dissect_result = dissect_result_tmp;
			}
			else /* */
			{
				(*pskb)->nfmark = APP_MISC_SOCKS_PROXY;
				goto pass;
			}
			break;
		}
		/* dissect_result == 0 */
		dissect_result = dissect_packet(payload, conntrack, &ptuple, ds_cmd, &ds_res, 0);
		if (dissect_result == APP_MISC_SOCKS_PROXY)
		{
			ds_cmd |= NDS_CMD_SKIPTM;
			DEBUGP(KERN_INFO "NSC: found an UDP SOCKS connection, do it again!\n");
			new_payload = get_socks_datapt(payload, &ptuple);
			dissect_result_tmp = dissect_packet(new_payload, conntrack, &ptuple, ds_cmd, &ds_res, APP_MISC_SOCKS_PROXY);
			if (dissect_result_tmp != APP_UNCLASSIFIED) /* ds_res & NDS_RES_BISTOURY */
			{
				DEBUGP(KERN_INFO "NSC: Found a tunneled UDP socks connection from the first packet: 0x%04x=>0x%04x\n", dissect_result, dissect_result_tmp);
				dissect_result = dissect_result_tmp;
			}
		}
		break;
	}
	/* no other values here */
	default:
		goto pass;
	}

	(*pskb)->nfmark = dissect_result;

	write_lock_bh(&ip_conntrack_lock);
	DEBUGP(KERN_INFO "NSC: dissect_result = 0x%04x; connmark = 0x%04x; ds_cmd = 0x%04x; ds_res = 0x%04x;\n",
			dissect_result, conntrack->mark, ds_cmd, ds_res);
	if (dissect_result != APP_UNCLASSIFIED)
	{
		set_connmark(conntrack, dissect_result);
		if (dissect_result == APP_MISC_SOCKS_PROXY)
		{
			clear_bit(IPS_BYTUPLE_BIT, &conntrack->status);
			goto unlock;
		}
		if (ds_res & NDS_RES_TUPLE)
		{
			if (ds_res & NDS_RES_USRDEF)
			{
				/* we won't classify user defined protocol any more */
				set_bit(IPS_CLASSIFIED_BIT, &conntrack->status);
			}
			else
				set_bit(IPS_BYTUPLE_BIT, &conntrack->status);
		}
		else 
		{
			clear_bit(IPS_BYTUPLE_BIT, &conntrack->status);
			set_bit(IPS_CLASSIFIED_BIT, &conntrack->status);
			DEBUGP(KERN_INFO "NSC: matched by bistoury(not socks), need no further dissecting. "
				"dissect_result = 0x%04x\n conntrack->status=0x%08x\n", dissect_result, conntrack->status);		
		}

	}
   unlock:
	write_unlock_bh(&ip_conntrack_lock);
   pass:
	return IPT_CONTINUE;
}

struct ns_dissector *
create_ds_bytuple(const struct match_tuple *tuple)
{
	struct ns_dissector *nds;
	DEBUGP(KERN_INFO "NSC: creating tuple 0x%x ...\n", tuple->app_code);

	nds = kmalloc(sizeof(struct ns_dissector), GFP_KERNEL);
	if (!nds)
		return NULL;
	memset(nds, 0, sizeof(struct ns_dissector));
	nds->proto = tuple->proto;
	nds->app_code = tuple->app_code;
	//nds->plen_min = tuple->plen_min;
	//nds->plen_max = tuple->plen_max;
	nds->plen_min = 0;
	nds->plen_max = 2000;
	nds->type = NDS_TUPLEMATCH;
	nds->action.mtuple = (struct match_tuple *)tuple;
	return nds;
}

/* no locking needed */
int
register_tuple(void)
{
	struct ns_dissector *nds;
	int i;

	if (tm_nds_idx != 0)
	{
		DEBUGP(KERN_INFO "NSC: tuple-match dissector list not clean.\n");
		/*
		for (i = 0; i < tm_nds_idx; i++)
		{
			if(tm_nds_list[i])
			{
				nds = tm_nds_list[i];
				kfree(nds);
				tm_nds_list[i] = NULL;
			}
		}
		tm_nds_idx = 0;
		*/
		return 0;
	}
	/* create dissector for each valid match-tuple */
	for (i = 0; i < nsc_info.mtuple_count; i++)
	{
		if(!(nds = create_ds_bytuple(&(nsc_info.mtuples[i]))))
		{
			DEBUGP(KERN_INFO "NSC: create dissector from match-tuple failed. out of memory.\n");
			/* fixme : need clear routines here */

			return 0;
		}
		nds->id = tm_nds_idx + 1;
		tm_nds_list[tm_nds_idx] = nds;
		tm_nds_idx++;
		ipt_nsc_register_dissector(nds);
	}
	DEBUGP(KERN_INFO "NSC: %u dissector registered from match-tuple\n", tm_nds_idx);
	return 1;
}

void
unregister_tuple(void)
{
	int i;
	struct ns_dissector *nds;
	DEBUGP(KERN_INFO "NSC: %u dissector registered from match-tuple will be unregistered\n", tm_nds_idx);
	for (i = 0; i < tm_nds_idx; i++)
	{
		if(tm_nds_list[i])
		{
			nds = tm_nds_list[i];
			ipt_nsc_unregister_dissector(nds);
			kfree(nds);
			tm_nds_list[i] = NULL;
		}
	}
	tm_nds_idx = 0;
}

static int
checkentry(const char *tablename,
			const struct ipt_entry *e,
			void *targinfo,
			unsigned int targinfosize,
			unsigned int hook_mask)
{
	DEBUGP(KERN_INFO "NSC: you came into my checkentry.\n");
	if (targinfosize != IPT_ALIGN(sizeof(struct ipt_nsc_target_info))) {
		printk(KERN_WARNING "NSC: targinfosize %u != %Zu\n",
		       targinfosize,
		       IPT_ALIGN(sizeof(struct ipt_nsc_target_info)));
		return 0;
	}
	if (strcmp(tablename, "mangle") != 0)
	{
		DEBUGP(KERN_WARNING "NSC: can only be called from \"mangle\" table, not \"%s\"\n", tablename);
		return 0;
	}
	if (hook_mask & ~(1 << NF_IP_PRE_ROUTING))// | 1 << NF_IP_LOCAL_OUT))
	{
		DEBUGP(KERN_INFO "NSC: bad hooks %x.\n", hook_mask);
		return 0;
	}
	down(&nsc_mutex);
	mod_ref++;
	DEBUGP(KERN_INFO "NSC: checkentry : mod_ref = %hu.\n", mod_ref);
	/* do some initialization job here */
	if (mod_ref == 1) {
		memcpy(&nsc_info, targinfo, sizeof(struct ipt_nsc_target_info));
		if (!register_tuple()) {
			up(&nsc_mutex);
			/* tuple-match dissector list not clean or out of memory */
			return 0;
		}
	}
	up(&nsc_mutex);
	return 1;
}

static void 
destroy(void *targinfo,
		unsigned int targinfosize)
{
	DEBUGP(KERN_INFO "NSC: you came into my destroy.\n");
	down(&nsc_mutex);
	DEBUGP(KERN_INFO "NSC: destroy : mod_ref = %hu.\n", mod_ref);
	if (mod_ref == 1) {
		unregister_tuple();
	}
	mod_ref--;
	up(&nsc_mutex);
}

/********************proc*****************/

static int seq_printf_tuple(struct seq_file *s, const struct match_tuple *mtuple)
{
	return seq_printf(s, "tuple=(%hu,%hu,%u.%u.%u.%u,%u.%u.%u.%u,%hu,%hu,%hu,%hu,%u)",
			mtuple->proto,
			mtuple->tuple_mask,
			NIPQUAD(mtuple->src_ip),
			NIPQUAD(mtuple->dst_ip),
			mtuple->src_port,
			mtuple->dst_port,
			mtuple->plen_min,
			mtuple->plen_max,
			mtuple->app_code);
}

static struct list_head *list_get_nth_element(struct list_head *list, loff_t *pos)
{
	struct list_head *node;
	loff_t i = 0;

	list_for_each(node, list)
		if (i++ == *pos)
			return node;

	return NULL;
}

static struct list_head *list_get_next_element(struct list_head *list, struct list_head *element, loff_t *pos)
{
	if (element->next == list)
		return NULL;

	++(*pos);
	return element->next;
}

static void *ns_seq_start(struct list_head *my_list, rwlock_t *my_lock, loff_t *pos)
{
	read_lock_bh(my_lock);
	return list_get_nth_element(my_list, pos);
}

static void *ns_seq_next(struct list_head *my_list, void *v, loff_t *pos)
{
	return list_get_next_element(my_list, v, pos);
}

static void ns_seq_stop(rwlock_t *my_lock, void *v)
{
	read_unlock_bh(my_lock);
}

/////////////////////////////////////////////////////////////
static void *ntil_seq_start(struct seq_file *s, loff_t *pos)
{
	return ns_seq_start(&tcp_dissector_list, &tcp_dissector_lock, pos);
}
static void *ntil_seq_next(struct seq_file *s, void *v, loff_t *pos)
{
	return ns_seq_next(&tcp_dissector_list, v, pos);
}
static void ntil_seq_stop(struct seq_file *s, void *v)
{
	ns_seq_stop(&tcp_dissector_lock, v);
}

static void *nuil_seq_start(struct seq_file *s, loff_t *pos)
{
	return ns_seq_start(&udp_dissector_list, &udp_dissector_lock, pos);
}
static void *nuil_seq_next(struct seq_file *s, void *v, loff_t *pos)
{
	return ns_seq_next(&udp_dissector_list, v, pos);
}
static void nuil_seq_stop(struct seq_file *s, void *v)
{
	ns_seq_stop(&udp_dissector_lock, v);
}

/* return 0 on success, 1 in case of error */
static int ns_seq_show(struct seq_file *s, void *v)
				
{
	struct ns_dissector *nds = v;
	if (seq_printf(s, "%hu,0x%04x,plen_min=%hu,plen_max=%hu,prioriy=%u,",
				nds->proto,
				nds->app_code,
				nds->plen_min,
				nds->plen_max,
				nds->priority))
		return 1;

	switch (nds->type)
	{
	case NDS_TUPLEMATCH:
		if (seq_printf(s, "type=%s,", "NDS_TUPLEMATCH"))
			return 1;
		if (seq_printf_tuple(s, nds->action.mtuple))
			return 1;
		break;
	case NDS_BISTOURY:
		if (seq_printf(s, "type=%s,", "NDS_BISTOURY"))
			return 1;
		if (seq_printf(s, "bistoury=%p", nds->action.bistoury))
			return 1;
		break;
	case NDS_PLENPATT:
		if (seq_printf(s, "type=%s,", "NDS_PLENPATT"))
			return 1;
		if (seq_printf(s, "pattern=%p", nds->action.ppattern))
			return 1;
		break;
	default:
		;
	}

	if(seq_putc(s, '\n'))
		return 1;

	return 0;
}
static struct seq_operations ntil_seq_ops = {
	.start = ntil_seq_start,
	.next  = ntil_seq_next,
	.stop  = ntil_seq_stop,
	.show  = ns_seq_show
};

static struct seq_operations nuil_seq_ops = {
	.start = nuil_seq_start,
	.next  = nuil_seq_next,
	.stop  = nuil_seq_stop,
	.show  = ns_seq_show
};
/////////////////////////////////////////////////////////

static int ntil_open(struct inode *inode, struct file *file)
{
	return seq_open(file, &ntil_seq_ops);
}
static int nuil_open(struct inode *inode, struct file *file)
{
	return seq_open(file, &nuil_seq_ops);
}

static struct file_operations ntil_file_ops = {
	.owner   = THIS_MODULE,
	.open    = ntil_open,
	.read    = seq_read,
	.llseek  = seq_lseek,
	.release = seq_release
};

static struct file_operations nuil_file_ops = {
	.owner   = THIS_MODULE,
	.open    = nuil_open,
	.read    = seq_read,
	.llseek  = seq_lseek,
	.release = seq_release
};
//#endif

static struct xt_target ipt_nsc_reg = { 
	.name		= "NSC",
	.target		= target, /* packet handle */
	.checkentry	= checkentry, /* when add iptables rules */
	.destroy	= destroy, /* when remove iptables rules */
	.me			= THIS_MODULE
};

/*
static int tm_nds_max_user;
module_param(tm_nds_max_user, int, 0600);
MODULE_PARM_DESC(tm_nds_max_user, "maximal number of tuple-match dissector");
*/
static int __init init(void)
{
	int ret = -ENOMEM;

//#ifdef CONFIG_PROC_FS
	struct proc_dir_entry *proc_tcp_list, *proc_udp_list;
//#endif

	printk(KERN_INFO "ipt_NSC v%s loading...\n", NSC_VERSION);

	need_ip_conntrack(); /* we need conntrack --2007.1.8 */

	INIT_LIST_HEAD(&tcp_dissector_list);
	INIT_LIST_HEAD(&udp_dissector_list);
	/* tuple-match list */
	tm_nds_list = vmalloc(sizeof(struct ns_dissector *) * tm_nds_max);
	if (!tm_nds_list) {
		DEBUGP(KERN_INFO "NSC: Unable to create tm_nds_list\n");
		return ret;
	}
	memset(tm_nds_list, 0, sizeof(struct ns_dissector *) * tm_nds_max);

//#ifdef CONFIG_PROC_FS
	proc_tcp_list = proc_net_fops_create("ns_tcp_nds_list", 0440, &ntil_file_ops);
	if (!proc_tcp_list) goto cleanup_tcp;

	proc_udp_list = proc_net_fops_create("ns_udp_nds_list", 0440, &nuil_file_ops);
	if (!proc_udp_list) goto cleanup_proc;
//#endif
	ret = xt_register_target(&ipt_nsc_reg);
	if (ret != 0)
		goto cleanup_proc;
	return ret;

  cleanup_proc:
//#ifdef CONFIG_PROC_FS
	proc_net_remove("ns_udp_nds_list");
  cleanup_tcp:
	proc_net_remove("ns_tcp_nds_list");
//#endif
	vfree(tm_nds_list);
	return ret;
}

static void __exit fini(void)
{
	proc_net_remove("ns_udp_nds_list");
	proc_net_remove("ns_tcp_nds_list");
	xt_unregister_target(&ipt_nsc_reg);
	vfree(tm_nds_list);
	/* Make sure noone calls it, meanwhile. */
	synchronize_net();
	printk(KERN_INFO "ipt_NSC v%s unloaded.\n", NSC_VERSION);
}
/*
int
app_is_in_list(const struct ns_dissector *ds)
{
	int i;
	for (i = 0; i < ucfg_cnt; i++)
	{
		if (ds->app_code == nsc_info.cfg[i].app_code)
		{
			return 1;
		}
	}
	return 0;
}
*/
uint32_t
get_prio_by_app(const struct ns_dissector *ds)
{
	int i;
	for (i = 0; i < nsc_info.cfg_count; i++)
	{
		if (ds->app_code == nsc_info.cfg[i].app_code)
			return nsc_info.cfg[i].priority;
	}
	return 0;
}

/* dissector register interface */
int 
ipt_nsc_register_dissector(struct ns_dissector *nds)
{
	int ret = 0;
	uint32_t nds_prio;
	struct list_head *i;
	if(!(nds_prio = get_prio_by_app(nds)))
	{
		printk(KERN_INFO "NSC: application '0x%x' is not in list.\n", nds->app_code);
		return ret;
	}
	nds->priority = nds_prio;
	if (nds->proto == IPPROTO_TCP)
	{
		write_lock_bh(&tcp_dissector_lock);
		if (nds == find_nds_byid(nds->id, IPPROTO_TCP)) {
			printk(KERN_INFO "NSC: TCP dissector already exist. [app_code = '0x%x' ; id = %u]\n",
					nds->app_code, nds->id);
			write_unlock_bh(&tcp_dissector_lock);
			return ret;
		}
		if (!try_module_get(THIS_MODULE)) {
			ret = -EFAULT;
			write_unlock_bh(&tcp_dissector_lock);
			return ret;
		}
		list_for_each(i, &tcp_dissector_list) {
			if (nds->priority < ((struct ns_dissector *)i)->priority)
				break;
		}
		list_add(&nds->list, i->prev);
		DEBUGP(KERN_INFO "NSC: TCP dissector registered. [app_code = '0x%x' ; id = %u]\n", nds->app_code, nds->id);
		write_unlock_bh(&tcp_dissector_lock);
	}
	else if (nds->proto == IPPROTO_UDP)
	{
		write_lock_bh(&udp_dissector_lock);
		if (nds == find_nds_byid(nds->id, IPPROTO_UDP)) {
			printk(KERN_INFO "NSC: UDP dissector already exist. [app_code = '0x%x' ; id = %u]\n",
					nds->app_code, nds->id);
			write_unlock_bh(&udp_dissector_lock);
			return ret;
		}
		if (!try_module_get(THIS_MODULE)) {
			ret = -EFAULT;
			write_unlock_bh(&udp_dissector_lock);
			return ret;
		}
		list_for_each(i, &udp_dissector_list) {
			if (nds->priority < ((struct ns_dissector *)i)->priority)
				break;
		}
		list_add(&nds->list, i->prev);
		DEBUGP(KERN_INFO "NSC: UDP dissector registered. [app_code = '0x%x' ; id = %u]\n", nds->app_code, nds->id);
		write_unlock_bh(&udp_dissector_lock);
	}
	return ret;
}

void
ipt_nsc_unregister_dissector(struct ns_dissector *nds)
{
	if (!nds) {
		printk(KERN_INFO "NSC: error, trying to unregister NULL dissector!\n");
		return;
	}
	if (nds->proto == IPPROTO_TCP)
	{
		write_lock_bh(&tcp_dissector_lock);
		if (nds != find_nds_byid(nds->id, IPPROTO_TCP)) {
			printk(KERN_INFO "NSC: TCP dissector not registered? [app_code = '0x%x' ; id = %u]\n",
					nds->app_code, nds->id);
			write_unlock_bh(&tcp_dissector_lock);
			return;
		}
		LIST_DELETE(&tcp_dissector_list, nds);
		module_put(THIS_MODULE);
		DEBUGP(KERN_INFO "NSC: TCP dissector unregistered. [app_code = '0x%x' ; id = %u]\n", nds->app_code, nds->id);
		write_unlock_bh(&tcp_dissector_lock);
	}
	else if (nds->proto == IPPROTO_UDP)
	{
		write_lock_bh(&udp_dissector_lock);
		if (nds != find_nds_byid(nds->id, IPPROTO_UDP)) {
			printk(KERN_INFO "NSC: UDP dissector not registered? [app_code = '0x%x' ; id = %u]\n",
					nds->app_code, nds->id);
			write_unlock_bh(&udp_dissector_lock);
			return;
		}
		LIST_DELETE(&tcp_dissector_list, nds);
		module_put(THIS_MODULE);
		DEBUGP(KERN_INFO "NSC: UDP dissector unregistered. [app_code = '0x%x' ; id = %u]\n", nds->app_code, nds->id);
		write_unlock_bh(&udp_dissector_lock);
	}
	/* Someone could be still looking at the dissector in a bh. */
	synchronize_net();
}

int
get_nsc_status()
{
	//read_lock(&mod_ref_lock);
	down(&nsc_mutex);
	if(mod_ref > 0)
	{
		//read_unlock(&mod_ref_lock);
		up(&nsc_mutex);
		return 1;
	}
	//read_unlock(&mod_ref_lock);
	up(&nsc_mutex);
	return 0;
}

module_init(init);
module_exit(fini);

EXPORT_SYMBOL(ipt_nsc_register_dissector);
EXPORT_SYMBOL(ipt_nsc_unregister_dissector);
EXPORT_SYMBOL(get_nsc_status);
EXPORT_SYMBOL(ns_check_emule_peer);
EXPORT_SYMBOL(ns_check_emule_hm);
