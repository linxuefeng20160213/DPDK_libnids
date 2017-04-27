/*
  Copyright (c) 1999 Rafal Wojtczuk <nergal@7bulls.com>. All rights reserved.
  See the file COPYING for license details.
*/

#include <sys/types.h>
#include <sys/queue.h>
#include <setjmp.h>
#include <stdarg.h>
#include <ctype.h>
#include <errno.h>
#include <getopt.h>

#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <inttypes.h>
#include <syslog.h>
#include <alloca.h>
#include <pcap.h>
#include <errno.h>

#if (HAVE_UNISTD_H)
#include <unistd.h>
#endif
#include <stdlib.h>
#include "checksum.h"
#include "ip_fragment.h"
#include "scan.h"
#include "tcp.h"
#include "util.h"
#include "nids.h"
#ifdef HAVE_LIBGTHREAD_2_0
#include <glib.h>
#endif

#include <rte_common.h>
#include <rte_vect.h>
#include <rte_byteorder.h>
#include <rte_log.h>
#include <rte_memory.h>
#include <rte_memcpy.h>
#include <rte_memzone.h>
#include <rte_eal.h>
#include <rte_per_lcore.h>
#include <rte_launch.h>
#include <rte_atomic.h>
#include <rte_cycles.h>
#include <rte_prefetch.h>
#include <rte_lcore.h>
#include <rte_per_lcore.h>
#include <rte_branch_prediction.h>
#include <rte_interrupts.h>
#include <rte_pci.h>
#include <rte_random.h>
#include <rte_debug.h>
#include <rte_ether.h>
#include <rte_ethdev.h>
#include <rte_ring.h>
#include <rte_mempool.h>
#include <rte_mbuf.h>
#include <rte_ip.h>
#include <rte_tcp.h>
#include <rte_udp.h>
#include <rte_string_fns.h>

#include <cmdline_parse.h>
#include <cmdline_parse_etheraddr.h>


#ifdef __linux__
extern int set_all_promisc();
#endif

#define int_ntoa(x)	inet_ntoa(*((struct in_addr *)&x))
extern int ip_options_compile(unsigned char *);
extern int raw_init();
static void nids_syslog(int, int, struct ip *, void *);
static int nids_ip_filter(struct ip *, int);

static struct proc_node *ip_frag_procs;
static struct proc_node *ip_procs;
static struct proc_node *udp_procs;

struct proc_node *tcp_procs;
static int linktype;
static pcap_t *desc = NULL;


#ifdef HAVE_LIBGTHREAD_2_0

/* async queue for multiprocessing - mcree */
static GAsyncQueue *cap_queue;

/* items in the queue */
struct cap_queue_item {
     void *data;
     bpf_u_int32 caplen;
};

/* marks end of queue */
static struct cap_queue_item EOF_item;

/* error buffer for glib calls */
static GError *gerror = NULL;

#endif

char nids_errbuf[PCAP_ERRBUF_SIZE];
struct pcap_pkthdr * nids_last_pcap_header = NULL;
u_char *nids_last_pcap_data = NULL;
u_int nids_linkoffset = 0;

char *nids_warnings[] = {
    "Murphy - you never should see this message !",
    "Oversized IP packet",
    "Invalid IP fragment list: fragment over size",
    "Overlapping IP fragments",
    "Invalid IP header",
    "Source routed IP frame",
    "Max number of TCP streams reached",
    "Invalid TCP header",
    "Too much data in TCP receive queue",
    "Invalid TCP flags"
};

struct nids_prm nids_params = {
    1040,			/* n_tcp_streams */
    256,			/* n_hosts */
    NULL,			/* device */
    NULL,			/* filename */
    168,			/* sk_buff_size */
    -1,				/* dev_addon */
    nids_syslog,		/* syslog() */
    LOG_ALERT,			/* syslog_level */
    256,			/* scan_num_hosts */
    3000,			/* scan_delay */
    10,				/* scan_num_ports */
    nids_no_mem,		/* no_mem() */
    nids_ip_filter,		/* ip_filter() */
    NULL,			/* pcap_filter */
    1,				/* promisc */
    0,				/* one_loop_less */
    1024,			/* pcap_timeout */
    0,				/* multiproc */
    20000,			/* queue_limit */
    0,				/* tcp_workarounds */
    NULL			/* pcap_desc */
};

/*DPDK*/
#define NB_SOCKETS 8
#define NB_MBUF   8192

#define MAX_PKT_BURST 32
#define BURST_TX_DRAIN_US 100 /* TX drain every ~100us */

#define RTE_LOGTYPE_L2FWD RTE_LOGTYPE_USER1

/* ethernet addresses of ports */
static struct ether_addr l2fwd_ports_eth_addr[RTE_MAX_ETHPORTS];
static uint64_t dest_eth_addr[RTE_MAX_ETHPORTS];

/*
 * Configurable number of RX/TX ring descriptors
 */
#define RTE_TEST_RX_DESC_DEFAULT 128
#define RTE_TEST_TX_DESC_DEFAULT 512
static uint16_t nb_rxd = RTE_TEST_RX_DESC_DEFAULT;
static uint16_t nb_txd = RTE_TEST_TX_DESC_DEFAULT;

struct mbuf_table {
	unsigned len;
	struct rte_mbuf *m_table[MAX_PKT_BURST];
};

/*l2fwd*/
#define MAX_RX_QUEUE_PER_LCORE 16
#define MAX_TX_QUEUE_PER_PORT 16
struct lcore_queue_conf {
	unsigned n_rx_port;
	unsigned rx_port_list[MAX_RX_QUEUE_PER_LCORE];
	struct mbuf_table tx_mbufs[RTE_MAX_ETHPORTS];

} __rte_cache_aligned;
struct lcore_queue_conf lcore_queue_conf[RTE_MAX_LCORE];


/* mask of enabled ports */
static uint32_t enabled_port_mask = 0;
static int promiscuous_on = 0; /**< Ports set in promiscuous mode off by default. */
static int numa_on = 1; /**< NUMA is enabled by default. */

/* list of enabled ports */
static uint32_t l2fwd_dst_ports[RTE_MAX_ETHPORTS];

/* mask of enabled ports */
static uint32_t l2fwd_enabled_port_mask = 0;

static unsigned int l2fwd_rx_queue_per_lcore = 1;


static struct rte_eth_conf port_conf = {
	.rxmode = {
		.mq_mode = ETH_MQ_RX_RSS,
		.max_rx_pkt_len = ETHER_MAX_LEN,
		.split_hdr_size = 0,
		.header_split   = 0, /**< Header Split disabled */
		.hw_ip_checksum = 1, /**< IP checksum offload enabled */
		.hw_vlan_filter = 0, /**< VLAN filtering disabled */
		.jumbo_frame    = 0, /**< Jumbo Frame Support disabled */
		.hw_strip_crc   = 0, /**< CRC stripped by hardware */
	},
	.rx_adv_conf = {
		.rss_conf = {
			.rss_key = NULL,
			.rss_hf = ETH_RSS_IP,
		},
	},
	.txmode = {
		.mq_mode = ETH_MQ_TX_NONE,
	},
};

struct rte_mempool * l2fwd_pktmbuf_pool = NULL;//static struct rte_mempool * pktmbuf_pool[NB_SOCKETS];
#define TIMER_MILLISECOND 2000000ULL /* around 1ms at 2 Ghz */
#define MAX_TIMER_PERIOD 86400 /* 1 day max */
static int64_t timer_period = 10 * TIMER_MILLISECOND * 1000; /* default period is 10 seconds */

/* Per-port statistics struct */
struct l2fwd_port_statistics {
	uint64_t tx;
	uint64_t rx;
	uint64_t dropped;
} __rte_cache_aligned;
struct l2fwd_port_statistics port_statistics[RTE_MAX_ETHPORTS];


/*DPDK Declare*/




static int nids_ip_filter(struct ip *x, int len)
{
    (void)x;
    (void)len;
    return 1;
}

static void nids_syslog(int type, int errnum, struct ip *iph, void *data)
{
    char saddr[20], daddr[20];
    char buf[1024];
    struct host *this_host;
    unsigned char flagsand = 255, flagsor = 0;
    int i;

    switch (type) {

    case NIDS_WARN_IP:
	if (errnum != NIDS_WARN_IP_HDR) {
	    strcpy(saddr, int_ntoa(iph->ip_src.s_addr));
	    strcpy(daddr, int_ntoa(iph->ip_dst.s_addr));
	    syslog(nids_params.syslog_level,
		   "%s, packet (apparently) from %s to %s\n",
		   nids_warnings[errnum], saddr, daddr);
	} else
	    syslog(nids_params.syslog_level, "%s\n",
		   nids_warnings[errnum]);
	break;

    case NIDS_WARN_TCP:
	strcpy(saddr, int_ntoa(iph->ip_src.s_addr));
	strcpy(daddr, int_ntoa(iph->ip_dst.s_addr));
	if (errnum != NIDS_WARN_TCP_HDR)
	    syslog(nids_params.syslog_level,
		   "%s,from %s:%hu to  %s:%hu\n", nids_warnings[errnum],
		   saddr, ntohs(((struct tcphdr *) data)->th_sport), daddr,
		   ntohs(((struct tcphdr *) data)->th_dport));
	else
	    syslog(nids_params.syslog_level, "%s,from %s to %s\n",
		   nids_warnings[errnum], saddr, daddr);
	break;

    case NIDS_WARN_SCAN:
	this_host = (struct host *) data;
	sprintf(buf, "Scan from %s. Scanned ports: ",
		int_ntoa(this_host->addr));
	for (i = 0; i < this_host->n_packets; i++) {
	    strcat(buf, int_ntoa(this_host->packets[i].addr));
	    sprintf(buf + strlen(buf), ":%hu,",
		    this_host->packets[i].port);
	    flagsand &= this_host->packets[i].flags;
	    flagsor |= this_host->packets[i].flags;
	}
	if (flagsand == flagsor) {
	    i = flagsand;
	    switch (flagsand) {
	    case 2:
		strcat(buf, "scan type: SYN");
		break;
	    case 0:
		strcat(buf, "scan type: NULL");
		break;
	    case 1:
		strcat(buf, "scan type: FIN");
		break;
	    default:
		sprintf(buf + strlen(buf), "flags=0x%x", i);
	    }
	} else
	    strcat(buf, "various flags");
	syslog(nids_params.syslog_level, "%s", buf);
	break;

    default:
	syslog(nids_params.syslog_level, "Unknown warning number ?\n");
    }
}

/* called either directly from pcap_hand() or from cap_queue_process_thread()
 * depending on the value of nids_params.multiproc - mcree
 */
static void call_ip_frag_procs(void *data,bpf_u_int32 caplen)
{
    struct proc_node *i;
    for (i = ip_frag_procs; i; i = i->next)
	(i->item) (data, caplen);
}


/* wireless frame types, mostly from tcpdump (wam) */
#define FC_TYPE(fc)             (((fc) >> 2) & 0x3)
#define FC_SUBTYPE(fc)          (((fc) >> 4) & 0xF)
#define DATA_FRAME_IS_QOS(x)    ((x) & 0x08)
#define FC_WEP(fc)              ((fc) & 0x4000)
#define FC_TO_DS(fc)            ((fc) & 0x0100)
#define FC_FROM_DS(fc)          ((fc) & 0x0200)
#define T_MGMT 0x0		/* management */
#define T_CTRL 0x1		/* control */
#define T_DATA 0x2		/* data */
#define T_RESV 0x3		/* reserved */
#define EXTRACT_LE_16BITS(p) \
	((unsigned short)*((const unsigned char *)(p) + 1) << 8 | \
	(unsigned short)*((const unsigned char *)(p) + 0))
#define EXTRACT_16BITS(p)	((unsigned short)ntohs(*(const unsigned short *)(p)))
#define LLC_FRAME_SIZE 8
#define LLC_OFFSET_TO_TYPE_FIELD 6
#define ETHERTYPE_IP 0x0800

void nids_pcap_handler(u_char * par, struct pcap_pkthdr *hdr, u_char * data)
{
    u_char *data_aligned;
#ifdef HAVE_LIBGTHREAD_2_0
    struct cap_queue_item *qitem;
#endif
#ifdef DLT_IEEE802_11
    unsigned short fc;
    int linkoffset_tweaked_by_prism_code = 0;
    int linkoffset_tweaked_by_radio_code = 0;
#endif

    /*
     * Check for savagely closed TCP connections. Might
     * happen only when nids_params.tcp_workarounds is non-zero;
     * otherwise nids_tcp_timeouts is always NULL.
     */
    if (NULL != nids_tcp_timeouts)
      tcp_check_timeouts(&hdr->ts);

    nids_last_pcap_header = hdr;
    nids_last_pcap_data = data;
    (void)par; /* warnings... */
    switch (linktype) {
    case DLT_EN10MB:
	if (hdr->caplen < 14)
	    return;
	/* Only handle IP packets and 802.1Q VLAN tagged packets below. */
	if (data[12] == 8 && data[13] == 0) {
	    /* Regular ethernet */
	    nids_linkoffset = 14;
	} else if (data[12] == 0x81 && data[13] == 0) {
	    /* Skip 802.1Q VLAN and priority information */
	    nids_linkoffset = 18;
	} else
	    /* non-ip frame */
	    return;
	break;
#ifdef DLT_PRISM_HEADER
#ifndef DLT_IEEE802_11
#error DLT_PRISM_HEADER is defined, but DLT_IEEE802_11 is not ???
#endif
    case DLT_PRISM_HEADER:
	nids_linkoffset = 144; //sizeof(prism2_hdr);
	linkoffset_tweaked_by_prism_code = 1;
        //now let DLT_IEEE802_11 do the rest
#endif
#ifdef DLT_IEEE802_11_RADIO
    case DLT_IEEE802_11_RADIO:
        // just get rid of the radio tap header
        if (!linkoffset_tweaked_by_prism_code) {
          nids_linkoffset = EXTRACT_LE_16BITS(data + 2); // skip radiotap header
          linkoffset_tweaked_by_radio_code = 1;
        }
        //now let DLT_IEEE802_11 do the rest
#endif
#ifdef DLT_IEEE802_11
    case DLT_IEEE802_11:
	/* I don't know why frame control is always little endian, but it 
	 * works for tcpdump, so who am I to complain? (wam)
	 */
	if (!linkoffset_tweaked_by_prism_code && !linkoffset_tweaked_by_radio_code)
		nids_linkoffset = 0;
	fc = EXTRACT_LE_16BITS(data + nids_linkoffset);
	if (FC_TYPE(fc) != T_DATA || FC_WEP(fc)) {
	    return;
	}
	if (FC_TO_DS(fc) && FC_FROM_DS(fc)) {
	    /* a wireless distribution system packet will have another
	     * MAC addr in the frame
	     */
	    nids_linkoffset += 30;
	} else {
	    nids_linkoffset += 24;
	}
	if (DATA_FRAME_IS_QOS(FC_SUBTYPE(fc)))
	  nids_linkoffset += 2;
	if (hdr->len < nids_linkoffset + LLC_FRAME_SIZE)
	    return;
	if (ETHERTYPE_IP !=
	    EXTRACT_16BITS(data + nids_linkoffset + LLC_OFFSET_TO_TYPE_FIELD)) {
	    /* EAP, LEAP, and other 802.11 enhancements can be 
	     * encapsulated within a data packet too.  Look only at
	     * encapsulated IP packets (Type field of the LLC frame).
	     */
	    return;
	}
	nids_linkoffset += LLC_FRAME_SIZE;
	break;
#endif
    default:;
    }
    if (hdr->caplen < nids_linkoffset)
	return;

/*
* sure, memcpy costs. But many EXTRACT_{SHORT, LONG} macros cost, too. 
* Anyway, libpcap tries to ensure proper layer 3 alignment (look for
* handle->offset in pcap sources), so memcpy should not be called.
*/
#ifdef LBL_ALIGN
    if ((unsigned long) (data + nids_linkoffset) & 0x3) {
	data_aligned = alloca(hdr->caplen - nids_linkoffset + 4);
	data_aligned -= (unsigned long) data_aligned % 4;
	memcpy(data_aligned, data + nids_linkoffset, hdr->caplen - nids_linkoffset);
    } else 
#endif
  data_aligned = data + nids_linkoffset;

 #ifdef HAVE_LIBGTHREAD_2_0
     if(nids_params.multiproc) { 
        /* 
         * Insert received fragment into the async capture queue.
         * We hope that the overhead of memcpy 
         * will be saturated by the benefits of SMP - mcree
         */
        qitem=malloc(sizeof(struct cap_queue_item));
        if (qitem && (qitem->data=malloc(hdr->caplen - nids_linkoffset))) {
          qitem->caplen=hdr->caplen - nids_linkoffset;
          memcpy(qitem->data,data_aligned,qitem->caplen);
          g_async_queue_lock(cap_queue);
          /* ensure queue does not overflow */
          if(g_async_queue_length_unlocked(cap_queue) > nids_params.queue_limit) {
	    /* queue limit reached: drop packet - should we notify user via syslog? */
	    free(qitem->data);
	    free(qitem);
	    } else {
	    /* insert packet to queue */
	    g_async_queue_push_unlocked(cap_queue,qitem);
          }
          g_async_queue_unlock(cap_queue);
	}
     } else { /* user requested simple passthru - no threading */
        call_ip_frag_procs(data_aligned,hdr->caplen - nids_linkoffset);
     }
 #else
     call_ip_frag_procs(data_aligned,hdr->caplen - nids_linkoffset);
 #endif
}

static void gen_ip_frag_proc(u_char * data, int len)
{
    struct proc_node *i;
    struct ip *iph = (struct ip *) data;
	{
	#define NIPQUAD(addr) \
	((unsigned char *)&addr)[0], \
    ((unsigned char *)&addr)[1], \
    ((unsigned char *)&addr)[2], \
    ((unsigned char *)&addr)[3]	

    printf("gen_ip_frag_proc: Protocol:%d %d.%d.%d.%d -> %d.%d.%d.%d\n",iph->ip_p,NIPQUAD(iph->ip_src),NIPQUAD(iph->ip_dst));

	}
    int need_free = 0;
    int skblen;
    void (*glibc_syslog_h_workaround)(int, int, struct ip *, void*)=
        nids_params.syslog;

    if (!nids_params.ip_filter(iph, len))
	return;

    if (len < (int)sizeof(struct ip) || iph->ip_hl < 5 || iph->ip_v != 4 ||
	ip_fast_csum((unsigned char *) iph, iph->ip_hl) != 0 ||
	len < ntohs(iph->ip_len) || ntohs(iph->ip_len) < iph->ip_hl << 2) {
	glibc_syslog_h_workaround(NIDS_WARN_IP, NIDS_WARN_IP_HDR, iph, 0);
	return;
    }
    if (iph->ip_hl > 5 && ip_options_compile((unsigned char *)data)) {
	glibc_syslog_h_workaround(NIDS_WARN_IP, NIDS_WARN_IP_SRR, iph, 0);
	return;
    }
    switch (ip_defrag_stub((struct ip *) data, &iph)) {
    case IPF_ISF:
	return;
    case IPF_NOTF:
	need_free = 0;
	iph = (struct ip *) data;
	break;
    case IPF_NEW:
	need_free = 1;
	break;
    default:;
    }
    skblen = ntohs(iph->ip_len) + 16;
    if (!need_free)
	skblen += nids_params.dev_addon;
    skblen = (skblen + 15) & ~15;
    skblen += nids_params.sk_buff_size;

    for (i = ip_procs; i; i = i->next)
	(i->item) (iph, skblen);
    if (need_free)
	free(iph);
}

#if HAVE_BSD_UDPHDR
#define UH_ULEN uh_ulen
#define UH_SPORT uh_sport
#define UH_DPORT uh_dport
#else
#define UH_ULEN len
#define UH_SPORT source
#define UH_DPORT dest
#endif

static void process_udp(char *data)
{
    struct proc_node *ipp = udp_procs;
    struct ip *iph = (struct ip *) data;
    struct udphdr *udph;
    struct tuple4 addr;
    int hlen = iph->ip_hl << 2;
    int len = ntohs(iph->ip_len);
    int ulen;
    if (len - hlen < (int)sizeof(struct udphdr))
	return;
    udph = (struct udphdr *) (data + hlen);
    ulen = ntohs(udph->UH_ULEN);
    if (len - hlen < ulen || ulen < (int)sizeof(struct udphdr))
	return;
    /* According to RFC768 a checksum of 0 is not an error (Sebastien Raveau) */
    if (udph->uh_sum && my_udp_check
	((void *) udph, ulen, iph->ip_src.s_addr,
	 iph->ip_dst.s_addr)) return;
    addr.source = ntohs(udph->UH_SPORT);
    addr.dest = ntohs(udph->UH_DPORT);
    addr.saddr = iph->ip_src.s_addr;
    addr.daddr = iph->ip_dst.s_addr;
    while (ipp) {
	ipp->item(&addr, ((char *) udph) + sizeof(struct udphdr),
		  ulen - sizeof(struct udphdr), data);
	ipp = ipp->next;
    }
}
static void gen_ip_proc(u_char * data, int skblen)
{
    switch (((struct ip *) data)->ip_p) {
    case IPPROTO_TCP:
	printf("process_TCP\n");
	process_tcp(data, skblen);
	break;
    case IPPROTO_UDP:
	printf("process_UDP\n");
	process_udp((char *)data);
	break;
    case IPPROTO_ICMP:
	if (nids_params.n_tcp_streams)
	    process_icmp(data);
	break;
    default:
	break;
    }
}
static void init_procs()
{
    ip_frag_procs = mknew(struct proc_node);
    ip_frag_procs->item = gen_ip_frag_proc;
    ip_frag_procs->next = 0;
    ip_procs = mknew(struct proc_node);
    ip_procs->item = gen_ip_proc;
    ip_procs->next = 0;
    tcp_procs = 0;
    udp_procs = 0;
}

void nids_register_udp(void (*x))
{
    register_callback(&udp_procs, x);
}

void nids_unregister_udp(void (*x))
{
    unregister_callback(&udp_procs, x);
}

void nids_register_ip(void (*x))
{
    register_callback(&ip_procs, x);
}

void nids_unregister_ip(void (*x))
{
    unregister_callback(&ip_procs, x);
}

void nids_register_ip_frag(void (*x))
{
    register_callback(&ip_frag_procs, x);
}

void nids_unregister_ip_frag(void (*x))
{
    unregister_callback(&ip_frag_procs, x);
}

static int open_live()
{
    char *device;
    int promisc = 0;

    if (nids_params.device == NULL)
	nids_params.device = pcap_lookupdev(nids_errbuf);
    if (nids_params.device == NULL)
	return 0;

    device = nids_params.device;
    if (!strcmp(device, "all"))
	device = "any";
    else
	promisc = (nids_params.promisc != 0);

    if ((desc = pcap_open_live(device, 16384, promisc,
			       nids_params.pcap_timeout, nids_errbuf)) == NULL)
	return 0;
#ifdef __linux__
    if (!strcmp(device, "any") && nids_params.promisc
	&& !set_all_promisc()) {
	nids_errbuf[0] = 0;
	strncat(nids_errbuf, strerror(errno), sizeof(nids_errbuf) - 1);
	return 0;
    }
#endif
    if (!raw_init()) {
	nids_errbuf[0] = 0;
	strncat(nids_errbuf, strerror(errno), sizeof(nids_errbuf) - 1);
	return 0;
    }
    return 1;
}

#ifdef HAVE_LIBGTHREAD_2_0

#define START_CAP_QUEUE_PROCESS_THREAD() \
    if(nids_params.multiproc) { /* threading... */ \
	 if(!(g_thread_create_full((GThreadFunc)cap_queue_process_thread,NULL,0,FALSE,TRUE,G_THREAD_PRIORITY_LOW,&gerror))) { \
	    strcpy(nids_errbuf, "thread: "); \
	    strncat(nids_errbuf, gerror->message, sizeof(nids_errbuf) - 8); \
	    return 0; \
	 }; \
    }

#define STOP_CAP_QUEUE_PROCESS_THREAD() \
    if(nids_params.multiproc) { /* stop the capture process thread */ \
	 g_async_queue_push(cap_queue,&EOF_item); \
    }


/* thread entry point 
 * pops capture queue items and feeds them to
 * the ip fragment processors - mcree
 */
static void cap_queue_process_thread()
{
     struct cap_queue_item *qitem;
     
     while(1) { /* loop "forever" */
	  qitem=g_async_queue_pop(cap_queue);
	  if (qitem==&EOF_item) break; /* EOF item received: we should exit */
	  call_ip_frag_procs(qitem->data,qitem->caplen);
	  free(qitem->data);
	  free(qitem);
     }
     g_thread_exit(NULL);
}

#else

#define START_CAP_QUEUE_PROCESS_THREAD()
#define STOP_CAP_QUEUE_PROCESS_THREAD()

#endif

/*DPDK Functions*/
static void
print_ethaddr(const char *name, const struct ether_addr *eth_addr)
{
	char buf[ETHER_ADDR_FMT_SIZE];
	ether_format_addr(buf, ETHER_ADDR_FMT_SIZE, eth_addr);
	printf("%s%s", name, buf);
}


/* Send the burst of packets on an output interface */
static int
l2fwd_send_burst(struct lcore_queue_conf *qconf, unsigned n, uint8_t port)
{
	struct rte_mbuf **m_table;
	unsigned ret;
	unsigned queueid =0;

	m_table = (struct rte_mbuf **)qconf->tx_mbufs[port].m_table;

	ret = rte_eth_tx_burst(port, (uint16_t) queueid, m_table, (uint16_t) n);
	port_statistics[port].tx += ret;
	if (unlikely(ret < n)) {
		port_statistics[port].dropped += (n - ret);
		do {
			rte_pktmbuf_free(m_table[ret]);
		} while (++ret < n);
	}

	return 0;
}

/* Print out statistics on packets dropped */
static void
print_stats(void)
{
	uint64_t total_packets_dropped, total_packets_tx, total_packets_rx;
	unsigned portid;

	total_packets_dropped = 0;
	total_packets_tx = 0;
	total_packets_rx = 0;

	const char clr[] = { 27, '[', '2', 'J', '\0' };
	const char topLeft[] = { 27, '[', '1', ';', '1', 'H','\0' };

		/* Clear screen and move to top left */
	printf("%s%s", clr, topLeft);

	printf("\nPort statistics ====================================");

	for (portid = 0; portid < RTE_MAX_ETHPORTS; portid++) {
		/* skip disabled ports */
		if ((l2fwd_enabled_port_mask & (1 << portid)) == 0)
			continue;
		printf("\nStatistics for port %u ------------------------------"
			   "\nPackets sent: %24"PRIu64
			   "\nPackets received: %20"PRIu64
			   "\nPackets dropped: %21"PRIu64,
			   portid,
			   port_statistics[portid].tx,
			   port_statistics[portid].rx,
			   port_statistics[portid].dropped);

		total_packets_dropped += port_statistics[portid].dropped;
		total_packets_tx += port_statistics[portid].tx;
		total_packets_rx += port_statistics[portid].rx;
	}
	printf("\nAggregate statistics ==============================="
		   "\nTotal packets sent: %18"PRIu64
		   "\nTotal packets received: %14"PRIu64
		   "\nTotal packets dropped: %15"PRIu64,
		   total_packets_tx,
		   total_packets_rx,
		   total_packets_dropped);
	printf("\n====================================================\n");
}

static void
l2fwd_simple_forward(struct rte_mbuf *m, unsigned portid)
{
	struct proc_node *i;

	struct ether_hdr *eth;
	void *tmp;
	unsigned dst_port;
	u_char *data_aligned;

	dst_port = l2fwd_dst_ports[portid];
	eth = rte_pktmbuf_mtod(m, struct ether_hdr *);
	#define NIPQUAD(addr) \
	((unsigned char *)&addr)[0], \
    ((unsigned char *)&addr)[1], \
    ((unsigned char *)&addr)[2], \
    ((unsigned char *)&addr)[3]	
	
	printf("eth->ether_type:%04x,pkt len:%d\n",eth->ether_type,m->pkt_len);

	if(0x0008 == eth->ether_type){
		nids_linkoffset = 14;
		//printf("Ips: %d.%d.%d.%d -> %d.%d.%d.%d\n",NIPQUAD(eth+26),NIPQUAD(eth+30));	
	}
	else if(0x0081 == eth->ether_type){
		nids_linkoffset = 18;
		//printf("Other Ips: %d.%d.%d.%d -> %d.%d.%d.%d\n",NIPQUAD(eth+26+4),NIPQUAD(eth+30+4));
	}

	data_aligned = eth + 1;  
	for(i = ip_frag_procs; i; i = i->next)
		(i->item) (data_aligned, m->pkt_len - nids_linkoffset); //可能是一个问题点

	rte_pktmbuf_free(m);

	/* 02:00:00:00:00:xx */
	//tmp = &eth->d_addr.addr_bytes[0];
	//*((uint64_t *)tmp) = 0x000000000002 + ((uint64_t)dst_port << 40);

	/* src addr */
	//ether_addr_copy(&l2fwd_ports_eth_addr[dst_port], &eth->s_addr);

	//l2fwd_send_packet(m, (uint8_t) dst_port);
}


/* main processing loop */
static void
l2fwd_main_loop(void)
{
	struct rte_mbuf *pkts_burst[MAX_PKT_BURST];
	struct rte_mbuf *m;
	unsigned lcore_id;
	uint64_t prev_tsc, diff_tsc, cur_tsc, timer_tsc;
	unsigned i, j, portid, nb_rx;
	struct lcore_queue_conf *qconf;
	const uint64_t drain_tsc = (rte_get_tsc_hz() + US_PER_S - 1) / US_PER_S * BURST_TX_DRAIN_US;

	prev_tsc = 0;
	timer_tsc = 0;

	lcore_id = rte_lcore_id();
	qconf = &lcore_queue_conf[lcore_id];

	if (qconf->n_rx_port == 0) {
		RTE_LOG(INFO, L2FWD, "lcore %u has nothing to do\n", lcore_id);
		return;
	}

	RTE_LOG(INFO, L2FWD, "entering main loop on lcore %u\n", lcore_id);

	for (i = 0; i < qconf->n_rx_port; i++) {

		portid = qconf->rx_port_list[i];
		RTE_LOG(INFO, L2FWD, " -- lcoreid=%u portid=%u\n", lcore_id,
			portid);
	}

	while (1) {

		cur_tsc = rte_rdtsc();

		/*
		 * TX burst queue drain
		 */
		diff_tsc = cur_tsc - prev_tsc;
		if (unlikely(diff_tsc > drain_tsc)) {

			for (portid = 0; portid < RTE_MAX_ETHPORTS; portid++) {
				if (qconf->tx_mbufs[portid].len == 0)
					continue;
				l2fwd_send_burst(&lcore_queue_conf[lcore_id],
						 qconf->tx_mbufs[portid].len,
						 (uint8_t) portid);
				qconf->tx_mbufs[portid].len = 0;
			}

			/* if timer is enabled */
			//if (timer_period > 0) {

				/* advance the timer */
				//timer_tsc += diff_tsc;

				/* if timer has reached its timeout */
				//if (unlikely(timer_tsc >= (uint64_t) timer_period)) {

					/* do this only on master core */
					//if (lcore_id == rte_get_master_lcore()) {
						//print_stats();
						/* reset the timer */
						//timer_tsc = 0;
					//}
				//}
			//}

			prev_tsc = cur_tsc;
		}

		/*
		 * Read packet from RX queues
		 */
		for (i = 0; i < qconf->n_rx_port; i++) {

			portid = qconf->rx_port_list[i];
			nb_rx = rte_eth_rx_burst((uint8_t) portid, 0,
						 pkts_burst, MAX_PKT_BURST);

			port_statistics[portid].rx += nb_rx;

			for (j = 0; j < nb_rx; j++) {
				m = pkts_burst[j];
				rte_prefetch0(rte_pktmbuf_mtod(m, void *));
				l2fwd_simple_forward(m, portid);
			}
		}
	}
}

static int
l2fwd_launch_one_lcore(__attribute__((unused)) void *dummy)
{
	l2fwd_main_loop();
	return 0;
}


/* Check the link status of all ports in up to 9s, and print them finally */
static void
check_all_ports_link_status(uint8_t port_num, uint32_t port_mask)
{
#define CHECK_INTERVAL 100 /* 100ms */
#define MAX_CHECK_TIME 90 /* 9s (90 * 100ms) in total */
	uint8_t portid, count, all_ports_up, print_flag = 0;
	struct rte_eth_link link;

	printf("\nChecking link status");
	fflush(stdout);
	for (count = 0; count <= MAX_CHECK_TIME; count++) {
		all_ports_up = 1;
		for (portid = 0; portid < port_num; portid++) {
			if ((port_mask & (1 << portid)) == 0)
				continue;
			memset(&link, 0, sizeof(link));
			rte_eth_link_get_nowait(portid, &link);
			/* print link status if flag set */
			if (print_flag == 1) {
				if (link.link_status)
					printf("Port %d Link Up - speed %u "
						"Mbps - %s\n", (uint8_t)portid,
						(unsigned)link.link_speed,
				(link.link_duplex == ETH_LINK_FULL_DUPLEX) ?
					("full-duplex") : ("half-duplex\n"));
				else
					printf("Port %d Link Down\n",
						(uint8_t)portid);
				continue;
			}
			/* clear all_ports_up flag if any link down */
			if (link.link_status == 0) {
				all_ports_up = 0;
				break;
			}
		}
		/* after finally printing all link status, get out */
		if (print_flag == 1)
			break;

		if (all_ports_up == 0) {
			printf(".");
			fflush(stdout);
			rte_delay_ms(CHECK_INTERVAL);
		}

		/* set the print_flag if all ports up or timeout */
		if (all_ports_up == 1 || count == (MAX_CHECK_TIME - 1)) {
			print_flag = 1;
			printf("done\n");
		}
	}
}

static int
l2fwd_parse_timer_period(const char *q_arg)
{
	char *end = NULL;
	int n;

	/* parse number string */
	n = strtol(q_arg, &end, 10);
	if ((q_arg[0] == '\0') || (end == NULL) || (*end != '\0'))
		return -1;
	if (n >= MAX_TIMER_PERIOD)
		return -1;

	return n;
}

static unsigned int
l2fwd_parse_nqueue(const char *q_arg)
{
	char *end = NULL;
	unsigned long n;

	/* parse hexadecimal string */
	n = strtoul(q_arg, &end, 10);
	if ((q_arg[0] == '\0') || (end == NULL) || (*end != '\0'))
		return 0;
	if (n == 0)
		return 0;
	if (n >= MAX_RX_QUEUE_PER_LCORE)
		return 0;

	return n;
}

/* display usage */
static void
l2fwd_usage(const char *prgname)
{
	printf("%s [EAL options] -- -p PORTMASK [-q NQ]\n"
	       "  -p PORTMASK: hexadecimal bitmask of ports to configure\n"
	       "  -q NQ: number of queue (=ports) per lcore (default is 1)\n"
		   "  -T PERIOD: statistics will be refreshed each PERIOD seconds (0 to disable, 10 default, 86400 maximum)\n",
	       prgname);
}

static int
l2fwd_parse_portmask(const char *portmask)
{
	char *end = NULL;
	unsigned long pm;

	/* parse hexadecimal string */
	pm = strtoul(portmask, &end, 16);
	if ((portmask[0] == '\0') || (end == NULL) || (*end != '\0'))
		return -1;

	if (pm == 0)
		return -1;

	return pm;
}

/* Parse the argument given in the command line of the application */
static int
l2fwd_parse_args(int argc, char **argv)
{
	int opt, ret;
	char **argvopt;
	int option_index;
	char *prgname = argv[0];
	static struct option lgopts[] = {
		{NULL, 0, 0, 0}
	};

	argvopt = argv;

	while ((opt = getopt_long(argc, argvopt, "p:q:T:",
				  lgopts, &option_index)) != EOF) {

		switch (opt) {
		/* portmask */
		case 'p':
			l2fwd_enabled_port_mask = l2fwd_parse_portmask(optarg);
			if (l2fwd_enabled_port_mask == 0) {
				printf("invalid portmask\n");
				l2fwd_usage(prgname);
				return -1;
			}
			break;

		/* nqueue */
		case 'q':
			l2fwd_rx_queue_per_lcore = l2fwd_parse_nqueue(optarg);
			if (l2fwd_rx_queue_per_lcore == 0) {
				printf("invalid queue number\n");
				l2fwd_usage(prgname);
				return -1;
			}
			break;

		/* timer period */
		case 'T':
			timer_period = l2fwd_parse_timer_period(optarg) * 1000 * TIMER_MILLISECOND;
			if (timer_period < 0) {
				printf("invalid timer period\n");
				l2fwd_usage(prgname);
				return -1;
			}
			break;

		/* long options */
		case 0:
			l2fwd_usage(prgname);
			return -1;

		default:
			l2fwd_usage(prgname);
			return -1;
		}
	}

	if (optind >= 0)
		argv[optind-1] = prgname;

	ret = optind-1;
	optind = 0; /* reset getopt lib */
	return ret;
}


int nids_dpdk_init()
{
	init_procs();
    tcp_init(nids_params.n_tcp_streams);
    ip_frag_init(nids_params.n_hosts);
    scan_init();
	return 1;
}

int nids_dpdk_run(int argc,char **argv){
	
	struct lcore_queue_conf *qconf;
	struct rte_eth_dev_info dev_info;

	int ret;
	uint8_t nb_ports;
	uint8_t nb_ports_available;
	uint8_t portid, last_port;
	unsigned lcore_id, rx_lcore_id;
	unsigned nb_ports_in_mask = 0;

	
	/*init EAL*/
	ret = rte_eal_init(argc,argv);//可以用一个配置文件配置参数
	if(ret < 0)
		rte_exit(EXIT_FAILURE, "Invalid EAL parameters\n");
	argc -= ret;
	argv += ret;

	/* parse application arguments (after the EAL ones) */
	ret = l2fwd_parse_args(argc, argv);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "Invalid L2FWD arguments\n");
	
	/*create the mbuf pool*/
	l2fwd_pktmbuf_pool = rte_pktmbuf_pool_create("mbuf_pool", NB_MBUF, 32,
		0, RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());
	if (l2fwd_pktmbuf_pool == NULL)
		rte_exit(EXIT_FAILURE, "Cannot init mbuf pool\n");

	nb_ports = rte_eth_dev_count();
	if (nb_ports == 0)
		rte_exit(EXIT_FAILURE, "No Ethernet ports - bye\n");
	
	if (nb_ports > RTE_MAX_ETHPORTS)
		nb_ports = RTE_MAX_ETHPORTS;

	/* reset l2fwd_dst_ports */
	for (portid = 0; portid < RTE_MAX_ETHPORTS; portid++)
			l2fwd_dst_ports[portid] = 0;
	last_port = 0;

	/*
	 * Each logical core is assigned a dedicated TX queue on each port.
	 */
	 for (portid = 0; portid < nb_ports; portid++) {
		/* skip ports that are not enabled */
		if ((l2fwd_enabled_port_mask & (1 << portid)) == 0)
			continue;

		if (nb_ports_in_mask % 2) {
			l2fwd_dst_ports[portid] = last_port;
			l2fwd_dst_ports[last_port] = portid;
		}
		else
			last_port = portid;

		nb_ports_in_mask++;

		rte_eth_dev_info_get(portid, &dev_info);
	}
	if (nb_ports_in_mask % 2) {
		printf("Notice: odd number of ports in portmask.\n");
		l2fwd_dst_ports[last_port] = last_port;
	}

	rx_lcore_id = 0;
	qconf = NULL;
	
	
	/* Initialize the port/queue configuration of each logical core */
	for (portid = 0; portid < nb_ports; portid++) {
		/* skip ports that are not enabled */
		if ((l2fwd_enabled_port_mask & (1 << portid)) == 0)
			continue;

		/* get the lcore_id for this port */
		while (rte_lcore_is_enabled(rx_lcore_id) == 0 ||
			lcore_queue_conf[rx_lcore_id].n_rx_port ==
			l2fwd_rx_queue_per_lcore) {
			rx_lcore_id++;
			if (rx_lcore_id >= RTE_MAX_LCORE)
				rte_exit(EXIT_FAILURE, "Not enough cores\n");
			}
	
			if (qconf != &lcore_queue_conf[rx_lcore_id])
				/* Assigned a new logical core in the loop above. */
				qconf = &lcore_queue_conf[rx_lcore_id];
	
			qconf->rx_port_list[qconf->n_rx_port] = portid;
			qconf->n_rx_port++;
			printf("Lcore %u: RX port %u\n", rx_lcore_id, (unsigned) portid);
	}

	nb_ports_available = nb_ports;

	/*Initialise each port*/
	for (portid = 0; portid < nb_ports; portid++) {
		/* skip ports that are not enabled */
		if ((l2fwd_enabled_port_mask & (1 << portid)) == 0) {
			printf("Skipping disabled port %u\n", (unsigned) portid);
			nb_ports_available--;
			continue;
		}
		/* init port */
		printf("Initializing port %u... ", (unsigned) portid);
		fflush(stdout);
		ret = rte_eth_dev_configure(portid, 1, 1, &port_conf);
		if (ret < 0)
			rte_exit(EXIT_FAILURE, "Cannot configure device: err=%d, port=%u\n",
				  ret, (unsigned) portid);

		rte_eth_macaddr_get(portid,&l2fwd_ports_eth_addr[portid]);

		/* init one RX queue */
		fflush(stdout);
		ret = rte_eth_rx_queue_setup(portid, 0, nb_rxd,
					     rte_eth_dev_socket_id(portid),
					     NULL,
					     l2fwd_pktmbuf_pool);
		if (ret < 0)
			rte_exit(EXIT_FAILURE, "rte_eth_rx_queue_setup:err=%d, port=%u\n",
				  ret, (unsigned) portid);

		/* init one TX queue on each port */
		fflush(stdout);
		ret = rte_eth_tx_queue_setup(portid, 0, nb_txd,
				rte_eth_dev_socket_id(portid),
				NULL);
		if (ret < 0)
			rte_exit(EXIT_FAILURE, "rte_eth_tx_queue_setup:err=%d, port=%u\n",
				ret, (unsigned) portid);

		/* Start device */
		ret = rte_eth_dev_start(portid);
		if (ret < 0)
			rte_exit(EXIT_FAILURE, "rte_eth_dev_start:err=%d, port=%u\n",
				  ret, (unsigned) portid);

		printf("done: \n");

		rte_eth_promiscuous_enable(portid);

		printf("Port %u, MAC address: %02X:%02X:%02X:%02X:%02X:%02X\n\n",
				(unsigned) portid,
				l2fwd_ports_eth_addr[portid].addr_bytes[0],
				l2fwd_ports_eth_addr[portid].addr_bytes[1],
				l2fwd_ports_eth_addr[portid].addr_bytes[2],
				l2fwd_ports_eth_addr[portid].addr_bytes[3],
				l2fwd_ports_eth_addr[portid].addr_bytes[4],
				l2fwd_ports_eth_addr[portid].addr_bytes[5]);

		/* initialize port stats */
		memset(&port_statistics, 0, sizeof(port_statistics));
		
	}

	if(!nb_ports_available){
		rte_exit(EXIT_FAILURE,
			"All available ports are disabled. Please set portmask.\n");
	}

	check_all_ports_link_status(nb_ports, l2fwd_enabled_port_mask);

	/* launch per-lcore init on every lcore */
	rte_eal_mp_remote_launch(l2fwd_launch_one_lcore, NULL, CALL_MASTER);
	RTE_LCORE_FOREACH_SLAVE(lcore_id) {
		if (rte_eal_wait_lcore(lcore_id) < 0)
			return -1;
	}

	/*init_procs();
    tcp_init(nids_params.n_tcp_streams);
    ip_frag_init(nids_params.n_hosts);
    scan_init();*/

	return 0;

	
}


int nids_init()
{
    /* free resources that previous usages might have allocated */
    nids_exit();

    if (nids_params.pcap_desc)
        desc = nids_params.pcap_desc;
    else if (nids_params.filename) {
	if ((desc = pcap_open_offline(nids_params.filename,
				      nids_errbuf)) == NULL)
	    return 0;
    } else if (!open_live())
	return 0;

    if (nids_params.pcap_filter != NULL) {
	u_int mask = 0;
	struct bpf_program fcode;

	if (pcap_compile(desc, &fcode, nids_params.pcap_filter, 1, mask) <
	    0) return 0;
	if (pcap_setfilter(desc, &fcode) == -1)
	    return 0;
    }
    switch ((linktype = pcap_datalink(desc))) {
#ifdef DLT_IEEE802_11
#ifdef DLT_PRISM_HEADER
    case DLT_PRISM_HEADER:
#endif
#ifdef DLT_IEEE802_11_RADIO
    case DLT_IEEE802_11_RADIO:
#endif
    case DLT_IEEE802_11:
	/* wireless, need to calculate offset per frame */
	break;
#endif
#ifdef DLT_NULL
    case DLT_NULL:
        nids_linkoffset = 4;
        break;
#endif        
    case DLT_EN10MB:
	nids_linkoffset = 14;
	break;
    case DLT_PPP:
	nids_linkoffset = 4;
	break;
	/* Token Ring Support by vacuum@technotronic.com, thanks dugsong! */
    case DLT_IEEE802:
	nids_linkoffset = 22;
	break;

    case DLT_RAW:
    case DLT_SLIP:
	nids_linkoffset = 0;
	break;
#define DLT_LINUX_SLL   113
    case DLT_LINUX_SLL:
	nids_linkoffset = 16;
	break;
#ifdef DLT_FDDI
    case DLT_FDDI:
        nids_linkoffset = 21;
        break;
#endif        
#ifdef DLT_PPP_SERIAL 
    case DLT_PPP_SERIAL:
        nids_linkoffset = 4;
        break;
#endif        
    default:
	strcpy(nids_errbuf, "link type unknown");
	return 0;
    }
    if (nids_params.dev_addon == -1) {
	if (linktype == DLT_EN10MB)
	    nids_params.dev_addon = 16;
	else
	    nids_params.dev_addon = 0;
    }
    if (nids_params.syslog == nids_syslog)
	openlog("libnids", 0, LOG_LOCAL0);

    init_procs();
    tcp_init(nids_params.n_tcp_streams);
    ip_frag_init(nids_params.n_hosts);
    scan_init();

    if(nids_params.multiproc) {
#ifdef HAVE_LIBGTHREAD_2_0
	 g_thread_init(NULL);
	 cap_queue=g_async_queue_new();
#else
	 strcpy(nids_errbuf, "libnids was compiled without threads support");
	 return 0;        
#endif
    }

    return 1;
}

int nids_run()
{
	/*
    if (!desc) {
	strcpy(nids_errbuf, "Libnids not initialized");
	return 0;
    }*/
    START_CAP_QUEUE_PROCESS_THREAD(); /* threading... */
    //pcap_loop(desc, -1, (pcap_handler) nids_pcap_handler, 0);
    /* FIXME: will this code ever be called? Don't think so - mcree */
    //STOP_CAP_QUEUE_PROCESS_THREAD(); 
    //nids_exit();
    return 0;
}


void nids_exit()
{
    if (!desc) {
        strcpy(nids_errbuf, "Libnids not initialized");
	return;
    }
#ifdef HAVE_LIBGTHREAD_2_0
    if (nids_params.multiproc) {
    /* I have no portable sys_sched_yield,
       and I don't want to add more synchronization...
    */
      while (g_async_queue_length(cap_queue)>0) 
        usleep(100000);
    }
#endif
    tcp_exit();
    ip_frag_exit();
    scan_exit();
    strcpy(nids_errbuf, "loop: ");
    strncat(nids_errbuf, pcap_geterr(desc), sizeof nids_errbuf - 7);
    if (!nids_params.pcap_desc)
        pcap_close(desc);
    desc = NULL;

    free(ip_procs);
    free(ip_frag_procs);
}

int nids_getfd()
{
    if (!desc) {
	strcpy(nids_errbuf, "Libnids not initialized");
	return -1;
    }
    return pcap_get_selectable_fd(desc);
}

int nids_next()
{
    struct pcap_pkthdr h;
    char *data;

    if (!desc) {
	strcpy(nids_errbuf, "Libnids not initialized");
	return 0;
    }
    if (!(data = (char *) pcap_next(desc, &h))) {
	strcpy(nids_errbuf, "next: ");
	strncat(nids_errbuf, pcap_geterr(desc), sizeof(nids_errbuf) - 7);
	return 0;
    }
    /* threading is quite useless (harmful) in this case - should we do an API change?  */
    START_CAP_QUEUE_PROCESS_THREAD();
    nids_pcap_handler(0, &h, (u_char *)data);
    STOP_CAP_QUEUE_PROCESS_THREAD();
    return 1;
}

int nids_dispatch(int cnt)
{
    int r;

    if (!desc) {
	strcpy(nids_errbuf, "Libnids not initialized");
	return -1;
    }
    START_CAP_QUEUE_PROCESS_THREAD(); /* threading... */
    if ((r = pcap_dispatch(desc, cnt, (pcap_handler) nids_pcap_handler,
                                    NULL)) == -1) {
	strcpy(nids_errbuf, "dispatch: ");
	strncat(nids_errbuf, pcap_geterr(desc), sizeof(nids_errbuf) - 11);
    }
    STOP_CAP_QUEUE_PROCESS_THREAD(); 
    return r;
}
