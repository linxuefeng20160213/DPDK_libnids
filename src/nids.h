/*
  Copyright (c) 1999 Rafal Wojtczuk <nergal@7bulls.com>. All rights reserved.
  See the file COPYING for license details.
*/

#ifndef _NIDS_NIDS_H
# define _NIDS_NIDS_H

# include <sys/types.h>
#include <netinet/in_systm.h>
#include <netinet/in.h>
# include <netinet/ip.h>
# include <netinet/tcp.h>
# include <pcap.h>

# ifdef __cplusplus
extern "C" {
# endif

# define NIDS_MAJOR 1
# define NIDS_MINOR 24

enum
{
  NIDS_WARN_IP = 1,//IP数据包异常
  NIDS_WARN_TCP,//TCP数据包异常
  NIDS_WARN_UDP,//UDP数据包异常
  NIDS_WARN_SCAN//表示有扫描攻击发生
};

enum
{
  NIDS_WARN_UNDEFINED = 0,/*表示未定义*/
  NIDS_WARN_IP_OVERSIZED,/*表示IP数据包超长*/
  NIDS_WARN_IP_INVLIST,/*表示无效的碎片队列*/
  NIDS_WARN_IP_OVERLAP,/*表示发生重叠*/
  NIDS_WARN_IP_HDR,/*表示无效IP首部，IP数据包发生异常*/
  NIDS_WARN_IP_SRR,/*表示源路由IP数据包*/
  NIDS_WARN_TCP_TOOMUCH,/*表示tcp数据个数太多，因为在libnids中在同一时刻捕获的tcp个数最大值为tcp连接参数的哈希表长度3/4  */
  NIDS_WARN_TCP_HDR,/*表示无效TCP首部，TCP数据包发生异常*/
  NIDS_WARN_TCP_BIGQUEUE,/*表示TCP接收的队列数据过多*/
  NIDS_WARN_TCP_BADFLAGS/*表示错误标记*/
};

# define NIDS_JUST_EST 1/*表示tcp连接建立*/
# define NIDS_DATA 2  /*表示接受数据的状态*/
# define NIDS_CLOSE 3 /*表示tcp连接正常关闭*/
# define NIDS_RESET 4 /*表示tcp连接被重置关闭*/
# define NIDS_TIMED_OUT 5  /*表示由于超时tcp连接被关闭*/
# define NIDS_EXITING   6	/* 表示由于超时tcp连接被关闭nids is exiting; last chance to get data */

# define NIDS_DO_CHKSUM  0
# define NIDS_DONT_CHKSUM 1

struct tuple4
{
  u_short source;
  u_short dest;
  u_int saddr;
  u_int daddr;
};/*用于描述一个地址端口对，它表示发送方IP和端口以及接收方IP和端口*/

struct half_stream
{
  char state;
  char collect;
  char collect_urg;

  char *data;
  int offset;
  int count;
  int count_new;
  int bufsize;
  int rmem_alloc;

  int urg_count;
  u_int acked;
  u_int seq;
  u_int ack_seq;
  u_int first_data_seq;
  u_char urgdata;
  u_char count_new_urg;
  u_char urg_seen;
  u_int urg_ptr;
  u_short window;
  u_char ts_on;
  u_char wscale_on;
  u_int curr_ts; 
  u_int wscale;
  struct skbuff *list;
  struct skbuff *listtail;
};

struct tcp_stream
{
  struct tuple4 addr;
  char nids_state;
  struct lurker_node *listeners;
  struct half_stream client;
  struct half_stream server;
  struct tcp_stream *next_node;
  struct tcp_stream *prev_node;
  int hash_index;
  struct tcp_stream *next_time;
  struct tcp_stream *prev_time;
  int read;
  struct tcp_stream *next_free;
  void *user;
};

/*描述libnids的一些全局参数信息*/
struct nids_prm
{
  int n_tcp_streams;/*表示哈西表大小,此哈西表用来存放tcp_stream数据结构,*/
  int n_hosts;/*表示存放ip碎片信息的哈西表的大小*/
  char *device;
  char *filename;/*用来存储网络数据捕获文件.如果设置了文件,与此同时就应该设置成员device为null,默认值为NULL*/
  int sk_buff_size;/*表示数据结构sk_buff的大小.数据结构sk_buff是linux内核中一个重要的数据结构,是用来进行数据包队列操作的*/
  int dev_addon;/*表示在数据结构sk_buff中用于网络接口上信息的字节数,如果是-1(默认值),那么libnids会根据不同的网络接口进行修正*/
  void (*syslog) ();//函数指针,默认值为nids_syslog()函数.在syslog中可以检测入侵攻击,如:网络扫描攻击
  /*函数定义类型为nids_syslog(int type,int errnum,struct ip_header * iph,void *data)*/
  int syslog_level;//表示日志等级,默认值为LOG_ALERT.
  int scan_num_hosts;//表示存储端口扫描信息的哈西表的大小
  int scan_delay;//表示在扫描检测中,两端口扫描的间隔时间
  int scan_num_ports;//表示相同源地址必须扫描的tcp端口数目
  void (*no_mem) (char *);//当libnids发生内存溢出时被调用
  int (*ip_filter) ();//函数指针,此函数可以用来分析ip数据包,当有ip数据包到达时,此函数被调用.默认值为nids_ip_filter,该函数的定义如下：
  /*static int nids_ip_filter(struct ip * x,int len) */
  char *pcap_filter;//表示过滤规则
  int promisc;//表示网卡模式,非0为混杂模式,否则为非混杂模式,默认值为1
  int one_loop_less;
  int pcap_timeout;
  int multiproc;
  int queue_limit;
  int tcp_workarounds;
  pcap_t *pcap_desc;
};

struct tcp_timeout
{
  struct tcp_stream *a_tcp;
  struct timeval timeout;
  struct tcp_timeout *next;
  struct tcp_timeout *prev;
};

int nids_init (void);
void nids_register_ip_frag (void (*));
void nids_unregister_ip_frag (void (*));
void nids_register_ip (void (*));
void nids_unregister_ip (void (*));
void nids_register_tcp (void (*));
void nids_unregister_tcp (void (*x));
void nids_register_udp (void (*));
void nids_unregister_udp (void (*));
void nids_killtcp (struct tcp_stream *);
void nids_discard (struct tcp_stream *, int);
int nids_run (void);
void nids_exit(void);
int nids_getfd (void);
int nids_dispatch (int);
int nids_next (void);
void nids_pcap_handler(u_char *, struct pcap_pkthdr *, u_char *);
struct tcp_stream *nids_find_tcp_stream(struct tuple4 *);
void nids_free_tcp_stream(struct tcp_stream *);

int nids_dpdk_init();
int nids_dpdk_run(int argc,char **argv);

extern struct nids_prm nids_params;
extern char *nids_warnings[];
extern char nids_errbuf[];
extern struct pcap_pkthdr *nids_last_pcap_header;
extern u_char *nids_last_pcap_data;
extern u_int nids_linkoffset;
extern struct tcp_timeout *nids_tcp_timeouts;

struct nids_chksum_ctl {
	u_int netaddr;
	u_int mask;
	u_int action;
	u_int reserved;
};
extern void nids_register_chksum_ctl(struct nids_chksum_ctl *, int);

# ifdef __cplusplus
}
# endif

#endif /* _NIDS_NIDS_H */
