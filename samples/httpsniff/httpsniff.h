#ifndef _HTTPSNIFF_H
#define _HTTPSNIFF_H

#include "list.h"
#include <pthread.h>

/*
*      Display an IP address in readable format.
*      derive from include/linux/kernel.h
*/

#define NIPQUAD(addr) \
	((unsigned char *)&addr)[0], \
	((unsigned char *)&addr)[1], \
	((unsigned char *)&addr)[2], \
	((unsigned char *)&addr)[3]

#define HIPQUAD(addr) \
	((unsigned char *)&addr)[3], \
	((unsigned char *)&addr)[2], \
	((unsigned char *)&addr)[1], \
	((unsigned char *)&addr)[0]

enum http_state
{
	STATE_INIT=0,
	STATE_READ_HDR,
	STATE_HDR_OK,
	STATE_READ_DATA,
	STATE_BOUNDARY_START,	
	STATE_FILENAME_OK,
	STATE_READ_FILECONTENT1,	
	STATE_READ_FILECONTENT2,
	STATE_FILECONTENT_OK,	
	STATE_BOUNDARY_END,
};

struct conn_ctx
{
	struct list_head list;

	unsigned int src;
	unsigned int dst;
	unsigned short sport;
	unsigned short dport;

	int state;
	int content_length;	// 数据部分总长
	char post_url[256];	// POST的action地址
	char ref_url[256];	// 访问的地址

	// test
	char ua[128]; // user agent

	int start_time;	// TCP 连接建立时间
	int last_time;	// 上次TCP活动时间
	int file_fd;
	char boundary1[128];
	char cur_filename[256];
	char cur_filepath[256];
	char cur_filetype[128];
	int cur_len;

	unsigned char md5_hash[16];
	char show_hash[32];
	MD5_CTX md5;
};

#define HASHSIZE	(255)
static inline unsigned int hash_by_tuple4(unsigned int src,unsigned int dst,unsigned short sport,unsigned short dport)
{
	return (src+dst+sport+dport)%HASHSIZE;
}

struct conn_list
{
	struct list_head list;

	pthread_rwlock_t lock;

	int qlen;
};

// for debug print
#define USER_EMERG (0)
#define USER_ALERT (1)
#define USER_CRIT (2)
#define USER_ERR (3)
#define USER_WARNING (4)
#define USER_NOTICE (5)
#define USER_INFO (6)
#define USER_DEBUG (7)
#define USER_DETAIL (8)

#define P_EMERG(fmt,args...) do{if(debug >= USER_EMERG) printf(fmt,##args);}while(0)
#define P_ALERT(fmt,args...) do{if(debug >= USER_ALERT) printf(fmt,##args);}while(0)
#define P_CRIT(fmt,args...) do{if(debug >= USER_CRIT) printf(fmt,##args);}while(0)
#define P_ERR(fmt,args...) do{if(debug >= USER_ERR) printf(fmt,##args);}while(0)
#define P_WARNING(fmt,args...) do{if(debug >= USER_WARNING) printf(fmt,##args);}while(0)
#define P_NOTICE(fmt,args...) do{if(debug >= USER_NOTICE) printf(fmt,##args);}while(0)
#define P_INFO(fmt,args...) do{if(debug >= USER_INFO) printf(fmt,##args);}while(0)
#define P_DEBUG(fmt,args...) do{if(debug >= USER_DEBUG) printf(fmt,##args);}while(0)

// print hex (in byte)
static inline void PByte(char *tag,void *data,int len)
{
	int i;
	unsigned char *p=(unsigned char *)data;
	printf("%s",tag);
	for(i=0;i<len;i++)
	{
		if(i%16 == 0)
			printf("\n%04xh: ",i);
		printf("%02X ",*p++);
	}
	printf("\n");
}
#define P_BYTE(tag,data,len) do{if(debug >= USER_DETAIL) PByte(tag,data,len);}while(0)

#define SYSLOG(level,fmt,args...) syslog(LOG_LOCAL1|level,fmt,##args)

#endif
