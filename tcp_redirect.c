/******************************************************************************
 *
 *       Filename:  tcp_redirect.c
 *
 *    Description:  test tcp redirect 
 *    ./tcp_redirect 12345
 *    接收执行iptables redirect后内核转发的数据
 *	  一直以下iptables后本机使用nc 63.223.66.11 9000 ,建立63.223.66.11 9000的tcp 连接会被./tcp_redirect 12345捕获,
 *	  也就是把目的地址改为本机地址。
 *	  并且可以通过SO_ORIGINAL_DST获取到原始目的地址
 *    iptables -t nat -N REDSOCKS
 *    # 引用
 *    iptables -t nat -I OUTPUT -j REDSOCKS
 *    # 默认配置为不处理（放最后面）
 *    iptables -t nat -A REDSOCKS -j RETURN
 *    # 将despip 63.223.66.11 dest port 9000的数据包转到端口12345,也就是reddirect程序处理
 *    iptables -t nat -I REDSOCKS -p tcp -d 63.223.66.11 --dport 9000 -j REDIRECT --to-ports 12345
 *
 *    # 将目的为157.240.19.1的所有数据包转发(要放最前面)
 *    iptables -t nat -I REDSOCKS -p tcp -d 157.240.19.1 -j REDIRECT --to-ports 12345
 *    
 *
 *
 *        Version:  1.0
 *        Created:  2021年07月13日 20时19分16秒
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  yangkun (yk)
 *          Email:  xyyangkun@163.com
 *        Company:  yangkun.com
 *
 *****************************************************************************/
#ifdef __linux__
#include <sys/types.h>
#include <netinet/in.h>
#include <linux/netfilter_ipv4.h> /* SO_ORIGINAL_DST 此头文件需要在netinet/in.h下main*/
#else
/* from linux/netfilter_ipv4.h: */
# undef  SO_ORIGINAL_DST
# define SO_ORIGINAL_DST 80
#endif

#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>     /* strtol */
#include <assert.h>

int handle_client (int c, struct sockaddr_in *clntaddr)
{
	char *s_buf="abcd1234";
	char r_buf[100]={0};
	int ret;

	// 获取原始目的地址,方便在这个地方连接
	struct sockaddr_in origin_dst_addr;
	int n = sizeof(struct sockaddr_in);
	ret = getsockopt (c, SOL_IP, SO_ORIGINAL_DST, &origin_dst_addr, &n);
	assert(ret == 0);
	printf("origin dst  addr: %s, port:%d\n",inet_ntoa(origin_dst_addr.sin_addr), ntohs(origin_dst_addr.sin_port));

	printf("client addr: %s, port:%d\n",inet_ntoa(clntaddr->sin_addr), ntohs(clntaddr->sin_port));
	write(c, s_buf, strlen(s_buf));
	read(c, r_buf, sizeof(r_buf));
	printf("recv buf:%s\n", r_buf);
	close(c);
	return 0;
}

int tunnel_transparently (int c, struct sockaddr_in *clntaddr, struct sockaddr_in *dstaddr);

int main (int argc, char **argv)
{
	int s;
	int c;
	short int port;
	struct sockaddr_in servaddr;
	struct sockaddr_in clntaddr;
	int n;
	int ret;
	struct msghdr msg;
	char cntrlbuf[64];
	struct iovec iov[1];
	char *endptr;

	if (argc < 2)
	{
		printf ("usage: %s listen_port\n", argv[0]);
		return -1;
	}

	port = strtol (argv[1], &endptr, 0);
	if (*endptr || port <= 0)
	{
		fprintf (stderr, "invalid port number %s.\n", argv[1]);
		return -2;
	}

	if ((s = socket (AF_INET, SOCK_STREAM, 0)) < 0)
	{
		fprintf (stderr, "error creating listening socket.\n");
		return -3;
	}

	n=1;
	ret=setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &n, sizeof(n));
	assert(ret==0);
	ret = setsockopt(s, SOL_SOCKET, SO_BROADCAST, &n, sizeof(n));
	assert(ret==0);

	/*
	在设置完iptables规则之后，还须为socket设置IP_TRANSPARENT选项。
	设置之后可以bind一个不属于本机的IP地址，作为客户端，
	它可以使用一个不属于本机地址的IP地址作为源IP发起连接，
	作为服务端，它可以侦听在一个不属于本机的IP地址上，
	而这正是透明代理所必须的。面对真实的客户端，
	透明代理明知道目标地址不是自己，却还是要接受连接，对于真实的服务器，
	透明代理明显不是真实的客户端，
	却还要使用真实客户端的地址发起连接。
	*/
	/* Enable TPROXY IP preservation */
	n=1;
	ret = setsockopt (s, SOL_IP, IP_TRANSPARENT, &n, sizeof(int));
	if (ret != 0)
	{
		fprintf (stderr, "error setting transparency for listening socket. err (#%d %s)\n", errno, strerror(errno));
		close (s);
		return -4;
	}

	memset (&servaddr, 0, sizeof (servaddr));
	servaddr.sin_family = AF_INET;
	servaddr.sin_addr.s_addr = htonl (INADDR_ANY);
	servaddr.sin_port = htons (port);
	if (bind (s, (struct sockaddr *) &servaddr, sizeof (servaddr)) < 0)
	{
		fprintf (stderr, "error calling bind()\n");
		return -6;
	}

	listen (s, 1024);
	while (1)
	{
		n=sizeof(clntaddr);
		if ((c = accept (s, (struct sockaddr *)&clntaddr, &n)) < 0)
		{
			fprintf (stderr, "error calling accept()\n");
			break;
		}
		handle_client (c, &clntaddr);
	}
	close (s);
	return 0;
}
