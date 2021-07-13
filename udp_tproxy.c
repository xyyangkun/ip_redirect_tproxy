/******************************************************************************
 *
 *       Filename:  udp_tproxy.c
 *
 *    Description:  udp tproxy 
 *    运行方式：./udp_tproxy 10053
 *    需要在路由还有iptables中添加以下规则：
 *    ip rule add fwmark 0x01/0x01 table 100
 *    ip route add local 0.0.0.0/0 dev lo table 100
 *
 *    iptables -t mangle -N REDSOCKS2
 *    # 将目的地址端口为9000的udp数据转到10053上面处理
 *    iptables -t mangle -A REDSOCKS2 -p udp --dport 9000 -j TPROXY --on-port 10053 --tproxy-mark 0x01/0x01 --on-ip 127.0.0.1
 *    # 将PREROUTING数据转到REDSOCKS2处理
 *    iptables -t mangle -A PREROUTING -j REDSOCKS2
 *    iptables -t mangle -I OUTPUT -p udp --dport 9000 -j MARK --set-mark 1
 *		https://github.com/darkk/redsocks/issues/79
 *		https://blog.csdn.net/weixin_35950365/article/details/113546197
 *		https://blog.csdn.net/u014209688/article/details/71311973
 *
 *        Version:  1.0
 *        Created:  2021年07月13日 21时06分08秒
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
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <linux/netfilter_ipv4.h> /* SO_ORIGINAL_DST 此头文件需要在netinet/in.h下main*/
#else
/* from linux/netfilter_ipv4.h: */
# undef  SO_ORIGINAL_DST
# define SO_ORIGINAL_DST 80
#endif

#include <sys/ioctl.h>
#include <unistd.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>     /* strtol */
#include <assert.h>


#define MAX_RECV_BUF (1000)

int handle_msg (struct msghdr *msg, int s);
int send_transparently (struct msghdr *msg, struct sockaddr_in *dstaddr);

int main (int argc, char **argv)
{
	int s;
	short int port;
	struct sockaddr_in servaddr;
	struct sockaddr_in clntaddr;
	int n;
	int ret;
	struct msghdr msg;
	char cntrlbuf[64];
	struct iovec iov[1];
	char buffer[MAX_RECV_BUF];
	char *endptr;

	if (argc < 2)
	{
		printf ("usage: %s  listen_port\n", argv[0]);
		return -1;
	}
	port = strtol (argv[1], &endptr, 0);
	if (*endptr || port <= 0)
	{
		fprintf (stderr, "invalid port number %s.\n", argv[1]);
		return -2;
	}

	if ((s = socket (AF_INET, SOCK_DGRAM, 0)) < 0)
	{
		fprintf (stderr, "error creating listening socket.\n");
		return -3;
	}
	n=1;
	setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &n, sizeof(n));
	setsockopt(s, SOL_SOCKET, SO_BROADCAST, &n, sizeof(n));

	n=1;
	ret = setsockopt (s, SOL_IP, IP_TRANSPARENT, &n, sizeof(int));
	if (ret != 0)
	{
		fprintf (stderr, "error setting transparency for listening socket. err (#%d %s)\n", errno, strerror(errno));
		close (s);
		return -4;
	}
	n=1;
	ret = setsockopt (s, IPPROTO_IP, IP_RECVORIGDSTADDR, &n, sizeof(int));
	if (ret != 0)
	{
		fprintf (stderr, "error setting the listening socket to IP_TRANSPARENT. err (#%d %s)\n", errno, strerror(errno));
		close (s);
		return -5;
	}
	n = 1;
#if defined(IP_PKTINFO)
    setsockopt(s, IPPROTO_IP, IP_PKTINFO, &n, sizeof(n));
#elif defined(IP_RECVDSTADDR)
    setsockopt(s, IPPROTO_IP, IP_RECVORIGDSTADDR, &n, sizeof(n));
#endif

	memset (&servaddr, 0, sizeof (servaddr));
	servaddr.sin_family = AF_INET;
	servaddr.sin_addr.s_addr = htonl (INADDR_ANY);
	servaddr.sin_port = htons (port);
	if (bind (s, (struct sockaddr *) &servaddr, sizeof (servaddr)) < 0)
	{
		fprintf (stderr, "error calling bind()\n");
		return -6;
	}

	while (1)
	{
		msg.msg_name = &clntaddr;
		msg.msg_namelen = sizeof(clntaddr);
		msg.msg_control = cntrlbuf;
		msg.msg_controllen = sizeof(cntrlbuf);
		iov[0].iov_base = buffer;
		iov[0].iov_len = sizeof (buffer);
		msg.msg_iov = iov;
		msg.msg_iovlen = 1;
		ret = recvmsg (s, &msg, 0);
		if (ret <= 0)
		{
			fprintf (stderr, "error calling recvmsg(). err (#%d %s)\n", errno, strerror(errno));
			break;
		}
		msg.msg_iov[0].iov_len = ret;
		handle_msg (&msg, s);
	}

	close (s);
	return 0;

}

int handle_msg (struct msghdr *msg, int s)
{
	struct sockaddr_in *clntaddr;
	struct sockaddr_in origin_dstaddr={0,};
	struct sockaddr_in dstaddr={0,};
	struct cmsghdr *cmsg;
	int ret;
	int found=0;
	clntaddr = msg->msg_name;
	//printf ("recvd msg from %X:%d\n", clntaddr->sin_addr.s_addr, clntaddr->sin_port);
	printf ("recvd msg from %s:%d\n", inet_ntoa(clntaddr->sin_addr), ntohs(clntaddr->sin_port));

	/* get original destination address */
	for (cmsg = CMSG_FIRSTHDR(msg); cmsg; cmsg = CMSG_NXTHDR(msg, cmsg))
	{
		if (cmsg->cmsg_level == SOL_IP && cmsg->cmsg_type == IP_RECVORIGDSTADDR)
		{
			memcpy (&origin_dstaddr, CMSG_DATA(cmsg), sizeof (struct sockaddr_in));
			origin_dstaddr.sin_family = AF_INET;
			// printf ("original dst address %X:%d\n", origin_dstaddr.sin_addr.s_addr, origin_dstaddr.sin_port);
			printf ("original dst address %s:%d\n", inet_ntoa(origin_dstaddr.sin_addr), ntohs(origin_dstaddr.sin_port));
			found = 1;
		}

	}

	if (! found)
	{
		return -1;
	}

#if 1
	ret = send_transparently (msg, &origin_dstaddr);
	if (ret <= 0)
	{
		return -2;
	}
#else
	printf("recv msg:%s\n", (char *)(msg->msg_iov[0].iov_base));

	struct msghdr send_msg;
	char send_buf[64]="0123456789";
#if 0
	send_msg.msg_name = NULL;
	send_msg.msg_namelen = 0;
#else
	send_msg.msg_name = msg->msg_name;
	send_msg.msg_namelen = msg->msg_namelen;
#endif
	send_msg.msg_control = NULL;
	send_msg.msg_controllen = 0;
	struct iovec iov[1];
	iov[0].iov_base = send_buf;
	iov[0].iov_len = sizeof (send_buf);
	send_msg.msg_iov = iov;
	send_msg.msg_iovlen = 1;
	int n = sendmsg(s, &send_msg, 0);
	if(n < 0)
	{
		printf("error to sendmsg:%s\n", strerror(errno));
	}
		
#endif
	return 0;
}

// 此处要模拟一个 远端的udp server,返回数据
int send_transparently (struct msghdr *msg, struct sockaddr_in *dstaddr)
{
	int d;
	int n;
	int ret;
	if (msg == NULL || dstaddr == NULL)
	{
		return -1;
	}
	d = socket (AF_INET, SOCK_DGRAM, 0);
	if (d == -1)
	{
		fprintf (stderr, "error creating socket (#%d %s)\n", errno, strerror(errno));
		return -2;
	}

	n=1;
	// 设置之后可以bind一个不属于本机的IP地址，作为客户端，
	// 它可以使用一个不属于本机地址的IP地址作为源IP发起连接，
	// 作为服务端，它可以侦听在一个不属于本机的IP地址上，而这正是透明代理所必须的
	ret = setsockopt (d, SOL_IP, IP_TRANSPARENT, &n, sizeof(int));
	if (ret != 0)
	{
		fprintf (stderr, "error setting transparency towards destination. err (#%d %s)\n", errno, strerror(errno));
		close (d);
		return -3;

	}

	// dstaddr不属于本地的ip地址
	// ret = bind (d, (struct sockaddr *)msg->msg_name, sizeof (struct sockaddr_in));
	ret = bind (d, (struct sockaddr *)dstaddr, sizeof (struct sockaddr_in));
	if (ret != 0)
	{
		fprintf (stderr, "error binding to client . err (#%d %s)\n", errno, strerror(errno));
		close (d);
		return -4;
	}

	// 发给本地的ip地址
	// ret = sendto (d, msg->msg_iov[0].iov_base, msg->msg_iov[0].iov_len, 0, (struct sockaddr *)dstaddr, sizeof (*dstaddr));
	char send_buf[100]= "1234567890\n";
	// ret = sendto (d, msg->msg_iov[0].iov_base, msg->msg_iov[0].iov_len, 0, (struct sockaddr *)msg->msg_name, sizeof (struct sockaddr_in));
	ret = sendto (d, send_buf, strlen(send_buf), 0, (struct sockaddr *)msg->msg_name, sizeof (struct sockaddr_in));
	if (ret <= 0)
	{
		fprintf (stderr, "error sending to detination. err (#%d %s)\n", errno, strerror(errno));
		close (d);
		return -5;
	}

	close (d);
	return 0;
}
