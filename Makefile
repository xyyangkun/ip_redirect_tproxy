

all:
	gcc tcp_redirect.c -o tcp_redirect
	gcc udp_tproxy.c -o udp_tproxy
	gcc tcp_tproxy.c -o tcp_tproxy

clean:
	rm -rf *.o
