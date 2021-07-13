

all:
	gcc tcp_redirect.c -o tcp_redirect
	gcc udp_tproxy.c -o udp_tproxy

clean:
	rm -rf *.o
