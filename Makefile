CROSS_ARCH="Linux"
CROSS_COMPILE="$(TARGET_CROSS)"
CFLAGS=-O2 -Wall -g -I/usr/local/include

%.lo : %.c
	$(CC) $(CFLAGS) -o $@ -c $<

all:	rtpnatscan

rtpnatscan:	rtp_nat_scan.o rtpp_time.o rtp.o rtp_server.o mmfile.c
	$(CC) -o rtpnatscan $^ -lpthread -lm -L/usr/local/lib -lelperiodic

rtcpnatscan:	rtcp_nat_scan.o
	$(CC) -o rtcpnatscan $^ -lpthread -lm

clean:
	rm -f *.o rtpnatscan rtcpnatscan
