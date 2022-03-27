#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <time.h>
#include <unistd.h>

#include <stdio.h>

#include <elperiodic.h>

#include "mmfile.h"
#include "rtp_server.h"
#include "rtp_scan.h"
#include "rtp.h"

#define MAX_IDLE_NPKTS 5

void *
rtp_server_thread(void *arg)
{
  struct rtp_server *sp = (struct rtp_server *)arg;
  double freq;
  void *pd;
  int npkts_in_pre = rtp_server_get_npkts_in(sp);
  int fd;
  char *fname;
  union {
    struct rtp_hdr hdr;
    char raw[sizeof(struct rtp_hdr) + 512];
  } packet;
  const struct rtp_scan_args *rsap = sp->rsap;

  freq = 1000.0 / rsap->payload.tsstep_ms;

  asprintf(&fname, "%s.%d", rsap->playfile, rsap->payload.type);
  if (fname == NULL)
    abort();

  fd = mopen(fname, O_RDONLY);
  if (fd < 0)
    abort();
  free(fname);

  pd = prdic_init(freq, 0.0);
  if (pd == NULL)
    abort();

  memset(&packet, 0, sizeof(packet));
  packet.hdr.version = 2; // RTP version 2
  packet.hdr.pt = rsap->payload.type;
  packet.hdr.ssrc = rsap->ssrc_seed % (((uint32_t)sp->destport << 14) | (sp->destport >> 1));

  uint16_t seq = rsap->seq_seed % (((uint32_t)sp->destport << 14) | (sp->destport >> 1));
  uint32_t ts = rsap->ts_seed % (((uint32_t)sp->destport << 14) | (sp->destport >> 1));
  int tsstep = RTP_SRATE * rsap->payload.tsstep_ms / 1000;
  seq += rsap->ppp;
  ts += rsap->ppp * tsstep;

  int loops = 0;
  for (int idle_ncycles = 0; idle_ncycles < MAX_IDLE_NPKTS; idle_ncycles++) {
    prdic_procrastinate(pd);

    ssize_t rval = mread(fd, packet.raw + sizeof(struct rtp_hdr), rsap->payload.size);
    if (rval == rsap->payload.size) {
      packet.hdr.seq = htons(seq + loops); // increase seq with every packet
      packet.hdr.ts = htonl(ts + (loops * tsstep));
      sendto(rsap->udp_socket, &packet, sizeof(struct rtp_hdr) + rsap->payload.size, 0, (const struct sockaddr *)&sp->target, sizeof(struct sockaddr_in));
      loops += 1;
    }

    int npkts_in_post = rtp_server_get_npkts_in(sp);
    if (npkts_in_pre == npkts_in_post)
      continue;
    npkts_in_pre = npkts_in_post;
    idle_ncycles = 0;
  }

  printf("%d went idle after %d\n", sp->destport, npkts_in_pre);

  mclose(fd);
  prdic_free(pd);

  return (NULL);
}

void
rtp_server_inpkt(struct rtp_server *rsp)
{

  pthread_mutex_lock(&rsp->lock);
  rsp->npkts_in += 1;
  pthread_mutex_unlock(&rsp->lock);
}

int
rtp_server_get_npkts_in(struct rtp_server *rsp)
{
  int rval;

  pthread_mutex_lock(&rsp->lock);
  rval = rsp->npkts_in;
  pthread_mutex_unlock(&rsp->lock);
  return (rval);
}
