#include <stdint.h>
#include <stdlib.h>
#include <pthread.h>
#include <time.h>

#include <elperiodic.h>

#include "rtp_server.h"
#include "rtp_scan.h"

void *
rtp_server_thread(void *arg)
{
  struct rtp_server *sp = (struct rtp_server *)arg;
  double freq;
  void *pd;

  freq = 1000.0 / sp->rsap->payload.tsstep_ms;

  pd = prdic_init(freq, 0.0);
  if (pd == NULL)
    abort();

  prdic_free(pd);

  return (NULL);
}
