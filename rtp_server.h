struct rtp_scan_args;

struct rtp_server {
  pthread_mutex_t lock;
  pthread_t sthr;
  int destport;
  int npkts_in;
  const struct rtp_scan_args *rsap;
};

void *rtp_server_thread(void *);
