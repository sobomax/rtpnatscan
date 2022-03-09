struct rtp_scan_args;

struct rtp_server {
  pthread_mutex_t lock;
  pthread_t sthr;
  struct sockaddr_in target;
  int destport;
  int npkts_in;
  const struct rtp_scan_args *rsap;
};

void *rtp_server_thread(void *);
void rtp_server_inpkt(struct rtp_server *);
int rtp_server_get_npkts_in(struct rtp_server *);
