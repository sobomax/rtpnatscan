struct rtp_receiver_stats;

struct rtp_scan_args {
  int ppp;
  struct {
    int size;
    int type;
    int tsstep_ms;
  } payload;
  int udp_socket;
  uint64_t ssrc_seed;
  uint64_t seq_seed;
  uint64_t ts_seed;
  struct rtp_receiver_stats *rrsp;
};
