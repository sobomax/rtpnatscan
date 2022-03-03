#include <arpa/inet.h>
#include <stdint.h>
#include <stdlib.h>

#include "rtp.h"

int
rtp_pt_info(int pt, struct rtp_pt_profile *res)
{
    switch (pt) {
    case RTP_PCMU:
    case RTP_PCMA:
        res->bytes_per_frame = 8;
        res->ticks_per_frame = 1;
        break;

    case RTP_G729:
        /* 10 ms per 8 kbps G.729 frame */
        res->bytes_per_frame = 10;
        res->ticks_per_frame = 10;
        break;

    case RTP_G723:
        /* 30 ms per 6.3 kbps G.723 frame */
        res->bytes_per_frame = 24;
        res->ticks_per_frame = 30;
        break;

    case RTP_GSM:
        /* 20 ms per 13 kbps GSM frame */
        res->bytes_per_frame = 33;
        res->ticks_per_frame = 20;
        break;

    case RTP_G722:
        res->bytes_per_frame = 8;
        res->ticks_per_frame = 1;
        break;

    default:
        return (-1);
    }
    return (0);
}
