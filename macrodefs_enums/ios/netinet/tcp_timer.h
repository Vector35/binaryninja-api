// Correctnes: ok
// /Users/mstanchin/share/git-reps/binaryninja/contributing/origin/iPhoneOS18.6.sdk/usr/include/netinet/tcp_timer.h

enum macro_tcp_ntimers_ext {
/* Keep the external definition the same for binary compatibility */
/*line: 70*/    TCPT_NTIMERS_EXT = 0x4,  // 4
};

// Depends on identifiers
enum macro_tcp_timers {
/*
 * Definitions of the TCP timers.
 *
 * The TCPT_PTO timer is used for probing for a tail loss in a send window.
 * If this probe gets acknowledged using SACK, it will allow the connection
 * to enter fast-recovery instead of hitting a retransmit timeout. A probe
 * timeout will send the last unacknowledged segment to generate more acks
 * with SACK information which can be used for fast-retransmiting the lost
 * packets. This will fire in the order of 10ms.
 *
 * The TCPT_REXMT timer is used to force retransmissions.
 * The TCP has the TCPT_REXMT timer set whenever segments
 * have been sent for which ACKs are expected but not yet
 * received.  If an ACK is received which advances tp->snd_una,
 * then the retransmit timer is cleared (if there are no more
 * outstanding segments) or reset to the base value (if there
 * are more ACKs expected).  Whenever the retransmit timer goes off,
 * we retransmit one unacknowledged segment, and do a backoff
 * on the retransmit timer.
 *
 * The TCPT_DELACK timer is used for transmitting delayed acknowledgements
 * if an acknowledgement was delayed in anticipation of a new segment.
 *
 * The TCPT_PERSIST timer is used to keep window size information
 * flowing even if the window goes shut.  If all previous transmissions
 * have been acknowledged(so that there are no retransmissions in progress),
 * and the window is too small to bother sending anything, then we start
 * the TCPT_PERSIST timer.  When it expires, if the window is nonzero,
 * we go to transmit state.  Otherwise, at intervals send a single byte
 * into the peer's window to force him to update our window information.
 * We do this at most as often as TCPT_PERSMIN time intervals,
 * but no more frequently than the current estimate of round-trip
 * packet time.  The TCPT_PERSIST timer is cleared whenever we receive
 * a window update from the peer.
 *
 * The TCPT_KEEP timer is used to keep connections alive.  If an
 * connection is idle (no segments received) for TCPTV_KEEP_INIT amount
 * of time, but not yet established, then we drop the connection.
 * Once the connection is established, if the connection is idle for
 * TCPTV_KEEP_IDLE time (and keepalives have been enabled on the socket),
 * we begin to probe the connection.  We force the peer to send us a
 * segment by sending:
 *	<SEQ=SND.UNA-1><ACK=RCV.NXT><CTL=ACK>
 * This segment is (deliberately) outside the window, and should elicit
 * an ack segment in response from the peer.  If, despite the TCPT_KEEP
 * initiated segments we cannot elicit a response from a peer in
 * TCPT_MAXIDLE amount of time probing, then we drop the connection.
 *
 * The TCPT_2MSL timer is used for keeping the conenction in Time-wait state
 * before fully closing it so that the connection 4-tuple can be reused.
 */
/*line: 123*/   TCPT_REXMT = 0x0, /* retransmit */ // 0
/*line: 124*/   TCPT_PERSIST = 0x1, /* retransmit persistence */ // 1
/*line: 125*/   TCPT_KEEP = 0x2, /* keep alive */ // 2
/*line: 126*/   TCPT_2MSL = 0x3, /* 2*msl quiet time timer */ // 3
/*line: 127*/   TCPT_DELACK = 0x4, /* delayed ack timer */ // 4
/*line: 132*/   TCPT_MAX = 0x4,  // 4
/*line: 134*/   TCPT_NONE = 0x5,  // (TCPT_MAX+1)
/*line: 135*/   TCPT_NTIMERS = 0x5,  // (TCPT_MAX+1)
};

