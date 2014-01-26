/*
 * rrcstate.h
 *
 * Created by: Qi Alfred Chen, 1/25/2014
 *
 */
#ifndef RRCSTATE_H_INCLUDED
#define RRCSTATE_H_INCLUDED
#include "stl.h"
#include "pcap.h"
#include "basic.h"
#include "io.h"
#include <arpa/inet.h>

#define LTE_TPRO_MS 300
#define LTE_TTAIL_MS 10000

class RRCStateMachine {
public:
    string state;
    long prev_ts;
    unsigned int pkt_counter;

    RRCStateMachine();
    void clearData();
    void packetArrival(const struct pcap_pkthdr *header, const u_char *pkt_data);
};


#endif // RRCSTATE_H_INCLUDED
