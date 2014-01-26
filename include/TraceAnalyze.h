/*
 * TraceAnalyze.h
 *
 * Created by: Qi Alfred Chen, 1/07/2013
 *
 */
#ifndef _TRACEANALYZE_H
#define _TRACEANALYZE_H

#include "stl.h"
#include "pcap.h"
#include "basic.h"
#include "io.h"
#include "tcp_ip.h"
#include "context.h"
#include "DNSops.h"
#include "tcpflowstat.h"
#include "rrcstate.h"

class TraceAnalyze {
private:
    int pktcnt;
    vector<struct DNSQueryComb*> dnsquery;

    double aveInterPacketArriveTime;
    double lastPacketArriveTime;
    int gt5pktcnt;

public:
    RRCStateMachine rrcstate;
    vector<struct TCPFlowStat*> tcpflows;
    vector<struct DNSQueryComb*> ansdnsquery;
    vector<string> gt5state;
    TraceAnalyze();
    void clearData();
    void printTitle(ofstream &output);
    int printLine(ofstream &output,int i);
    void bswapIP(ip* ip);
    void bswapTCP(tcphdr* tcphdr);
    void bswapUDP(udphdr* udphdr);
    void bswapDNS(struct DNS_HEADER* dnshdr);
    void feedTracePacket(Context ctx, const struct pcap_pkthdr *header, const u_char *pkt_data);

};

#endif /* _TRACEANALYZE_H */
