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
#include <deque>
#include "tcp_ip.h"
#include "context.h"
#include "DNSops.h"
#include "tcpflowstat.h"
#include "rrcstate.h"

class TraceAnalyze {
private:
    int pktcnt;
    vector<struct DNSQueryComb> dnsquery;

    double aveInterPacketArriveTime;
    double lastPacketArriveTime;

    double flowExpireTime;
    double latencySTime;
    string latencySTestname;
    string latencySAction;
    double latencySInd;
    vector<int> flowNoInLatency;

public:
    int gt5pktcnt;
    RRCStateMachine rrcstate;
    deque<struct TCPFlowStat> tcpflows;
    vector<struct DNSQueryComb> ansdnsquery;
    vector<string> gt5state;

    //period accounting
    double periodnum;
    int period_pktcnt,period_datacnt;
    int period_cltsndbytes,period_svrsndbytes,period_cltsndnum,period_svrsndnum;
    double period_ui_before, period_ui_after,period_net_time,period_ui_time;

    TraceAnalyze();
    void clearData();
    void addToVectorNoDup(vector<int> &vec, int val);
    void printTitle(ofstream &output);
    int printLine(ofstream &output,int i);
    void getStrAddr(long ip, char* res);
    void bswapIP(ip* ip);
    void bswapIPv6(struct ip6_hdr* ip6);
    void bswapTCP(tcphdr* tcphdr);
    void bswapUDP(udphdr* udphdr);
    void bswapDNS(struct DNS_HEADER* dnshdr);
    vector<char*> getDNSNames(string svrip);
    bool handleBreakdown(Context &ctx, double ts);
    void handleTCPFlow(string ip_src, string ip_dst, int ippayloadlen, struct tcphdr* tcphdr, double ts, int pcappktcnt, bool inlatency);
    void handleDNS(struct DNS_HEADER * dns, double ts);
    void feedTracePacket(Context ctx, const struct pcap_pkthdr *header, const u_char *pkt_data);

};

#endif /* _TRACEANALYZE_H */
