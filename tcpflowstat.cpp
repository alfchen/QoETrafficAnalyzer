#include "tcpflowstat.h"

TCPFlowStat::TCPFlowStat(){
    clearData();
};

void TCPFlowStat::clearData(){
    tcpconnstate=0;
    pktcnt=0;
    simulsyn=0;
    simulsynackstate=SIMUL_SYNACK_NOT_RECEIVED;

    tcpconnsetuptime=0;
    cltretxbytes=0; svrretxbytes=0;
    cltretxnum=0; svrretxnum=0;
    lastpacketarrivaltime=-1;
}


int TCPFlowStat::getPacketDirection(string ip_src, string ip_dst, u_short srcport, u_short dstport){
    if (cltip.compare(ip_src)==0 && svrip.compare(ip_dst)==0 && cltport==srcport && svrport==dstport) return PKTSENDER_CLT;
    if (cltip.compare(ip_dst)==0 && svrip.compare(ip_src)==0 && cltport==dstport && svrport==srcport) return PKTSENDER_SVR;
    return -1;

}

int TCPFlowStat::isNewFlow(string ip_src, string ip_dst, struct tcphdr* tcphdr){
    if (tcphdr->syn==1 && tcphdr->ack!=1) return 1;
    return 0;
}

int TCPFlowStat::isMyPacket(string ip_src, string ip_dst, struct tcphdr* tcphdr) {
    if (!(cltip.compare(ip_src)==0 && svrip.compare(ip_dst)==0 \
          && cltport==tcphdr->source && svrport==tcphdr->dest) \
        &&
        !(cltip.compare(ip_dst)==0 && svrip.compare(ip_src)==0 \
          && cltport==tcphdr->dest && svrport==tcphdr->source)) return 0;
    int pktdir=getPacketDirection(ip_src, ip_dst, tcphdr->source, tcphdr->dest);

  /*  if (tcphdr->syn==1 && )
      return 0;

    if (tcphdr->syn==1 && tcphdr->ack==1 \
        && !(tcpconnstate==TCPCONSTATE_SYN_SEND && pktsdr==PKTSENDER_)){
            return 0;
    }*/
  /*  if (tcphdr->syn==1 && tcphdr->ack!=1 \
        && !(tcpconnstate==TCPCONSTATE_SYN_SEND && pktdir==PKTSENDER_SVR)) {
            return 0;
    }
*/
    if (tcpconnstate==TCPCONSTATE_FIN){
            return 0;
    }

    return 1;
}

void TCPFlowStat::swapcltsvr(){
    //only swap those updated before TCPCONSTATE_ESTABLISHED
    string stri=cltip; cltip=svrip; svrip=stri;
    u_short ts=cltport; cltport=svrport; svrport=ts;

    u_int ti=ti=cltseq; cltseq=svrseq; svrseq=ti;
    ti=cltackseq; cltackseq=svrackseq; svrackseq=ti;
    ti=cltinitseq; cltinitseq=svrinitseq; svrinitseq=ti;
};

void TCPFlowStat::printStat(){
    //for debug
    if (0 && cltip.compare("192.168.1.139")==0 && svrip.compare("31.13.74.144")==0)
    printf("\ncltip:%s svrip:%s cltport:%d svrport:%d cltseq:%u cltackseq:%u svrseq:%u svrackseq:%u\n",\
                       cltip.c_str(),svrip.c_str(), cltport,svrport,cltseq,cltackseq,svrseq,svrackseq);
}

void TCPFlowStat::addPacket(string ip_src, string ip_dst, int ippayloadlen, struct tcphdr* tcphdr, double ts){
    if (!isNewFlow(ip_src, ip_dst, tcphdr) && isMyPacket(ip_src, ip_dst, tcphdr)!=1) return;
    int pktdir=getPacketDirection(ip_src, ip_dst, tcphdr->source, tcphdr->dest);
    int tcpdatalen=ippayloadlen-tcphdr->doff*4;

    pktcnt++;
    //packet inter-arrival time
    if (lastpacketarrivaltime!=-1){
        double iat=ts-lastpacketarrivaltime;
        avepacketinterarrivaltime=(avepacketinterarrivaltime*(pktcnt-2)+iat)/(pktcnt-1);
    }
    lastpacketarrivaltime=ts;

    switch (tcpconnstate){
        case TCPCONSTATE_CLOSED: {
            if (tcphdr->syn==1 && tcphdr->ack!=1){
                syntime=ts;
                cltip=ip_src;
                svrip=ip_dst;
                cltport=tcphdr->source;
                svrport=tcphdr->dest;
                cltseq=tcphdr->seq;
                svrackseq=tcphdr->seq+1; cltinitseq=tcphdr->seq+1;
                flowinitby=FLOWINITBYCLT;
                printStat();

                tcpconnstate=TCPCONSTATE_SYN_SEND;
            }
            else {
                printf("Unknown TCP packet.\n");
            };
        };break;
        case TCPCONSTATE_SYN_SEND:{
            if (tcphdr->syn==1 && tcphdr->ack==1 && tcphdr->ack_seq==svrackseq){
                synacktime=ts;
                syntosynacktime=synacktime-syntime;
                svrseq=tcphdr->seq;
                cltackseq=tcphdr->seq+1; svrinitseq=tcphdr->seq+1;
                cltseq=tcphdr->ack_seq;

                tcpconnstate=TCPCONSTATE_SYN_RECEIVED;
                printStat();
            }
            else if (tcphdr->syn==1 && tcphdr->ack!=1 && pktdir==PKTSENDER_SVR){
                //simultanous syn sent from both side
                simulsyn=1;
                svrseq=tcphdr->seq;
                cltackseq=tcphdr->seq+1; svrinitseq=tcphdr->seq+1;

                tcpconnstate=TCPCONSTATE_SYN_RECEIVED;
                printStat();
            }
            else{
                printf("Unknown TCP packet.\n");
            };

        };break;
        case TCPCONSTATE_SYN_RECEIVED: {
            if (tcphdr->syn!=1 &&tcphdr->ack==1 && tcphdr->seq==cltseq && tcphdr->ack_seq==cltackseq){
                acktime=ts;
                synacktoacktime=acktime-synacktime;
                if (synacktoacktime>syntosynacktime){
                //the server side is the local device
                    swapcltsvr();
                    flowinitby=FLOWINITBYSVR;
                }
                tcpconnsetuptime=acktime-syntime;


                pktdir=getPacketDirection(ip_src, ip_dst, tcphdr->source, tcphdr->dest);

                if (pktdir==PKTSENDER_CLT){
                    cltseq=tcphdr->seq+tcpdatalen;
                    cltackseq=tcphdr->ack_seq;
                    svrseq=tcphdr->ack_seq;
                }
                if (pktdir==PKTSENDER_SVR){
                    svrseq=tcphdr->seq+tcpdatalen;
                    svrackseq=tcphdr->ack_seq;
                    cltseq=tcphdr->ack_seq;
                }
                printStat();

                tcpconnstate=TCPCONSTATE_ESTABLISHED;
            }
            else
            if (tcphdr->syn==1 && tcphdr->ack==1 && simulsyn==1){
            //simultanous syn sent from both side
                if (pktdir==PKTSENDER_CLT && tcphdr->seq==cltseq && tcphdr->ack_seq==cltackseq){
                    if (simulsynackstate==SIMUL_SYNACK_NOT_RECEIVED)
                      simulsynackstate==SIMUL_SYNACK_NOT_RECEIVED;
                    if (simulsynackstate==SIMUL_SYNACK_RECEIVED)
                      tcpconnstate=TCPCONSTATE_ESTABLISHED;

                }
                if (pktdir==PKTSENDER_SVR && tcphdr->seq==svrseq && tcphdr->ack_seq==svrackseq){

                    if (simulsynackstate==SIMUL_SYNACK_NOT_RECEIVED)
                      simulsynackstate==SIMUL_SYNACK_NOT_RECEIVED;
                    if (simulsynackstate==SIMUL_SYNACK_RECEIVED)
                      tcpconnstate=TCPCONSTATE_ESTABLISHED;
                }

                if (tcpconnstate==TCPCONSTATE_ESTABLISHED){
                    tcpconnsetuptime=ts-syntime;
                    cltseq=svrackseq;
                    svrseq=cltackseq;
                }

            }
            else {
                printf("Unknown TCP packet.\n");
            };
        };break;
        case TCPCONSTATE_ESTABLISHED: {
            if (tcphdr->syn!=1) {
                if (pktdir==PKTSENDER_CLT){
                    //calc metrics first
                    if (tcphdr->seq > cltseq){
                        printf("client seq is greater than expected, may be pcap's fault.\n");
                    }

                    if (tcphdr->seq < cltseq){
                    //has re-transmission
                        int retxb=cltseq-tcphdr->seq;
                        if (tcpdatalen<retxb)
                          retxb=tcpdatalen;

                        cltretxbytes+=retxb;
                        cltretxnum+=1;
                  //      printf("client retx %d bytes.\n", retxb);
                    };

                    //the last thing: update seq
                    if (tcphdr->seq+tcpdatalen > cltseq) {
                        cltseq=tcphdr->seq+tcpdatalen;
                    }

                    if (tcphdr->ack_seq >= cltackseq) {
                        cltackseq=tcphdr->ack_seq;
                    };

                    printStat();
                };

                if (pktdir==PKTSENDER_SVR){

                    if (tcphdr->seq > svrseq){
                 //       printf("svr seq is greater than expected, some server data are delayed or lost.\n");
                    }

                    if (tcphdr->seq < svrseq) {
                        int retxb=svrseq-tcphdr->seq;
                        if (tcpdatalen<retxb)
                          retxb=tcpdatalen;

                        svrretxbytes+=retxb;
                        svrretxnum+=1;
                   //     printf("server retx %d bytes.\n", retxb);
                    };

                    //the last thing: update seq

                    if (tcphdr->seq+tcpdatalen > svrseq) {
                        svrseq=tcphdr->seq+tcpdatalen;
                    }


                    if (tcphdr->ack_seq >= svrackseq) {
                        svrackseq=tcphdr->ack_seq;
                    };
                    printStat();

                };

                if (tcphdr->fin==1 || tcphdr->rst==1){
                    tcpconnstate=TCPCONSTATE_FIN;
                }
            }

        };break;
        case TCPCONSTATE_FIN:{

        };break;
        default: {
            printf("Unknown TCP connection state.\n");
        };break;
    };

}
