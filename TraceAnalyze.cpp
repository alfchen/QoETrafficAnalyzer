/*
 * TraceAnalyze.cpp
 *
 * Created by: Qi Alfred Chen, 1/07/2013
 *
 */
#include "TraceAnalyze.h"

TraceAnalyze::TraceAnalyze(){
    clearData();
}

void TraceAnalyze::clearData(){
    pktcnt=0;
    gt5pktcnt=0;
    aveInterPacketArriveTime=0;
  /*  for (int i=0;i<tcpflows.size();i++){
      free(tcpflows[i]);
    }
    */tcpflows.clear();
   /*  for (int i=0;i<dnsquery.size();i++){
      free(dnsquery[i]);
    }*/
    for (int i=0;i<dnsquery.size();i++){
        for (int j=0;j<dnsquery[i].urlsnum;j++){
            free(dnsquery[i].urls[j]);
        }
    }
    dnsquery.clear();
    for (int i=0;i<ansdnsquery.size();i++){
        for (int j=0;j<ansdnsquery[i].urlsnum;j++){
            free(ansdnsquery[i].urls[j]);
        }
    }
    ansdnsquery.clear();
    rrcstate.clearData();
    gt5state.clear();
}

double getTime(struct timeval time) {
    return time.tv_sec+(time.tv_usec/1000000.0);
}

void TraceAnalyze::getStrAddr(long ip, char* res){
 //   char* res=(char*)malloc(20);
    sprintf(res, "%d.%d.%d.%d", ip>>24,(ip>>16)&0xFF,(ip>>8)&0xFF,(ip)&0xFF);
//    return res;
}

void TraceAnalyze::bswapIP(struct ip* ip){
    ip->ip_len=bswap16(ip->ip_len);
    ip->ip_id=bswap16(ip->ip_id);
    ip->ip_off=bswap16(ip->ip_off);
    ip->ip_sum=bswap16(ip->ip_sum);
 //   ip->ip_src.s_addr=bswap32(ip->ip_src.s_addr);
 //   ip->ip_dst.s_addr=bswap32(ip->ip_dst.s_addr);
}

void TraceAnalyze::bswapIPv6(struct ip6_hdr* ip6){
    ip6->ip6_ctlun.ip6_un1.ip6_un1_flow=bswap32(ip6->ip6_ctlun.ip6_un1.ip6_un1_flow);
    ip6->ip6_ctlun.ip6_un1.ip6_un1_plen=bswap16(ip6->ip6_ctlun.ip6_un1.ip6_un1_plen);
}

void TraceAnalyze::bswapTCP(struct tcphdr* tcphdr){
    tcphdr->source=bswap16(tcphdr->source);
    tcphdr->dest=bswap16(tcphdr->dest);
    tcphdr->window=bswap16(tcphdr->window);
    tcphdr->check=bswap16(tcphdr->check);
    tcphdr->urg_ptr=bswap16(tcphdr->urg_ptr);
    tcphdr->seq=bswap32(tcphdr->seq);
    tcphdr->ack_seq=bswap32(tcphdr->ack_seq);
}

void TraceAnalyze::bswapUDP(struct udphdr* udphdr){
    udphdr->source=bswap16(udphdr->source);
    udphdr->dest=bswap16(udphdr->dest);
    udphdr->len=bswap16(udphdr->len);
    udphdr->check=bswap16(udphdr->check);
}

void TraceAnalyze::bswapDNS(struct DNS_HEADER* dnshdr){
    dnshdr->id=bswap16(dnshdr->id);
    dnshdr->q_count=bswap16(dnshdr->q_count);
    dnshdr->ans_count=bswap16(dnshdr->ans_count);
    dnshdr->auth_count=bswap16(dnshdr->auth_count);
    dnshdr->add_count=bswap16(dnshdr->add_count);
}

void TraceAnalyze::printTitle(ofstream &output){
    output<<",\"Average Packet Inter-Arrival Time\"" \
          <<",\"Packet Inter-Arrival Greater than 0.5s\"" \
          <<",\"Device Radio State when Packet Inter-Arrival Time is Greater than 5s\"" \
          <<",\"DNS Query No.\""\
          <<",\"DNS Query Name\""\
          <<",\"DNS Query Response Time (s)\""\
          <<",\"TCP Flow No.\""\
          <<",\"TCP Device IP Address\""\
          <<",\"TCP Device TCP Port\""\
          <<",\"TCP Server IP Address\""\
          <<",\"TCP Server TCP Port\""\
          <<",\"TCP Server Possible DNS Names\""\
          <<",\"TCP Flow Average Packet Inter-Arrival Time\"" \
          <<",\"TCP Flow Connection Setup Time (s)\""\
          <<",\"TCP Flow # of Retransmissions from Device to Server\""\
          <<",\"TCP Flow # of Retransmissions Bytes from Device to Server\""\
          <<",\"TCP Flow # of Retransmissions from Server to Device\""\
          <<",\"TCP Flow # of Retransmissions Bytes from Server to Device\"";
}

int TraceAnalyze::printLine(ofstream &output,int i){
    bool printsth=false;
    if (i==0){
        printsth=true;
       output<<","<<aveInterPacketArriveTime;
       output<<","<<gt5pktcnt*1.0/(pktcnt-1);
    }
    else {
       output<<",,";
    }


    if (i<gt5state.size()){
        printsth=true;
       output<<","<<"\""<<gt5state[i]<<"\"";
    }
    else{
       output<<",";
    }

    //DNS
    if (i<ansdnsquery.size()){
        printsth=true;
        output<<","<<i;
        output<<",\"";
        if (ansdnsquery[i].urlsnum>=0){
          output<<ansdnsquery[i].urls[0];
          for (int j=1;j<ansdnsquery[i].urlsnum;j++)
          output<<";"<<ansdnsquery[i].urls[j];
        }
        output<<"\"";
         output<<","<<ansdnsquery[i].ts;
    }
    else {
        output<<",,,";
    }

    //TCP
    if (i<tcpflows.size()){
        printsth=true;
        output<<","<<i;
    //    char res[3000];
     //   getStrAddr(tcpflows[i].cltip, res);
        output<<","<<tcpflows[i].cltip;
        output<<","<<tcpflows[i].cltport;
    //    getStrAddr(tcpflows[i].svrip, res);
        output<<","<<tcpflows[i].svrip;
        output<<","<<tcpflows[i].svrport;
        output<<",";
        vector<char*> outputvec;
        for (int j=0; j<ansdnsquery.size();j++){
            bool isthisentry=false;
            for (int k=0;k<ansdnsquery[j].ansnum;k++){
           //     printf("compare %s %s\n",getStrAddr(tcpflows[i]->svrip),getStrAddr(ansdnsquery[j]->ansips[k]));
                if (tcpflows[i].svrip.compare(ansdnsquery[j].ansips[k])==0){
                    isthisentry=true;
                    break;
                }
            }
            if (isthisentry){
            for (int k=0;k<ansdnsquery[j].urlsnum;k++){
                bool invec=false;
                for (int tt=0;tt<outputvec.size();tt++){
                  if (strcmp(outputvec[tt],ansdnsquery[j].urls[k])==0){
                      invec=true;
                    break;
                  }
                }
                if (!invec){
                    outputvec.push_back(ansdnsquery[j].urls[k]);
                }
            }
            }
        }
        for (int tt=0;tt<outputvec.size();tt++){
            output<<outputvec[tt]<<";";
        }

        output<<","<<tcpflows[i].avepacketinterarrivaltime;
        output<<","<<tcpflows[i].tcpconnsetuptime;
        output<<","<<tcpflows[i].cltretxnum;
        output<<","<<tcpflows[i].cltretxbytes;
        output<<","<<tcpflows[i].svrretxnum;
        output<<","<<tcpflows[i].svrretxbytes;
    }
    else {
        output<<",,,,,,,,,,,,";
    }



    if (printsth)
      return 1;
    return 0;
}

void TraceAnalyze::handleTCPFlow(string ip_src, string ip_dst, int ippayloadlen, struct tcphdr* tcphdr, double ts){
   int belongsToSomeone=0;
   for (int i=0;i<tcpflows.size();i++){
       if (tcpflows[i].tcpconnstate<TCPCONSTATE_FIN \
            && tcpflows[i].tcpconnstate>=TCPCONSTATE_CLOSED \
            && tcpflows[i].isMyPacket(ip_src,ip_dst, tcphdr)==1){

           tcpflows[i].addPacket(ip_src,ip_dst, ippayloadlen, tcphdr,ts);
           belongsToSomeone=1;
       }
   }

   if (belongsToSomeone==0 && TCPFlowStat::isNewFlow(ip_src,ip_dst,tcphdr)==1){
       struct TCPFlowStat tfs;
       tfs.clearData();
       tfs.addPacket(ip_src,ip_dst, ippayloadlen, tcphdr,ts);
       tcpflows.push_back(tfs);
   }


/*       while (true && tcpflows.size()>=1){
           struct TCPFlowStat tfs=tcpflows.front();
           if (tfs.tcpconnstate>=TCPCONSTATE_FIN \
               || (tfs.lastpacketarrivaltime>TCPCONSTATE_CLOSED \
                    && ts-tfs.lastpacketarrivaltime>60*30)){
                   tcpflows.pop_front();
           }
           else
                   break;
   }
*/
}

void TraceAnalyze::feedTracePacket(Context ctx, const struct pcap_pkthdr *header, const u_char *pkt_data) {
 // cout<<"here1\n";
    pktcnt++;

 //   if (pktcnt<200){
 //   cout<<pktcnt<<endl;

    rrcstate.packetArrival(header, pkt_data);

 //   cout<<rrcstate.state<<endl;

    double ts = getTime(header->ts);
    //packet inter-arrival time
    if (pktcnt>1){
       double iat=ts-lastPacketArriveTime;
       aveInterPacketArriveTime=(aveInterPacketArriveTime*(pktcnt-2)+iat)/(pktcnt-1);
       if (iat>0.5)
         gt5pktcnt++;
       if (iat>5){
         gt5state.push_back(rrcstate.state);
       }
    }
    lastPacketArriveTime=ts;
 //   printf("Frame ts: %f\n",ts);
 //   printf("Frame caplen: %d bytes\n",header->caplen);
 //   printf("Frame len: %d bytes\n",header->len);


    u_short ethertype=bswap16(*((u_short*)(pkt_data+ctx.getEtherLen()-2)));
    u_char* etherdatap=(u_char*)(pkt_data + ctx.getEtherLen());
    switch (ethertype){
        case 0x0800: {
            //IPv4
        //    printf("Network layer protocol: IPv4\n");

            ip* ip = (struct ip*)(etherdatap);
            bswapIP(ip);

            char ipsrcaddr[3000];
            char ipdstaddr[3000];
            inet_ntop(AF_INET, &(ip->ip_src.s_addr), ipsrcaddr, INET_ADDRSTRLEN);
            inet_ntop(AF_INET, &(ip->ip_dst.s_addr), ipdstaddr, INET_ADDRSTRLEN);
            string ip_src(ipsrcaddr);
            string ip_dst(ipdstaddr);
       //     long ipsrc=bswap32(ip->ip_src.s_addr);
       //     printf("IP source address: %d \n",(ip->ip_src.s_addr)&0xFF);
       //     printf("#%d: %s %s\n",pktcnt, ipsrcaddr, ipdstaddr);
//cout <<"here!\n";
            switch (ip->ip_p){
                case 0x06: {
                //TCP
            //    cout <<"here1!\n";
                   struct tcphdr* tcphdr=(struct tcphdr*)(etherdatap+ip->ip_hl*4);
                   bswapTCP(tcphdr);

                   handleTCPFlow(ip_src, ip_dst, ip->ip_len-ip->ip_hl*4, tcphdr, ts);

              //     printf("dport: %d \n",tcphdr->dest);



          //      cout <<"here2!\n";




                };break;
                case 0x11: {
                //UDP
             //   cout <<"here3!\n";
                   struct udphdr* udphdr=(struct udphdr*)(etherdatap+ip->ip_hl*4);
                   bswapUDP(udphdr);

                   if (udphdr->dest==0x35 || udphdr->source==0x35){
                     //  cout <<"here4!\n";

                       struct DNS_HEADER * dns = (struct DNS_HEADER *)(etherdatap+ip->ip_hl*4+sizeof (struct udphdr));
                       bswapDNS(dns);
                       if (dns->qr == 0){
                        //   printf("DNS query.\n");
//cout <<"here5!\n";
                           if (dns->q_count>0){
                           //    printf("qc: %d.\n",dns->q_count);
                           //    struct DNSQueryComb* newq=(struct DNSQueryComb*)malloc(sizeof(struct DNSQueryComb));
                               struct DNSQueryComb newq;
                               newq.clearData();
                               newq.ts=ts;
                               newq.trxid=dns->id;
                               int offset;
                               getQueryString((char *)dns+sizeof(struct DNS_HEADER), dns->q_count, newq, offset);
                               dnsquery.push_back(newq);
                           }

                       }
                       if (dns->qr == 1){
                    //       cout <<"here6!\n";
                    //      printf("DNS response.\n");

                          if (dns->q_count>0){
                      //        cout <<"here7!\n";
                      //        struct DNSQueryComb* newq=(struct DNSQueryComb*)malloc(sizeof(struct DNSQueryComb));
                              struct DNSQueryComb newq;
                              newq.clearData();
                              newq.trxid=dns->id;
                              int offset;
                              char* endquery=getQueryString((char *)dns+sizeof(struct DNS_HEADER), dns->q_count, newq, offset);
                              offset+=sizeof(struct DNS_HEADER);
                          //    printf("%x %x\n", (unsigned char)(*endquery), (unsigned char)(*(endquery+1)));

//cout <<pktcnt<<" off: "<<offset<<" here8!\n";
                          //    struct DNSQueryComb* newansq=(struct DNSQueryComb*)malloc(sizeof(struct DNSQueryComb));
                              struct DNSQueryComb newansq;
                              newansq.clearData();
                              newansq.trxid=dns->id;
                           //   cout <<"here10!\n";
                              getAnswerString((unsigned char*)endquery, (unsigned char*)dns, dns->ans_count, newansq);
                          //    cout <<"here9!\n";
                              //resolve previous queries
                              for (int i=0;i<dnsquery.size();i++){
                                  if (newq.trxid == dnsquery[i].trxid){
                                      if (dnsquery[i].deleteurl(newq, newansq)==1){
                                          newansq.ts=ts-(dnsquery[i]).ts;
                                          ansdnsquery.push_back(newansq);
                              /*             printf("%f %f %f\n",dnsquery[i]->ts, ts, newansq->ts);
                                          for (int j=0;j<newansq->urlsnum;j++)
                                            printf("%s\n",newansq->urls[j]);
                              */
                                          if (dnsquery[i].urlsnum==0){
                                            dnsquery.erase(dnsquery.begin()+i);
                                            break;
                                          }

                                      };


                                  }
                              }
                       //       cout <<"here10!\n";
                          };


                       };
                   };


                };break;
                case 0x01: {
                //ICMP
                 //   printf("pkt #:%d tranportation layer protocol: ICMP\n",pktcnt);
                };break;
                case 0x02: {
                //IGMP
                 //   printf("pkt #:%d tranportation layer protocol: IGMP\n",pktcnt);
                };break;
                default: {
                    printf("pkt #:%d Unknown tranportation layer protocol in IP: 0x%x\n",pktcnt, ip->ip_p);
                };break;

            }
        };break;
        case 0x86DD: {
            //IPv6
       //     printf("pkt #:%d Network layer protocol: IPv6\n",pktcnt);

            ip6_hdr* ip6 = (struct ip6_hdr*)(etherdatap);
            bswapIPv6(ip6);
            char ip6srcaddr[3000];
            char ip6dstaddr[3000];
            inet_ntop(AF_INET6, &(ip6->ip6_src), ip6srcaddr, INET6_ADDRSTRLEN);
            inet_ntop(AF_INET6, &(ip6->ip6_dst), ip6dstaddr, INET6_ADDRSTRLEN);
            string ip_src(ip6srcaddr);
            string ip_dst(ip6dstaddr);

        //    printf("pkt #:%d plen: %d proto: %d \nsrc: %s \ndst: %s\n",pktcnt, ip6->ip6_ctlun.ip6_un1.ip6_un1_plen, ip6->ip6_ctlun.ip6_un1.ip6_un1_nxt, ip6srcaddr, ip6dstaddr);
           switch (ip6->ip6_ctlun.ip6_un1.ip6_un1_nxt){
                case 0x06: {
                //TCP
                   struct tcphdr* tcphdr=(struct tcphdr*)(etherdatap+40);
                   bswapTCP(tcphdr);

                   handleTCPFlow(ip_src, ip_dst, ip6->ip6_ctlun.ip6_un1.ip6_un1_plen, tcphdr, ts);

                };break;
                case 0x11: {
                //UDP
                };break;
                case 0x3a: {
                //ICMP
                };break;
                default: {
                    printf("pkt #:%d Unknown tranportation layer protocol in IPv6: 0x%x\n",pktcnt, ip6->ip6_ctlun.ip6_un1.ip6_un1_nxt);
                };break;
           }
        };break;
        default: {
            printf("pkt #:%d Unknown network layer protocol in Ether: 0x%x\n",pktcnt,ethertype);
        };break;
    };

 //   u_char c=*(pkt_data);
 //   printf("Ether Protocol: %d %x %x\n",sizeof(u_char), *(pkt_data),*(pkt_data+1));

  //  };
}
