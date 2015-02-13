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
    flowExpireTime=30;
    latencySTime=-1;
    latencySTestname.assign("-1");
    latencySAction.assign("-1");
    latencySInd=0;
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
    flowNoInLatency.clear();

    periodnum=0;
    period_pktcnt=0;
    period_datacnt=0;
    period_cltsndbytes=0;
    period_svrsndbytes=0;
    period_cltsndnum=0;
    period_svrsndnum=0;
    period_ui_before=0;
    period_ui_after=0;
    period_net_time=0;
    period_ui_time=0;
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

vector<char*> TraceAnalyze::getDNSNames(string svrip){
            vector<char*> outputvec;
        for (int j=0; j<ansdnsquery.size();j++){
            bool isthisentry=false;
            for (int k=0;k<ansdnsquery[j].ansnum;k++){
         //       printf("compare %s %s\n",(tcpflows[i].svrip).c_str(),(ansdnsquery[j].ansips[k]).c_str());
                if (svrip.compare(ansdnsquery[j].ansips[k])==0){
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
        return outputvec;
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
        vector<char*> outputvec=getDNSNames(tcpflows[i].svrip);
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


int getNextSubString(char* fullstring, int &i, char* substring, char endChar=' '){
//substring should not be null
  int strleni=strlen(fullstring);
  while (i<strleni && (fullstring[i]==' ' || fullstring[i]=='\t')) i++;
  if (!(i<strleni)){
      return -1;
  }

  int j=0;
  while (i<strleni && fullstring[i]!=' ' \
          && fullstring[i]!='\t' && fullstring[i]!=endChar)
    substring[j++]=fullstring[i++];
  substring[j]='\0';
  return 0;
}

void getAppBehavior(string linestr, long &timestmp,char* testname,char* action,char* status){
    int i=0;
    char timestmpstr[3000];
    char* line=(char*)linestr.c_str();
    getNextSubString(line, i, timestmpstr);
    sscanf(timestmpstr,"%ld",&timestmp);
    getNextSubString(line, i, testname);
    getNextSubString(line, i, action);
    getNextSubString(line, i, status);
}

void TraceAnalyze::addToVectorNoDup(vector<int> &vec, int val){
    for (int i=0;i<vec.size();i++)
        if (vec[i]==val)
          return;
    vec.push_back(val);
}

bool isTargetServer(string svrip, int svrport){
    //wifi: 31.13.81.33:443
    //LTE: 31.13.74.49:443 31.13.74.128:443
  //  if (!(strcmp(svrip,"31.13.81.33")==0 && svrport==443)) return false;

 //   if (!(svrip.compare("31.13.74.49")==0 && svrport==443 \
 //         || svrip.compare("31.13.74.128")==0 && svrport==443)) return false;

    return true;

}

bool TraceAnalyze::handleBreakdown(Context &ctx, double ts){
//return whether it is in user-perceived latency period
    for (;latencySInd<ctx.getAppBehaviorLog().size();latencySInd++){
        long timestmp;
        char testname[3000];
        char action[3000];
        char status[3000];

        getAppBehavior(ctx.getAppBehaviorByIndex(latencySInd),timestmp,testname,action,status);
        double apptime=timestmp/1000.0;

        if (apptime>ts)
           break;

     //   if (strcmp(testname, "AppPullToUpdate")==0){
     //       if (strcmp(action, "list_update")==0){
                if (strcmp(status, "S")==0){
                    latencySTime=apptime;
                    latencySTestname.assign(testname);
                    latencySAction.assign(action);
                    flowNoInLatency.clear();
                }
                if (strcmp(status, "F")==0 \
                      && latencySTestname.compare(testname)==0 \
                      && latencySAction.compare(action)==0){
                    //print info
                    int tarflowno=-1;
                    int maxpktcnt=0;
                    printf("%ld %s %s:\n",timestmp, testname, action);
                    vector<int> consideredflows;
                    for (int i=0;i<flowNoInLatency.size();i++){
                        int flowno=flowNoInLatency[i];

                    //    char ressvr[3000];
                   //     getStrAddr(tcpflows[flowno].svrip,ressvr);
                        //wifi: 31.13.81.33:443
                        //LTE: 31.13.81.33:443
                        if (isTargetServer(tcpflows[flowno].svrip, tcpflows[flowno].svrport) && \
                            (tcpflows[flowno].period_datacnt>0) && \
                            (maxpktcnt < tcpflows[flowno].period_pktcnt)){
                            tarflowno=flowno;
                            maxpktcnt=tcpflows[flowno].period_pktcnt;
                        }
              //          char resclt[3000];
              //      getStrAddr(tcpflows[flowno].cltip,resclt);
                    if (tcpflows[flowno].period_datacnt>0){
                        consideredflows.push_back(flowno);
                        /*
                        printf("No.%d: src: %s:%d dst: %s:%d pktcnt: %d datalen: %d newflow: %d\n",i,\
                               tcpflows[flowno].cltip.c_str(),tcpflows[flowno].cltport, \
                               tcpflows[flowno].svrip.c_str(),tcpflows[flowno].svrport, \
                               tcpflows[flowno].period_pktcnt, tcpflows[flowno].period_datacnt, \
                               (tcpflows[flowno].syntime >= latencySTime));
                        vector<char*> outputvec=getDNSNames(tcpflows[flowno].svrip);
                        for (int tt=0;tt<outputvec.size();tt++){
                            printf("%s; ",outputvec[tt]);
                        }
                        printf("\n");
                        */
                    }


                    }

                    if (tarflowno!=-1){

                    double endtoendlatency=apptime-latencySTime;

                    double ui_before=tcpflows[tarflowno].period_firstpacketarrivaltime-latencySTime;
                    double ui_after=apptime-tcpflows[tarflowno].period_lastdatapacketarrivaltime;
                 //   if (ui_after>=100){
      //           if (ui_before>=0 && ui_after>=0 && tcpflows[tarflowno].period_lastdatapacketarrivaltime!=-1 \
        //             && tcpflows[tarflowno].period_lastdatapacketarrivaltime-tcpflows[tarflowno].period_firstpacketarrivaltime<5){
               /*     char resclt[3000];
                    getStrAddr(tcpflows[tarflowno].cltip,resclt);
                    char ressvr[3000];
                    getStrAddr(tcpflows[tarflowno].svrip,ressvr);

                    printf("Flow for list_update %lf %lf delta %lf:\n",latencySTime,apptime,ui_before+ui_after);
                    printf("first: %lf last: %lf delta: %lf\n",tcpflows[tarflowno].period_firstpacketarrivaltime,tcpflows[tarflowno].period_lastdatapacketarrivaltime,tcpflows[tarflowno].period_lastdatapacketarrivaltime-tcpflows[tarflowno].period_firstpacketarrivaltime);
                    printf("src: %s:%d dst: %s:%d pktcnt: %d datalen: %d ",\
                           resclt,tcpflows[tarflowno].cltport, \
                           ressvr,tcpflows[tarflowno].svrport, \
                           tcpflows[tarflowno].period_pktcnt, tcpflows[tarflowno].period_datacnt);
                    printf("ui_before: %f ui_after: %f clt: %d %d svr %d %d\n",\
                           ui_before,ui_after, \
                           tcpflows[tarflowno].period_cltsndnum, tcpflows[tarflowno].period_cltsndbytes,\
                           tcpflows[tarflowno].period_svrsndnum, tcpflows[tarflowno].period_svrsndbytes);
                    printf("\n");
                    */



             //    if (endtoendlatency <= 5){
                    periodnum++;
                    period_ui_before+=ui_before;
                    period_ui_after+=ui_after;
                    period_pktcnt+=tcpflows[tarflowno].period_pktcnt;
                    period_datacnt+=tcpflows[tarflowno].period_datacnt;
                    period_cltsndnum+=tcpflows[tarflowno].period_cltsndnum;
                    period_svrsndnum+=tcpflows[tarflowno].period_svrsndnum;
                    period_cltsndbytes+=tcpflows[tarflowno].period_cltsndbytes;
                    period_svrsndbytes+=tcpflows[tarflowno].period_svrsndbytes;
                    period_net_time+=tcpflows[tarflowno].period_lastdatapacketarrivaltime-tcpflows[tarflowno].period_firstpacketarrivaltime;
                    period_ui_time+=ui_before+ui_after;
           //      }
                 }

                    latencySTime=-1;
                    latencySTestname.assign("-1");
                    latencySAction.assign("-1");

                    for (int i=0;i<flowNoInLatency.size();i++){
                        tcpflows[flowNoInLatency[i]].endPeriodCollect();
                    }


                }
     //       }
     //   }
     //   printf("%d %s %s %s\n",timestmp,testname,action,status);
    }
    return (latencySTime!=-1);
}

void TraceAnalyze::handleTCPFlow(string ip_src, string ip_dst, int ippayloadlen, struct tcphdr* tcphdr, double ts, int pcappktcnt, bool inlatency){
   int belongsToSomeone=0;
   for (int i=0;i<tcpflows.size();i++){
       if (tcpflows[i].tcpconnstate<TCPCONSTATE_FIN \
            && tcpflows[i].tcpconnstate>=TCPCONSTATE_CLOSED \
            && tcpflows[i].isMyPacket(ip_src,ip_dst, tcphdr)==1){

           if (inlatency){
           //printf("pkt # %d into latency set %d %d\n",pktcnt,i,flowNoInLatency.size());
             addToVectorNoDup(flowNoInLatency,i);
             tcpflows[i].addPacket(ip_src,ip_dst, ippayloadlen, tcphdr, ts, pcappktcnt, inlatency);
           }
           else {
            tcpflows[i].addPacket(ip_src,ip_dst, ippayloadlen, tcphdr,ts, pcappktcnt, inlatency);
           }
           belongsToSomeone=1;
       }
   }

   if (belongsToSomeone==0 && TCPFlowStat::isNewFlow(ip_src,ip_dst,tcphdr)==1){
       struct TCPFlowStat tfs;
       tfs.clearData();
       if (inlatency){
           addToVectorNoDup(flowNoInLatency,tcpflows.size());
           tfs.addPacket(ip_src,ip_dst, ippayloadlen, tcphdr,ts, pcappktcnt, inlatency);
       }
       else {
           tfs.addPacket(ip_src,ip_dst, ippayloadlen, tcphdr,ts, pcappktcnt, inlatency);
       }
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

void TraceAnalyze::handleDNS(struct DNS_HEADER * dns, double ts){
       if (dns->qr == 0){
    //       printf("DNS query.\n");
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
              getAnswerString((unsigned char*)endquery, (unsigned char*)dns, dns->ans_count, newansq);
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
                          };


                      };


                  }
              }
          //    cout <<"here11!\n";
          };


       };
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
//    if (pktcnt==1)
//    printf("pkt #:%d Frame ts: %f\n",pktcnt, ts);
 //   printf("Frame ts: %f\n",ts);
 //   printf("Frame caplen: %d bytes\n",header->caplen);
 //   printf("Frame len: %d bytes\n",header->len);

    bool inlatency=handleBreakdown(ctx, ts);


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

                /*
                   //appname
                   int appIndex = *((u_short *)(pkt_data + 6)) & 0xFF;
                   string appName("none");
                   //cout << "1I am here!!!!" << endl;
                   //cout << ctx.getAppNameMap().size() << endl;
                   //cout << "2I am here!!!!" << endl;
                   if (appIndex < ctx.getAppNameMap().size()) {
                        appName.assign(ctx.getAppNameByIndex(appIndex));
                   }
                   */

                   handleTCPFlow(ip_src, ip_dst, ip->ip_len-ip->ip_hl*4, tcphdr, ts, pktcnt, inlatency);

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
                       handleDNS(dns, ts);
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

                   handleTCPFlow(ip_src, ip_dst, ip6->ip6_ctlun.ip6_un1.ip6_un1_plen, tcphdr, ts, pktcnt, inlatency);

                };break;
                case 0x11: {
                //UDP
                   struct udphdr* udphdr=(struct udphdr*)(etherdatap+40);
                   bswapUDP(udphdr);

                   if (udphdr->dest==0x35 || udphdr->source==0x35){
               //        cout <<"DNS "<<pktcnt<<"\n";

                       struct DNS_HEADER * dns = (struct DNS_HEADER *)(etherdatap+40+sizeof (struct udphdr));
                       bswapDNS(dns);
                       handleDNS(dns, ts);
                   };
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
