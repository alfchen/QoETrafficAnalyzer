#include "rrcstate.h"

RRCStateMachine::RRCStateMachine(){
    clearData();
}

void RRCStateMachine::clearData(){
    prev_ts=-1;
	state="";
	pkt_counter=0;
}

void RRCStateMachine::packetArrival(const struct pcap_pkthdr *header, const u_char *pkt_data){
    u_char *pkt_ptr = (u_char *)pkt_data; //cast a pointer to the packet data

    time_t timestamp=header->ts.tv_sec;
    long int ts_usec=header->ts.tv_usec;

    long ts=(timestamp*1000000)+ts_usec;
    if(prev_ts!=-1){

        long diff_ms=(ts-prev_ts)/1000;
        if(diff_ms>=LTE_TTAIL_MS){
            ts-=(LTE_TPRO_MS*1000);
            state="IDLE->CONNECTED";
        }
        else{
            state="CONNECTED";
        }
     //   cout<<timestamp<<" "<<diff_ms<<" "<<state<<endl;

    }
    prev_ts=ts;
    pkt_counter++; //increment number of packets seen

}
