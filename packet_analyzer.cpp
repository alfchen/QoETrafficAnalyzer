
#include "packet_analyzer.h"

void dispatcher_handler(u_char *c, const struct pcap_pkthdr *header, const u_char *pkt_data) {
  //  cout<<"in dispatcher_handler\n";
  PacketAnalyzer* analyzer = (PacketAnalyzer *) c;
  (analyzer->mTraceAnalyze).feedTracePacket(analyzer->getContext(), header, pkt_data);
}

PacketAnalyzer::PacketAnalyzer() {
}

void PacketAnalyzer::checkSystem() {
	int xx = -1;
#if BYTE_ORDER == LITTLE_ENDIAN
	xx = 0;
#endif
#if BYTE_ORDER == BIG_ENDIAN
	xx = 1;
#endif
	switch (xx) {
		case 0:
			cout << "BYTE_ORDER LITTLE_ENDIAN" << endl;
			break;
		case 1:
			cout << "BYTE_ORDER BIG_ENDIAN" << endl;
			break;
		default:
			cout << "BYTE_ORDER NOT BIG NOT SMALL" << endl;
			break;
	}

	//test uint64
	cout << "Length of uint64 should be 8: " << sizeof(uint64) << endl;
}

void PacketAnalyzer::init(){
    checkSystem();
}

void PacketAnalyzer::configTraceList() {
	ifstream trace_list(mTraceListFileName.c_str());
	string s;
	while (getline(trace_list, s)) {
	    if (s.length()>0)
		mTraceList.push_back(s);
	}
}

void PacketAnalyzer::clearConfig(){
    mTraceListFileName="";
    mTraceList.clear();
}

void PacketAnalyzer::setTraceListFileName(string fn){
    mTraceListFileName=fn;
    configTraceList();
}

void PacketAnalyzer::addTrace(string tracename){
    mTraceList.push_back(tracename);
}

string PacketAnalyzer::getTraceListFileName(){
    return mTraceListFileName;
}

Context PacketAnalyzer::getContext(){
    return mTraceCtx;
}

string PacketAnalyzer::getFolder(string s) {
	int pos = s.rfind("/");
	return s.substr(0, pos);
}

string PacketAnalyzer::getLastFolder(string s) {
	int pos = s.rfind("/");
	int start=0;
	if (pos!=std::string::npos){
      start=pos;
    }
	return s.substr(start+1, s.length()-start-1);
}

void PacketAnalyzer::setOutputFileFolder(string fdr) {
    outputFileFolder=fdr;
}

string PacketAnalyzer::getNetworkType(string datafolder){
    string propfoldername=datafolder+"/NetworkType";
    ifstream propfile(propfoldername.c_str());
    if (propfile.is_open()){
        string nettype,s;
        while (getline(propfile, s)) {
            if (s.length()>0 && s.find("[")!=std::string::npos){
                nettype=s;
                break;
            }
        }
        propfile.close();
        int poss=nettype.rfind("[");
        int pose=nettype.rfind("]");
        return nettype.substr(poss+1,pose-poss-1);
    }
    return "No Input";
}


vector<struct DNSQueryComb> dnsgroup;

int strstartwith(char* str, char* prefix){
    if (strlen(prefix)>strlen(str)) return 0;
    for (int i=0;i<strlen(prefix);i++){
        if (prefix[i]!=str[i]){
          return 0;
        }
    }
    return 1;
}
int urlstrcmp(char* urla, char* urlb){
 /*  if (strstartwith(urla,"fbcdn-dragon")==1 && strstartwith(urlb,"fbcdn-dragon")==1) return 0;
   if (strstartwith(urla,"fbcdn-profile")==1 && strstartwith(urlb,"fbcdn-profile")==1) return 0;
   if (strstartwith(urla,"scontent")==1 && strstartwith(urlb,"scontent")==1) return 0;
   if (strstartwith(urla,"fbexternal")==1 && strstartwith(urlb,"fbexternal")==1) return 0;
   if (strstartwith(urla,"fbcdn-sphotos")==1 && strstartwith(urlb,"fbcdn-sphotos")==1) return 0;
   if (strstartwith(urla,"fbstatics")==1 && strstartwith(urlb,"fbstatics")==1) return 0;
   if (strstartwith(urla,"api")==1 && strstartwith(urlb,"graph.facebook.com")==1) return 0;
   if (strstartwith(urla,"static")==1 && strstartwith(urlb,"scontent")==1) return 0;
   if (strstartwith(urla,"scontent")==1 && strstartwith(urlb,"static")==1) return 0;
   if (strstartwith(urla,"external")==1 && strstartwith(urlb,"scontent")==1) return 0;
   if (strstartwith(urla,"scontent")==1 && strstartwith(urlb,"external")==1) return 0;
*/

   return strcmp(urla,urlb);

}

void PacketAnalyzer::outputTraceAnalyze(string datafolder, int firsttime){
    string datafoldername=getLastFolder(datafolder);
    ofstream  output;
    if (firsttime==1) {
       output.open((outputFileFolder+"/"+"result_"+datafoldername+".csv").c_str());
       output<<"\"Logfile name\""<<",\"Network Type\"";
        //title
        mTraceAnalyze.printTitle(output);
        output<<endl;

    }
    else {
        output.open((outputFileFolder+"/"+"result"+".csv").c_str(),ios::app);
    }




    output<<"\""<<datafoldername<<"\""<<",\""<<getNetworkType(datafolder)<<"\"";


    int i=0;

    while (true) {
        //lastline
        if (mTraceAnalyze.printLine(output,i)!=1)
          break;
        output<<endl;
        output<<",";
        i++;
    }
    output<<endl;

    output.close();

//aggregate
/*
        for (int i=0; i<mTraceAnalyze.ansdnsquery.size();i++){
            int ingroup=-1;

            bool notrelated=false;

            for (int m=0;m<mTraceAnalyze.ansdnsquery[i].urlsnum;m++){
                string stra(mTraceAnalyze.ansdnsquery[i].urls[m]);
   if (stra.find("fb")==string::npos && stra.find("facebook")==string::npos) {
       notrelated=true;
       break;
   }
            }
            if (notrelated) continue;

            for (int j=0;j<dnsgroup.size();j++){
                bool samegroup=false;
                for (int m=0;m<mTraceAnalyze.ansdnsquery[i].urlsnum;m++){
                    bool findit=false;
                    for (int n=0;n<dnsgroup[j].urlsnum;n++){
                        if (urlstrcmp(mTraceAnalyze.ansdnsquery[i].urls[m],dnsgroup[j].urls[n])==0){
                            findit=true;
                            break;
                        }
                    }
                    if (findit){
                        samegroup=true;
                        break;
                    }
                }
                for (int m=0;m<mTraceAnalyze.ansdnsquery[i].ansnum;m++){
                    bool findit=false;
                    for (int n=0;n<dnsgroup[j].ansnum;n++){
                            if (mTraceAnalyze.ansdnsquery[i].ansips[m].compare(dnsgroup[j].ansips[n])==0){
                                findit=true;
                                break;
                            }
                        }
                }

                if (samegroup){
                    ingroup=j;
                    break;
                }
            }

            if (ingroup==-1){
                struct DNSQueryComb newq;
                newq.clearData();
                for (int j=0;j<mTraceAnalyze.ansdnsquery[i].urlsnum;j++){
                    char* nu=(char*)malloc(strlen(mTraceAnalyze.ansdnsquery[i].urls[j])+1);
                    strcpy(nu,mTraceAnalyze.ansdnsquery[i].urls[j]);
                    newq.urls[newq.urlsnum++]=nu;
                }
                cout<<mTraceAnalyze.ansdnsquery[i].ansnum<<endl;
          //      for (int j=0;j<mTraceAnalyze.ansdnsquery[i].ansnum;j++){
          //          newq.ansips[newq.ansnum++]=mTraceAnalyze.ansdnsquery[i].ansips[j];
          //          cout<<mTraceAnalyze.ansdnsquery[i].ansips[j]<<endl;
          //      }
               dnsgroup.push_back(newq);
                ingroup=dnsgroup.size()-1;
            }
            else {
                for (int m=0;m<mTraceAnalyze.ansdnsquery[i].urlsnum;m++){
                    bool findit=false;
                    for (int n=0;n<dnsgroup[ingroup].urlsnum;n++){
                        if (strcmp(mTraceAnalyze.ansdnsquery[i].urls[m],dnsgroup[ingroup].urls[n])==0){
                            findit=true;
                            break;
                        }
                    }
                    if (!findit){
                        char* nu=(char*)malloc(strlen(mTraceAnalyze.ansdnsquery[i].urls[m])+1);
                        strcpy(nu,mTraceAnalyze.ansdnsquery[i].urls[m]);
                        dnsgroup[ingroup].urls[dnsgroup[ingroup].urlsnum++]=nu;
                    }

                }
                for (int m=0;m<mTraceAnalyze.ansdnsquery[i].ansnum;m++){
                    bool findit=false;
                    for (int n=0;n<dnsgroup[ingroup].ansnum;n++){
                        if (mTraceAnalyze.ansdnsquery[i].ansips[m].compare(dnsgroup[ingroup].ansips[n])==0){
                            findit=true;
                            break;
                        }
                    }
                    if (!findit){
                        dnsgroup[ingroup].ansips[dnsgroup[ingroup].ansnum++]=mTraceAnalyze.ansdnsquery[i].ansips[m];
                    }
                }
            }

            char outputfn[3000];
            sprintf(outputfn,"./sampledata/output/dns_%d",ingroup);
            ofstream foutdns(outputfn,ios::app);
            foutdns<<mTraceAnalyze.ansdnsquery[i].ts;
            for (int j=0;j<dnsgroup[ingroup].urlsnum;j++){
                foutdns<<"\t"<<dnsgroup[ingroup].urls[j];
            }
           // for (int j=0;j<dnsgroup[ingroup].ansnum;j++){
          //      foutdns<<"\t"<<dnsgroup[ingroup].ansips[j];
         //   }
            foutdns<<endl;
            foutdns.close();
        }

        ofstream fouttcn("./sampledata/output/tcpconnnum",ios::app);
        fouttcn<<mTraceAnalyze.tcpflows.size()<<endl;
        fouttcn.close();

        for (int ii=0;ii<mTraceAnalyze.tcpflows.size();ii++){
        //tcpconn
        ofstream fouttc("./sampledata/output/tcpconnection",ios::app);
        fouttc<<mTraceAnalyze.tcpflows[ii].tcpconnsetuptime<<endl;
        fouttc.close();
        }

            int gt5highnum=0;
    for (int ii=0;ii<mTraceAnalyze.gt5state.size();ii++)
     if (mTraceAnalyze.gt5state[ii].compare("CONNECTED")==0){
       gt5highnum++;
       }

        ofstream foutgt("./sampledata/output/gt5high",ios::app);
        foutgt<<gt5highnum<<endl;
        foutgt.close();

        ofstream foutgtr("./sampledata/output/gt5highratio",ios::app);
        foutgtr<<gt5highnum*1.0/mTraceAnalyze.gt5pktcnt<<endl;
        foutgtr.close();
   */
  //  cout<<getLastFolder(datafolder)<<endl;
}

string PacketAnalyzer::trimNameFormat(string fdr){
    const char* strfdr=fdr.c_str();
    int pos=strlen(strfdr)-1;
    while (strfdr[pos]=='/' && pos>=0) pos--;
    return fdr.substr(0,pos+1);
}

void PacketAnalyzer::run() {
	// read packet
	char errbuf[PCAP_ERRBUF_SIZE];
	vector<string>::iterator it;
	pcap_t *trace_file;

	string currfolder, tmpfolder, tracefile, tmp_s;
	int trace_count = 0;
	int firsttime=1;
	for (it = mTraceList.begin(); it != mTraceList.end(); it++) {
	    mTraceAnalyze.clearData();

		if (trace_count % 1000 == 0) {
			cout << trace_count << " files processed." << endl;
		}
		string datafolder=trimNameFormat(*it);

		cout << "\n\nData Folder:"<<datafolder<<endl;
        tracefile=datafolder+"/traffic.cap";

		// open pcap file successfully?
		if ((trace_file = pcap_open_offline(tracefile.c_str(), errbuf)) == NULL) {
			cout << " Unable to open the file: " << tracefile << endl;
			continue;
		}



	/*	// read application map
		tmpfolder = getFolder(tracefile);
		tmpfolder += "/appname";
		if (tmpfolder.compare(currfolder) != 0) {
			currfolder = tmpfolder;
		//	cout << "Folder Name: " << currfolder << endl;
			mTraceCtx.clearAppNameMap();

			ifstream appNameFile(tmpfolder.c_str());
			while (getline(appNameFile, tmp_s)) {
				mTraceCtx.addAppName(tmp_s);
			}
		}
        */

		// pcap link layer header length

		if (pcap_datalink(trace_file) == DLT_LINUX_SLL) {
			mTraceCtx.setEtherLen(16);
		} else {
			mTraceCtx.setEtherLen(14);
		}

		cout << "Pcap trace Ethernet header length: " << mTraceCtx.getEtherLen() << endl;

		/* read and dispatch packets until EOF is reached */
    //  filename=datafolder.length;
      string tstmp=datafolder.substr(datafolder.length()-8,8);
      //cout<<tstmp<<endl;
  //    if (tstmp.compare("05-00-00")>=0 && tstmp.compare("11-00-00")<0){
  //  if (tstmp.compare("11-00-00")>=0 && tstmp.compare("17-00-00")<0){
  //  if (tstmp.compare("17-00-00")>=0 && tstmp.compare("23-00-00")<0){
  //  if ((tstmp.compare("23-00-00")>=0 && tstmp.compare("24-00-00")<=0) || (tstmp.compare("00-00-00")>=0 && tstmp.compare("05-00-00")<0)){
		pcap_loop(trace_file, 0, dispatcher_handler, (u_char*)this);
		pcap_close(trace_file);
        outputTraceAnalyze(datafolder,firsttime);
  //	 }

        if (firsttime==1) firsttime=0;
		trace_count++;
	}
}
