
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
    string wififoldername=datafolder+"/arodata/wifi_events";
    ifstream wififile(wififoldername.c_str());
	string s;
	bool iswifi=false;
	while (getline(wififile, s)) {
	    if (s.length()>0 && s.find("CONNECTED")){
	        iswifi=true;
	        break;
	    }
	}
	wififile.close();
	if (iswifi){
	    return "WiFi";
	}
	else {
	    string propfoldername=datafolder+"/arodata/prop";
	    ifstream propfile(propfoldername.c_str());
        string nettype,s;
        while (getline(propfile, s)) {
            if (s.length()>0 && s.find("gsm.network.type")!=std::string::npos){
                nettype=s;
                break;
            }
        }
        propfile.close();
        int poss=nettype.rfind("[");
        int pose=nettype.rfind("]");
        return nettype.substr(poss+1,pose-poss-1);
    }
    return "Unknown";
}

void PacketAnalyzer::outputTraceAnalyze(string datafolder){
    string datafoldername=getLastFolder(datafolder);
    ofstream  output((outputFileFolder+"/"+datafoldername+".csv").c_str());

    output<<"\"Logfile name\""<<",\"Network Type\"";
    //title
    mTraceAnalyze.printTitle(output);
    output<<endl;



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

    output.close();

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

	string currfolder, tmpfolder, arofolder, tracefile, tmp_s;
	int trace_count = 0;
	for (it = mTraceList.begin(); it != mTraceList.end(); it++) {
	    mTraceAnalyze.clearData();

		if (trace_count % 1000 == 0) {
			cout << trace_count << " files processed." << endl;
		}
		string datafolder=trimNameFormat(*it);

		cout << "\n\nData Folder:"<<datafolder<<endl;
        arofolder=datafolder+"/arodata";
        tracefile=arofolder+"/traffic.cap";

		// open pcap file successfully?
		if ((trace_file = pcap_open_offline(tracefile.c_str(), errbuf)) == NULL) {
			cout << " Unable to open the file: " << tracefile << endl;
			continue;
		}



		// read application map
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


		// pcap link layer header length

		if (pcap_datalink(trace_file) == DLT_LINUX_SLL) {
			mTraceCtx.setEtherLen(16);
		} else {
			mTraceCtx.setEtherLen(14);
		}

		cout << "Pcap trace Ethernet header length: " << mTraceCtx.getEtherLen() << endl;

		/* read and dispatch packets until EOF is reached */
		pcap_loop(trace_file, 0, dispatcher_handler, (u_char*)this);
		pcap_close(trace_file);


        outputTraceAnalyze(datafolder);
		trace_count++;
	}
}
