#include "packet_analyzer.h"
using namespace std;

PacketAnalyzer analyzer;

void addTracesFromFolderList(string fl){
    ifstream traceList(fl.c_str());
	string s;
	while (getline(traceList, s)) {
		analyzer.addTrace(s);
	}
	traceList.close();
}

string trimNameFormat(string fdr){
    const char* strfdr=fdr.c_str();
    int pos=strlen(strfdr)-1;
    while (strfdr[pos]=='/' && pos>=0) pos--;
    return fdr.substr(0,pos+1);
}


int main(int argc, char **argv) {
//	string traceList("/home/alfred/Project/TMobile/Facebook/tracelist");
//ls -d $PWD/*
    if (argc<=2){
       printf("Wrong input! Input should have 2 arguments!\n");
       printf("correct input format:\n ./qoetranalyzer <trace list file name> <output file folder name>\n");
       printf("Example: ./qoetranalyzer ./sampledata/traceList ./sampledata/output/\n");
       return -1;
    }
    string tracelist(argv[1]);
    string outputfolder(argv[2]);
 //   cout<<tracelist<<endl;
 //   cout<<outputfolder<<endl;

	addTracesFromFolderList(tracelist);



//	analyzer.setTraceListFileName(traceList);
	analyzer.init();
	analyzer.setOutputFileFolder(trimNameFormat(outputfolder));
	analyzer.run();


	return 0;
}
