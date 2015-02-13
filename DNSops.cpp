
#include "DNSops.h"

char* getQueryString(char* querystr, int querynum, struct DNSQueryComb &newq, int &offset){
    char url[1000];
    int i=0;

    for (int qn=0;qn<querynum;qn++){
        int urlind=0;

        while (querystr[i]!=0){
            int sublen=querystr[i++];
            for (int j=0;j<sublen;j++){
               url[urlind++]=querystr[i++];
            }
            url[urlind++]='.';
        }
        url[urlind-1]='\0';
        i++;
      //  printf("%s\n",url);
        char* nu=(char*)malloc(strlen(url)+1);
        strcpy(nu,url);

        newq.urls[newq.urlsnum++]=nu;
        i=i+4;
    }
    offset=i;
    return querystr+i;


}

unsigned char* ReadName(unsigned char* reader,unsigned char* buffer,int* count)
{
	unsigned char *name;
	unsigned int p=0,jumped=0,offset;
	int i , j;

	*count = 1;
	name = (unsigned char*)malloc(256);

	name[0]='\0';

	//read the names in 3www6google3com format
	while(*reader!=0)
	{
		if(*reader>=192)
		{
			offset = (*reader)*256 + *(reader+1) - 49152; //49152 = 11000000 00000000 ;)
			reader = buffer + offset - 1;
			jumped = 1; //we have jumped to another location so counting wont go up!
		}
		else
		{
			name[p++]=*reader;
		}

		reader = reader+1;

		if(jumped==0)
		{
			*count = *count + 1; //if we havent jumped to another location then we can count up
		}
	}

	name[p]='\0'; //string complete
	if(jumped==1)
	{
		*count = *count + 1; //number of steps we actually moved forward in the packet
	}

	//now convert 3www6google3com0 to www.google.com
	for(i=0;i<(int)strlen((const char*)name);i++)
	{
		p=name[i];
		for(j=0;j<(int)p;j++)
		{
			name[i]=name[i+1];
			i=i+1;
		}
		name[i]='.';
	}
	name[i-1]='\0'; //remove the last dot
	return name;
}

char * getStrAddr(long ip){
    char* res=(char*)malloc(20);
    sprintf(res, "%d.%d.%d.%d", ip>>24,(ip>>16)&0xFF,(ip>>8)&0xFF,(ip)&0xFF);
    return res;
}


void getAnswerString(unsigned char* ansstr,unsigned char* buf, int ansnum, struct DNSQueryComb &newq){
  //  printf("ans cnt:%d\n", ansnum);
  //  printf("wuha\n");
    struct RES_RECORD answers[20];
	//Start reading answers
    int stop=0;
	for(int i=0;i<ansnum;i++)
	{
	//    printf("haha\n");
		answers[i].name=ReadName(ansstr,buf,&stop);
	//	printf("name: %s\n", answers[i].name);
		if (strlen((const char*)answers[i].name)==0)
		  break;

	//	printf("%s\n",answers[i].name);
		ansstr = ansstr + stop;
		answers[i].resource = (struct R_DATA*)(ansstr);
		ansstr = ansstr + sizeof(struct R_DATA);

		if(ntohs(answers[i].resource->type) == 1) //if its an ipv4 address
		{
	//	    printf("qaha\n");

			answers[i].rdata = (unsigned char*)malloc(ntohs(answers[i].resource->data_len));

			for(int j=0 ; j<ntohs(answers[i].resource->data_len) ; j++){
				answers[i].rdata[j]=ansstr[j];
			}

			answers[i].rdata[ntohs(answers[i].resource->data_len)] = '\0';
			ansstr = ansstr + ntohs(answers[i].resource->data_len);

			long p=ntohl(*((long*)answers[i].rdata));
			char ipaddr[3000];
            inet_ntop(AF_INET, &(p), ipaddr, INET_ADDRSTRLEN);
            string ip_src(ipaddr);
        //    printf("has IPv4 address : %s in %d\n",ip_src.c_str(),newq.ansnum);
            newq.ansips[newq.ansnum++]=ip_src;
		}
		else
        if(ntohs(answers[i].resource->type) == 0x1c) //if its an ipv4 address
		{
		//    printf("ipv6\n");
		    answers[i].rdata = (unsigned char*)malloc(ntohs(answers[i].resource->data_len));

			for(int j=0 ; j<ntohs(answers[i].resource->data_len) ; j++){
				answers[i].rdata[j]=ansstr[j];
			}

			answers[i].rdata[ntohs(answers[i].resource->data_len)] = '\0';
			ansstr = ansstr + ntohs(answers[i].resource->data_len);

		//	long p=ntohl(*((long*)answers[i].rdata));
			char ipaddr[3000];
            inet_ntop(AF_INET6, answers[i].rdata, ipaddr, INET6_ADDRSTRLEN);
            string ip_src(ipaddr);
        //    printf("has IPv6 address : %s in %d\n",ip_src.c_str(),newq.ansnum);
            newq.ansips[newq.ansnum++]=ip_src;
		}
        else
        if(ntohs(answers[i].resource->type) == 0x05) //if its an CNAME
		{
		    answers[i].rdata = ReadName(ansstr, buf,&stop);
        //    printf("has cname : %s in %d, num: %d\n",answers[i].rdata, newq.urlsnum);
            int rdatalen=strlen((const char*)answers[i].rdata)+1;
            newq.urls[newq.urlsnum]=(char*)malloc(rdatalen);
            strcpy(newq.urls[newq.urlsnum], (const char*)(answers[i].rdata));
            newq.urlsnum++;
			ansstr = ansstr + stop;
		}
		else
		{
		    printf("unknown DNS type %d\n",ntohs(answers[i].resource->type));
		    int datalen = ntohs(answers[i].resource->data_len);
			ansstr = ansstr + datalen;
		}
	//	break;
	}
}
