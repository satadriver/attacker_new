

#include <windows.h>
#include "../attacker.h"
#include "../ssl/sslPublic.h"
#include "DnsServer.h"
#include "../Packet.h"
#include "../utils/lock.h"


DnsServer*gDnsCenter = 0;

DnsServer::~DnsServer() {

}


DnsServer::DnsServer() {
	if (gDnsCenter)
	{
		return;
	}
	mInstance = this;
	gDnsCenter = this;

	gDnsCenterMap.clear();

	InitializeCriticalSection(&mCS);
}

unsigned long DnsServer::getIPAddr(string host){
	
	int ret = 0;

	unsigned long ip = 0;

	__try
	{
		EnterCriticalSection(&gDnsCenter->mCS);

		unordered_map <string, DOMAININFO >::iterator it = gDnsCenter->gDnsCenterMap.find(host);
		if (it != gDnsCenter->gDnsCenterMap.end() )
		{
			ip = it->second.ip;
		}

		LeaveCriticalSection(&gDnsCenter->mCS);

		if (ip)
		{
			return ip;
		}
		else {
			ip = getIPFromHost(host, DNS_SERVER_ADDRESS);
			if (ip == 0) {
				ip = getIPFromHost(host, BACK_DNS_SERVER_ADDRESS);
			}
			if (ip)
			{
				DOMAININFO info = { 0 };
				info.dnstime = time(0);
				info.ip = ip;

				EnterCriticalSection(&gDnsCenter->mCS);

				it = gDnsCenter->gDnsCenterMap.find(host);
				if (it != gDnsCenter->gDnsCenterMap.end())
				{
					it->second.dnstime = info.dnstime;
					it->second.ip = ip;
				}
				else {
					pair< std::unordered_map<string, DOMAININFO>::iterator, bool > retit;
					retit = gDnsCenter->gDnsCenterMap.insert(pair<string, DOMAININFO>(host, info));
					if (retit.second == 0)
					{
						printf("DnsServer insert ip:%x,dns:%s error:%u\r\n", ip, host.c_str(), GetLastError());
					}
				}

				LeaveCriticalSection(&gDnsCenter->mCS);
			}
			else {
				char szout[1024];
				wsprintfA(szout, "getIPFromDomainName:%s error\r\n", host.c_str());
				Public::writeLogFile(szout);
				printf(szout);
			}
		}
	}
	__except(1) 
	{
		printf("getDnsFromMap exception\r\n");
		Public::writeLogFile("getDnsFromMap exception\r\n");
	}
	
	return ip;
}




unsigned int DnsServer::getIPFromHost(string host,DWORD dnsserver) {
	int ret = 0;

	char dnsbuf[DNS_PACKET_LIMIT+16] = { 0 };
	LPDNSHEADER dnshdr = (LPDNSHEADER)dnsbuf;
	dnshdr->TransactionID = LOCAL_QUERY_DNS_ID;
	dnshdr->Flags = 1;
	dnshdr->Questions = 0x100;
	dnshdr->AdditionalRRS = 0;
	dnshdr->AnswerRRS = 0;
	dnshdr->AuthorityRRS = 0;

	char * lpdnsname = dnsbuf + sizeof(DNSHEADER);
	string lphost = host;
	while (1)
	{
		int pos = lphost.find(".");
		if (pos > 0)
		{
			string sub = lphost.substr(0, pos);
			int sublen = sub.length();
			*lpdnsname = sublen;
			lpdnsname++;
			memcpy(lpdnsname, sub.c_str(), sublen);
			lpdnsname += sublen;
			lphost = lphost.substr(pos + 1);
		}
		else if (pos < 0 && lphost.length() > 0)
		{
			int lastlen = lphost.length();
			*lpdnsname = lastlen;
			lpdnsname++;
			memcpy(lpdnsname, lphost.c_str(), lastlen);
			lpdnsname += lastlen;
			break;
		}
		else {
			printf("%s parse dns:%s error\r\n",__FUNCTION__, host.c_str());
			return 0;
		}
	}

	*(lpdnsname) = 0;
	lpdnsname++;
	LPDNSTYPECLASS lptype = (LPDNSTYPECLASS)lpdnsname;
	lptype->dnstype = 0x0100;
	lptype->dnsclass = 0x0100;
	lpdnsname = (char*)lptype + sizeof(DNSTYPECLASS);

	int sendlen = lpdnsname - dnsbuf;

	int dnssock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (dnssock == INVALID_SOCKET)
	{
		printf("%s socket error:%s\r\n", __FUNCTION__, host.c_str());
		return FALSE;
	}

	int timeout = 1000;
	ret = setsockopt(dnssock, SOL_SOCKET, SO_RCVTIMEO, (char *)&timeout, sizeof(timeout));

	sockaddr_in si = { 0 };
	si.sin_port = ntohs(DNS_PORT);
	si.sin_family = AF_INET;
	si.sin_addr.S_un.S_addr = dnsserver ;

	int sendsize = sendto(dnssock, dnsbuf, sendlen, 0, (sockaddr*)&si, sizeof(sockaddr_in));
	if (sendsize != sendlen)
	{
		closesocket(dnssock);
		printf("%s sendto error:%s\r\n", __FUNCTION__, host.c_str());
		return FALSE;
	}

	int sockaddrlen = sizeof(sockaddr_in);
	int recvsize = recvfrom(dnssock, dnsbuf, sizeof(dnsbuf), 0, (sockaddr*)&si, &sockaddrlen);
	
	if (recvsize <= 0)
	{
		closesocket(dnssock);
		printf("%s %s recvfrom error:%d\r\n", __FUNCTION__, host.c_str(),WSAGetLastError());
		return 0;
	}

	closesocket(dnssock);

	DWORD dwip = 0;
	//int answersize = recvsize - (lpdnsname - dnsbuf);
	LPDNSANSWERHEADER lpanswer = (LPDNSANSWERHEADER)lpdnsname;
	while (((char*)lpanswer < dnsbuf + recvsize))
	{
		if (lpanswer->AddrLen == 0x400 && lpanswer->Type == 0x100 /*&& lpanswer->Class == 0x100*/)
		{
			dwip = *(DWORD*)((char*)lpanswer + sizeof(DNSANSWERHEADER));
			break;
		}
		else {
			int answerlen = ntohs(lpanswer->AddrLen);
			if (answerlen > DNS_PACKET_LIMIT || answerlen <= 0)
			{
				break;
			}
			lpanswer = (LPDNSANSWERHEADER)((char*)lpanswer + sizeof(DNSANSWERHEADER) + answerlen);
		}
	}

	if (dwip == 0) {
		printf("get ip from dns:%s error\r\n", host.c_str() );
	}
	return dwip;
}
