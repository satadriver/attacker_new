

#ifndef NETCARDINFO_H_H_H
#define NETCARDINFO_H_H_H

#include <Windows.h>
#include <iptypes.h>
#include <string>


using namespace std;

class NetworkDevice {
public:
	static PIP_ADAPTER_INFO ShowNetCardInfo(int *);
	static PIP_ADAPTER_INFO GetNetCardAdapter(PIP_ADAPTER_INFO pAdapterInfo, int seq);
	static string getAdapterAlias(string adaptername);
	static string selectNetcard(unsigned long * localIP,unsigned long * netmask,unsigned long * netgate,unsigned char *,
		int & selectedcard);
};

#endif