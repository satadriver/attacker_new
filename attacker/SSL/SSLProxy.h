

#pragma once

#ifndef SSLPROXY_H_H_H
#define SSLPROXY_H_H_H

#include "sslPublic.h"
#include "../utils/Lock.h"

#define PEEK_SERVERNAME_BUF_SIZE 2048


class SSLProxy {
public:
	SSLProxy();
	~SSLProxy();

	SSLProxy* mInstance;

	static int SSLProxy::ReadPendingData(char * lpdata, int size, SSL * ssl);

	static int SSLProxy::SSL_ProxyBoth(LPSSLPROXYPARAM pstSSLProxyParam);

	static int SSLProxy::SSL_ProxyClient(LPSSLPROXYPARAM pstSSLProxyParam);

	static int __stdcall SSLProxy::SSL_Proxy(MIM_THREAD_PARAMS * param);

	static int SSLProxy::getServerNameFromClientHello(char * data, int len,unsigned char * servername,int & version);

};

#endif