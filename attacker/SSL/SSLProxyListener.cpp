

#include <windows.h>
#include <WINSOCK2.H>

#include "sslPublic.h"
#include "sslPacket.h"
#include "SSLProxy.h"
#include "sslproxylistener.h"
#include "../utils/BaseSocket.h"
#include "../attacker.h"
#include "../Deamon.h"
#include "../HttpUtils.h"
#include "..\\include\\openssl\\ssl.h"
#include "..\\include\\openssl\\err.h"
#include "../utils/Tools.h"
#include "sslEntry.h"

//vmvare-hosted.exe 占用443端口

SSLProxyListener::SSLProxyListener() {
	if (mInstance)
	{
		return;
	}
	mInstance = this;

	SSLProxy*sslproxy = new SSLProxy();

	SSL_library_init();
	SSL_load_error_strings();
	OpenSSL_add_all_algorithms();

	SSLPublic::freeSSLPort();

	mSock = BaseSocket::listenPort(SSL_PORT);
	if ((mSock == SOCKET_ERROR) || (mSock == INVALID_SOCKET))
	{
		printf("SSL listenPort error\r\n");
		Public::writeLogFile("SSL listenPort error\r\n");
		MessageBoxA(0, "ssl init error", "ssl init error", MB_OK);
		exit(-1);
	}
	else
	{
		printf("SSL listener is ready\n");
	}

	g_thread_params.gSSLEvent = CreateEventA(0, 0, 0, "gSSLEvent");

	g_thread_params.gSSLListenEvent = CreateEventA(0, 0, TRUE, "gSSLListenEvent");

	CloseHandle(CreateThread(0, PROXY_THREAD_STACK_SIZE, (LPTHREAD_START_ROUTINE)SSLProxyListener::listener, this,
		STACK_SIZE_PARAM_IS_A_RESERVATION, 0));

	int cnt = SSL_WORK_THREAD_CNT;
	for (int i = 0; i < cnt; i++)
	{
		CloseHandle(CreateThread(0, 0, (LPTHREAD_START_ROUTINE)SSLProxy::SSL_Proxy, &g_thread_params, 0, 0));
	}
}


SSLProxyListener::~SSLProxyListener() {
	closesocket(mSock);
}

int __stdcall SSLProxyListener::listener(SSLProxyListener*instance)
{
	char szout[1024];
	int ret = 0;
	while (TRUE)
	{
		__try
		{
			ret = WaitForSingleObject(g_thread_params.gSSLListenEvent, INFINITE);

			sockaddr_in saclient = { 0 };
			int iClientSockSize = sizeof(sockaddr_in);
			int sockclient = accept(instance->mSock, (sockaddr*)&saclient, &iClientSockSize);
			if ((sockclient != INVALID_SOCKET) && (sockclient > 0))
			{
				LPSSLPROXYPARAM pstSSLProxyParam = (LPSSLPROXYPARAM)new SSLPROXYPARAM;
				memset(pstSSLProxyParam, 0, sizeof(SSLPROXYPARAM));
				pstSSLProxyParam->usPort = SSL_PORT;
				pstSSLProxyParam->saToClient = saclient;
				pstSSLProxyParam->sockToClient = sockclient;
				pstSSLProxyParam->timeclient = time(0);
				pstSSLProxyParam->timeserver = pstSSLProxyParam->timeclient;

				Deamon::addSSL(pstSSLProxyParam);

				g_thread_params.gSSLProxyParam = pstSSLProxyParam;

				ret = SetEvent(g_thread_params.gSSLEvent);
			}
			else
			{
				wsprintfA(szout, "SSL监听线程accept错误码:%d\n", WSAGetLastError());
				Public::writeLogFile(szout);
				printf(szout);

				closesocket(instance->mSock);

				instance->mSock = BaseSocket::listenPort(SSL_PORT);
				if ((instance->mSock == SOCKET_ERROR) || (instance->mSock == INVALID_SOCKET))
				{
					printf("SSL listenPort error\r\n");
					Public::writeLogFile("SSL listenPort error\r\n");
					exit(-1);
				}

				SetEvent(g_thread_params.gSSLListenEvent);
			}
		}
		__except (1)
		{
			SYSTEMTIME stSysTm = { 0 };
			GetLocalTime(&stSysTm);
			int len = wsprintfA(szout, "SSL监听线程发生异常,错误码:%u,时间:%d.%d.%d %d:%d:%d\r\n", WSAGetLastError(),
				stSysTm.wYear, stSysTm.wMonth, stSysTm.wDay, stSysTm.wHour, stSysTm.wMinute, stSysTm.wSecond);

			Public::writeFile(ATTACK_LOG_FILENAME, szout, len);
			printf(szout);
		}
	}
	return TRUE;
}

