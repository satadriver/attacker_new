

#include <windows.h>

#include "sslPublic.h"
#include "HttpProxy.h"
#include "HttpProxyListener.h"
#include "../HttpUtils.h"
#include "../Deamon.h"
#include "../Public.h"
#include "../utils/BaseSocket.h"
#include "../utils/Tools.h"

#include "sslEntry.h"

HttpProxyListener::HttpProxyListener() {
	if (mInstance)
	{
		return;
	}

	mInstance = this;

	mSock = BaseSocket::listenPort(HTTP_PORT);
	if ((mSock == SOCKET_ERROR) || (mSock == INVALID_SOCKET))
	{
		printf("HTTP listenPort error\r\n");
		Public::writeLogFile("HTTP listenPort error\r\n");
		MessageBoxA(0, "HTTPProxyListener listenPort error", "HTTPProxyListener listenPort error", MB_OK);
		exit(-1);
	}
	else
	{
		printf("HTTP listener is ready\r\n");
	}

	g_thread_params.gHTTPEvent = CreateEventA(0, 0, 0, "gHTTPEvent");

	g_thread_params.gHTTPListenEvent = CreateEventA(0, 0, TRUE, "gHTTPListenEvent");

	CloseHandle(CreateThread(0, PROXY_THREAD_STACK_SIZE, (LPTHREAD_START_ROUTINE)HttpProxyListener::listener,
		this, STACK_SIZE_PARAM_IS_A_RESERVATION, 0));

	int cnt = HTTP_WORK_THREAD_CNT;
	for (int i = 0; i < cnt; i++)
	{
		CloseHandle(CreateThread(0, 0, (LPTHREAD_START_ROUTINE)HttpProxy::HTTPProxy, &g_thread_params, 0, 0));
	}
}



HttpProxyListener::~HttpProxyListener() {
	closesocket(mSock);
}

int __stdcall HttpProxyListener::listener(HttpProxyListener * instance)
{
	int ret = 0;
	char szout[1024];
	__try
	{
		while (TRUE)
		{
			ret = WaitForSingleObject(g_thread_params.gHTTPListenEvent, INFINITE);

			int iClientSockSize = sizeof(sockaddr_in);
			sockaddr_in saClient = { 0 };
			int sockClient = accept(instance->mSock, (sockaddr*)&saClient, &iClientSockSize);
			if (sockClient != INVALID_SOCKET && sockClient > 0)
			{
				LPHTTPPROXYPARAM pstHttpProxyParam = (LPHTTPPROXYPARAM)new HTTPPROXYPARAM;
				memset(pstHttpProxyParam, 0, sizeof(HTTPPROXYPARAM));
				pstHttpProxyParam->usPort = HTTP_PORT;
				pstHttpProxyParam->timeclient = time(0);
				pstHttpProxyParam->timeserver = pstHttpProxyParam->timeclient;
				pstHttpProxyParam->sockToClient = sockClient;
				pstHttpProxyParam->saToClient = saClient;

				Deamon::addHttp(pstHttpProxyParam);

				g_thread_params.gHTTPProxyParam = pstHttpProxyParam;

				ret = SetEvent(g_thread_params.gHTTPEvent);
			}
			else
			{
				wsprintfA(szout, "HTTP�����߳�accept������:%d\n", WSAGetLastError());
				Public::writeLogFile(szout);
				printf(szout);

				closesocket(instance->mSock);

				instance->mSock = BaseSocket::listenPort(HTTP_PORT);
				if ((instance->mSock == SOCKET_ERROR) || (instance->mSock == INVALID_SOCKET))
				{
					printf("HTTP listenPort error\r\n");
					Public::writeLogFile("HTTP listenPort error\r\n");
					exit(-1);
					return FALSE;
				}

				SetEvent(g_thread_params.gHTTPListenEvent);
			}
		}
	}
	__except (1)
	{
		SYSTEMTIME stSysTm = { 0 };
		GetLocalTime(&stSysTm);
		int len = wsprintfA(szout, "HTTP�����̷߳����쳣,������:%u,ʱ��:%d.%d.%d %d:%d:%d\r\n", GetLastError(),
			stSysTm.wYear, stSysTm.wMonth, stSysTm.wDay, stSysTm.wHour, stSysTm.wMinute, stSysTm.wSecond);
		printf(szout);
		Public::writeFile(ATTACK_LOG_FILENAME, szout, len);
		return FALSE;
	}
}