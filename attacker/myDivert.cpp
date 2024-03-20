
#include <windows.h>
#include <stdio.h>

#include "windivert.h"
#include "windivert_device.h"
#include <winsock.h>

#pragma comment(lib,"lib/windivert.lib")

#ifdef WINDIVERT_KERNEL
#undef WINDIVERT_KERNEL
#endif

#define MAX_DIVERT_PACKET 0x10000


 int __stdcall winDivert(DWORD dwip) {

	int result = 0;
	char* packet = new char[MAX_DIVERT_PACKET];
	int packetLen = MAX_DIVERT_PACKET;
	WINDIVERT_ADDRESS addr;
	UINT32 recvSize = 0;

	PWINDIVERT_IPHDR iphdr;
	PWINDIVERT_TCPHDR tcphdr;
	PWINDIVERT_UDPHDR udphdr;

	// �򿪹��˶���
	
	HANDLE mHandle = WinDivertOpen("outbound  and (tcp.DstPort == 443 or tcp.SrcPort == 443)", //���˹���
		WINDIVERT_LAYER_NETWORK, //���˵Ĳ�
		0, 0);
	if (mHandle == INVALID_HANDLE_VALUE) //�������˶��󣬿���ͨ��������ʶ�����
	{
		result = GetLastError();
		return 0;  //error
	}

	while (1)
	{
		result = WinDivertRecv(mHandle,  // windivert����
			packet, packetLen,  //char* packet��buff����
			&recvSize,   // int ʵ�ʶ�ȡ�����ݳ���
			&addr);
		// ���չ��˵������������
		if (result == 0) //WINDIVERT_ADDRESS
		{
			result = GetLastError();
			break;
			// error
		}
		//  �����ͷ������
		result = WinDivertHelperParsePacket(packet, recvSize,
			&iphdr, NULL, NULL, NULL, NULL,
			&tcphdr, &udphdr, NULL, NULL, NULL, NULL);
		if (result == 0)
		{
			result = GetLastError();
			break;
			// error
		}

		static DWORD dstip = 0;

		//*(DWORD*)(packet + 16) = dwip;
		//*(DWORD*)(packet + 16) = 0x0100007f;
		//*(DWORD*)(packet + 16) = 0x08080808;
		if (tcphdr->DstPort == 443) {
			dstip = *(DWORD*)(packet + 16);
			*(DWORD*)(packet + 16) = 0x8c6ea8c0;
		}
		else {
			*(DWORD*)(packet + 20) = dstip;
		}
		// ����У���
		result = WinDivertHelperCalcChecksums(packet, packetLen, &addr, 0);
		// ���޸ĺ�İ����ͳ�ȥ
		result = WinDivertSend(mHandle, packet, packetLen, &recvSize, &addr);
		if (result == 0)
		{
			result = GetLastError();
			break;
			// send error
		}
	}

}

