

#include <Windows.h>
#include <string.h>
#include <string>
#include <memory.h>
#include "compression.h"
#include <conio.h>
#include <stdio.h>

#pragma comment(lib,"lib/zlib.lib")

using namespace std;


int isHttpResponse(const char* lpdata) {

	if (memcmp(lpdata, "HTTP/1.1 ", 9) == 0 || memcmp(lpdata, "HTTP/1.0 ", 9) == 0) {
		return TRUE;
	}
	return FALSE;

}

string getHttpHeader(const char* data, int len, char** lphttpdata) {

	char* lphdr = strstr((char*)data, "\r\n\r\n");
	if (lphdr <= FALSE)
	{
		*lphttpdata = 0;
		return string(data);
	}

	lphdr += 4;
	string httphdr = string(data, lphdr - data);
	*lphttpdata = lphdr;
	return httphdr;
}


int isHttpPacket(const char* lpdata) {

	//HTTP 1.0
	if (memcmp(lpdata, "POST ", 5) == 0) {
		return 5;
	}
	else if (memcmp(lpdata, "GET ", 4) == 0)
	{
		return 4;
	}
	else if (memcmp(lpdata, "HEAD ", 5) == 0)
	{
		return 5;
	}
	//HTTP 1.1
	else if (memcmp(lpdata, "PUT ", 4) == 0)
	{
		return 4;
	}
	else if (memcmp(lpdata, "CONNECT ", 8) == 0)
	{
		return 8;
	}
	else if (memcmp(lpdata, "OPTIONS ", 8) == 0)
	{
		return 8;
	}
	else if (memcmp(lpdata, "DELETE ", 7) == 0)
	{
		return 7;
	}
	else if (memcmp(lpdata, "TRACE ", 6) == 0)
	{
		return 6;
	}

	return FALSE;
}


string getValueFromKey(const char* lphttphdr, string  searchkey) {

	string key = "\r\n" + searchkey + ": ";
	char* phdr = strstr((char*)lphttphdr, key.c_str());
	if (phdr)
	{
		phdr += key.length();
		char* pend = strstr(phdr, "\r\n");
		if (pend)
		{
			int len = pend - phdr;
			if (len > 0 && len < 256) {
				string value = string(phdr, len);
				return value;
			}
		}
	}

	return "";
}

int getNextPacket(char* httpdata) {
	return 0;
}


int getPackLen(char* data) {
	return 0;
}

int getChunkSize(char* data, int* value) {
	char slen[16] = { 0 };
	int len = 0;
	for (int j = 0; j < sizeof(slen); j++) {
		if (isalnum(data[j])) {
			slen[j] = data[j];
		}
		else {
			if (data[j] == '\r' && data[j + 1] == '\n') {
				len = j + 2;
				*value = stol(slen, 0, 16);
			}
			else {

			}

			break;
		}
	}

	return len;
}




int getZipType(string httphdr,char * httpdata,char * gz,int * gzsize){
	char* chunked = strstr((char*)httphdr.c_str(), "Transfer-Encoding: chunked\r\n");
	if (chunked) {

		int cslen = 0;
		int chunklen = getChunkSize(httpdata, &cslen);
		httpdata += chunklen;

		if (cslen > 0) {
			gz = httpdata;
			*gzsize = cslen;
			return 1;
		}
	}
	else {
		string cs = getValueFromKey(httphdr.c_str(), "Content-Length");
		int cslen = atoi(cs.c_str());
		if (cslen > 0) {
			char* gzip = strstr((char*)httphdr.c_str(), "Content-Encoding: gzip\r\n");
			if (gzip) {
				gz = httpdata;
				*gzsize = cslen;
				return 2;
			}
		}
	}
	return 0;
}


int mainproc(char* infile,char* outfile) {

	int ret = 0;

	char* outfn = 0;

	if (outfile) {
		outfn = outfile;
	}
	else {
		outfn = (char*)"sslout.txt";	
	}	
	HANDLE hfout = CreateFileA(outfn, GENERIC_WRITE, 0, 0, CREATE_ALWAYS, 0, 0);
	if (hfout == INVALID_HANDLE_VALUE) {
		printf("open output file:%s\r\n error:%d\r\n", outfn, GetLastError());
		return -1;
	}
	else {
		//printf("open output file:%s\r\n successfully\r\n", outfn);
	}

	char* infn = 0;
	if (infile) {
		infn = infile;	
	}
	else {
		infn = (char*)"ssl.dat";
	}
	HANDLE hf = CreateFileA(infn, GENERIC_READ, 0, 0, OPEN_EXISTING, 0, 0);
	if (hf == INVALID_HANDLE_VALUE) {
		printf("open input file:%s\r\n error:%d\r\n", infn, GetLastError());
		return -1;
	}
	else {
		//printf("open input file:%s\r\n successfully\r\n", infn);
	}

	DWORD fs_high = 0;
	int fs = GetFileSize(hf, &fs_high);
	char* buf = new char[fs + 16];
	DWORD cnt = 0;
	ret = ReadFile(hf, buf, fs, &cnt, 0);
	CloseHandle(hf);
	if (ret == 0) {
		printf("read file:%s\r\n error:%d\r\n", infn,GetLastError());
		return FALSE;
	}
	buf[fs] = 0;

	int notHttpTotal = 0;
	int httpTotal = 0;
	int unzipTotal = 0;

	for (int idx = 0; idx < fs; idx++) {
		int type = isHttpPacket(buf + idx) || isHttpResponse(buf + idx);
		if (type) {
			char* httpdata = strstr(buf + idx, "\r\n\r\n");
			if (httpdata <= 0) {
				printf("no http header at offset:%d\r\n", idx);
				continue;
			}
			httpdata += 4;
			char* data = httpdata;
			string httphdr = string(buf + idx, httpdata - (buf + idx));
			
			const char* tag ="\r\n\r\n--------------------------------------------------------------------------------\r\n\r\n";
			ret = WriteFile(hfout, tag, lstrlenA(tag), &cnt, 0);
			ret = WriteFile(hfout, buf + idx, (char*)data - (buf + idx), &cnt, 0);

			httpTotal++;

			char* chunked = strstr((char*)httphdr.c_str(), "Transfer-Encoding: chunked\r\n");
			if (chunked) {

				int cslen = 0;
				int chunklen = getChunkSize(data, &cslen);
				data += chunklen;

				DWORD unziplen = cslen << 5;
				unsigned char* unzipbuf = new unsigned char[unziplen];
				if (unzipbuf) {
					if (memcmp(data, "\x1f\x8b\x08\x00", 4) == 0) {
						ret = Compress::gzdecompress((unsigned char*)data + 10, cslen - 10, unzipbuf, &unziplen);
					}
					else {
						ret = Compress::gzdecompress((unsigned char*)data, cslen, unzipbuf, &unziplen);
					}

					if (ret == 0) {
						
						ret = WriteFile(hfout, unzipbuf, unziplen, &cnt, 0);

						unzipTotal++;
					}
					else {
						printf("unzip size:%d error:%d\r\n", cslen, GetLastError());
					}
					delete[] unzipbuf;
				}

				data += cslen;
				idx = data - buf;
			}
			else {
				string cs = getValueFromKey(httphdr.c_str(), "Content-Length");
				int cslen = atoi(cs.c_str());
				if (cslen > 0) {
					char* gzip = strstr((char*)httphdr.c_str(), "Content-Encoding: gzip\r\n");
					if (gzip) {
						DWORD unziplen = cslen << 5;
						unsigned char* unzipbuf = new unsigned char[unziplen];
						if (unzipbuf) {
							if (memcmp(data, "\x1f\x8b\x08\x00", 4) == 0) {
								ret = Compress::gzdecompress((unsigned char*)data + 10, cslen - 10, unzipbuf, &unziplen);
							}
							else {
								ret = Compress::gzdecompress((unsigned char*)data, cslen, unzipbuf, &unziplen);
							}

							if (ret == 0) {


								ret = WriteFile(hfout, unzipbuf, unziplen, &cnt, 0);
								unzipTotal++;
							}
							else {
								printf("unzip size:%d error:%d\r\n", cslen, GetLastError());
							}

							delete[] unzipbuf;
						}
					}
					else {
						//no gzip
					}

					data += cslen;
				}
				else {
					//cslen < 0
					//printf("packet Content-Length:%d error\r\n", cslen);
				}
				idx = data - buf;
			}
		}
		else {
			//not http
			//printf("not http packet offset:%d\r\n", idx);
			//notHttpTotal++;
		}
	}

	CloseHandle(hfout);

	delete[]buf;

	printf("process http packet:%d,unzip http packet:%d\r\n", httpTotal, unzipTotal);

	return 0;
}



int main(int argc, char** argv) {
	int ret = 0;
	if (argc >= 3) {
		ret = mainproc(argv[1], argv[2]);
	}
	else {
		ret = mainproc(0,0);
	}

	printf("Press any key to quit...\r\n");

	ret = _getch();

	return ret;
}