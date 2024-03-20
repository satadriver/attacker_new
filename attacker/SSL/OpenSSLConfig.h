#pragma once
#include <windows.h>
#include <iostream>

using namespace std;


class OpenSSLConfig {
public:
	static string getOpenSSLPath();
	static int initOpensslPath(int control);
	static int getOpenSSLPathFromCfg();
	static int clearOpenssl();
	static int addRunPath(string path);
	static int delFolder(CHAR* path);
};