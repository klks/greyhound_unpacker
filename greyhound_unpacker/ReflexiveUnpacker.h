#pragma once
#include "defines.h"
#include "SharedFunctions.h"

#pragma comment(lib, "greyhound_hook.lib")

class CReflexiveUnpacker
{
public:
	bool bUnpacking;
	CRITICAL_SECTION lpInternalCS;
	HANDLE dwThreadHandle;

	//Unpacker Shit Starts Here
	STARTUPINFO si;
	PROCESS_INFORMATION pi;

	//ALL HANDLES
	HANDLE hRwgFile;
	HANDLE hRwgMap;
	HANDLE hDumpFile;
	HGLOBAL hgDmpMem;
	LPVOID hRwgPtr;

public:
	CReflexiveUnpacker(void);
	~CReflexiveUnpacker(void);
	bool bIsValidProduct();
	void Unpack();
	static DWORD WINAPI UnpackThread(void * pthis);
	void Abort();
	void Cleanup();
};
