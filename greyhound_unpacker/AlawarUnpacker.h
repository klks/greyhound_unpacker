#pragma once
#include "defines.h"
#include "SharedFunctions.h"

#pragma comment(lib, "greyhound_hook.lib")

class CAlawarUnpacker
{
public:
	bool bUnpacking;
	CRITICAL_SECTION lpInternalCS;
	HANDLE dwThreadHandle;

	//Unpacker Shit Starts Here
	STARTUPINFO si;
	PROCESS_INFORMATION pi;

public:
	CAlawarUnpacker(void);
	~CAlawarUnpacker(void);
	bool bIsValidProduct();
	void Unpack();
	static DWORD WINAPI UnpackThread(void * pthis);
	void Abort();
	void Cleanup();
};
