#pragma once
#include "defines.h"
#include "SharedFunctions.h"

class CGameHouseUnpacker
{
public:
	bool bUnpacking;
	CRITICAL_SECTION lpInternalCS;
	HANDLE dwThreadHandle;

	//Used to set the PAGE_GUARD
	DWORD dwBaseAddr;
	DWORD dwFirstVA;
	DWORD dwFirstSize;
	STARTUPINFO si;
	PROCESS_INFORMATION pi;
public:
	CGameHouseUnpacker(void);
	~CGameHouseUnpacker(void);
	bool bIsValidProduct();
	void Unpack();
	static DWORD WINAPI UnpackThread(void * pthis);
	void Abort();
	void Cleanup();
};
