#pragma once
#include "defines.h"
#include "SharedFunctions.h"

class CPlayrixUnpacker
{
public:
	bool bUnpacking;
	CRITICAL_SECTION lpInternalCS;
	HANDLE dwThreadHandle;

public:
	CPlayrixUnpacker(void);
	~CPlayrixUnpacker(void);
	bool bIsValidProduct();
	void Unpack();
	static DWORD WINAPI UnpackThread(void * pthis);
	void Abort();
	void Cleanup();
};
