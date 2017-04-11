#pragma once
#include "defines.h"
#include "SharedFunctions.h"

class CPopcapUnpacker
{
public:
	bool bUnpacking;
	CRITICAL_SECTION lpInternalCS;
	HANDLE dwThreadHandle;

public:
	CPopcapUnpacker(void);
	~CPopcapUnpacker(void);
	bool bIsValidProduct();
	void Unpack();
	static DWORD WINAPI UnpackThread(void * pthis);
	void Abort();
	void Cleanup();
};
