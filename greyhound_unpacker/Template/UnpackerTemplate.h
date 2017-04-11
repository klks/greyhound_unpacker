#pragma once
#include "..\defines.h"
#include "..\SharedFunctions.h"

class CUnpackerTemplate
{
public:
	bool bUnpacking;
	CRITICAL_SECTION lpInternalCS;
	HANDLE dwThreadHandle;

	//Unpacker Shit Starts Here

public:
	CUnpackerTemplate(void);
	~CUnpackerTemplate(void);
	bool bIsValidProduct();
	void Unpack();
	static DWORD WINAPI UnpackThread(void * pthis);
	void Abort();
	void Cleanup();
};
