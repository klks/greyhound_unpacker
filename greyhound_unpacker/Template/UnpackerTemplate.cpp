#include "UnpackerTemplate.h"

//Externs
extern char cTargetDirectory[DEF_MAXPATH];
extern char cExeFileName[DEF_MAXPATH];
extern char cExeFileNameOnly[DEF_MAXPATH];
extern char cOwnDirectory[DEF_MAXPATH];

CUnpackerTemplate::CUnpackerTemplate(void)
{
	bUnpacking = false;
	dwThreadHandle = NULL;
	InitializeCriticalSection(&lpInternalCS);

	//Add your Code Here
}

CUnpackerTemplate::~CUnpackerTemplate(void)
{
	DeleteCriticalSection(&lpInternalCS);

	//Add your Code Here
}

bool CUnpackerTemplate::bIsValidProduct()
{
#ifdef DEBUG
	Log("CUnpackerTemplate::bIsValidProduct()");
#endif

	//Add your Code Here

	return true;
}

void CUnpackerTemplate::Unpack()
{
#ifdef DEBUG
	Log("CUnpackerTemplate::Unpack()");
#endif
	DWORD dwThreadID;

	if(bUnpacking) //Are we unpacking?
	{
		Log("Unpacking already in progress");
		return;
	}
	Log("Unpacking ...");
	bUnpacking = true;
	dwThreadHandle = CreateThread(NULL, NULL, &CUnpackerTemplate::UnpackThread, (void*)this, 0, &dwThreadID);
}

DWORD CUnpackerTemplate::UnpackThread(void * pthis)
{
#ifdef DEBUG
	Log("CUnpackerTemplate::UnpackThread()");
#endif
	//Add your Code Here

	CUnpackerTemplate *pt = (CUnpackerTemplate *) pthis;

	//Unpacking routine
	TryEnterCriticalSection(&pt->lpInternalCS);
	//Make sure the hooking DLL exists
	/* OPTIONAL - only add if you need to use the hook
	if(!bFileExists(cFullHookPath))
	{
		Log("Please ensure %s exists!", cHookName);
		system("pause");
		goto FAILED;
	}*/

	//Make sure executable exists
	if(!bFileExists(cExeFileName))
	{
		Log("Please make sure file %s exists.", cExeFileNameOnly);
		LeaveCriticalSection(&pt->lpInternalCS);
		goto FAILED;
	}

	LeaveCriticalSection(&pt->lpInternalCS);
	Log("Unpacking completed successfully!");
	goto CLEANUP;

FAILED:
	Log("Unpacking Failed!");
CLEANUP:
	//Cleanup
	pt->Cleanup();
	return 0;
}

void CUnpackerTemplate::Abort()
{
#ifdef DEBUG
	Log("CUnpackerTemplate::Abort()");
#endif
	TryEnterCriticalSection(&lpInternalCS);
	SuspendThread(dwThreadHandle);
	TerminateThread(dwThreadHandle, 1);
	LeaveCriticalSection(&lpInternalCS);
	Cleanup();
	Log("Aborting Complete!");
}

void CUnpackerTemplate::Cleanup()
{
#ifdef DEBUG
	Log("CUnpackerTemplate::Cleanup()");
#endif

	TryEnterCriticalSection(&lpInternalCS);
	//Add your Code Here

	if(dwThreadHandle != NULL)
	{
		CloseHandle(dwThreadHandle);
		dwThreadHandle = NULL;
	}
	bUnpacking = false;
	ResetButtons();
	LeaveCriticalSection(&lpInternalCS);
}
