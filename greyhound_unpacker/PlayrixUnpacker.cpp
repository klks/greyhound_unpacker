#include "PlayrixUnpacker.h"

//Externs
extern char cTargetDirectory[DEF_MAXPATH];
extern char cExeFileName[DEF_MAXPATH];
extern char cExeFileNameOnly[DEF_MAXPATH];
extern char cOwnDirectory[DEF_MAXPATH];

char cGameRunName[DEF_MAXPATH+20];

CPlayrixUnpacker::CPlayrixUnpacker(void)
{
	bUnpacking = false;
	dwThreadHandle = NULL;
	InitializeCriticalSection(&lpInternalCS);

	//Add your Code Here
}

CPlayrixUnpacker::~CPlayrixUnpacker(void)
{
	DeleteCriticalSection(&lpInternalCS);

	//Add your Code Here
}

bool CPlayrixUnpacker::bIsValidProduct()
{
#ifdef DEBUG
	Log("CPlayrixUnpacker::bIsValidProduct()");
#endif

	//Add your Code Here
	bool bPlayrixIcon = false;
	bool bGameRun = false;

	//Check for playrix.ico
	ZeroMemory(cGameRunName, sizeof(cGameRunName));
	memcpy(cGameRunName, cTargetDirectory, strlen(cTargetDirectory));
	strcat(cGameRunName, "playrix.ico");
	if(bFileExists(cGameRunName))
		bPlayrixIcon = true;

	//Check for game.run
	ZeroMemory(cGameRunName, sizeof(cGameRunName));
	memcpy(cGameRunName, cTargetDirectory, strlen(cTargetDirectory));
	strcat(cGameRunName, "game.run");
	if(bFileExists(cGameRunName))
		bGameRun = true;

	if(bPlayrixIcon && bGameRun)
		return true;

	if(bPlayrixIcon || bGameRun)
	{
		Log("Possible new version of Playrix product");
		return false;
	}

	return false;
}

void CPlayrixUnpacker::Unpack()
{
#ifdef DEBUG
	Log("CPlayrixUnpacker::Unpack()");
#endif
	DWORD dwThreadID;

	if(bUnpacking) //Are we unpacking?
	{
		Log("Unpacking already in progress");
		return;
	}
	Log("Unpacking ...");
	bUnpacking = true;
	dwThreadHandle = CreateThread(NULL, NULL, &CPlayrixUnpacker::UnpackThread, (void*)this, 0, &dwThreadID);
}

DWORD CPlayrixUnpacker::UnpackThread(void * pthis)
{
#ifdef DEBUG
	Log("CPlayrixUnpacker::UnpackThread()");
#endif
	//Add your Code Here

	CPlayrixUnpacker *pt = (CPlayrixUnpacker *) pthis;

	//Unpacking routine
	TryEnterCriticalSection(&pt->lpInternalCS);
	//Make sure the hooking DLL exists

	//Make sure executable exists
	if(!bFileExists(cExeFileName))
	{
		Log("Please make sure file %s exists.", cExeFileNameOnly);
		LeaveCriticalSection(&pt->lpInternalCS);
		goto FAILED;
	}

	DeleteFile(cExeFileName);
	MoveFile(cGameRunName, cExeFileName);
	//Remove Hidden flag
	SetFileAttributes(cExeFileName, FILE_ATTRIBUTE_NORMAL);
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

void CPlayrixUnpacker::Abort()
{
#ifdef DEBUG
	Log("CPlayrixUnpacker::Abort()");
#endif
	TryEnterCriticalSection(&lpInternalCS);
	SuspendThread(dwThreadHandle);
	TerminateThread(dwThreadHandle, 1);
	LeaveCriticalSection(&lpInternalCS);
	Cleanup();
	Log("Aborting Complete!");
}

void CPlayrixUnpacker::Cleanup()
{
#ifdef DEBUG
	Log("CPlayrixUnpacker::Cleanup()");
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
