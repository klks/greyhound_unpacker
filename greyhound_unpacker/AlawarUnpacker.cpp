#include "AlawarUnpacker.h"
#include "..\greyhound_hook\greyhound_hook.h"

//Externs
extern char cTargetDirectory[DEF_MAXPATH];
extern char cExeFileName[DEF_MAXPATH];
extern char cExeFileNameOnly[DEF_MAXPATH];
extern char cOwnDirectory[DEF_MAXPATH];

char cWrpFileName[DEF_MAXPATH+20];
char cWrpDllName[DEF_MAXPATH+20];

CAlawarUnpacker::CAlawarUnpacker(void)
{
	bUnpacking = false;
	dwThreadHandle = NULL;
	InitializeCriticalSection(&lpInternalCS);

	//Add your Code Here
}

CAlawarUnpacker::~CAlawarUnpacker(void)
{
	DeleteCriticalSection(&lpInternalCS);

	//Add your Code Here
}

bool CAlawarUnpacker::bIsValidProduct()
{
#ifdef DEBUG
	Log("CAlawarUnpacker::bIsValidProduct()");
#endif

	//Add your Code Here

	bool bWrapperExists = false;
	bool bWrpExeExists = false;

	//Check for wrapper.dll
	ZeroMemory(cWrpDllName, sizeof(cWrpDllName));
	memcpy(cWrpDllName, cTargetDirectory, strlen(cTargetDirectory));
	strcat(cWrpDllName, "wrapper.dll");
	if(bFileExists(cWrpDllName))
		bWrapperExists = true;

	//Check for game.wrp.exe
	ZeroMemory(cWrpFileName, sizeof(cWrpFileName));
	memcpy(cWrpFileName, cExeFileName, strlen(cExeFileName)-3);
	strcat(cWrpFileName, "wrp.exe");
	if(bFileExists(cWrpFileName))
		bWrpExeExists = true;

	if(bWrapperExists && bWrpExeExists)
		return true;

	if(bWrapperExists || bWrpExeExists)
	{
		Log("Possible new version of Alawar product");
		return false;
	}

	return false;
}

void CAlawarUnpacker::Unpack()
{
#ifdef DEBUG
	Log("CAlawarUnpacker::Unpack()");
#endif
	DWORD dwThreadID;

	if(bUnpacking) //Are we unpacking?
	{
		Log("Unpacking already in progress");
		return;
	}
	Log("Unpacking ...");
	bUnpacking = true;
	dwThreadHandle = CreateThread(NULL, NULL, &CAlawarUnpacker::UnpackThread, (void*)this, 0, &dwThreadID);
}

DWORD CAlawarUnpacker::UnpackThread(void * pthis)
{
#ifdef DEBUG
	Log("CAlawarUnpacker::UnpackThread()");
#endif
	//Add your Code Here

	CAlawarUnpacker *pt = (CAlawarUnpacker *) pthis;

	//Unpacking routine
	TryEnterCriticalSection(&pt->lpInternalCS);
	//Make sure the hooking DLL exists
	
	if(!bFileExists(cFullHookPath))
	{
		Log("Please ensure %s exists!", cHookName);
		system("pause");
		goto FAILED;
	}

	//Make sure executable exists
	if(!bFileExists(cExeFileName))
	{
		Log("Please make sure file %s exists.", cExeFileNameOnly);
		goto FAILED;
	}

	//Try to inject DLL Hook
	if(!InjectDLLHook(PROD_ALAWAR, pt->pi.dwProcessId, pt->si, pt->pi))
	{
		Log("Unable to inject DLL into target process");
		HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pt->pi.dwProcessId);
		if(hProcess != NULL)
		{
			TerminateProcess(hProcess, 0);
			CloseHandle(hProcess);
		}
		LeaveCriticalSection(&pt->lpInternalCS);
		goto FAILED;
	}

	//Give time for user to abort ;)
	LeaveCriticalSection(&pt->lpInternalCS);

	Log("Please click on the Play Demo Now button");
	DWORD time_start = GetTickCount();
	while(!GetUnpackStatus())
	{
		Sleep(100);
		TryEnterCriticalSection(&pt->lpInternalCS);
		if((GetTickCount() - time_start) > 30000)
		{
			Log("30 Seconds passed, unpacker timed out...");
			//Let DLL do the killings
			DLLFailedCleanup();
			LeaveCriticalSection(&pt->lpInternalCS);
			goto FAILED;
		}
		LeaveCriticalSection(&pt->lpInternalCS);
	}

	//Did the unpacking fail?
	if(bUnpackFailed()) goto FAILED;

	DWORD dwFileEP = Alawar_GetFileEP();
	if(dwFileEP == 0) goto FAILED;

	TryEnterCriticalSection(&pt->lpInternalCS);

	//Wait for cleanup to finish
	Sleep(2000);

	//Write new EP
	HANDLE hFile, hFileMap;
	LPVOID hFilePtr;

	if(!bOpenForMapping(cWrpFileName, &hFile, &hFileMap, &hFilePtr, MAP_READWRITE))
	{
		LeaveCriticalSection(&pt->lpInternalCS);
		goto FAILED;
	}

	IMAGE_DOS_HEADER *idh = (IMAGE_DOS_HEADER *)(hFilePtr);
	IMAGE_FILE_HEADER       *ifh = (IMAGE_FILE_HEADER *)((DWORD)(idh) + idh->e_lfanew + sizeof(DWORD));
	IMAGE_OPTIONAL_HEADER   *ioh = (IMAGE_OPTIONAL_HEADER *)((DWORD)(ifh) + sizeof(IMAGE_FILE_HEADER));
	ioh->AddressOfEntryPoint = dwFileEP;

	FlushViewOfFile(hFilePtr, 0);

	CloseMapping(&hFile, &hFileMap, &hFilePtr);

	//Delete wrapper
	DeleteFile(cExeFileName);
	DeleteFile(cWrpDllName);
	MoveFile(cWrpFileName, cExeFileName);

	Log("Unpacking completed successfully!");
	goto CLEANUP;

FAILED:
	TryEnterCriticalSection(&pt->lpInternalCS);
	Log("Unpacking Failed!");
CLEANUP:
	//Cleanup
	
	pt->Cleanup();
	LeaveCriticalSection(&pt->lpInternalCS);
	return 0;
}

void CAlawarUnpacker::Abort()
{
#ifdef DEBUG
	Log("CAlawarUnpacker::Abort()");
#endif
	TryEnterCriticalSection(&lpInternalCS);
	SuspendThread(dwThreadHandle);
	TerminateThread(dwThreadHandle, 1);
	LeaveCriticalSection(&lpInternalCS);
	Cleanup();
	Log("Aborting Complete!");
}

void CAlawarUnpacker::Cleanup()
{
#ifdef DEBUG
	Log("CAlawarUnpacker::Cleanup()");
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
