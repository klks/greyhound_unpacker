#include "ReflexiveUnpacker.h"
#include "..\greyhound_hook\greyhound_hook.h"

//Externs
extern char cTargetDirectory[DEF_MAXPATH];
extern char cExeFileName[DEF_MAXPATH];
extern char cExeFileNameOnly[DEF_MAXPATH];
extern char cOwnDirectory[DEF_MAXPATH];

char cRwgFileName[DEF_MAXPATH+20];
char cDmpFileName[DEF_MAXPATH+20];

CReflexiveUnpacker::CReflexiveUnpacker(void)
{
	bUnpacking = false;
	dwThreadHandle = NULL;
	InitializeCriticalSection(&lpInternalCS);

	//Add Your Code Here
	hRwgFile=NULL;
	hRwgMap=NULL;
	hDumpFile=NULL;
	hgDmpMem=NULL;
	hRwgPtr=NULL;
}

CReflexiveUnpacker::~CReflexiveUnpacker(void)
{
	DeleteCriticalSection(&lpInternalCS);
}

bool CReflexiveUnpacker::bIsValidProduct()
{
#ifdef DEBUG
	Log("CReflexiveUnpacker::bIsValidProduct()");
#endif
	//RWG
	ZeroMemory(cRwgFileName, sizeof(cRwgFileName));
	memcpy(cRwgFileName, cExeFileName, strlen(cExeFileName)-3);
	strcat(cRwgFileName, "rwg");

	//Make sure GWS with the same name exists
	if(!bFileExists(cRwgFileName))
	{
		//Check for RAW_001.exe
		ZeroMemory(cDmpFileName, sizeof(cDmpFileName));
		memcpy(cDmpFileName, cTargetDirectory, strlen(cTargetDirectory));
		strcat(cDmpFileName, "RAW_001.exe");
		if(bFileExists(cDmpFileName))
		{
			CopyFile(cDmpFileName, cRwgFileName, TRUE);
			return true;
		}

		return false;
	}

	return true;
}

void CReflexiveUnpacker::Unpack()
{
#ifdef DEBUG
	Log("CReflexiveUnpacker::Unpack()");
#endif
	DWORD dwThreadID;

	if(bUnpacking) //Are we unpacking?
	{
		Log("Unpacking already in progress");
		return;
	}
	Log("Unpacking ...");
	bUnpacking = true;
	dwThreadHandle = CreateThread(NULL, NULL, &CReflexiveUnpacker::UnpackThread, (void*)this, 0, &dwThreadID);
}

DWORD CReflexiveUnpacker::UnpackThread(void * pthis)
{
#ifdef DEBUG
	Log("CReflexiveUnpacker::UnpackThread()");
#endif

	CReflexiveUnpacker *pt = (CReflexiveUnpacker *) pthis;

	//Unpacking routine
	TryEnterCriticalSection(&pt->lpInternalCS);
	//Make sure the hooking DLL exists
	if(!bFileExists(cFullHookPath))
	{
		Log("Please ensure %s exists!", cHookName);
		LeaveCriticalSection(&pt->lpInternalCS);
		goto FAILED;
	}

	//Make sure executable exists
	if(!bFileExists(cExeFileName))
	{
		Log("Please make sure file %s exists.", cExeFileName);
		LeaveCriticalSection(&pt->lpInternalCS);
		goto FAILED;
	}

	//DMP
	ZeroMemory(cDmpFileName, sizeof(cDmpFileName));
	memcpy(cDmpFileName, cRwgFileName, strlen(cRwgFileName));
	strcat(cDmpFileName, ".dmp");

	//Make sure GWS with the same name exists
	if(!bFileExists(cRwgFileName))
	{
		Log("Please make sure file %s exists as well!", cRwgFileName);
		LeaveCriticalSection(&pt->lpInternalCS);
		goto FAILED;
	}

	//Try to inject hooks
	if(!InjectDLLHook(PROD_REFLEXIVE, pt->pi.dwProcessId, pt->si, pt->pi))
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

	Log("Please click on the Play Game button");
	DWORD time_start = GetTickCount();
	while(!GetUnpackStatus())
	{
		Sleep(100);
		TryEnterCriticalSection(&pt->lpInternalCS);
		if((GetTickCount() - time_start) > 30000)
		{
			Log("30 Seconds passed, unpacker timed out...");
			TerminateProcess(pt->pi.hProcess, 0);
			LeaveCriticalSection(&pt->lpInternalCS);
			goto FAILED;
		}
		LeaveCriticalSection(&pt->lpInternalCS);
	}

	//Did the unpacking fail?
	if(bUnpackFailed()) goto FAILED;

	TryEnterCriticalSection(&pt->lpInternalCS);

	//Wait for cleanup to finish
	Sleep(2000);
	//Make sure .dmp file exists
	if(!bFileExists(cDmpFileName))
	{
		Log("Unable to locate memory dump file %s", cDmpFileName);
		LeaveCriticalSection(&pt->lpInternalCS);
		goto FAILED;
	}

	//Verify that the OEP is good
	if(!bOpenForMapping(cRwgFileName, &(pt->hRwgFile), &(pt->hRwgMap), &(pt->hRwgPtr), MAP_READWRITE))
	{
		LeaveCriticalSection(&pt->lpInternalCS);
		goto FAILED;
	}

	//Verify information
	IMAGE_DOS_HEADER *idh = (IMAGE_DOS_HEADER *)(pt->hRwgPtr);
	IMAGE_FILE_HEADER       *ifh = (IMAGE_FILE_HEADER *)((DWORD)(idh) + idh->e_lfanew + sizeof(DWORD));
	IMAGE_OPTIONAL_HEADER   *ioh = (IMAGE_OPTIONAL_HEADER *)((DWORD)(ifh) + sizeof(IMAGE_FILE_HEADER));

	//To find OEP, we need to traverse the object table and find which section the EntryPoint belongs to
	IMAGE_SECTION_HEADER *ish = (IMAGE_SECTION_HEADER *)((DWORD)(ioh) + ifh->SizeOfOptionalHeader);
	for(int i=0; i<ifh->NumberOfSections;i++)
	{
		//Check and see if our OEP falls within any of these sections
		if((DWORD)ioh->AddressOfEntryPoint >= ish->VirtualAddress && 
			(DWORD)ioh->AddressOfEntryPoint <= (DWORD)(ish->VirtualAddress+ish->Misc.VirtualSize)){
#ifdef DEBUG
			Log("Section Name = %s, Phy RVA = 0x%.8X, Phy Size = 0x%.8X, Vir RVA = 0x%.8X, Vir Size = 0x%.8X", ish->Name, ish->PointerToRawData, ish->SizeOfRawData, ish->VirtualAddress, ish->Misc.VirtualSize);
#endif
			break;
		}
		ish = (IMAGE_SECTION_HEADER *)((DWORD)(ish) +  sizeof(IMAGE_SECTION_HEADER));
	}
	
	//Calculation to get file OEP
	DWORD dwFileOEP = (DWORD)((ioh->AddressOfEntryPoint-ish->VirtualAddress)+ish->PointerToRawData);
	LPVOID hRwgOEP = (LPVOID)((DWORD)pt->hRwgPtr + dwFileOEP);
#ifdef DEBUG
	Log("FileOEP = 0x%.8X, MemOEP = 0x%.8X", dwFileOEP,hRwgOEP);
#endif

	//Copy dumped memory over to game
	pt->hDumpFile = CreateFile(cDmpFileName, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if(pt->hDumpFile == INVALID_HANDLE_VALUE)
	{
		Log("Unable to open file %s for reading", cDmpFileName);
		LeaveCriticalSection(&pt->lpInternalCS);
		goto FAILED;
	}

	//Copy contents to memory
	DWORD dwDumpFileSize = GetFileSize(pt->hDumpFile, NULL);
	pt->hgDmpMem = GlobalAlloc(GPTR, dwDumpFileSize);
	if(pt->hgDmpMem == NULL)
	{
		Log("Unable to allocate memory to store dump file");
		LeaveCriticalSection(&pt->lpInternalCS);
		goto FAILED;
	}
	
	DWORD lpNumberOfBytesRead;
	ReadFile(pt->hDumpFile, pt->hgDmpMem, dwDumpFileSize, &lpNumberOfBytesRead, NULL);
	
	//Check to veryify bytes in OEP
	if(!bCheckOEPBytes((BYTE *)hRwgOEP))
	{
		Log("OEP Bytes Do Not Match Dumped Version");
		LeaveCriticalSection(&pt->lpInternalCS);
		goto FAILED;
	}

	//Write contents back to real exe
	memcpy(hRwgOEP, pt->hgDmpMem, dwDumpFileSize);

	//Flush Buffers
	FlushViewOfFile(pt->hRwgPtr, 0);

	//Delete loader
	DeleteFile(cExeFileName);
#ifdef DEBUG
	Log("Deleting Game Loader %s", cExeFileName);
#endif

	Log("Unpacking completed successfully!");
	goto CLEANUP;

FAILED:
	TryEnterCriticalSection(&pt->lpInternalCS);
	Log("Unpacking Failed!");
CLEANUP:
	//Cleanup
	
	pt->Cleanup();

	//Final step to rename RWG to exe
	MoveFile(cRwgFileName, cExeFileName);
#ifdef DEBUG
	Log("Renaming File %s to %s", cRwgFileName, cExeFileName);
#endif

	LeaveCriticalSection(&pt->lpInternalCS);
	return 0;
}

void CReflexiveUnpacker::Abort()
{
#ifdef DEBUG
	Log("CReflexiveUnpacker::Abort()");
#endif
	TryEnterCriticalSection(&lpInternalCS);
	SuspendThread(dwThreadHandle);
	TerminateThread(dwThreadHandle, 1);
	LeaveCriticalSection(&lpInternalCS);
	Cleanup();
	Log("Aborting Complete!");
}

void CReflexiveUnpacker::Cleanup()
{
#ifdef DEBUG
	Log("CReflexiveUnpacker::Cleanup()");
#endif

	TryEnterCriticalSection(&lpInternalCS);

	//Run this again just incase
	TerminateProcess(pi.hProcess, 0);
	//We set NULL because function may be called in the future

	CloseMapping(&hRwgFile, &hRwgMap, &hRwgPtr);

	if(hgDmpMem != NULL)
	{
		GlobalFree(hgDmpMem);
		hgDmpMem = NULL;
	}
	if(hDumpFile != NULL)
	{
		CloseHandle(hDumpFile);
		hDumpFile = NULL;
	}

	//Delete memory dump
	DeleteFile(cDmpFileName);
#ifdef DEBUG
	Log("Deleting memory dump file %s", cDmpFileName);
#endif

	if(dwThreadHandle != NULL)
	{
		CloseHandle(dwThreadHandle);
		dwThreadHandle = NULL;
	}
	bUnpacking = false;
	ResetButtons();
	LeaveCriticalSection(&lpInternalCS);
}