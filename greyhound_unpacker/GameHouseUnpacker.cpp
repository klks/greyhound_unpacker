#include "GameHouseUnpacker.h"

//Externs
extern char cTargetDirectory[DEF_MAXPATH];
extern char cExeFileName[DEF_MAXPATH];
extern char cExeFileNameOnly[DEF_MAXPATH];
extern char cOwnDirectory[DEF_MAXPATH];

CGameHouseUnpacker::CGameHouseUnpacker(void)
{
	bUnpacking = false;
	dwThreadHandle = NULL;
	InitializeCriticalSection(&lpInternalCS);

	//Add your Code Here
}

CGameHouseUnpacker::~CGameHouseUnpacker(void)
{
	DeleteCriticalSection(&lpInternalCS);

	//Add your Code Here
}

bool CGameHouseUnpacker::bIsValidProduct()
{
#ifdef DEBUG
	Log("CGameHouseUnpacker::bIsValidProduct()");
#endif

	//Add your Code Here

	HANDLE hFile, hFileMap;
	LPVOID hFilePtr;
	bool bRet = false;

	if(!bOpenForMapping(cExeFileName, &hFile, &hFileMap, &hFilePtr))
		goto CLEANUP;

	//Verify information
	IMAGE_DOS_HEADER *idh = (IMAGE_DOS_HEADER *)(hFilePtr);
	IMAGE_FILE_HEADER       *ifh = (IMAGE_FILE_HEADER *)((DWORD)(idh) + idh->e_lfanew + sizeof(DWORD));
	IMAGE_OPTIONAL_HEADER   *ioh = (IMAGE_OPTIONAL_HEADER *)((DWORD)(ifh) + sizeof(IMAGE_FILE_HEADER));

	//Get Last Section
	IMAGE_SECTION_HEADER *ish = (IMAGE_SECTION_HEADER *)( ((DWORD)(ioh) + ifh->SizeOfOptionalHeader) + ((ifh->NumberOfSections-1) * sizeof(IMAGE_SECTION_HEADER)) );

#ifdef DEBUG
			Log("Last Section Name = %s, Phy RVA = 0x%.8X, Phy Size = 0x%.8X, Vir RVA = 0x%.8X, Vir Size = 0x%.8X", ish->Name, ish->PointerToRawData, ish->SizeOfRawData, ish->VirtualAddress, ish->Misc.VirtualSize);
#endif
	if(strcmp(".garr", (char *)ish->Name) == 0)
	{
		//Check if OEP resides within this section
		if((DWORD)ioh->AddressOfEntryPoint >= ish->VirtualAddress && 
			(DWORD)ioh->AddressOfEntryPoint <= (DWORD)(ish->VirtualAddress+ish->Misc.VirtualSize))
		{	
			IMAGE_SECTION_HEADER *ish = (IMAGE_SECTION_HEADER *)((DWORD)(ioh) + ifh->SizeOfOptionalHeader);

			dwFirstVA = ish->VirtualAddress;
			dwFirstSize = ish->Misc.VirtualSize;
			bRet = true;
		}
		else
		{
#ifdef DEBUG
			Log("Possible new protection of GameHouse!!!");
#endif
		}
	}

CLEANUP:
	CloseMapping(&hFile, &hFileMap, &hFilePtr);
	return bRet;
}

void CGameHouseUnpacker::Unpack()
{
#ifdef DEBUG
	Log("CGameHouseUnpacker::Unpack()");
#endif
	DWORD dwThreadID;

	if(bUnpacking) //Are we unpacking?
	{
		Log("Unpacking already in progress");
		return;
	}
	Log("Unpacking ...");
	bUnpacking = true;
	dwThreadHandle = CreateThread(NULL, NULL, &CGameHouseUnpacker::UnpackThread, (void*)this, 0, &dwThreadID);
}

DWORD CGameHouseUnpacker::UnpackThread(void * pthis)
{
#ifdef DEBUG
	Log("CGameHouseUnpacker::UnpackThread()");
#endif
	//Add your Code Here

	CGameHouseUnpacker *pt = (CGameHouseUnpacker *) pthis;

	//Unpacking routine
	TryEnterCriticalSection(&pt->lpInternalCS);

	//Make sure executable exists
	if(!bFileExists(cExeFileName))
	{
		Log("Please make sure file %s exists.", cExeFileNameOnly);
		LeaveCriticalSection(&pt->lpInternalCS);
		goto FAILED;
	}

	//Debug process to extract OEP
	DEBUG_EVENT DebugEv;                   // debugging event information 
	DWORD dwContinueStatus = DBG_CONTINUE; // exception continuation 
	bool bExit = false;
	DWORD oldProtect;
	DWORD dwImageBase = 0;
	DWORD dwOEP = 0;

	ZeroMemory( &pt->si, sizeof(pt->si) );
    pt->si.cb = sizeof(pt->si);
	pt->si.wShowWindow = TRUE;
    ZeroMemory( &pt->pi, sizeof(pt->pi) );
	//Open process in debug mode
	if(!CreateProcess(cExeFileName, NULL, NULL, NULL, FALSE, DEBUG_PROCESS|DEBUG_ONLY_THIS_PROCESS, NULL, cTargetDirectory, &pt->si, &pt->pi))
	{
#ifdef DEBUG
		Log("Failed to create process to debug");
#endif
		goto CLEANUP;
	}
	LeaveCriticalSection(&pt->lpInternalCS);

	Log("Please click the Play Now button");
	//Watch for debug events
	while(!bExit)
	{
		TryEnterCriticalSection(&pt->lpInternalCS);
		DWORD dwContinueStatus = DBG_EXCEPTION_NOT_HANDLED;
		WaitForDebugEvent(&DebugEv, INFINITE);
		switch (DebugEv.dwDebugEventCode) 
		{
			case EXCEPTION_DEBUG_EVENT: 
            switch(DebugEv.u.Exception.ExceptionRecord.ExceptionCode)
            { 
				case EXCEPTION_GUARD_PAGE:
				{
#ifdef DEBUG
					Log("OEP at = 0x%.8X", DebugEv.u.Exception.ExceptionRecord.ExceptionAddress);
#endif
					dwOEP = (DWORD)DebugEv.u.Exception.ExceptionRecord.ExceptionAddress;
					TerminateProcess(pt->pi.hProcess, 1);
					dwContinueStatus = DBG_CONTINUE;
				}
					break;

                case EXCEPTION_ACCESS_VIOLATION:
				{
#ifdef DEBUG
					Log("Access Violation : 0x%.8X", DebugEv.u.Exception.ExceptionRecord.ExceptionAddress);
#endif
					bExit = true;
					LeaveCriticalSection(&pt->lpInternalCS);
				}
                    continue;
 
                case EXCEPTION_BREAKPOINT:
				{
					dwContinueStatus = DBG_CONTINUE;
#ifdef DEBUG
					Log("Breakpoint : 0x%.8X", DebugEv.u.Exception.ExceptionRecord.ExceptionAddress);
#endif
				}
                    break;
            }
			break;

			case CREATE_PROCESS_DEBUG_EVENT: 
			{
				CREATE_PROCESS_DEBUG_INFO cpdi = DebugEv.u.CreateProcessInfo;
#ifdef DEBUG
				Log("Create Process OEP=%.8X (ImageBase=%.8X)", cpdi.lpStartAddress, cpdi.lpBaseOfImage);
#endif

				HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pt->pi.dwProcessId);
				if(hProcess == NULL)
				{
#ifdef DEBUG
					Log("Failed to OpenProcess for PAGE_GUARD");
#endif
					bExit = true;
					LeaveCriticalSection(&pt->lpInternalCS);
					continue;
				}

				/* Remove access protection */
				DWORD dwSectionVA = (DWORD)cpdi.lpBaseOfImage + pt->dwFirstVA;
				dwImageBase = (DWORD)cpdi.lpBaseOfImage;
				if (!VirtualProtectEx(hProcess, (LPVOID)(dwSectionVA), pt->dwFirstSize, PAGE_READONLY|PAGE_GUARD, &oldProtect))
				{
#ifdef DEBUG
					Log("Failed to set PAGE_GUARD on section");
#endif
					bExit = true;
				}
				else
				{
#ifdef DEBUG
					Log("PAGE_GUARD Set! 0x%.8X (%d)", dwSectionVA, pt->dwFirstSize);
#endif
				}
				CloseHandle(hProcess);
			}
				break;
 
			case EXIT_PROCESS_DEBUG_EVENT: 
#ifdef DEBUG
				Log("Process Terminating");
#endif
				bExit = true;
				//Stop Debug or we cant write to file
				DebugActiveProcessStop(pt->pi.dwProcessId);
				LeaveCriticalSection(&pt->lpInternalCS);
				continue;
		}
		LeaveCriticalSection(&pt->lpInternalCS);
		ContinueDebugEvent(DebugEv.dwProcessId, DebugEv.dwThreadId, dwContinueStatus);
	}

	//Set OEP to File
	Sleep(100);
	TryEnterCriticalSection(&pt->lpInternalCS);
	//Check if OEP = 0
	if(dwOEP == 0){
#ifdef DEBUG
		Log("OEP is empty");
#endif
		LeaveCriticalSection(&pt->lpInternalCS);
		goto FAILED;
	}

	DWORD dwFileEP = dwOEP - dwImageBase;
#ifdef DEBUG
	Log("FileEP = 0x%.8X", dwFileEP);
#endif

	//Write new EP
	HANDLE hFile, hFileMap;
	LPVOID hFilePtr;

	if(!bOpenForMapping(cExeFileName, &hFile, &hFileMap, &hFilePtr, MAP_READWRITE))
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

void CGameHouseUnpacker::Abort()
{
#ifdef DEBUG
	Log("CGameHouseUnpacker::Abort()");
#endif
	TryEnterCriticalSection(&lpInternalCS);
	SuspendThread(dwThreadHandle);
	TerminateThread(dwThreadHandle, 1);
	LeaveCriticalSection(&lpInternalCS);
	Cleanup();
	Log("Aborting Complete!");
}

void CGameHouseUnpacker::Cleanup()
{
#ifdef DEBUG
	Log("CGameHouseUnpacker::Cleanup()");
#endif

	TryEnterCriticalSection(&lpInternalCS);
	//Add your Code Here

	if(pi.hProcess != 0)
		TerminateProcess(pi.hProcess, 0);

	if(dwThreadHandle != NULL)
	{
		CloseHandle(dwThreadHandle);
		dwThreadHandle = NULL;
	}
	bUnpacking = false;
	ResetButtons();
	LeaveCriticalSection(&lpInternalCS);
}
