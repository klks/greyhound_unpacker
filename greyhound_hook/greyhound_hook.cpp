// greyhound_hook.cpp : Defines the entry point for the DLL application.
//
#include "stdafx.h"
#include "greyhound_hook.h"

#ifdef _MANAGED
#pragma managed(push, off)
#endif

#pragma data_seg(".KLKS")
//Global stuff
DWORD dwLoaderBase=0;
DWORD dwLoaderPID=0;
HWND g_hWndLog=NULL;
char gLoaderName[DEF_MAXPATH]={0};
char gTempFileName[DEF_MAXPATH]={0};
bool bUnpackedFailed=false;
bool bUnpacked=false;
bool bAbortUnpacking=false;
int iUnpackerToDeploy=0;
DWORD dwChildPid=0;

//Define stuff for reflexive
BYTE bReadBuffer[10]={0};

//Define stuff for alawar
DWORD Ala_dwFileEP=0;
#pragma data_seg()

#pragma comment(linker, "/section:.KLKS,RWS")

//Global Variables
//API HOOK STRUCTURES
stAPIPtr apiCreateProcessA;
stAPIPtr apiWriteProcessMemory;
stAPIPtr apiReadProcessMemory;
stAPIPtr apiResumeThread;
char cTargetDirectory[DEF_MAXPATH];

//Used by Reflexive
char cChildFileName[DEF_MAXPATH];
char cNewChildFileName[DEF_MAXPATH+20];	//No BO today plis
bool bReadProcessMemory_Called = false;
DWORD dwReadAddress;
DWORD dwReadSize;

BOOL APIENTRY DllMain( HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
		if(dwLoaderBase != 0)
		{
#ifdef DEBUG
			Log("Preparing To Install Hooks");
#endif
			InstallHooks();
		}
		break;
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
		break;
	case DLL_PROCESS_DETACH:
		break;
	}
    return TRUE;
}

#ifdef _MANAGED
#pragma managed(pop)
#endif

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// INTERNAL FUNCTIONS CODE START
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

//Logging function
void Log(char* fmt, ...)
{
	va_list list;

	if(g_hWndLog == NULL) return;

	//Allocate some memory to use
	HGLOBAL hMem = GlobalAlloc(GPTR, 20000);	//About 20kb
	if(hMem == NULL){
		if(g_hWndLog != NULL)
		SendMessage(g_hWndLog, LB_ADDSTRING, 0, (LPARAM)"Log() : Failed to allocate memory");
		return;
	}

	va_start(list, fmt);
	//Format
	wvsprintf((LPSTR)hMem, fmt,list);

	SendMessage(g_hWndLog,LB_ADDSTRING,0,(LPARAM)hMem);
	//Highlight Last Active Message
	SendMessage(g_hWndLog,LB_SETCURSEL,SendMessage(g_hWndLog,LB_GETCOUNT,0,0)-1,0);

	//Cleanup
	va_end(list);
	GlobalFree(hMem);
}

void InstallHooks()
{
	bUnpacked = false;
	//Extract target directory
	ZeroMemory(gTempFileName, sizeof(gTempFileName));
	char *pdest = strrchr((char*)gLoaderName, '\\');
	int nPos = (int)(pdest - gLoaderName + 1);
	strcpy(cTargetDirectory, gLoaderName);
	cTargetDirectory[nPos] = 0;

	if(iUnpackerToDeploy == PROD_REFLEXIVE)
		InstallReflexiveHooks();
	else if(iUnpackerToDeploy == PROD_ALAWAR)
		InstallAlawarHooks();
}

//HOOKS FOR DLL APIS
bool HookDllFunction(char *cDllName, char *cHookFunctionName, DWORD dwMyFunctionPtr, stAPIPtr *apiPtr)
{
	static HMODULE	hDllModule = NULL;
	static IMAGE_DOS_HEADER			*idh = NULL;
	static IMAGE_FILE_HEADER		*ifh = NULL;
	static IMAGE_OPTIONAL_HEADER	*ioh = NULL;
	static IMAGE_EXPORT_DIRECTORY	*ied = NULL;
	static DWORD *cNamePtr = NULL;
	static DWORD *cFuncPtr = NULL;

	if(apiPtr->bDLLFound) return false;

	//To save cycles, check if its already resolved
	HMODULE hTmpMod = GetModuleHandle(cDllName);
	if(!hDllModule || hDllModule != hTmpMod){
		hDllModule = hTmpMod;
		if (!hDllModule) 
		{
			hDllModule = LoadLibrary(cDllName);
			if (!hDllModule) return false;
		}
		idh = (IMAGE_DOS_HEADER *)(hDllModule);
		ifh = (IMAGE_FILE_HEADER *)((DWORD)(idh) + (idh)->e_lfanew + sizeof(DWORD));
		ioh = (IMAGE_OPTIONAL_HEADER *)((DWORD)(ifh) + sizeof(IMAGE_FILE_HEADER));
		ied	= (IMAGE_EXPORT_DIRECTORY *)((DWORD)(idh) + ioh->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
		cNamePtr = (DWORD *)((DWORD)idh + ied->AddressOfNames);
		cFuncPtr = (DWORD *)((DWORD)idh + ied->AddressOfFunctions);
	}

	DWORD oldProtect;
	/* Remove access protection */
	if (!VirtualProtect((LPVOID)((DWORD)(idh) + ioh->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress), ioh->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size, PAGE_READWRITE, &oldProtect))
	{
		return false;
	}

	for(int i=0; i < ied->NumberOfNames; i++)
	{
		if(!lstrcmpi(cHookFunctionName, (char *) (DWORD)(idh) + *(cNamePtr + i))){
			//Check if this patch is our
			DWORD ptrAPI = (DWORD)dwMyFunctionPtr - (DWORD)idh;
			DWORD *dwOrgAPI = cFuncPtr + i;
			if(ptrAPI != *dwOrgAPI){
				//Save original hook
				apiPtr->dwOrgFnAddr = *dwOrgAPI;
				*dwOrgAPI = ptrAPI;
				apiPtr->bDLLFound = true;
			}
			break;
		}
	}

	/* Put access protection back on */
	if (!VirtualProtect((LPVOID)((DWORD)(idh) + ioh->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress), ioh->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size, oldProtect, &oldProtect))
	{
		return false;
	}

	return apiPtr->bDLLFound;
}

//HOOKS FOR IAT APIS
void HookApiFunction(char *cFindAPI, DWORD MyIAT ,stAPIPtr *iatPtr, IMAGE_IMPORT_BY_NAME *API_NAME, IMAGE_THUNK_DATA *pThunk2)
{
	if(!lstrcmpi(cFindAPI, (char *)API_NAME->Name)){
		if(!iatPtr->bIATFound){
			iatPtr->bIATFound = true;
#ifdef DEBUG
			Log("APIHOOK : %s", API_NAME->Name);
#endif
			//Hook function
			iatPtr->pOrgThunk = pThunk2;
			iatPtr->dwOrgIATPtr = pThunk2->u1.Function;
			pThunk2->u1.Function = (DWORD)MyIAT;
		}
		else{	//Omg 2 API's??
#ifdef DEBUG
			Log("APIHOOK : %s (DUPLICATE FOUND)", API_NAME->Name);
#endif
		}
	}
}

DWORD GetProcessBase(DWORD dwPID, char* cProcessName)
{
	HANDLE hModuleSnap = INVALID_HANDLE_VALUE;
	MODULEENTRY32 me32;

	hModuleSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, dwPID);
	if(hModuleSnap == INVALID_HANDLE_VALUE)
	{
#ifdef DEBUG
		Log("CreateToolhelp32Snapshot (of modules) Failed!");
#endif
		return 0;
	}

	DWORD dwBaseAddr = 0;

	// Set the size of the structure before using it.
	me32.dwSize = sizeof( MODULEENTRY32 );

	// Retrieve information about the first module,
	// and exit if unsuccessful
	if( !Module32First( hModuleSnap, &me32 ) )
	{
#ifdef DEBUG
		Log( "Module32First Failed!");  // Show cause of failure
#endif
		CloseHandle(hModuleSnap);     // Must clean up the snapshot object!
		return 0;
	}

	// Now walk the module list of the process,
	// and display information about each module
	do
	{
		if(strcmp(cProcessName, me32.szModule) == 0)
		{
#ifdef DEBUG
			Log("PID = %d BaseAddr = 0x%.8X (%s)", dwPID, me32.modBaseAddr, me32.szModule);
#endif
			dwBaseAddr = (DWORD) me32.modBaseAddr;
			break;
		}
	} while( Module32Next( hModuleSnap, &me32 ) );

	CloseHandle( hModuleSnap );

	return dwBaseAddr;
}

void KillSelf()
{
	HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwLoaderPID);
	if(hProc != NULL)
	{
#ifdef DEBUG
		Log("Terminating Loader Process [PID=%d]", dwLoaderPID);
#endif
		TerminateProcess(hProc, 0);
	}
}
void KillChild()
{
	if(dwChildPid != NULL){
		HANDLE hChild = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwChildPid);
		if(hChild != NULL)
		{
#ifdef DEBUG
			Log("Terminating Child Process [PID=%d]", dwChildPid);
#endif
			TerminateProcess(hChild, 0);
		}
		dwChildPid = NULL;
	}
}

bool bMakeTempFile(char *RecvBuff)
{
	if(GetTempFileName(cTargetDirectory, "ghu", 0, RecvBuff) == 0)
	{
#ifdef DEBUG
		Log("Call to GetTempFileName Failed!");
#endif
		return false;
	}
	return true;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// INTERNAL FUNCTIONS CODE END
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// GENERAL EXPORTED FUNCTIONS CODE START
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

GREYHOUND_HOOK_API void SetBasicInformation(HWND hLogWnd, int iUseUnpacker, char* cLoaderName, DWORD dwBaseAddress, DWORD dwGameLoaderPID)
{
#ifdef DEBUG
			Log("SetBasicInformation()");
#endif
	g_hWndLog = hLogWnd;
	iUnpackerToDeploy = iUseUnpacker;
	strncpy(gLoaderName, cLoaderName, sizeof(gLoaderName));
	dwLoaderPID = dwGameLoaderPID;
	//Copy this last
	dwLoaderBase = dwBaseAddress;
}

GREYHOUND_HOOK_API bool GetUnpackStatus()
{
	return bUnpacked;
}

GREYHOUND_HOOK_API bool bUnpackFailed()
{
	return bUnpackedFailed;
}

GREYHOUND_HOOK_API void AbortUnpacking()
{
	bAbortUnpacking = true;
}

GREYHOUND_HOOK_API BOOL bCheckOEPBytes(BYTE *bPtrOEP)
{
	for(int i=0; i<5; i++){
		if(bPtrOEP[i] != bReadBuffer[i])
			return false;
	}
	return true;
}

GREYHOUND_HOOK_API void DLLFailedCleanup()
{
	bUnpackedFailed = true;
	bUnpacked = true;

	KillChild();
	KillSelf();
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// GENERAL EXPORTED FUNCTIONS CODE END
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// REFLEXIVE ARCADE CODE START
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//85 ? 0F 84 ? ? ? ? 6A 49 AOB for new? reflexive games?
//need to add S&R for games like AirportMania, need to sample afew more games
//with the same protection to ensure AOB is consistent

void InstallReflexiveHooks()
{
#ifdef DEBUG
			Log("Deploying Reflexive Arcade Hooks");
#endif
	
	DWORD PELocation = 0; SIZE_T nbytes = 0;
	IMAGE_DOS_HEADER *idh = (IMAGE_DOS_HEADER *)(GetModuleHandle(gLoaderName));
	if (!idh || (DWORD)idh != dwLoaderBase)
	{
		Log("Unable to locate game or base address mismatch");
#ifdef DEBUG
		Log("Expected Base = 0x%.8X Presented Base = 0x%.8X", (DWORD)idh, dwLoaderBase);
		Log("Terminating Process [PID=%d]", dwLoaderPID);
#endif
		DLLFailedCleanup();
		return;
	}

	//Walk to OEP
	IMAGE_FILE_HEADER       *ifh = (IMAGE_FILE_HEADER *)((DWORD)(idh) + idh->e_lfanew + sizeof(DWORD));
	IMAGE_OPTIONAL_HEADER   *ioh = (IMAGE_OPTIONAL_HEADER *)((DWORD)(ifh) + sizeof(IMAGE_FILE_HEADER));
	IMAGE_IMPORT_DESCRIPTOR *iid = (IMAGE_IMPORT_DESCRIPTOR *)((DWORD)(idh) + ioh->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
	DWORD oldProtect;

	/* Remove access protection */
	if (!VirtualProtect((LPVOID)((DWORD)(idh) + ioh->DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].VirtualAddress), ioh->DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].Size, PAGE_READWRITE, &oldProtect))
	{
#ifdef DEBUG
		Log("VirtualProtect Failed to set PAGE_READWRITE to IAT");
#endif
		DLLFailedCleanup();
		return;
	}

	//Clear structures before using them
	memset(&apiCreateProcessA, 0, sizeof(apiCreateProcessA));
	memset(&apiWriteProcessMemory, 0, sizeof(apiWriteProcessMemory));
	memset(&apiReadProcessMemory, 0, sizeof(apiReadProcessMemory));

	/* Lets hook up all the functions we need */
	while (iid->Name) {
		if(!lstrcmpi("Kernel32.dll", (char *)((DWORD)(idh) + iid->Name))){
			IMAGE_THUNK_DATA *pThunk = (IMAGE_THUNK_DATA *)((DWORD)(idh) + (DWORD)iid->OriginalFirstThunk);
			IMAGE_THUNK_DATA *pThunk2 = (IMAGE_THUNK_DATA *)((DWORD)(idh) + (DWORD)iid->FirstThunk);
			
			while(pThunk->u1.Ordinal) {
				IMAGE_IMPORT_BY_NAME *API_NAME = (IMAGE_IMPORT_BY_NAME *)((DWORD)(idh) + (DWORD)pThunk->u1.AddressOfData);

				//HOOK START
				HookApiFunction("CreateProcessA", (DWORD)Reflexive_MyCreateProcessA, &apiCreateProcessA, API_NAME, pThunk2);
				HookApiFunction("WriteProcessMemory", (DWORD)Reflexive_MyWriteProcessMemory, &apiWriteProcessMemory, API_NAME, pThunk2);
				HookApiFunction("ReadProcessMemory", (DWORD)Reflexive_MyReadProcessMemory, &apiReadProcessMemory, API_NAME, pThunk2);
				//HOOK END

				pThunk++;
				pThunk2++;
			}
		}
		iid++;
	}

	/* Put access protection back on */
	if (!VirtualProtect((LPVOID)((DWORD)(idh) + ioh->DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].VirtualAddress), ioh->DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].Size, oldProtect, &oldProtect))
	{
#ifdef DEBUG
		Log("VirtualProtect Failed to set old state back to IAT");
#endif
		DLLFailedCleanup();
		return;
	}
}

BOOL WINAPI Reflexive_MyCreateProcessA(LPCTSTR lpApplicationName, LPTSTR lpCommandLine, LPSECURITY_ATTRIBUTES lpProcessAttributes,
					 LPSECURITY_ATTRIBUTES lpThreadAttributes, BOOL bInheritHandles, DWORD dwCreationFlags,
					 LPVOID lpEnvironment, LPCTSTR lpCurrentDirectory, LPSTARTUPINFO lpStartupInfo,
					 LPPROCESS_INFORMATION lpProcessInformation)
{

	//Call real API and store results
	BOOL bRet = CreateProcess(lpApplicationName, lpCommandLine, lpProcessAttributes, lpThreadAttributes, bInheritHandles, dwCreationFlags, lpEnvironment, lpCurrentDirectory, lpStartupInfo, lpProcessInformation);

	if(dwChildPid == NULL)
	{
		//Clear out placeholder
		ZeroMemory(cChildFileName, sizeof(cChildFileName));
		ZeroMemory(cNewChildFileName, sizeof(cNewChildFileName));
		//Copy new data over
		strncpy(cChildFileName, lpApplicationName, sizeof(cChildFileName));
		strncpy(cNewChildFileName, cChildFileName, sizeof(cNewChildFileName));
		strcat(cNewChildFileName, ".dmp");
		dwChildPid = lpProcessInformation->dwProcessId;

#ifdef DEBUG
	Log("HOOK : CreateProcess Called (%s) [PID=%d]", lpApplicationName, dwChildPid);
#endif
	}
	return bRet;
}

BOOL WINAPI Reflexive_MyWriteProcessMemory(HANDLE hProcess, LPVOID lpBaseAddress, LPCVOID lpBuffer, SIZE_T nSize, SIZE_T* lpNumberOfBytesWritten)
{
DWORD lpWritten;

#ifdef DEBUG
	Log("WriteProcessMemory Called, Address: 0x%.8X Size: 0x%.8X", (DWORD)lpBaseAddress, (DWORD)nSize);
#endif
	if(!bReadProcessMemory_Called){
#ifdef DEBUG
		Log("WriteProcessMemory called before ReadProcessMemory, Possible new version?");
#endif
		DLLFailedCleanup();
	}

	if((DWORD)lpBaseAddress != dwReadAddress && nSize != dwReadSize){
#ifdef DEBUG
		Log("WriteProcessMemory offsets/size differ from ReadProcessMemory, Possible new version?");
#endif
		DLLFailedCleanup();
	}

	//Terminate child process, we dont need it anymore
	KillChild();

	//Dump memory to disk
	DeleteFile(cNewChildFileName);	//Delete if theres one
#ifdef DEBUG
	Log("Deleting old %s if one exists", cNewChildFileName);
#endif

	HANDLE hFile = CreateFile(cNewChildFileName, GENERIC_WRITE, 0, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if(hFile == INVALID_HANDLE_VALUE){
#ifdef DEBUG
		Log("Unable open file %s for writing", cNewChildFileName);
#endif
		DLLFailedCleanup();
	}

	//Copy data over to temp file
	WriteFile(hFile, lpBuffer, nSize, &lpWritten, NULL);

	//Cleanup
	CloseHandle(hFile);
#ifdef DEBUG
	Log("Dumped memory at 0x%.8X with a size of 0x%.8X to %s [Write Offset = 0x%.8X]",\
		(DWORD)lpBuffer, nSize, cNewChildFileName, lpBaseAddress);
#endif

	bUnpacked = true;
	//Ok now we die
	KillSelf();

	return false;
}

BOOL WINAPI Reflexive_MyReadProcessMemory(HANDLE hProcess, LPCVOID lpBaseAddress, LPVOID lpBuffer, SIZE_T nSize, SIZE_T* lpNumberOfBytesRead)
{
	//Store information
	bReadProcessMemory_Called = true;
	dwReadAddress = (DWORD)lpBaseAddress;
	dwReadSize = nSize;

#ifdef DEBUG
	Log("ReadProcessMemory Called, Address: 0x%.8X Size: 0x%.8X", dwReadAddress, dwReadSize);
#endif

	//Call real API
	BOOL bRet = ReadProcessMemory(hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesRead);
	memcpy(bReadBuffer, lpBuffer, 10);

	//Log first 5 bytes
#ifdef DEBUG
	Log("HOOK : ReadProcessMemory First 5 Bytes %.2X %.2X %.2X %.2X %.2X",\
		bReadBuffer[0], bReadBuffer[1], bReadBuffer[2], bReadBuffer[3], bReadBuffer[4]);
#endif
	return bRet;
}
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// REFLEXIVE ARCADE CODE END
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// ALAWAR CODE START
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

GREYHOUND_HOOK_API DWORD Alawar_GetFileEP()
{
	return Ala_dwFileEP;
}

void InstallAlawarHooks()
{
#ifdef DEBUG
			Log("Deploying Alawar Hooks");
#endif

	DWORD PELocation = 0; SIZE_T nbytes = 0;
	IMAGE_DOS_HEADER *idh = (IMAGE_DOS_HEADER *)(GetModuleHandle("wrapper.dll"));
	if (!idh)
	{
		Log("Unable to locate wrapper module");
#ifdef DEBUG
		Log("Terminating Process [PID=%d]", dwLoaderPID);
#endif
		DLLFailedCleanup();
		return;
	}

	//Walk to OEP
	IMAGE_FILE_HEADER       *ifh = (IMAGE_FILE_HEADER *)((DWORD)(idh) + idh->e_lfanew + sizeof(DWORD));
	IMAGE_OPTIONAL_HEADER   *ioh = (IMAGE_OPTIONAL_HEADER *)((DWORD)(ifh) + sizeof(IMAGE_FILE_HEADER));
	IMAGE_IMPORT_DESCRIPTOR *iid = (IMAGE_IMPORT_DESCRIPTOR *)((DWORD)(idh) + ioh->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
	DWORD oldProtect;

	/* Remove access protection */
	if (!VirtualProtect((LPVOID)((DWORD)(idh) + ioh->DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].VirtualAddress), ioh->DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].Size, PAGE_READWRITE, &oldProtect))
	{
#ifdef DEBUG
		Log("VirtualProtect Failed to set PAGE_READWRITE to IAT");
#endif
		DLLFailedCleanup();
		return;
	}

	//Clear structures before using them
	memset(&apiCreateProcessA, 0, sizeof(apiCreateProcessA));
	memset(&apiWriteProcessMemory, 0, sizeof(apiWriteProcessMemory));

	/* Lets hook up all the functions we need */
	while (iid->Name) {
		if(!lstrcmpi("Kernel32.dll", (char *)((DWORD)(idh) + iid->Name))){
			IMAGE_THUNK_DATA *pThunk = (IMAGE_THUNK_DATA *)((DWORD)(idh) + (DWORD)iid->OriginalFirstThunk);
			IMAGE_THUNK_DATA *pThunk2 = (IMAGE_THUNK_DATA *)((DWORD)(idh) + (DWORD)iid->FirstThunk);
			
			while(pThunk->u1.Ordinal) {
				IMAGE_IMPORT_BY_NAME *API_NAME = (IMAGE_IMPORT_BY_NAME *)((DWORD)(idh) + (DWORD)pThunk->u1.AddressOfData);

				//HOOK START
				HookApiFunction("WriteProcessMemory", (DWORD)Alawar_MyWriteProcessMemory, &apiWriteProcessMemory, API_NAME, pThunk2);
				//HOOK END

				pThunk++;
				pThunk2++;
			}
		}
		iid++;
	}

	/* Put access protection back on */
	if (!VirtualProtect((LPVOID)((DWORD)(idh) + ioh->DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].VirtualAddress), ioh->DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].Size, oldProtect, &oldProtect))
	{
#ifdef DEBUG
		Log("VirtualProtect Failed to set old state back to IAT");
#endif
		DLLFailedCleanup();
		return;
	}

	//Install DLL hook for CreateProcessW
	if(!HookDllFunction("Kernel32.dll", "CreateProcessW", (DWORD)Alawar_MyCreateProcessW, &apiCreateProcessA))
	{
#ifdef DEBUG
		Log("Failed to hook CreateProcessW");
#endif
		DLLFailedCleanup();
	}
}

BOOL WINAPI Alawar_MyCreateProcessW(LPCWSTR lpApplicationName, LPWSTR lpCommandLine, LPSECURITY_ATTRIBUTES lpProcessAttributes,\
									LPSECURITY_ATTRIBUTES lpThreadAttributes, BOOL bInheritHandles, DWORD dwCreationFlags, \
									LPVOID lpEnvironment, LPCWSTR lpCurrentDirectory, LPSTARTUPINFOW lpStartupInfo,\
									LPPROCESS_INFORMATION lpProcessInformation)
{

#ifdef DEBUG
	DWORD dwCalledFrom = 0;
	__asm{
		push eax
		mov eax, dword ptr [ebp+4]
		mov dwCalledFrom, eax
		pop eax
	}
#endif

	//Call real API and store results
	BOOL bRet = CreateProcessW(lpApplicationName, lpCommandLine, lpProcessAttributes, lpThreadAttributes, bInheritHandles, dwCreationFlags, lpEnvironment, lpCurrentDirectory, lpStartupInfo, lpProcessInformation);

	if(dwChildPid == NULL)
	{
		dwChildPid = lpProcessInformation->dwProcessId;

		//Extract Application Name
		ZeroMemory(cChildFileName, sizeof(cChildFileName));

		if(lpCommandLine != NULL)
		{
			WideCharToMultiByte( CP_ACP, 0, lpCommandLine, -1, cNewChildFileName, sizeof(cNewChildFileName), NULL, NULL );
		}
		else if(lpApplicationName != NULL)
		{
			WideCharToMultiByte( CP_ACP, 0, lpApplicationName, -1, cNewChildFileName, sizeof(cNewChildFileName), NULL, NULL );
		}

		char *pdest = strrchr(cNewChildFileName, '\\');
		if(pdest == NULL)
		{
			strncpy(cChildFileName, cNewChildFileName, sizeof(cChildFileName));
		}
		else
		{
			int nPos = (int)(pdest - cNewChildFileName + 1);
			strcpy(cChildFileName, &cNewChildFileName[nPos]);
		}

#ifdef DEBUG
	Log("HOOK : CreateProcess Called (%s) [PID=%d] from 0x%.8X", cChildFileName, dwChildPid, dwCalledFrom);
#endif
	}
	return bRet;
}

BOOL WINAPI Alawar_MyWriteProcessMemory(HANDLE hProcess, LPVOID lpBaseAddress, LPCVOID lpBuffer, SIZE_T nSize, SIZE_T* lpNumberOfBytesWritten)
{
	//Call real WPM so we dont crash
	BOOL bRet = WriteProcessMemory(hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesWritten);

#ifdef DEBUG
	Log("WriteProcessMemory Called, Address: 0x%.8X Size: 0x%.8X", (DWORD)lpBaseAddress, (DWORD)nSize);
#endif

	//Check if the len is 6 bytes
	//push OEP = 68 XX XX XX XX XX
	//ret = C3
	if(nSize != 6)
	{
#ifdef DEBUG
		Log("Expecting WriteProcessMemory to write 6 bytes");
#endif
		DLLFailedCleanup();
	}

	//Extract OEP
	char* cp = (char *)lpBuffer;
	cp++;
	DWORD* dwp = (DWORD*)cp;
	Ala_dwFileEP = *dwp;

	Sleep(100);
	DWORD dwProcessBase = GetProcessBase(GetCurrentProcessId(), cChildFileName);
	if(dwProcessBase == 0)
	{
#ifdef DEBUG
		Log("GetProcessBase Failed");
#endif
		DLLFailedCleanup();
	}
#ifdef DEBUG
	Log("OEP = 0x%.8X, BaseAddr = 0x%.8X", Ala_dwFileEP, dwProcessBase);
#endif
	Ala_dwFileEP -= dwProcessBase;

#ifdef DEBUG
	Log("FileEP = 0x%.8X", Ala_dwFileEP);
#endif

	//Terminate child process, we dont need it anymore
	KillChild();
	bUnpacked = true;
	//Ok now we die
	KillSelf();

	return false;
}
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// ALAWAR CODE END
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////