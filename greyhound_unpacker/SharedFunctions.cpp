#include "SharedFunctions.h"
#include "..\greyhound_hook\greyhound_hook.h"

extern char cExeFileName[DEF_MAXPATH];
extern char cExeFileNameOnly[DEF_MAXPATH];

//Functions used throughout app
bool bFileExists(char *cFileName)
{
	HANDLE hFile = CreateFile(cFileName, NULL, NULL, NULL, OPEN_EXISTING, NULL, NULL);
	if(hFile == INVALID_HANDLE_VALUE){
#ifdef DEBUG
		Log("Unable to locate file %s", cFileName);
#endif
		return false;
	}
	CloseHandle(hFile);
#ifdef DEBUG
	Log("File %s Found", cFileName);
#endif
	return true;
}

/******************************************************
*
* Gets the details of a procces's module
* Thank you Microsoft for this code
*
*******************************************************/
bool bGetProccessModule(DWORD dwPID, char *cModuleName, MODULEENTRY32 &ret_me32)
{

HANDLE hModuleSnap = INVALID_HANDLE_VALUE;
MODULEENTRY32 me32;

	//Basic checking
	if(dwPID == 0 || (char *)cModuleName == NULL) return false;

	// Take a snapshot of all modules in the specified process.
	hModuleSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, dwPID);
	if(hModuleSnap == INVALID_HANDLE_VALUE)
		return false;

	// Set the size of the structure before using it.
	me32.dwSize = sizeof(MODULEENTRY32);

	// Retrieve information about the first module,
	// and exit if unsuccessful
	if( !Module32First(hModuleSnap, &me32))
	{
		CloseHandle(hModuleSnap);     // Must clean up the snapshot object!
		return false;
	}

	// Now walk the module list of the process,
	// and display information about each module
	do
	{
		if(lstrcmpi(cModuleName, me32.szModule) == 0){
			//Copy data over
			memcpy(&ret_me32, &me32, sizeof(MODULEENTRY32));
			CloseHandle(hModuleSnap);
			return true;
		}
	} while(Module32Next(hModuleSnap, &me32 ));

	//Cleanup
	CloseHandle(hModuleSnap);

	//If we are here it means nothing was found
	return false;
}

//Logging function
void Log(char* fmt, ...)
{
	va_list list;

	TryEnterCriticalSection(&lpCriticalSection);
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
	LeaveCriticalSection(&lpCriticalSection);

}

void ResetButtons()
{
	SetWindowText(g_hBtnUnpack, "Unpack");
}

bool InjectDLLHook(int PROD_TYPE, DWORD dwProcessId, STARTUPINFO &si, PROCESS_INFORMATION &pi)
{
#ifdef DEBUG
	Log("InjectDLLHook()");
#endif
	void*   pLibRemote=NULL;
	HANDLE hProcess=NULL;
	HANDLE hThread=NULL;
	HMODULE hKernel32= NULL;
	MODULEENTRY32 loader_me32;

	ZeroMemory(&si, sizeof(STARTUPINFO));
    si.cb = sizeof(si);
	si.wShowWindow = SW_SHOW;
    ZeroMemory(&pi, sizeof(PROCESS_INFORMATION));

	//Create game loader
#ifdef DEBUG
	Log("Loading Game Loader");
#endif
	CreateProcess(cExeFileName, NULL, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi);
	Sleep(300);	//Give it some time to load

#ifdef DEBUG
	Log("Retrieving Game Loader Information");
#endif
	bool bRet = bGetProccessModule(pi.dwProcessId, cExeFileNameOnly, loader_me32);
	if(!bRet)
	{
		Log("Unable to get game loader information...terminating game");
		TerminateProcess(pi.hProcess, 0);
		return false;
	}

#ifdef DEBUG
	Log("Game Loader Base : 0x%.8x", (DWORD)loader_me32.modBaseAddr);
#endif
	//Pass whatever info we need to DLL here
	SetBasicInformation(g_hWndLog, PROD_TYPE, cExeFileName, (DWORD)loader_me32.modBaseAddr, pi.dwProcessId);

	hKernel32 = GetModuleHandle("Kernel32.dll");
	if(hKernel32 == NULL)
	{
#ifdef DEBUG
		Log("InjectDLLHook(): GetModuleHandle Failed!");
#endif
		return false;
	}

	hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pi.dwProcessId);
	if(hProcess == NULL)
	{
#ifdef DEBUG
		Log("InjectDLLHook(): OpenProcess Failed!");
#endif
		return false;
	}
	//Inject hook
	pLibRemote = VirtualAllocEx(hProcess, NULL, sizeof(cFullHookPath), MEM_COMMIT, PAGE_READWRITE);
	if(pLibRemote == NULL)
	{
#ifdef DEBUG
		Log("InjectDLLHook(): VirtualAllocEx Failed!");
#endif
		return false;
	}
	WriteProcessMemory(hProcess, pLibRemote, (void*)cFullHookPath, sizeof(cFullHookPath), NULL);
#ifdef DEBUG
		Log("Injecting %s Into Game Loader", cHookName);
#endif

	hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE) GetProcAddress(hKernel32, "LoadLibraryA"), pLibRemote, 0, NULL);
	if(hThread == NULL)
	{
#ifdef DEBUG
		Log("InjectDLLHook(): CreateRemoteThread Failed!");
#endif
		CloseHandle(hProcess);
		return false;
	}
	WaitForSingleObject(hThread, INFINITE);
	// Clean up
	CloseHandle(hThread);
	VirtualFreeEx(hProcess, (void*)pLibRemote, sizeof(cFullHookPath), MEM_RELEASE);
	CloseHandle(hProcess);
#ifdef DEBUG
		Log("InjectDLLHook(): Injection Successful!");
#endif
	return true;
}

bool bOpenForMapping(char *cFileToMap, HANDLE *hFile, HANDLE *hFileMap, LPVOID *hFilePtr, int MapMode)
{
	if(hFile == NULL || hFileMap == NULL || hFilePtr == NULL)
	{
#ifdef DEBUG
		Log("bOpenForMapping Failed due to NULL pointer");
#endif
		return false;
	}
	*hFile = *hFileMap = *hFilePtr = NULL;

	//Check if Exe's last sections RawAddr+RawSize > Total file size
	if(MapMode == MAP_READWRITE)
		*hFile = CreateFile(cFileToMap, GENERIC_READ+GENERIC_WRITE, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	else
		*hFile = CreateFile(cFileToMap, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	
	if(hFile == INVALID_HANDLE_VALUE)
	{
		Log("Unable to open file %s (CreateFile)", cFileToMap);
		return false;
	}

	if(MapMode == MAP_READWRITE)
		*hFileMap = CreateFileMapping(*hFile, NULL, PAGE_READWRITE, 0, 0, NULL);
	else
		*hFileMap = CreateFileMapping(*hFile, NULL, PAGE_READONLY, 0, 0, NULL);
	if(*hFileMap == NULL)
	{
		Log("Unable to open file %s (CreateFileMapping)", cFileToMap);
		CloseHandle(*hFile);
		*hFile = NULL;
		return false;
	}

	if(MapMode == MAP_READWRITE)
		*hFilePtr = MapViewOfFile(*hFileMap, FILE_MAP_READ+FILE_MAP_WRITE, 0, 0, 0);
	else
		*hFilePtr = MapViewOfFile(*hFileMap, FILE_MAP_READ, 0, 0, 0);

	if(*hFilePtr == NULL)
	{
		Log("Unable to map file %s (MapViewOfFile)", cFileToMap);
		CloseHandle(*hFileMap);
		CloseHandle(*hFile);
		*hFileMap = NULL;
		*hFile = NULL;
		return false;
	}

	return true;
}

void CloseMapping(HANDLE *hFile, HANDLE *hFileMap, LPVOID *hFilePtr)
{
	if(*hFilePtr != NULL)
	{
		UnmapViewOfFile(*hFilePtr);
		*hFilePtr = NULL;
	}
	if(*hFileMap != NULL)
	{
		CloseHandle(*hFileMap);
		*hFileMap = NULL;
	}
	if(*hFile != NULL)
	{
		CloseHandle(*hFile);
		*hFile = NULL;
	}
}