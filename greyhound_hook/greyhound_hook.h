#pragma once
// The following ifdef block is the standard way of creating macros which make exporting 
// from a DLL simpler. All files within this DLL are compiled with the GREYHOUND_HOOK_EXPORTS
// symbol defined on the command line. this symbol should not be defined on any project
// that uses this DLL. This way any other project whose source files include this file see 
// GREYHOUND_HOOK_API functions as being imported from a DLL, whereas this DLL sees symbols
// defined with this macro as being exported.
#ifdef GREYHOUND_HOOK_EXPORTS
#define GREYHOUND_HOOK_API __declspec(dllexport)
#else
#define GREYHOUND_HOOK_API __declspec(dllimport)
#endif

typedef struct _stAPIPtr
{
	bool bIATFound;		//Marks if we found function in the app's IAT
	bool bDLLFound;		//Marks if we found the function in the DLL
	//Data for items found in app's IAT
	IMAGE_THUNK_DATA *pOrgThunk;
	DWORD dwOrgIATPtr;
	//Data for items found in apps DLL
	DWORD dwOrgFnAddr;
}stAPIPtr;

//Internal Functions
void Log(char* fmt, ...);
void InstallHooks();
bool HookDllFunction(char *cDllName, char *cHookFunctionName, DWORD dwMyFunctionPtr, stAPIPtr *apiPtr);
void HookApiFunction(char *cFindAPI, DWORD MyIAT ,stAPIPtr *iatPtr, IMAGE_IMPORT_BY_NAME *API_NAME, IMAGE_THUNK_DATA *pThunk2);
DWORD GetProcessBase(DWORD dwPID, char* cProcessName);
void KillSelf();
void KillChild();
bool bMakeTempFile(char *RecvBuff);

//Exported Functions
GREYHOUND_HOOK_API void SetBasicInformation(HWND hLogWnd, int iUseUnpacker, char* cLoaderName, DWORD dwBaseAddress, DWORD dwGameLoaderPID);
GREYHOUND_HOOK_API bool GetUnpackStatus();
GREYHOUND_HOOK_API bool bUnpackFailed();
GREYHOUND_HOOK_API void AbortUnpacking();
GREYHOUND_HOOK_API BOOL bCheckOEPBytes(BYTE *bPtrOEP);
GREYHOUND_HOOK_API void DLLFailedCleanup();

//Reflexive Arcade
void InstallReflexiveHooks();
BOOL WINAPI Reflexive_MyCreateProcessA(LPCTSTR lpApplicationName, LPTSTR lpCommandLine, LPSECURITY_ATTRIBUTES lpProcessAttributes,\
					 LPSECURITY_ATTRIBUTES lpThreadAttributes, BOOL bInheritHandles, DWORD dwCreationFlags,\
					 LPVOID lpEnvironment, LPCTSTR lpCurrentDirectory, LPSTARTUPINFO lpStartupInfo,\
					 LPPROCESS_INFORMATION lpProcessInformation);
BOOL WINAPI Reflexive_MyReadProcessMemory(HANDLE hProcess, LPCVOID lpBaseAddress, LPVOID lpBuffer,\
										  SIZE_T nSize, SIZE_T* lpNumberOfBytesRead);
BOOL WINAPI Reflexive_MyWriteProcessMemory(HANDLE hProcess, LPVOID lpBaseAddress, LPCVOID lpBuffer,\
										   SIZE_T nSize, SIZE_T* lpNumberOfBytesWritten);

//Alawar
GREYHOUND_HOOK_API DWORD Alawar_GetFileEP();
void InstallAlawarHooks();
BOOL WINAPI Alawar_MyCreateProcessW(LPCWSTR lpApplicationName, LPWSTR lpCommandLine, LPSECURITY_ATTRIBUTES lpProcessAttributes,\
									LPSECURITY_ATTRIBUTES lpThreadAttributes, BOOL bInheritHandles, DWORD dwCreationFlags, \
									LPVOID lpEnvironment, LPCWSTR lpCurrentDirectory, LPSTARTUPINFOW lpStartupInfo,\
									LPPROCESS_INFORMATION lpProcessInformation);
BOOL WINAPI Alawar_MyWriteProcessMemory(HANDLE hProcess, LPVOID lpBaseAddress, LPCVOID lpBuffer,\
										   SIZE_T nSize, SIZE_T* lpNumberOfBytesWritten);