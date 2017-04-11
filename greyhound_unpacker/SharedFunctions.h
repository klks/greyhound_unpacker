#pragma once
#define _WIN32_WINNT	0x0501
#include <windows.h>
#include <tlhelp32.h>
#include "defines.h"

//Extern stuff from Greyhound.h
extern HWND g_hWndLog;
extern HWND g_hBtnUnpack;
extern CRITICAL_SECTION lpCriticalSection;
extern char* cHookName;
extern char cFullHookPath[DEF_MAXPATH];

//Functions
bool bFileExists(char *cFileName);
bool bGetProccessModule(DWORD dwPID, char *cModuleName, MODULEENTRY32 &ret_me32);
void Log(char* fmt, ...);
void ResetButtons();
bool InjectDLLHook(int PROD_TYPE, DWORD dwProcessId, STARTUPINFO &si, PROCESS_INFORMATION &pi);
bool bOpenForMapping(char *cFileToMap, HANDLE *hFile, HANDLE *hFileMap, LPVOID *hFilePtr, int MapMode=MAP_READ);
void CloseMapping(HANDLE *hFile, HANDLE *hFileMap, LPVOID *hFilePtr);