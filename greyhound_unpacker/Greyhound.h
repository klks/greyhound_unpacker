#pragma once
#include "defines.h"

#include <windows.h>
#include <tlhelp32.h>
#include <Psapi.h>
#include "resource.h"
#include "SharedFunctions.h"
#include "ReflexiveUnpacker.h"
#include "GameHouseUnpacker.h"
#include "AlawarUnpacker.h"
#include "PlayrixUnpacker.h"
#include "PopcapUnpacker.h"

#pragma comment(lib, "Psapi.lib")

//Static Strings
char *cHookName="greyhound_hook.dll";

//Unpackers
CReflexiveUnpacker cReflexive;
CGameHouseUnpacker cGameHouse;
CAlawarUnpacker cAlawar;
CPlayrixUnpacker cPlayrix;
CPopcapUnpacker cPopcap;

//Window Procs
HWND g_hWndProd=NULL;
HWND g_hWndLog=NULL;
HWND g_hBtnUnpack=NULL;
HWND g_hDlg=NULL;

int iRunningUnpacker;

//CS
CRITICAL_SECTION lpCriticalSection;

//Structures

//Variables
char cTargetDirectory[DEF_MAXPATH];		//Directory where target resides
char cExeFileName[DEF_MAXPATH];			//Target EXE, including path
char cExeFileNameOnly[DEF_MAXPATH];
char cOwnDirectory[DEF_MAXPATH];		//Unpackers own dir
char cFullHookPath[DEF_MAXPATH];		//Full hook path

//Strings
#ifdef DEBUG
char cAppName[] = "Greyhound Unpacker v1.6 [DEBUG MODE] - March 2008";
#else
char cAppName[] = "Greyhound Unpacker v1.6 - March 2008";
#endif

//Functions Declarations