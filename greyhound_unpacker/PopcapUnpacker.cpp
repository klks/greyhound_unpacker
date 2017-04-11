#include "PopcapUnpacker.h"

//Externs
extern char cTargetDirectory[DEF_MAXPATH];
extern char cExeFileName[DEF_MAXPATH];
extern char cExeFileNameOnly[DEF_MAXPATH];
extern char cOwnDirectory[DEF_MAXPATH];

char cTempBuff[DEF_MAXPATH+20];

CPopcapUnpacker::CPopcapUnpacker(void)
{
	bUnpacking = false;
	dwThreadHandle = NULL;
	InitializeCriticalSection(&lpInternalCS);

	//Add your Code Here
}

CPopcapUnpacker::~CPopcapUnpacker(void)
{
	DeleteCriticalSection(&lpInternalCS);

	//Add your Code Here
}

bool CPopcapUnpacker::bIsValidProduct()
{
#ifdef DEBUG
	Log("CPopcapUnpacker::bIsValidProduct()");
#endif

	//Add your Code Here
	bool bPopUninstall = false;
	bool bIsPopCap = false;

	//Look for PopUninstall.exe
	ZeroMemory(cTempBuff, sizeof(cTempBuff));
	memcpy(cTempBuff, cTargetDirectory, strlen(cTargetDirectory));
	strcat(cTempBuff, "PopUninstall.exe");
	if(bFileExists(cTempBuff))
		bPopUninstall = true;

	//Check if Exe's last sections RawAddr+RawSize > Total file size
	HANDLE hFile, hFileMap;
	LPVOID hFilePtr;

	if(!bOpenForMapping(cExeFileName, &hFile, &hFileMap, &hFilePtr))
		goto CLEANUP;

	DWORD dwFileSize = GetFileSize(hFile, NULL);

	//Verify information
	IMAGE_DOS_HEADER *idh = (IMAGE_DOS_HEADER *)(hFilePtr);
	IMAGE_FILE_HEADER       *ifh = (IMAGE_FILE_HEADER *)((DWORD)(idh) + idh->e_lfanew + sizeof(DWORD));
	IMAGE_OPTIONAL_HEADER   *ioh = (IMAGE_OPTIONAL_HEADER *)((DWORD)(ifh) + sizeof(IMAGE_FILE_HEADER));

	//Get Last Section
	IMAGE_SECTION_HEADER *ish = (IMAGE_SECTION_HEADER *)( ((DWORD)(ioh) + ifh->SizeOfOptionalHeader) + ((ifh->NumberOfSections-1) * sizeof(IMAGE_SECTION_HEADER)) );

#ifdef DEBUG
			Log("Last Section Name = %s, Phy RVA = 0x%.8X, Phy Size = 0x%.8X, Vir RVA = 0x%.8X, Vir Size = 0x%.8X", ish->Name, ish->PointerToRawData, ish->SizeOfRawData, ish->VirtualAddress, ish->Misc.VirtualSize);
#endif

	DWORD dwEndSection = ish->PointerToRawData+ish->SizeOfRawData;
	if(dwFileSize > dwEndSection)
		bIsPopCap = true;

	if(dwFileSize-dwEndSection > 0x200)
	{
		ZeroMemory(cTempBuff, sizeof(cTempBuff));
		char* cp = (char*)hFilePtr;
		cp += dwEndSection;
		memcpy(cTempBuff, cp, 18);

		if(strcmp(cTempBuff, "!popcapdrmprotect!") != 0)
		{
#ifdef DEBUG
			Log("Buffer returned %s", cTempBuff);
#endif
			bIsPopCap = false;
		}
	}

	CLEANUP:
	CloseMapping(&hFile, &hFileMap, &hFilePtr);

	if(bPopUninstall && bIsPopCap)
		return true;

	if(bPopUninstall || bIsPopCap)
	{
		Log("Possible new version of PopCap product or already unpacked");
		return false;
	}

	return false;
}

void CPopcapUnpacker::Unpack()
{
#ifdef DEBUG
	Log("CPopcapUnpacker::Unpack()");
#endif
	DWORD dwThreadID;

	if(bUnpacking) //Are we unpacking?
	{
		Log("Unpacking already in progress");
		return;
	}
	Log("Unpacking ...");
	bUnpacking = true;
	dwThreadHandle = CreateThread(NULL, NULL, &CPopcapUnpacker::UnpackThread, (void*)this, 0, &dwThreadID);
}

DWORD CPopcapUnpacker::UnpackThread(void * pthis)
{
#ifdef DEBUG
	Log("CPopcapUnpacker::UnpackThread()");
#endif
	//Add your Code Here

	CPopcapUnpacker *pt = (CPopcapUnpacker *) pthis;

	//Unpacking routine
	TryEnterCriticalSection(&pt->lpInternalCS);

	//Make sure executable exists
	if(!bFileExists(cExeFileName))
	{
		Log("Please make sure file %s exists.", cExeFileNameOnly);
		goto FAILED;
	}

	HANDLE hFile, hFileMap;
	LPVOID hFilePtr;
	
	if(!bOpenForMapping(cExeFileName, &hFile, &hFileMap, &hFilePtr))
		goto FAILED;

	DWORD dwFileSize = GetFileSize(hFile, NULL);

	//Verify information
	IMAGE_DOS_HEADER *idh = (IMAGE_DOS_HEADER *)(hFilePtr);
	IMAGE_FILE_HEADER       *ifh = (IMAGE_FILE_HEADER *)((DWORD)(idh) + idh->e_lfanew + sizeof(DWORD));
	IMAGE_OPTIONAL_HEADER   *ioh = (IMAGE_OPTIONAL_HEADER *)((DWORD)(ifh) + sizeof(IMAGE_FILE_HEADER));

	//Get Last Section
	IMAGE_SECTION_HEADER *ish = (IMAGE_SECTION_HEADER *)( ((DWORD)(ioh) + ifh->SizeOfOptionalHeader) + ((ifh->NumberOfSections-1) * sizeof(IMAGE_SECTION_HEADER)) );

#ifdef DEBUG
			Log("Last Section Name = %s, Phy RVA = 0x%.8X, Phy Size = 0x%.8X, Vir RVA = 0x%.8X, Vir Size = 0x%.8X", ish->Name, ish->PointerToRawData, ish->SizeOfRawData, ish->VirtualAddress, ish->Misc.VirtualSize);
#endif

	DWORD dwEndSection = ish->PointerToRawData+ish->SizeOfRawData;

	if(dwFileSize-dwEndSection > 0x200)
	{
		ZeroMemory(cTempBuff, sizeof(cTempBuff));
		char* cp = (char*)hFilePtr;
		cp += dwEndSection;
		memcpy(cTempBuff, cp, 18);

		if(strcmp(cTempBuff, "!popcapdrmprotect!") != 0)
		{
#ifdef DEBUG
			Log("Buffer returned %s instead of !popcapdrmprotect!", cTempBuff);
#endif
			goto FAILED;
		}

		//Point to the MZ Structure of real exe
		cp += 0x1A2;
		idh = (IMAGE_DOS_HEADER *)(cp);

		IMAGE_FILE_HEADER       *ifh = (IMAGE_FILE_HEADER *)((DWORD)(idh) + idh->e_lfanew + sizeof(DWORD));
		IMAGE_OPTIONAL_HEADER   *ioh = (IMAGE_OPTIONAL_HEADER *)((DWORD)(ifh) + sizeof(IMAGE_FILE_HEADER));

		//Get header size
		IMAGE_SECTION_HEADER *ish = (IMAGE_SECTION_HEADER *)( ((DWORD)(ioh) + ifh->SizeOfOptionalHeader));

		DWORD dwTotalRealSize = ish->PointerToRawData;

		for(int i=0; i< ifh->NumberOfSections; i++)
		{
			IMAGE_SECTION_HEADER *ish = (IMAGE_SECTION_HEADER *)( ((DWORD)(ioh) + ifh->SizeOfOptionalHeader) + (i * sizeof(IMAGE_SECTION_HEADER)) );
			dwTotalRealSize += ish->SizeOfRawData;
		}

#ifdef DEBUG
		Log("Real file size 0x%.8X", dwTotalRealSize);
#endif

		//Generate a temp file name
		if(GetTempFileName(cTargetDirectory, "ghu", 0, cTempBuff) == 0)
		{
#ifdef DEBUG
			Log("Call to GetTempFileName Failed!");
#endif
			goto FAILED;
		}
#ifdef DEBUG
		Log("Temp file name %s", cTempBuff);
#endif

		HANDLE hTemp = CreateFile(cTempBuff, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
		if(hTemp == INVALID_HANDLE_VALUE)
		{
#ifdef DEBUG
			Log("Call to CreateFile for %s Failed!", cTempBuff);
#endif
			DeleteFile(cTempBuff);
			goto FAILED;
		}

		DWORD dwWritten;
		WriteFile(hTemp, cp, dwTotalRealSize, &dwWritten, NULL);
		CloseHandle(hTemp);
		CloseMapping(&hFile, &hFileMap, &hFilePtr);
		DeleteFile(cExeFileName);
		MoveFile(cTempBuff, cExeFileName);
	}

	Log("Unpacking completed successfully!");
	goto CLEANUP;

FAILED:
	Log("Unpacking Failed!");
CLEANUP:
	CloseMapping(&hFile, &hFileMap, &hFilePtr);

	//Cleanup
	pt->Cleanup();
LeaveCriticalSection(&pt->lpInternalCS);
	return 0;
}

void CPopcapUnpacker::Abort()
{
#ifdef DEBUG
	Log("CPopcapUnpacker::Abort()");
#endif
	TryEnterCriticalSection(&lpInternalCS);
	SuspendThread(dwThreadHandle);
	TerminateThread(dwThreadHandle, 1);
	LeaveCriticalSection(&lpInternalCS);
	Cleanup();
	Log("Aborting Complete!");
}

void CPopcapUnpacker::Cleanup()
{
#ifdef DEBUG
	Log("CPopcapUnpacker::Cleanup()");
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
