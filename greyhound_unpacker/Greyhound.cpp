#include "Greyhound.h"

//Check if we have an unpacker for this product
void Unpack()
{
	OPENFILENAME ofn;

	ZeroMemory(&ofn, sizeof(ofn));
	ofn.lStructSize = sizeof(ofn);
	ofn.lpstrFile = cTargetDirectory;
	ofn.lpstrFile[0] = '\0';
	ofn.nMaxFile = sizeof(cTargetDirectory);
	ofn.lpstrFilter = "Executable Files (*.exe)\0*.exe\0";
	ofn.nFilterIndex = 1;
	ofn.lpstrFileTitle = NULL;
	ofn.nMaxFileTitle = 0;
	ofn.lpstrInitialDir = NULL;
	ofn.Flags = OFN_PATHMUSTEXIST | OFN_FILEMUSTEXIST;

	//Setup browse for target
	if(!GetOpenFileName(&ofn))
	{
		ResetButtons();
		return;
	}

	//Extract cExeFileName from TargetDirectory
	//Taken From MSDN, find last occurence of "\"
	strcpy(cExeFileName, cTargetDirectory);
	char *pdest = strrchr(cTargetDirectory, '\\');
	int nPos = (int)(pdest - cTargetDirectory + 1);
	cTargetDirectory[nPos] = 0;
	strcpy(cExeFileNameOnly, &cExeFileName[nPos]);

	//ADD NEW UNPACKERS HERE
	//Run through Unpackers
	if(cReflexive.bIsValidProduct())
	{
		iRunningUnpacker = PROD_REFLEXIVE;
		Log("Found Reflexive Arcade!");
		cReflexive.Unpack();
	}
	else if(cGameHouse.bIsValidProduct())
	{
		iRunningUnpacker = PROD_GAMEHOUSE;
		Log("Found GameHouse!");
		cGameHouse.Unpack();
	}
	else if(cAlawar.bIsValidProduct())
	{
		iRunningUnpacker = PROD_ALAWAR;
		Log("Found Alawar!");
		cAlawar.Unpack();
	}
	else if(cPlayrix.bIsValidProduct())
	{
		iRunningUnpacker = PROD_PLAYRIX;
		Log("Found Playrix!");
		cPlayrix.Unpack();
	}
	else if(cPopcap.bIsValidProduct())
	{
		iRunningUnpacker = PROD_POPCAP;
		Log("Found PopCap!");
		cPopcap.Unpack();
	}
	else
	{
		ResetButtons();
		Log("Error : Unsupported Product! :(");
	}
}

void Abort()
{
	Log("Preparing to Abort ...");
	//ADD NEW UNPACKERS HERE
	if(iRunningUnpacker == PROD_REFLEXIVE)
		cReflexive.Abort();
	else if(iRunningUnpacker == PROD_GAMEHOUSE)
		cGameHouse.Abort();
	else if(iRunningUnpacker == PROD_ALAWAR)
		cAlawar.Abort();
	else if(iRunningUnpacker == PROD_PLAYRIX)
		cPlayrix.Abort();
	else if(iRunningUnpacker == PROD_POPCAP)
		cPopcap.Abort();
	else
	{
		Log("You should not be seeing this, if you are, something is wrong");
		return;
	}
}

void AddSupportedProducts()
{
	SendMessage(g_hWndProd, LB_ADDSTRING, 0, (LPARAM)"Reflexive Arcade - http://www.reflexive.com/");
	SendMessage(g_hWndProd, LB_ADDSTRING, 0, (LPARAM)"GameHouse - http://www.gamehouse.com/");
	SendMessage(g_hWndProd, LB_ADDSTRING, 0, (LPARAM)"Alwar - http://www.alawar.com/");
	SendMessage(g_hWndProd, LB_ADDSTRING, 0, (LPARAM)"Playrix - http://www.playrix.com/");
	SendMessage(g_hWndProd, LB_ADDSTRING, 0, (LPARAM)"PopCap - http://www.popcap.com/");
}

void InitDialog(HWND hDlg)
{
	g_hDlg = hDlg;
	g_hWndProd = GetDlgItem(hDlg, IDC_LSTPROD);
	g_hWndLog = GetDlgItem(hDlg, IDC_LSTLOG);
	g_hBtnUnpack = GetDlgItem(hDlg, IDC_BTNUNPACK);

	InitializeCriticalSection(&lpCriticalSection);
	SetWindowText(hDlg, cAppName);
	GetCurrentDirectory(sizeof(cOwnDirectory), cOwnDirectory);
	strcpy(cFullHookPath, cOwnDirectory);
	strcat(cFullHookPath, "\\");
	strcat(cFullHookPath, cHookName);
}

void Cleanup()
{
	DeleteCriticalSection(&lpCriticalSection);
}

BOOL CALLBACK MainDialogProc(HWND hDlg, UINT uMsg, WPARAM wParam, LPARAM lParam){
	switch(uMsg) {
	case WM_CLOSE:
		Cleanup();
		EndDialog(hDlg, TRUE);
		break;

	case WM_INITDIALOG:
		InitDialog(hDlg);
		AddSupportedProducts();
		break;

	case WM_COMMAND:
		switch(LOWORD(wParam)) {
		case IDC_BTNEXIT:
			SendMessage(hDlg, WM_CLOSE, 0,0);
			break;
		case IDC_BTNUNPACK:
		{
			char cTempBuf[20];
			GetWindowText(g_hBtnUnpack, cTempBuf, sizeof(cTempBuf));
			if(strcmp(cTempBuf, "Unpack") == 0){
				SetWindowText(g_hBtnUnpack, "Abort");
				Unpack();
			}
			else
			{
				Abort();
				SetWindowText(g_hBtnUnpack, "Unpack");
			}
		}
			break;
		case IDC_BTNABOUT:
			MessageBox(hDlg, "Greyhound was devloped by [KLKS]\n" \
							 "Use at your own risk!", "About", MB_OK+MB_ICONINFORMATION);
			break;
		}
		break;

	default:
		return FALSE;
	}
	return TRUE;
}

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow)
{
	DialogBox(hInstance, MAKEINTRESOURCE(IDD_GREYDLG), NULL, (DLGPROC)MainDialogProc);
	return 0;
}