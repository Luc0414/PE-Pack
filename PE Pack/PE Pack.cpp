#include "CPEinfo.h"
#include "PEInfo.h"
#include "PeEdit.h"
#include <direct.h>
int main(int args,char ** argv)
{
	wchar_t szExePath[] = L"F:\\Development\\C++\\PE-Pack\\PE Pack\\notepad.exe";

	//char cExePath[] = "D:\\Wh0Am1\\C++\\PE Pack\\PE Pack\\notepad.exe";
	//char cExePath1[] = "D:\\Wh0Am1\\C++\\PE Pack\\PE Pack\\test.exe";

	char cExePath[] = "F:\\Development\\C++\\PE-Pack\\PE Pack\\notepad.exe";
	char cExePath1[] = "F:\\Development\\C++\\PE-Pack\\PE Pack\\test.exe";


	char overlay[] = "Whoami";
	//PEedit::addOverlay(cExePath1, (LPBYTE)overlay, sizeof(overlay));
	PEedit::setOepRva(cExePath1, 0x500);
	system("pause");
}

