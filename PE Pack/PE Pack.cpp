#include "CPEinfo.h"
#include "PEInfo.h"
#include "PeEdit.h"
#include <direct.h>

using namespace std;
int main(int args, char** argv)
{
	wchar_t szExePath[] = L"F:\\Development\\C++\\PE-Pack\\PE Pack\\notepad.exe";
	//char cExePath[] = "D:\\Wh0Am1\\C++\\PE Pack\\PE Pack\\notepad.exe";
	const char* in = "D:\\Wh0Am1\\C++\\PE-Pack\\PE Pack\\test.exe";
	const char * out = "D:\\Wh0Am1\\C++\\PE-Pack\\PE Pack\\Newtest.exe";
	const char* delSectHeader = "D:\\Wh0Am1\\C++\\PE-Pack\\PE Pack\\delSectHeader.exe";
	char cExePath[] = "F:\\Development\\C++\\PE-Pack\\PE Pack\\notepad.exe";
	char cExePath1[] = "F:\\Development\\C++\\PE-Pack\\PE Pack\\test.exe";


	char overlay[] = "Whoami";

	/* 文件写入 */
	std::unique_ptr<std::ofstream, std::function<void(std::ofstream*)>> foutGuard(new std::ofstream(delSectHeader, ios_base::binary | ios_base::out), [](std::ofstream* f) { f->close(); });
	/* 文件读取 */
	std::unique_ptr<std::ifstream, std::function<void(std::ifstream*)>> finGuard(new std::ifstream(out, std::ios_base::in | std::ios_base::binary), [](std::ifstream* f) {f->close(); });

	std::ifstream* fin = NULL;
	if (finGuard) { // 检查指针是否为空
		fin = finGuard.get(); // 获取原始指针
		// 移动到文件结尾
		fin->seekg(0, std::ios::end);
		// 获取文件大小 static_cast
		const DWORD fsize = static_cast<DWORD>(fin->tellg());
		/* 创建内存 */
		LPBYTE pFileBuf = new BYTE[fsize];
		memset(pFileBuf, 0, fsize);
		// 移动到文件开头
		fin->seekg(0, std::ios::beg);
		// 读取文件内容到指定缓冲区
		fin->read(reinterpret_cast<char*>(pFileBuf), fsize);

		int removeIdx[] = { 3 };
		DWORD result = PEedit::removeSectionDatas(pFileBuf,1, removeIdx);

		PEedit::savePeFile(delSectHeader, pFileBuf, 0);
		system("pause");
	}
	else {
		return 0;
	}

}

