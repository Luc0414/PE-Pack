#include "CPEinfo.h"
#include "PEInfo.h"
#include "PeEdit.h"
#include <direct.h>
#include "../lzmalib/LzmaLib.h"

using namespace std;
int main(int args, char** argv)
{
	const char* in = "D:\\Wh0Am1\\C++\\PE-Pack\\PE Pack\\test.exe";
	const char* out = "D:\\Wh0Am1\\C++\\PE-Pack\\PE Pack\\Newtest.exe";

	/* 文件写入 */
	std::unique_ptr<std::ofstream, std::function<void(std::ofstream*)>> foutGuard(new std::ofstream(out, ios_base::binary | ios_base::out), [](std::ofstream* f) { f->close(); });
	/* 文件读取 */
	std::unique_ptr<std::ifstream, std::function<void(std::ifstream*)>> finGuard(new std::ifstream(in, std::ios_base::in | std::ios_base::binary), [](std::ifstream* f) {f->close(); });
	std::ifstream* fin = NULL;
	if (finGuard) {
		fin = finGuard.get();
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

		LPBYTE pDstBuf = NULL;
		pDstBuf = new BYTE[(size_t)(fsize)]; //防止分配缓存区空间过小
		LzmaCompress()
	}

}

