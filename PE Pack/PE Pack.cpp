#include "CPEinfo.h"
#include "PEInfo.h"
#include "PeEdit.h"
#include <direct.h>
#include "../lzmalib/LzmaLib.h"
#include "dpackType.h"
using namespace std;

#pragma comment(lib,"lzmalib.lib")
int main(int args, char** argv)
{
	const char* in = "D:\\Wh0Am1\\C++\\PE-Pack\\PE Pack\\test.exe";
	const char* out = "D:\\Wh0Am1\\C++\\PE-Pack\\PE Pack\\Newtest.exe";

	/* 文件写入 */
	std::unique_ptr<std::ofstream, std::function<void(std::ofstream*)>> foutGuard(new std::ofstream(out, ios_base::binary | ios_base::out), [](std::ofstream* f) { f->close(); });
	/* 文件读取 */
	std::unique_ptr<std::ifstream, std::function<void(std::ifstream*)>> finGuard(new std::ifstream(in, std::ios_base::in | std::ios_base::binary), [](std::ifstream* f) {f->close(); });
	std::ifstream* fin = NULL;
	std::ofstream* fout = NULL;
	if (finGuard) {
		fin = finGuard.get();
		fout = foutGuard.get();
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

		size_t dstSize = -1;

		LPBYTE  pDstBuf = NULL;
		size_t propSize = sizeof(DLZMA_HEADER);
		PDLZMA_HEADER pDlzmah = NULL;
		for (double m = 1; m <= 2; m += 0.1) {
			size_t size = (size_t)(m * (double)fsize) + sizeof(DLZMA_HEADER);
			pDstBuf = new BYTE[size];
			pDlzmah = (PDLZMA_HEADER)pDstBuf;
			LzmaCompress(pDstBuf + sizeof(DLZMA_HEADER),&dstSize,pFileBuf,fsize, pDlzmah->LzmaProps, (size_t*)&propSize, -1, 0, -1, -1, -1, -1, -1);
			if (dstSize > 0) break;
			delete[] pDstBuf;
			pDlzmah = NULL;
		}

		pDlzmah->RawDataSize = fsize;
		pDlzmah->DataSize = dstSize;

		fout->write((char*)pDstBuf, pDlzmah->DataSize);

		LPBYTE pSrcBuf = new BYTE[fsize * 2];
		memset(pSrcBuf, 0, fsize * 2);
		size_t dstSizeUn = pDlzmah->RawDataSize;//release版不赋初值会出错，由于debug将其赋值为cccccccc很大的数
		LzmaUncompress(pSrcBuf, &dstSizeUn,//此处必须赋最大值
			pDstBuf + sizeof(DLZMA_HEADER), &dstSize,
			pDlzmah->LzmaProps, LZMA_PROPS_SIZE);
	}
}

