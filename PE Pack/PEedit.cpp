#include "PeEdit.h"
#include <fstream>
#include <functional>
using namespace std;

DWORD PEedit::addOverlay(const char* path, LPBYTE pOverlay, DWORD size) {
	if (pOverlay == NULL || size == 0) {
		return 0;
	}

	try {
		// RAII 模式管理文件句柄
		// &fout为std::ofstream，[](std::ofstream* f) { f->close(); }为 std::function<void(std::ofstream*)>
		std::unique_ptr<std::ofstream, std::function<void(std::ofstream*)>> foutGuard(
			new std::ofstream(path, ios_base::binary | ios_base::app),
			[](std::ofstream* f) { f->close(); });
		// std::ofstream 对象被创建并打开文件时，文件指针已经处于文件的末尾位置
		foutGuard->write((const char*)pOverlay, size);
	}
	catch (const std::ios_base::failure& e) {
		return 0;
	}

	return size;
}

DWORD PEedit::setOepRva(const char* path, DWORD RVA) {
	if (RVA == NULL) {
		return 0;
	}
	BYTE buf[PEHBUF_SIZE];
	int readsize = readFile(path, buf, PEHBUF_SIZE);
	if (readsize == 0) {
		return 0;
	}
	DWORD oldrva = setOepRva(buf, RVA);
	if (oldrva == 0) {
		return 0;
	}
	//ios::out则清空文件，ios::app每次写都是在最后，ios::ate可以用seekp
	std::unique_ptr<std::ofstream, std::function<void(std::ofstream*)>> foutGuard(
		new std::ofstream(path, std::ios_base::binary | std::ios_base::ate | std::ios::in),
		[](std::ofstream* f) { f->close(); });

	foutGuard->seekp(0, ios_base::beg);
	foutGuard->write((const char*)buf, readsize);
	return oldrva;

}

DWORD PEedit::setOepRva(LPBYTE pPeBuf, DWORD RVA) {
	if (pPeBuf == NULL) return 0;
	if (isPe(pPeBuf) <= 0) return 0;
	DWORD* pRVA = &GetOptionalHeader(pPeBuf)->AddressOfEntryPoint;
	DWORD oldrva = *pRVA;
	*pRVA = RVA;
	return oldrva;
}

DWORD PEedit::shiftReloc(LPBYTE pPeBuf, size_t oldImageBase, size_t newImageBase, DWORD offset, bool bMemAlign) {
	DWORD all_num = 0;
	DWORD sumsize = 0;
	auto pRelocEntry = &GetImageDataDirectory(pPeBuf)[IMAGE_DIRECTORY_ENTRY_BASERELOC];
	while (sumsize < pRelocEntry->Size)
	{
		auto pBaseRelocation =  PIMAGE_BASE_RELOCATION(pPeBuf + sumsize + (bMemAlign ? pRelocEntry->VirtualAddress : rva2faddr(pPeBuf, pRelocEntry->VirtualAddress)));
		auto pRelocOffset = (PRELOCOFFSET)((LPBYTE)pBaseRelocation + sizeof(IMAGE_BASE_RELOCATION));
		DWORD item_num = (pBaseRelocation->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(RELOCOFFSET);
		for (size_t i = 0; i < item_num; i++) {
			if (!pRelocOffset[i].type && !pRelocOffset[i].Offset) {
				continue;
			}
			DWORD toffset = pRelocOffset[i].Offset + pBaseRelocation->VirtualAddress;
			if (!bMemAlign) {
				toffset = rva2faddr(pPeBuf, toffset);
			}
			// 新的重定位地址 = 重定位后的地址(VA)-加载时的镜像基址(hModule VA) + 新的镜像基址(VA) + 新代码基址RVA（前面用于存放压缩的代码）
			// 由于讲dll附加在后面，需要在dll shell中的重定位加上偏移修正
			*(PDWORD)(pPeBuf + toffset) += newImageBase - oldImageBase + offset;//重定向每一项地址
		}
	}
	return all_num;

}