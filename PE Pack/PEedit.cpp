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
	// 重定位表中所有的重定位项的数量
	DWORD all_num = 0;
	// 已经遍历的重定位表数据大小
	DWORD sumsize = 0;
	// 获取重定位表的数据目录
	auto pRelocEntry = &GetImageDataDirectory(pPeBuf)[IMAGE_DIRECTORY_ENTRY_BASERELOC];
	// 遍历所有的重定位块
	while (sumsize < pRelocEntry->Size)
	{
		// 获取当前重定位块的首地址
		auto pBaseRelocation = PIMAGE_BASE_RELOCATION(pPeBuf + sumsize + (bMemAlign ? pRelocEntry->VirtualAddress : rva2faddr(pPeBuf, pRelocEntry->VirtualAddress)));
		// 获取当前重定位块中的所有偏移量项
		auto pRelocOffset = (PRELOCOFFSET)((LPBYTE)pBaseRelocation + sizeof(IMAGE_BASE_RELOCATION));
		// 计算当前重定位块中的偏移量项数量
		DWORD item_num = (pBaseRelocation->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(RELOCOFFSET);
		// 遍历当前重定位块中的所有偏移量项
		for (size_t i = 0; i < item_num; i++) {
			if (!pRelocOffset[i].type && !pRelocOffset[i].Offset) {
				continue;
			}
			/* 需要修改的RVA */
			DWORD toffset = pRelocOffset[i].Offset + pBaseRelocation->VirtualAddress;
			if (!bMemAlign) {
				// 如果需要修正偏移地址，将RVA转化为FOA
				toffset = rva2faddr(pPeBuf, toffset);
			}
			// 取需要修改位置的值
			DWORD* pRelocAddr = reinterpret_cast<DWORD*>(pPeBuf + toffset);
			// 修改VA,新基地址 - 旧基地址 + 壳的大小，这是因为内存空间多了个壳的段，跟原文件的内存空间分配不同
			*pRelocAddr += newImageBase - oldImageBase + offset;
		}
		// 修正重定位块的虚拟地址
		pBaseRelocation->VirtualAddress += offset;
		// 更新已经遍历的重定位表数据大小和重定位项数量
		sumsize += sizeof(PRELOCOFFSET) * item_num + sizeof(IMAGE_BASE_RELOCATION);
		all_num += item_num;
	}
	return all_num;

}

DWORD PEedit::shiftOft(LPBYTE pPeBuf, DWORD offset, bool bMemAlign, bool bResetFt) {
	auto pImportEntry = &GetImageDataDirectory(pPeBuf)[IMAGE_DIRECTORY_ENTRY_IMPORT];
	DWORD dll_num = pImportEntry->Size / sizeof(IMAGE_IMPORT_DESCRIPTOR);
	DWORD func_num = 0;
	auto pImportDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)(pPeBuf + (bMemAlign ? pImportEntry->VirtualAddress : rva2faddr(pPeBuf, pImportEntry->VirtualAddress)));
	for (size_t i = 0; i < dll_num; i++) {
		if (pImportDescriptor[i].OriginalFirstThunk == 0) continue;
		auto pOFT = (PIMAGE_THUNK_DATA)(pPeBuf + (bMemAlign ? pImportDescriptor[i].OriginalFirstThunk : rva2faddr(pPeBuf, pImportDescriptor[i].OriginalFirstThunk)));
		auto pFT = (PIMAGE_THUNK_DATA)(pPeBuf + (bMemAlign ? pImportDescriptor[i].FirstThunk : rva2faddr(pPeBuf, pImportDescriptor[i].FirstThunk)));
		DWORD item_num = 0;
		for (int j = 0; pOFT[j].u1.AddressOfData != 0; j++) {
			item_num++;
			if ((pOFT[j].u1.AddressOfData >> 31) != 0x1) {
				pOFT[j].u1.AddressOfData += offset;
				if (bResetFt) pFT[j].u1.AddressOfData = pOFT[j].u1.AddressOfData;
			}
		}
		pImportDescriptor[i].OriginalFirstThunk += offset;
		pImportDescriptor[i].FirstThunk += offset;
		pImportDescriptor[i].Name = offset;
		func_num += item_num;
	}
	return func_num;
}