#include "PeEdit.h"
#include <algorithm>
using namespace std;

/* 已调试 */
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

/* 已调试 */
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
	//ios::out则清空文件，ios::app 每次进行写入操作的时候都会重新定位到文件的末尾,ios::ate 打开文件之后立即定位到文件末尾
	std::unique_ptr<std::ofstream, std::function<void(std::ofstream*)>> foutGuard(
		new std::ofstream(path, std::ios_base::binary | std::ios_base::ate | std::ios::in),
		[](std::ofstream* f) { f->close(); });

	foutGuard->seekp(0, ios_base::beg);
	foutGuard->write((const char*)buf, readsize);
	return oldrva;

}

/* 已调试 */
DWORD PEedit::setOepRva(LPBYTE pPeBuf, DWORD RVA) {
	if (pPeBuf == NULL) return 0;
	if (isPe(pPeBuf) <= 0) return 0;
	DWORD* pRVA = &GetOptionalHeader(pPeBuf)->AddressOfEntryPoint;
	DWORD oldrva = *pRVA;
	*pRVA = RVA;
	return oldrva;
}

/* 未调试 */
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

/* 未调试 */
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

/* 已调试 */
DWORD PEedit::appendSection(LPBYTE pPeBuf, IMAGE_SECTION_HEADER newSectHeader, LPBYTE pNewSectBuf, DWORD newSectSize, bool bMemAlign) {
	// 增加一个区段，获取旧区段数量,先将旧区段数量赋值给oldSectNum，然后对NumberOfSections + 1
	WORD oldSectNum = GetFileHeader(pPeBuf)->NumberOfSections++;
	// 获取可选头指针
	auto pOptHeader = GetOptionalHeader(pPeBuf);
	// 获取区段头指针
	auto pSectHeader = GetSectionHeader(pPeBuf);
	// 获取文件对齐大小
	DWORD fileAlign = pOptHeader->FileAlignment;
	// 获取内存对齐大小
	DWORD memAlign = pOptHeader->SectionAlignment;

	// 如果新区段的SizeOfRawData字段为0，则设置为以fileAlign对齐的newSectSize
	if (!newSectHeader.SizeOfRawData) {
		newSectHeader.SizeOfRawData = toAlign(newSectSize, fileAlign);
	}
	// 如果新区段的Misc.VirtualSize字段为0，则设置为newSectSize
	if (!newSectHeader.Misc.VirtualSize) {
		newSectHeader.Misc.VirtualSize = newSectSize;
	}
	// 如果新区段的PointerToRawData字段为0，则设置为上一个区段的PointerToRawData加上上一个区段的SizeOfRawData，以fileAlign对齐
	if (!newSectHeader.PointerToRawData) {
		newSectHeader.PointerToRawData = toAlign(pSectHeader[oldSectNum - 1].PointerToRawData + pSectHeader[oldSectNum - 1].SizeOfRawData, fileAlign);
	}
	else {
		// 如果指定的PointerToRawData小于上一个区段的PointerToRawData加上上一个区段的SizeOfRawData，无法添加，返回0
		if (newSectHeader.PointerToRawData < pSectHeader[oldSectNum - 1].PointerToRawData + toAlign(pSectHeader[oldSectNum - 1].SizeOfRawData, fileAlign)) {
			return 0;
		}
	}
	// 如果新区段的VirtualAddress字段为0，则设置为上一个区段的VirtualAddress加上上一个区段的SizeOfRawData，以memAlign对齐
	if (!newSectHeader.VirtualAddress) {
		newSectHeader.VirtualAddress = toAlign(pSectHeader[oldSectNum - 1].VirtualAddress + pSectHeader[oldSectNum - 1].SizeOfRawData, memAlign);
	}
	else {
		// 如果指定的VirtualAddress小于上一个区段的VirtualAddress加上上一个区段的Misc.VirtualSize，无法添加，返回0
		if (newSectHeader.VirtualAddress < pSectHeader[oldSectNum - 1].VirtualAddress + toAlign(pSectHeader[oldSectNum - 1].Misc.VirtualSize, memAlign)) {
			return 0;
		}
		// 修改前一个区段的Misc.VirtualSize使得内存上没有空隙
		pSectHeader[oldSectNum - 1].Misc.VirtualSize += (newSectHeader.VirtualAddress - pSectHeader[oldSectNum - 1].VirtualAddress - pSectHeader[oldSectNum - 1].Misc.VirtualSize) / memAlign * memAlign;
	}

	memcpy(&pSectHeader[oldSectNum], &newSectHeader, sizeof(IMAGE_SECTION_HEADER));
	memset(&pSectHeader[oldSectNum + 1], 0, sizeof(IMAGE_SECTION_HEADER));

	LPBYTE pNewSectStart = pPeBuf + (bMemAlign ? pSectHeader[oldSectNum].VirtualAddress : pSectHeader[oldSectNum].PointerToRawData);
	memset(pNewSectStart, 0, bMemAlign ? memAlign : fileAlign);
	memcpy(pNewSectStart, pNewSectBuf, newSectSize);

	pOptHeader->SizeOfImage = pSectHeader[oldSectNum].VirtualAddress + toAlign(pSectHeader[oldSectNum].Misc.VirtualSize, memAlign);
	return bMemAlign ? toAlign(newSectSize, memAlign) : toAlign(newSectSize, fileAlign);
}

/* 已调试 */
DWORD PEedit::removeSectionDatas(LPBYTE pPeBuf, int removeNum, int removeIdx[]) {
	// 获取文件头指针，其中包括文件头信息和可选头信息
	WORD oldSectNum = GetFileHeader(pPeBuf)->NumberOfSections;
	auto pOtHeader = GetOptionalHeader(pPeBuf);
	auto pSectHeader = GetSectionHeader(pPeBuf);

	DWORD decreseRawSize = 0;
	std::sort(removeIdx, removeIdx + removeNum);
	int tmpidx = 0;
	for (int i = 0; i < oldSectNum; i++) {
		if (tmpidx < removeNum && i == removeIdx[tmpidx]) {
			decreseRawSize += pSectHeader[i].SizeOfRawData;
			pSectHeader[i].SizeOfRawData = 0;
			if (i < oldSectNum - 1) {
				// 将下一个节的地址更改为删除节的地址
				pSectHeader[i + 1].PointerToRawData = pSectHeader[i].PointerToRawData;
			}
			tmpidx++;
		}
	}

	return decreseRawSize;
}

/* 目前无异常 */
DWORD PEedit::savePeFile(const char* path, LPBYTE pPeBuf, DWORD FileBufSize, bool bMemAlign, bool bShrinkPe, LPBYTE pOverlayBuf, DWORD OverlayBufSize)
{
	if (pPeBuf == NULL) return 0;

	std::unique_ptr<std::ofstream, std::function<void(std::ofstream*)>> foutGuard(new std::ofstream(path, ios_base::binary | ios_base::out), [](std::ofstream* f) { f->close(); });
	std::ofstream* fout = NULL;
	if (foutGuard) fout = foutGuard.get(); else return 0;

	if (isPe((LPBYTE)pPeBuf) < 0) return 0;

	PIMAGE_OPTIONAL_HEADER pOptionalHeader = GetOptionalHeader(pPeBuf);
	PIMAGE_SECTION_HEADER pSecHeader = GetSectionHeader(pPeBuf);
	fout->write((const char*)pPeBuf, pOptionalHeader->SizeOfHeaders);
	DWORD writesize = pOptionalHeader->SizeOfHeaders;

	// 写入各区段
	for (int i = 0; i < GetFileHeader(pPeBuf)->NumberOfSections; i++) {
		DWORD sectOffset = bMemAlign ? pSecHeader[i].VirtualAddress : pSecHeader[i].PointerToRawData;
		DWORD sectsize = toAlign(pSecHeader[i].SizeOfRawData, pOptionalHeader->FileAlignment);

		auto cur = fout->tellp();//防止地址不对
		if (cur > pSecHeader[i].PointerToRawData) //防止重叠
		{
			fout->seekp(pSecHeader[i].PointerToRawData);
		}
		else if (cur < pSecHeader[i].PointerToRawData) 
		{
			/* 如果bShrinkPe为true，则直接更新pSecHeader[i].PointerToRawData，以便缩减文件大小。*/
			if (bShrinkPe)
			{
				pSecHeader[i].PointerToRawData = (DWORD)cur;
			}
			// 如果bShrinkPe为false，则使用循环填充字节来保证文件大小不变。
			else
			{
				for (std::streamoff j = cur; j < pSecHeader[i].PointerToRawData; j++) fout->put(0);
			}
		}

		fout->write((const char*)(pPeBuf + sectOffset), sectsize);
		writesize += sectsize;
	}
	// 写入附加段
	if (pOverlayBuf != NULL && OverlayBufSize != 0)
	{
		fout->write((const char*)pOverlayBuf, OverlayBufSize);
		writesize += OverlayBufSize;
	}

	//重新写入修正的PE头
	fout->seekp(0, ios::beg);
	fout->write((const char*)pPeBuf, pOptionalHeader->SizeOfHeaders);
}


/* public funcitons*/
DWORD PEedit::setOepRva(DWORD rva)
{
	return setOepRva(m_pPeBuf, rva);
}

DWORD  PEedit::shiftReloc(size_t oldImageBase, size_t newImageBase, DWORD offset)
{
	return shiftReloc(m_pPeBuf, oldImageBase, newImageBase, offset, m_bMemAlign);
}

DWORD  PEedit::shiftOft(DWORD offset, bool bResetFt)
{
	return shiftOft(m_pPeBuf, offset, m_bMemAlign, bResetFt);
}

DWORD PEedit::appendSection(IMAGE_SECTION_HEADER newSectHeader, LPBYTE pSectBuf, DWORD newSectSize)
{
	DWORD addedSize = toAlign(newSectSize), newBufSize = 0;
	if (m_bMemAlign)
	{
		newBufSize = (newSectHeader.VirtualAddress > m_dwPeBufSize ? newSectHeader.VirtualAddress : m_dwPeBufSize) + addedSize;
	}
	else
	{
		newBufSize = (newSectHeader.PointerToRawData > m_dwPeBufSize ?newSectHeader.PointerToRawData : m_dwPeBufSize) + addedSize;
	}

	LPBYTE pTmp = new BYTE[newBufSize];
	memset(pTmp, 0, newBufSize);
	memcpy(pTmp, m_pPeBuf, m_dwPeBufSize);
	if (m_bMemAlloc) delete[] m_pPeBuf;
	m_bMemAlloc = true;
	m_pPeBuf = pTmp;
	m_dwPeBufSize = newBufSize;
	return appendSection(m_pPeBuf, newSectHeader, pSectBuf, newSectSize, m_bMemAlign);
}