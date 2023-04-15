#include "PeEdit.h"
#include <algorithm>
using namespace std;

/* �ѵ��� */
DWORD PEedit::addOverlay(const char* path, LPBYTE pOverlay, DWORD size) {
	if (pOverlay == NULL || size == 0) {
		return 0;
	}

	try {
		// RAII ģʽ�����ļ����
		// &foutΪstd::ofstream��[](std::ofstream* f) { f->close(); }Ϊ std::function<void(std::ofstream*)>
		std::unique_ptr<std::ofstream, std::function<void(std::ofstream*)>> foutGuard(
			new std::ofstream(path, ios_base::binary | ios_base::app),
			[](std::ofstream* f) { f->close(); });
		// std::ofstream ���󱻴��������ļ�ʱ���ļ�ָ���Ѿ������ļ���ĩβλ��
		foutGuard->write((const char*)pOverlay, size);
	}
	catch (const std::ios_base::failure& e) {
		return 0;
	}

	return size;
}

/* �ѵ��� */
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
	//ios::out������ļ���ios::app ÿ�ν���д�������ʱ�򶼻����¶�λ���ļ���ĩβ,ios::ate ���ļ�֮��������λ���ļ�ĩβ
	std::unique_ptr<std::ofstream, std::function<void(std::ofstream*)>> foutGuard(
		new std::ofstream(path, std::ios_base::binary | std::ios_base::ate | std::ios::in),
		[](std::ofstream* f) { f->close(); });

	foutGuard->seekp(0, ios_base::beg);
	foutGuard->write((const char*)buf, readsize);
	return oldrva;

}

/* �ѵ��� */
DWORD PEedit::setOepRva(LPBYTE pPeBuf, DWORD RVA) {
	if (pPeBuf == NULL) return 0;
	if (isPe(pPeBuf) <= 0) return 0;
	DWORD* pRVA = &GetOptionalHeader(pPeBuf)->AddressOfEntryPoint;
	DWORD oldrva = *pRVA;
	*pRVA = RVA;
	return oldrva;
}

/* δ���� */
DWORD PEedit::shiftReloc(LPBYTE pPeBuf, size_t oldImageBase, size_t newImageBase, DWORD offset, bool bMemAlign) {
	// �ض�λ�������е��ض�λ�������
	DWORD all_num = 0;
	// �Ѿ��������ض�λ�����ݴ�С
	DWORD sumsize = 0;
	// ��ȡ�ض�λ�������Ŀ¼
	auto pRelocEntry = &GetImageDataDirectory(pPeBuf)[IMAGE_DIRECTORY_ENTRY_BASERELOC];
	// �������е��ض�λ��
	while (sumsize < pRelocEntry->Size)
	{
		// ��ȡ��ǰ�ض�λ����׵�ַ
		auto pBaseRelocation = PIMAGE_BASE_RELOCATION(pPeBuf + sumsize + (bMemAlign ? pRelocEntry->VirtualAddress : rva2faddr(pPeBuf, pRelocEntry->VirtualAddress)));
		// ��ȡ��ǰ�ض�λ���е�����ƫ������
		auto pRelocOffset = (PRELOCOFFSET)((LPBYTE)pBaseRelocation + sizeof(IMAGE_BASE_RELOCATION));
		// ���㵱ǰ�ض�λ���е�ƫ����������
		DWORD item_num = (pBaseRelocation->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(RELOCOFFSET);
		// ������ǰ�ض�λ���е�����ƫ������
		for (size_t i = 0; i < item_num; i++) {
			if (!pRelocOffset[i].type && !pRelocOffset[i].Offset) {
				continue;
			}
			/* ��Ҫ�޸ĵ�RVA */
			DWORD toffset = pRelocOffset[i].Offset + pBaseRelocation->VirtualAddress;
			if (!bMemAlign) {
				// �����Ҫ����ƫ�Ƶ�ַ����RVAת��ΪFOA
				toffset = rva2faddr(pPeBuf, toffset);
			}
			// ȡ��Ҫ�޸�λ�õ�ֵ
			DWORD* pRelocAddr = reinterpret_cast<DWORD*>(pPeBuf + toffset);
			// �޸�VA,�»���ַ - �ɻ���ַ + �ǵĴ�С��������Ϊ�ڴ�ռ���˸��ǵĶΣ���ԭ�ļ����ڴ�ռ���䲻ͬ
			*pRelocAddr += newImageBase - oldImageBase + offset;
		}
		// �����ض�λ��������ַ
		pBaseRelocation->VirtualAddress += offset;
		// �����Ѿ��������ض�λ�����ݴ�С���ض�λ������
		sumsize += sizeof(PRELOCOFFSET) * item_num + sizeof(IMAGE_BASE_RELOCATION);
		all_num += item_num;
	}
	return all_num;

}

/* δ���� */
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

/* �ѵ��� */
DWORD PEedit::appendSection(LPBYTE pPeBuf, IMAGE_SECTION_HEADER newSectHeader, LPBYTE pNewSectBuf, DWORD newSectSize, bool bMemAlign) {
	// ����һ�����Σ���ȡ����������,�Ƚ�������������ֵ��oldSectNum��Ȼ���NumberOfSections + 1
	WORD oldSectNum = GetFileHeader(pPeBuf)->NumberOfSections++;
	// ��ȡ��ѡͷָ��
	auto pOptHeader = GetOptionalHeader(pPeBuf);
	// ��ȡ����ͷָ��
	auto pSectHeader = GetSectionHeader(pPeBuf);
	// ��ȡ�ļ������С
	DWORD fileAlign = pOptHeader->FileAlignment;
	// ��ȡ�ڴ�����С
	DWORD memAlign = pOptHeader->SectionAlignment;

	// ��������ε�SizeOfRawData�ֶ�Ϊ0��������Ϊ��fileAlign�����newSectSize
	if (!newSectHeader.SizeOfRawData) {
		newSectHeader.SizeOfRawData = toAlign(newSectSize, fileAlign);
	}
	// ��������ε�Misc.VirtualSize�ֶ�Ϊ0��������ΪnewSectSize
	if (!newSectHeader.Misc.VirtualSize) {
		newSectHeader.Misc.VirtualSize = newSectSize;
	}
	// ��������ε�PointerToRawData�ֶ�Ϊ0��������Ϊ��һ�����ε�PointerToRawData������һ�����ε�SizeOfRawData����fileAlign����
	if (!newSectHeader.PointerToRawData) {
		newSectHeader.PointerToRawData = toAlign(pSectHeader[oldSectNum - 1].PointerToRawData + pSectHeader[oldSectNum - 1].SizeOfRawData, fileAlign);
	}
	else {
		// ���ָ����PointerToRawDataС����һ�����ε�PointerToRawData������һ�����ε�SizeOfRawData���޷���ӣ�����0
		if (newSectHeader.PointerToRawData < pSectHeader[oldSectNum - 1].PointerToRawData + toAlign(pSectHeader[oldSectNum - 1].SizeOfRawData, fileAlign)) {
			return 0;
		}
	}
	// ��������ε�VirtualAddress�ֶ�Ϊ0��������Ϊ��һ�����ε�VirtualAddress������һ�����ε�SizeOfRawData����memAlign����
	if (!newSectHeader.VirtualAddress) {
		newSectHeader.VirtualAddress = toAlign(pSectHeader[oldSectNum - 1].VirtualAddress + pSectHeader[oldSectNum - 1].SizeOfRawData, memAlign);
	}
	else {
		// ���ָ����VirtualAddressС����һ�����ε�VirtualAddress������һ�����ε�Misc.VirtualSize���޷���ӣ�����0
		if (newSectHeader.VirtualAddress < pSectHeader[oldSectNum - 1].VirtualAddress + toAlign(pSectHeader[oldSectNum - 1].Misc.VirtualSize, memAlign)) {
			return 0;
		}
		// �޸�ǰһ�����ε�Misc.VirtualSizeʹ���ڴ���û�п�϶
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

/* �ѵ��� */
DWORD PEedit::removeSectionDatas(LPBYTE pPeBuf, int removeNum, int removeIdx[]) {
	// ��ȡ�ļ�ͷָ�룬���а����ļ�ͷ��Ϣ�Ϳ�ѡͷ��Ϣ
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
				// ����һ���ڵĵ�ַ����Ϊɾ���ڵĵ�ַ
				pSectHeader[i + 1].PointerToRawData = pSectHeader[i].PointerToRawData;
			}
			tmpidx++;
		}
	}

	return decreseRawSize;
}

/* Ŀǰ���쳣 */
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

	// д�������
	for (int i = 0; i < GetFileHeader(pPeBuf)->NumberOfSections; i++) {
		DWORD sectOffset = bMemAlign ? pSecHeader[i].VirtualAddress : pSecHeader[i].PointerToRawData;
		DWORD sectsize = toAlign(pSecHeader[i].SizeOfRawData, pOptionalHeader->FileAlignment);

		auto cur = fout->tellp();//��ֹ��ַ����
		if (cur > pSecHeader[i].PointerToRawData) //��ֹ�ص�
		{
			fout->seekp(pSecHeader[i].PointerToRawData);
		}
		else if (cur < pSecHeader[i].PointerToRawData) 
		{
			/* ���bShrinkPeΪtrue����ֱ�Ӹ���pSecHeader[i].PointerToRawData���Ա������ļ���С��*/
			if (bShrinkPe)
			{
				pSecHeader[i].PointerToRawData = (DWORD)cur;
			}
			// ���bShrinkPeΪfalse����ʹ��ѭ������ֽ�����֤�ļ���С���䡣
			else
			{
				for (std::streamoff j = cur; j < pSecHeader[i].PointerToRawData; j++) fout->put(0);
			}
		}

		fout->write((const char*)(pPeBuf + sectOffset), sectsize);
		writesize += sectsize;
	}
	// д�븽�Ӷ�
	if (pOverlayBuf != NULL && OverlayBufSize != 0)
	{
		fout->write((const char*)pOverlayBuf, OverlayBufSize);
		writesize += OverlayBufSize;
	}

	//����д��������PEͷ
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