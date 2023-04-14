#include "PeEdit.h"
#include <fstream>
#include <functional>
using namespace std;

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
	//ios::out������ļ���ios::appÿ��д���������ios::ate������seekp
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