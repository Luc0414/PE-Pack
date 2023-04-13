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