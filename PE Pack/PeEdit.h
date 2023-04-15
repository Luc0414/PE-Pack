#pragma once
#include <fstream>
#include <functional>

#include "PEInfo.h"
#ifndef _PEEDIT_H
#define _PEEDIT_H

/* �̳� PEInfo */
class PEedit :public PEInfo {

public:
	static DWORD addOverlay(const char* path, LPBYTE pOverlay, DWORD size);
	static DWORD setOepRva(const char * path,DWORD RVA);
	static DWORD setOepRva(LPBYTE pPeBuf, DWORD RVA);
	// ��reloc��¼�Լ�relocָ��ĵ�ַ���л�ַ�任
	static DWORD shiftReloc(LPBYTE pPeBuf, size_t oldImageBase, size_t newImageBase, DWORD offset, bool bMemAlign = true);
	// ��IAT���л�ַ�任, �����޸�iat����
	static DWORD shiftOft(LPBYTE pPeBuf, DWORD offset, bool bMemAlign = true, bool bResetFt = true);
	static DWORD appendSection(LPBYTE pPeBuf, IMAGE_SECTION_HEADER newSectHeader,LPBYTE pNewSectBuf, DWORD newSectSize, bool bMemAlign = true);
	// �Ƴ��������ݣ�����ɾ��������raw size�͡����Ƴ�header�ˣ���Ϊ�����м��п�϶����pe�������
	static DWORD removeSectionDatas(LPBYTE pPeBuf, int removeNum, int removeIdx[]);
	// ���������е����ε�����������ļ�
	static DWORD savePeFile(const char* path, 
		LPBYTE pFileBuf, DWORD dwFileBufSize,
		bool bMemAlign = false, bool bShrinkPe = true, // �Ƴ��հף���ȥ�����������Ĳ���
		LPBYTE pOverlayBuf = NULL, DWORD OverlayBufSize = 0);//ʧ�ܷ���0���ɹ�����д�����ֽ���

public:

};

#endif