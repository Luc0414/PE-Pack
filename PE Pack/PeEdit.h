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
public:

};

#endif