#pragma once
#include <fstream>
#include <functional>

#include "PEInfo.h"
#ifndef _PEEDIT_H
#define _PEEDIT_H

/* 继承 PEInfo */
class PEedit :public PEInfo {

public:
	static DWORD addOverlay(const char* path, LPBYTE pOverlay, DWORD size);
	static DWORD setOepRva(const char * path,DWORD RVA);
	static DWORD setOepRva(LPBYTE pPeBuf, DWORD RVA);
	// 将reloc记录以及reloc指向的地址进行基址变换
	static DWORD shiftReloc(LPBYTE pPeBuf, size_t oldImageBase, size_t newImageBase, DWORD offset, bool bMemAlign = true);
	// 将IAT进行基址变换, 返回修改iat数量
	static DWORD shiftOft(LPBYTE pPeBuf, DWORD offset, bool bMemAlign = true, bool bResetFt = true);
	static DWORD appendSection(LPBYTE pPeBuf, IMAGE_SECTION_HEADER newSectHeader,LPBYTE pNewSectBuf, DWORD newSectSize, bool bMemAlign = true);
	// 移除区段数据，返回删除的区段raw size和。不移除header了，因为区段中间有空隙加载pe会出问题
	static DWORD removeSectionDatas(LPBYTE pPeBuf, int removeNum, int removeIdx[]);
	// 将缓存区中的区段调整并保存成文件
	static DWORD savePeFile(const char* path, 
		LPBYTE pFileBuf, DWORD dwFileBufSize,
		bool bMemAlign = false, bool bShrinkPe = true, // 移除空白，如去掉区段索引的部分
		LPBYTE pOverlayBuf = NULL, DWORD OverlayBufSize = 0);//失败返回0，成功返回写入总字节数

public:

};

#endif