#include <Windows.h>
#include "PeEdit.h"
#include <Psapi.h>	
#include "../lzmalib/LzmaLib.h"
#include "dpackType.h"

extern "C" // c++中引用c必须要这样
{
#include <Psapi.h>	
#include "dpackType.h"
}
#ifndef _SIMPLEDPACK_H
#define _SIMPLEDPACK_H

typedef struct _DPACK_TMPBUF_ENTRY {
	LPBYTE PackedBuf;
	DWORD DpackSize;
	DWORD OrgRva;
	DWORD OrgMemSize;
	DWORD Characteristics;
}DPACK_TMPBUF_ENTRY, * PDPACK_TMPBUF_ENTRY;

class CSimpleDpack {
public:
	/**
	 * @brief 使用LZMA算法对输入缓冲区进行压缩，并返回压缩后的数据
	 * @param pSrcBuf 输入缓冲区指针
	 * @param srcSize 输入缓冲区大小
	 * @param pDstSize 压缩后数据大小
	 * @param maxmul 最大倍数，用于控制目标缓冲区大小，根据实际情况调整
	 * @return LPBYTE 返回压缩后的数据，调用方负责释放内存
	*/
	static LPBYTE dlzmaPack(LPBYTE pSrcBuf, size_t srcSize, size_t* pDstSize, double maxmul = 2.0);
	/**
	 * @brief 解压缩 Lzma 压缩数据
	 *
	 * @param pSrcBuf 压缩数据缓冲区指针
	 * @param srcSize 压缩数据大小
	 * @return LPBYTE 解压缩后的数据缓冲区指针，若解压失败则返回 NULL
	 */
	static LPBYTE dlzmaUnpack(LPBYTE pSrcBuf, size_t srcSize);
private:
	char m_strFilePath[MAX_PATH];
protected:
	/* 需要加壳的PE结构 */
	PEedit m_packpe;
	/* 壳的PE结构 */
	PEedit m_shellpe;

	/* 初始化 m_dpackTmpbuf */
	WORD initDpackTmpbuf();
	/* 加壳区段临时缓冲区 */
	DPACK_TMPBUF_ENTRY m_dpackTmpbuf[MAX_DPACKSECTNUM];

	PDPACK_SHELL_INDEX m_pShellIndex; // dll中的导出结构
	HMODULE m_hShell; // 壳dll的句柄
	WORD m_dpackSectNum;

	bool m_packSectMap[MAX_DPACKSECTNUM]; // 区段是否被压缩map

	DWORD packSection(int type = DPACK_SECTION_DLZMA);	//pack各区段
public:
	CSimpleDpack(){iniValue();}
	CSimpleDpack(char* path);
	virtual ~CSimpleDpack(){release();}
	void iniValue();
	virtual	void release();
	DWORD loadPeFile(const char* path); //加载pe文件，返回isPE()值
	DWORD packPe(const char* dllpath, int type = DPACK_SECTION_DLZMA); // 加壳，失败返回0，成功返回pack数据大小
};
#endif