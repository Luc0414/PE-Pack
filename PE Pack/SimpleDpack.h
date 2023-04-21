#include <Windows.h>
#include "PeEdit.h"
#include <Psapi.h>	
#include <iostream>
#include "../lzmalib/LzmaLib.h"
#include "dpackType.h"

extern "C" // c++������c����Ҫ����
{
#include <Psapi.h>	
#include "dpackType.h"
}
#ifndef _SIMPLEDPACK_H
#define _SIMPLEDPACK_H

typedef struct _DPACK_TMPBUF_ENTRY {
	/* ѹ��������� */
	LPBYTE PackedBuf;
	/* ѹ��������ݴ�С */
	DWORD DpackSize;
	/* ѹ��ǰ��RVA��ַ */
	DWORD OrgRva;
	/* ѹ��ǰ���ڴ��С */
	DWORD OrgMemSize;
	/* ѹ��ǰ���ڴ�ҳ���� */
	DWORD Characteristics;
}DPACK_TMPBUF_ENTRY, * PDPACK_TMPBUF_ENTRY;

class CSimpleDpack {
public:
	/**
	 * @brief ʹ��LZMA�㷨�����뻺��������ѹ����������ѹ���������
	 * @param pSrcBuf ���뻺����ָ��
	 * @param srcSize ���뻺������С
	 * @param pDstSize ѹ�������ݴ�С
	 * @param maxmul ����������ڿ���Ŀ�껺������С������ʵ���������
	 * @return LPBYTE ����ѹ��������ݣ����÷������ͷ��ڴ�
	*/
	static LPBYTE dlzmaPack(LPBYTE pSrcBuf, size_t srcSize, size_t* pDstSize, double maxmul = 2.0);
	/**
	 * @brief ��ѹ�� Lzma ѹ������
	 *
	 * @param pSrcBuf ѹ�����ݻ�����ָ��
	 * @param srcSize ѹ�����ݴ�С
	 * @return LPBYTE ��ѹ��������ݻ�����ָ�룬����ѹʧ���򷵻� NULL
	 */
	static LPBYTE dlzmaUnpack(LPBYTE pSrcBuf, size_t srcSize);
private:
	char m_strFilePath[MAX_PATH];
protected:
	/* ��Ҫ�ӿǵ�PE�ṹ */
	PEedit m_packpe;
	/* �ǵ�PE�ṹ */
	PEedit m_shellpe;

	/* ��ʼ�� m_dpackTmpbuf */
	WORD initDpackTmpbuf();
	/* �ӿ�������ʱ������,����δ�ӿ�ǰ����ͷ����Ϣ */
	DPACK_TMPBUF_ENTRY m_dpackTmpbuf[MAX_DPACKSECTNUM];

	PDPACK_SHELL_INDEX m_pShellIndex; // dll�еĵ����ṹ
	HMODULE m_hShell; // ��dll�ľ��
	/* �ӿǵ��������� */
	WORD m_dpackSectNum;

	bool m_packSectMap[MAX_DPACKSECTNUM]; // �����Ƿ�ѹ��map

	DWORD packSection(int type = DPACK_SECTION_DLZMA);	//pack������
	DWORD loadShellDll(const char* dllpath);	//�������, return dll size

	WORD addDpackTmpbufEntry(LPBYTE packBuf, DWORD packBufSize,DWORD srcRva = 0, DWORD OrgMemSize = 0, DWORD Characteristics = 0xE0000000);//����dpack����
public:
	CSimpleDpack(){iniValue();}
	CSimpleDpack(char* path);
	virtual ~CSimpleDpack(){release();}
	void iniValue();
	virtual	void release();
	DWORD loadPeFile(const char* path); //����pe�ļ�������isPE()ֵ
	DWORD packPe(const char* dllpath, int type = DPACK_SECTION_DLZMA); // �ӿǣ�ʧ�ܷ���0���ɹ�����pack���ݴ�С
};
#endif