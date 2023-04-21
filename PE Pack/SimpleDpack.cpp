#include "SimpleDpack.h"


LPBYTE CSimpleDpack::dlzmaPack(LPBYTE pSrcBuf, size_t srcSize, size_t* pDstSize, double maxmul) {
	if (pSrcBuf == NULL) return 0;
	LPBYTE pDstBuf = NULL;
	size_t dstSize = 0;
	for (double m = 1; m <= maxmul; m += 0.1) {
		pDstBuf = new BYTE[(size_t)(m * (double)srcSize + sizeof(DLZMA_HEADER))];
		dstSize = ::dlzmaPack(pDstBuf, pSrcBuf, srcSize);
		if (dstSize > 0) break;
		delete[] pDstBuf;
	}
	if (pDstSize != NULL) *pDstSize = dstSize;
	if (dstSize == 0) {
		delete[] pDstBuf;
		pDstBuf = NULL;
	}
	return pDstBuf;
}

LPBYTE CSimpleDpack::dlzmaUnpack(LPBYTE pSrcBuf, size_t srcSize) {
	if (pSrcBuf == NULL) return 0;
	LPBYTE pDstBuf = NULL;
	auto pDlzmaHeader = (PDLZMA_HEADER)(pSrcBuf);
	size_t dstSize = pDlzmaHeader->RawDataSize;
	pDstBuf = new BYTE[dstSize]; //��ֹ���仺�����ռ��С
	::dlzmaUnpack(pDstBuf, pSrcBuf, srcSize); // �˴�Ҫ�ر�ע�⣬�������ߴ�
	return pDstBuf;
}

void CSimpleDpack::iniValue() {
	memset(m_strFilePath, 0, MAX_PATH);
	memset(m_packSectMap, 0, sizeof(m_packSectMap));
	m_hShell = NULL;
	m_pShellIndex = NULL;
	m_dpackSectNum = 0;
}

CSimpleDpack::CSimpleDpack(char* path) :CSimpleDpack() {
	loadPeFile(path);
}

void CSimpleDpack::release()
{
	initDpackTmpbuf();
	m_packpe.closePeFile();
	m_shellpe.closePeFile();
	if (m_hShell != NULL) FreeLibrary((HMODULE)m_hShell);
}

DWORD CSimpleDpack::loadPeFile(const char* path) {
	DWORD res = m_packpe.openPeFile(path);
	return res;
}

WORD CSimpleDpack::initDpackTmpbuf() {
	WORD oldDpackSectNum = m_dpackSectNum;
	if (m_dpackSectNum != 0)
	{
		for (int i = 0; i < m_dpackSectNum; i++) {
			if (m_dpackTmpbuf[i].PackedBuf != NULL && m_dpackTmpbuf[i].DpackSize != 0) {
				delete[] m_dpackTmpbuf[i].PackedBuf;
			}
		}
	}
	m_dpackSectNum = 0;
	memset(m_dpackTmpbuf, 0, sizeof(m_dpackTmpbuf));
	return oldDpackSectNum;
}

/* ������ѹ������ */
DWORD CSimpleDpack::packSection(int dpackSectionType) {
	switch (dpackSectionType)
	{
	case DPACK_SECTION_RAW:
	{
		break;
	}
	case DPACK_SECTION_DLZMA:
	{
		/* ѹ�������ݴ�С */
		DWORD allsize = 0;
		/* ��ȡ��ӿǵ��������� */
		WORD sectNum = m_packpe.getSectionNum();
		/* ��ȡ�����Header */
		auto pSectHeader = m_packpe.getSectionHeader();

		/* ������ѹ������������ */
		int sectIdx = -1;
		/* Ĭ�Ͻ������������ѹ�� */
		for (int i = 0; i < sectNum; i++)
		{
			m_packSectMap[i] = true;
		}
		/* rsrc,security,TLS,exception Ŀ¼�����ڵ����鲻����ѹ�� */
		/* rsrc */
		sectIdx = m_packpe.findRvaSectIdx(m_packpe.getImageDataDirectory()[IMAGE_DIRECTORY_ENTRY_RESOURCE].VirtualAddress);
		if (sectIdx != -1) {
			m_packSectMap[sectIdx] = false;
		}
		/* security */
		sectIdx = m_packpe.findRvaSectIdx(m_packpe.getImageDataDirectory()[IMAGE_DIRECTORY_ENTRY_SECURITY].VirtualAddress);
		if (sectIdx != -1) {
			m_packSectMap[sectIdx] = false;
		}
		/* TLS */
		sectIdx = m_packpe.findRvaSectIdx(m_packpe.getImageDataDirectory()[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress);
		if (sectIdx != -1) {
			m_packSectMap[sectIdx] = false;
		}
		/* exception */
		sectIdx = m_packpe.findRvaSectIdx(m_packpe.getImageDataDirectory()[IMAGE_DIRECTORY_ENTRY_EXCEPTION].VirtualAddress);
		if (sectIdx != -1) {
			m_packSectMap[sectIdx] = false;
		}

		/* ����ʹ�� */
		m_dpackSectNum = 0;
		// �ӿǸ����Σ�ѹ��֮����Ҫ��ԭʼ������ͷ��Ϣ���DPACK_TMPBUF_ENTRY���ݽṹ
		for (int i = 0; i < sectNum; i++)
		{
			/* ���ȡѹ����������ǰѭ�� */
			if (m_packSectMap[i] == false)
			{
				continue;
			}
			/* ��ȡ��Ҫѹ���������RVA��OFA */
			DWORD sectStartOffset = m_packpe.isMemAlign() ? pSectHeader[i].VirtualAddress : pSectHeader[i].PointerToRawData;
			/* �������ݵĿ�ʼλ�� */
			LPBYTE pSrcBuf = m_packpe.getPeBuf() + sectStartOffset;
			/* ��ȡ���ڴ�ʱ�����ݴ�С */
			DWORD srcSize = pSectHeader[i].Misc.VirtualSize;
			/* ѹ��������ݴ�С */
			size_t packedSize = 0;
			/* ����dlzmaPack���������ݽ���ѹ�������ش洢ѹ�������ݵ�ָ�� */
			LPBYTE pPacketBuf = dlzmaPack(pSrcBuf,srcSize,&packedSize);
			/* ����0��˵��ѹ���쳣 */
			if (packedSize == 0)
			{
				std::cout << "error: dlzmaPack failed in section " << i << std::endl;
				return 0;
			}
			/* ѹ��������ݣ�ѹ��������ݵĴ�С��������ڴ�RVA�����������ڴ��С��������ڴ����� */
			addDpackTmpbufEntry(pPacketBuf, (DWORD)packedSize + sizeof(DLZMA_HEADER), pSectHeader[i].VirtualAddress, pSectHeader[i].Misc.VirtualSize, pSectHeader[i].Characteristics);
			/* ��ѹ�������ݴ�С */
			allsize += (DWORD)packedSize;
		}
		/* ����ѹ�������ݴ�С */
		return allsize;
	}
	default:
		break;
	}
	return 0;
}
DWORD CSimpleDpack::packPe(const char* dllpath, int dpackSectionType) {
	if (m_packpe.getPeBuf() == NULL) return 0;
	initDpackTmpbuf();
	/* ����ѹ��������ѹ����С */
	DWORD packSize = packSection(dpackSectionType);
	/* ����dll shellcode */
	DWORD shellsize = loadShellDll(dllpath);
}

/* */
WORD CSimpleDpack::addDpackTmpbufEntry(LPBYTE packBuf, DWORD packBufSize, DWORD srcRva, DWORD OrgMemSize, DWORD Characteristics)
{
	m_dpackTmpbuf[m_dpackSectNum].PackedBuf = packBuf;
	m_dpackTmpbuf[m_dpackSectNum].DpackSize = packBufSize;
	m_dpackTmpbuf[m_dpackSectNum].OrgRva = srcRva;
	m_dpackTmpbuf[m_dpackSectNum].OrgMemSize = OrgMemSize;
	m_dpackTmpbuf[m_dpackSectNum].Characteristics = Characteristics;
	m_dpackSectNum++;
	return m_dpackSectNum;
}

//�������,����������ϵͳҪ��д,��ʱ����64λ����
DWORD CSimpleDpack::loadShellDll(const char* dllpath)
{
	m_hShell = LoadLibraryA(dllpath);
	printf("simpledpachshell64.dll load at %016lX\n",(unsigned long)m_hShell);
	MODULEINFO meminfo = { 0 };
	GetModuleInformation(GetCurrentProcess(), m_hShell, &meminfo, sizeof(MODULEINFO));
	m_shellpe.attachPeBuf((LPBYTE)m_hShell, meminfo.SizeOfImage, true);
	m_pShellIndex = (PDPACK_SHELL_INDEX)(m_shellpe.getPeBuf() + (size_t)GetProcAddress(m_hShell, "g_dpackShellIndex") - (size_t)m_hShell);
	return meminfo.SizeOfImage;

}