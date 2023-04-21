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
	pDstBuf = new BYTE[dstSize]; //防止分配缓存区空间过小
	::dlzmaUnpack(pDstBuf, pSrcBuf, srcSize); // 此处要特别注意，缓存区尺寸
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

DWORD CSimpleDpack::packSection(int dpackSectionType) {
	switch (dpackSectionType)
	{
	case DPACK_SECTION_RAW:
	{
		break;
	}
	case DPACK_SECTION_DLZMA:
	{
		DWORD allsize = 0;
		WORD sectNum = m_packpe.getSectionNum();
		auto pSectHeader = m_packpe.getSectionHeader();

		int sectIdx = -1;
		for (int i = 0; i < sectNum; i++)
		{
			m_packSectMap[i] = true;
		}

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
	}
	default:
		break;
	}

}
DWORD CSimpleDpack::packPe(const char* dllpath, int dpackSectionType) {
	if (m_packpe.getPeBuf() == NULL) return 0;
	initDpackTmpbuf();
	DWORD packSize =
}