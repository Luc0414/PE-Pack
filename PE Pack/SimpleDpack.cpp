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

/* 参数是压缩类型 */
DWORD CSimpleDpack::packSection(int dpackSectionType) {
	switch (dpackSectionType)
	{
	case DPACK_SECTION_RAW:
	{
		break;
	}
	case DPACK_SECTION_DLZMA:
	{
		/* 压缩的数据大小 */
		DWORD allsize = 0;
		/* 获取需加壳的区块数量 */
		WORD sectNum = m_packpe.getSectionNum();
		/* 获取区块的Header */
		auto pSectHeader = m_packpe.getSectionHeader();

		/* 不进行压缩的区块索引 */
		int sectIdx = -1;
		/* 默认将所有区块进行压缩 */
		for (int i = 0; i < sectNum; i++)
		{
			m_packSectMap[i] = true;
		}
		/* rsrc,security,TLS,exception 目录表所在的区块不进行压缩 */
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

		/* 暂无使用 */
		m_dpackSectNum = 0;
		// 加壳各区段，压缩之后需要将原始的区块头信息存进DPACK_TMPBUF_ENTRY数据结构
		for (int i = 0; i < sectNum; i++)
		{
			/* 如何取压缩则跳过当前循环 */
			if (m_packSectMap[i] == false)
			{
				continue;
			}
			/* 获取需要压缩的区块的RVA或OFA */
			DWORD sectStartOffset = m_packpe.isMemAlign() ? pSectHeader[i].VirtualAddress : pSectHeader[i].PointerToRawData;
			/* 区块数据的开始位置 */
			LPBYTE pSrcBuf = m_packpe.getPeBuf() + sectStartOffset;
			/* 获取在内存时的数据大小 */
			DWORD srcSize = pSectHeader[i].Misc.VirtualSize;
			/* 压缩后的数据大小 */
			size_t packedSize = 0;
			/* 调用dlzmaPack对区块数据进行压缩，返回存储压缩后数据的指针 */
			LPBYTE pPacketBuf = dlzmaPack(pSrcBuf,srcSize,&packedSize);
			/* 等于0则说明压缩异常 */
			if (packedSize == 0)
			{
				std::cout << "error: dlzmaPack failed in section " << i << std::endl;
				return 0;
			}
			/* 压缩后的数据，压缩后的数据的大小，区块的内存RVA，区块链的内存大小，区块的内存属性 */
			addDpackTmpbufEntry(pPacketBuf, (DWORD)packedSize + sizeof(DLZMA_HEADER), pSectHeader[i].VirtualAddress, pSectHeader[i].Misc.VirtualSize, pSectHeader[i].Characteristics);
			/* 总压缩后数据大小 */
			allsize += (DWORD)packedSize;
		}
		/* 返回压缩后数据大小 */
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
	/* 返回压缩区块后的压缩大小 */
	DWORD packSize = packSection(dpackSectionType);
	/* 载入dll shellcode */
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

//处理外壳,若其他操作系统要重写,暂时不加64位功能
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