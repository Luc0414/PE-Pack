#include <Windows.h>
#include "dpackType.h"


/**
 * @brief 解压Lzma压缩数据
 * @param pDstBuf 目标缓冲区指针
 * @param pSrcBuf 压缩数据缓冲区指针
 * @param srcSize 压缩数据大小
 * @return 解压后的数据大小
 */
size_t dlzmaUnpack(LPBYTE pDstBuf, LPBYTE pSrcBuf, size_t srcSize)
{
	// 获取Lzma头指针
	PDLZMA_HEADER pdlzmah = (PDLZMA_HEADER)pSrcBuf;
	// 获取目标缓冲区大小，即原始数据大小
	size_t dstSize = pdlzmah->RawDataSize;
	// 解压数据
	LzmaUncompress(pDstBuf, &dstSize, pSrcBuf + sizeof(DLZMA_HEADER), &srcSize, pdlzmah->LzmaProps, LZMA_PROPS_SIZE);
	// 返回解压后的数据大小
	return dstSize;
}