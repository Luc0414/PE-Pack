#include <Windows.h>
#include "dpackType.h"

/**
 * @brief 使用LZMA算法对输入数据进行压缩
 * @param pDstBuf 压缩后数据存放的目标缓冲区指针
 * @param pSrcBuf 需要压缩的原始数据缓冲区指针
 * @param srcSize 需要压缩的原始数据大小（单位：字节）
 * @return 返回压缩后的数据大小（单位：字节）
*/
size_t dlzmaPack(LPBYTE pDstBuf, LPBYTE pSrcBuf, size_t srcSize)
{
	size_t dstSize = -1;
	size_t propSize = sizeof(DLZMA_HEADER);
	PDLZMA_HEADER pDlzmah = (PDLZMA_HEADER)pDstBuf;
	LzmaCompress(pDstBuf + sizeof(DLZMA_HEADER), &dstSize, pSrcBuf, srcSize, pDlzmah->LzmaProps, (size_t*)&propSize, -1, 0, -1, -1, -1, -1, -1);
	pDlzmah->RawDataSize = srcSize;
	pDlzmah->DataSize = dstSize;
	return dstSize;
}