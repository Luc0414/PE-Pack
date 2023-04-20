#include <Windows.h>
#include "dpackType.h"

// 使用Lzma压缩算法对源数据进行压缩，将压缩结果写入目标缓冲区
// 参数：
//    pDstBuf - 目标缓冲区
//    pSrcBuf - 源数据缓冲区
//    srcSize - 源数据缓冲区大小
// 返回值：
//    返回压缩后的数据大小
size_t dlzmaPack(LPBYTE pDstBuf, LPBYTE pSrcBuf, size_t srcSize)
{
	// 目标缓冲区大小，初始化为-1，表示最大缓冲区大小
	size_t dstSize = -1;
	// Lzma压缩参数大小，初始化为dpack的Lzma头大小
	size_t propSize = sizeof(DLZMA_HEADER);
	// 获取目标缓冲区的Lzma头指针
	PDLZMA_HEADER pDlzmah = (PDLZMA_HEADER)pDstBuf;
	// 调用Lzma压缩函数进行压缩
	LzmaCompress(pDstBuf + sizeof(DLZMA_HEADER), &dstSize, pSrcBuf, srcSize, pDlzmah->LzmaProps, (size_t*)&propSize, -1, 0, -1, -1, -1, -1, -1);
	// 更新Lzma头中的原始数据大小
	pDlzmah->RawDataSize = srcSize;
	// 更新Lzma头中的压缩后数据大小
	pDlzmah->DataSize = dstSize;
	// 返回压缩后的数据大小
	return dstSize;
}