#include <Windows.h>
#include "dpackType.h"
size_t dlzmaUnpack(LPBYTE pDstBuf, LPBYTE pSrcBuf, size_t srcSize)
{
	PDLZMA_HEADER pdlzmah = (PDLZMA_HEADER)pSrcBuf;
	size_t dstSize = pdlzmah->RawDataSize;
	LzmaUncompress(pDstBuf, &dstSize,pSrcBuf + sizeof(DLZMA_HEADER), &srcSize,pdlzmah->LzmaProps, LZMA_PROPS_SIZE);
	return dstSize;
}