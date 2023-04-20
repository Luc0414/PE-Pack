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