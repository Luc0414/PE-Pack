#include "SimpleDpack.h"

#pragma comment(lib,"lzmalib.lib")

LPBYTE CSimpleDpack::dlzmaPack(LPBYTE pSrcBuf, size_t srcSize, size_t* pDstSize, double maxmul) {
	if (pSrcBuf == NULL) return 0;
	LPBYTE pDstBuf = NULL;
	size_t dstSize = 0;
	for (double m = 1; m <= maxmul; m += 0.1) {
		pDstBuf = new BYTE[(size_t)(m * (double)srcSize + sizeof(DLZMA_HEADER))];
		dstSize = ::D
	}
}

LPBYTE CSimpleDpack::dlzmaUnpack(LPBYTE pSrcBuf, size_t srcSize) {

}