#include "../lzmalib/LzmaLib.h"


#define MAX_DPACKSECTNUM 16 // 最多可pack区段数量
#define DPACK_SECTION_RAW 0
#define DPACK_SECTION_DLZMA 1

typedef struct _DLZMA_HEADER
{
	size_t RawDataSize;//原始数据尺寸(不含此头)
	size_t DataSize;//压缩后的数据大小
	unsigned char LzmaProps[LZMA_PROPS_SIZE];//原始lzma的文件头
}DLZMA_HEADER, * PDLZMA_HEADER;//此处外围添加适用于dpack的lzma头


/**
 * @brief 使用LZMA算法对输入数据进行压缩
 * @param pDstBuf 压缩后数据存放的目标缓冲区指针
 * @param pSrcBuf 需要压缩的原始数据缓冲区指针
 * @param srcSize 需要压缩的原始数据大小（单位：字节）
 * @return 返回压缩后的数据大小（单位：字节）
*/
size_t dlzmaPack(LPBYTE pDstBuf, LPBYTE pSrcBuf, size_t srcSize);

/**
 * @brief 解压Lzma压缩数据
 * @param pDstBuf 目标缓冲区指针
 * @param pSrcBuf 压缩数据缓冲区指针
 * @param srcSize 压缩数据大小
 * @return 解压后的数据大小
 */
size_t dlzmaUnpack(LPBYTE pDstBuf, LPBYTE pSrcBuf, size_t srcSize);