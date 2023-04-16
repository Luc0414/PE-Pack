#pragma once
#include <fstream>
#include <functional>

#include "PEInfo.h"
#ifndef _PEEDIT_H
#define _PEEDIT_H

/* 继承 PEInfo */
class PEedit :public PEInfo {

public:
	/**
	 * @brief 添加覆盖区段到PE文件中
	 * @param path PE文件路径
	 * @param pOverlay 待添加的覆盖区段缓冲区指针
	 * @param size 待添加的覆盖区段大小（字节数）
	 * @return DWORD 添加的字节数，如果发生错误返回0
	 */
	static DWORD addOverlay(const char* path, LPBYTE pOverlay, DWORD size);
	/**
	 * @brief 设置 PE 文件的入口地址 RVA
	 * @param path PE 文件路径
	 * @param RVA 新的入口地址 RVA
	 * @return DWORD 返回旧的入口地址 RVA，如果设置失败则返回 0
	 */
	static DWORD setOepRva(const char * path,DWORD RVA);
	/**
	 * @brief 设置 PE 文件的入口地址 RVA
	 * @param pPeBuf PE 文件缓冲区指针
	 * @param RVA 新的入口地址 RVA
	 * @return DWORD 返回旧的入口地址 RVA，如果设置失败则返回 0
	*/
	static DWORD setOepRva(LPBYTE pPeBuf, DWORD RVA);
	/**
	 * @brief 在PE文件中移动重定位表项地址
	 * @param[in] pPeBuf PE文件缓冲区指针
	 * @param[in] oldImageBase 原始映像基址
	 * @param[in] newImageBase 新的映像基址
	 * @param[in] offset 移动偏移量
	 * @param[in] bMemAlign 是否进行内存对齐，默认为true
	 * @return DWORD 移动成功的重定位表项数量，失败返回0
	*/
	static DWORD shiftReloc(LPBYTE pPeBuf, size_t oldImageBase, size_t newImageBase, DWORD offset, bool bMemAlign = true);

	/**
	 * @brief 将PE文件导入表的RVA值和名称地址偏移指定的偏移量
	 * param pPeBuf PE文件缓冲区指针
	 * @param offset 偏移量
	 * @param bMemAlign 是否内存对齐
	 * @param bResetFt 是否重置FirstThunk表项
	 * @return DWORD 修改的函数个数
	*/
	static DWORD shiftOft(LPBYTE pPeBuf, DWORD offset, bool bMemAlign = true, bool bResetFt = true);
	/**
	 * @brief 在PE文件中添加一个新的节
	 * @param[in] pPeBuf PE文件缓冲区指针
	 * @param[in] newSectHeader 新的节表头
	 * @param[in] pNewSectBuf 新的节数据缓冲区指针
	 * @param[in] newSectSize 新的节数据缓冲区大小
	 * @param[in] bMemAlign 是否进行内存对齐，默认为true
	 * @return DWORD 添加成功的节的大小，失败返回0
	*/
	static DWORD appendSection(LPBYTE pPeBuf, IMAGE_SECTION_HEADER newSectHeader,LPBYTE pNewSectBuf, DWORD newSectSize, bool bMemAlign = true);
	/**
	 * @brief 在PE文件中删除指定的节的数据
	 * @param[in] pPeBuf PE文件缓冲区指针
	 * @param[in] removeNum 要删除的节的数量
	 * @param[in] removeIdx 要删除的节的索引数组
	 * @return DWORD 删除的字节数，失败返回0
	 */
	static DWORD removeSectionDatas(LPBYTE pPeBuf, int removeNum, int removeIdx[]);
	/**
	 * @brief 将PE文件保存到指定路径
	 * @param[in] path 保存路径
	 * @param[in] pFileBuf PE文件缓冲区指针
	 * @param[in] dwFileBufSize PE文件缓冲区大小
	 * @param[in] bMemAlign 是否进行内存对齐，默认为false
	 * @param[in] bShrinkPe 是否压缩PE文件大小，默认为true
	 * @param[in] pOverlayBuf 要添加的覆盖数据缓冲区指针，默认为NULL
	 * @param[in] OverlayBufSize 要添加的覆盖数据缓况区大小，默认为0
	 * @return DWORD 成功保存的字节数，失败返回0
	*/
	static DWORD savePeFile(const char* path, LPBYTE pFileBuf, DWORD dwFileBufSize,bool bMemAlign = false, bool bShrinkPe = true,LPBYTE pOverlayBuf = NULL, DWORD OverlayBufSize = 0);

public:
	/**
	* @brief 设置程序入口点地址（OEP）的 RVA。
	* @param rva OEP 的 RVA 值。
	* @return DWORD 返回设置的 RVA 值。
	*/
	DWORD setOepRva(DWORD rva);
	/**
	* @brief 将重定位表中的 RVA 值按照新旧镜像基址差值进行调整。
	* @param oldImageBase 旧镜像基址。
	* @param newImageBase 新镜像基址。
	* @param offset RVA 值的调整偏移量。
	* @return DWORD 移动成功的重定位表项数量，失败返回0
	*/
	DWORD shiftReloc(size_t oldImageBase, size_t newImageBase, DWORD offset);
	/**
	* @brief 将导入表中的 RVA 值按照偏移量进行调整。
	* @param offset RVA 值的调整偏移量。
	* @param bResetFt 是否重置 First Thunk 中的 RVA 值为新值。
	* @return DWORD 返回调整后的函数数量。
	*/
	DWORD shiftOft(DWORD offset, bool bResetFt = true);
	/**
	* @brief 在 PE 文件中添加新的节。
	* @param newSectHeader 新节的节头。
	* @param pNewSectBuf 新节的数据内容。
	* @param newSectSize 新节的数据大小。
	* @return DWORD 添加成功的节的大小，失败返回0
	*/
	DWORD appendSection(IMAGE_SECTION_HEADER newSectHeader,LPBYTE pNewSectBuf, DWORD newSectSize); 
	/**
	* @brief 删除 PE 文件中的指定数量的节。
	* @param removeNum 需要删除的节的数量。
	* @param removeIdx 需要删除的节的索引数组。
	* @return DWORD 删除的字节数，失败返回0
	*/
	DWORD removeSectionDatas(int removeNum, int removeIdx[]); 
	/**
	* @brief 将当前 PE 文件保存到指定路径。
	* @param path 保存文件的路径。
	* @param bShrinkPe 是否缩减 PE 文件尺寸。
	* @return DWORD 返回保存的字节数。
	*/
	DWORD savePeFile(const char* path, bool bShrinkPe = true); 
};

#endif