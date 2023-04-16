#pragma once
#include <fstream>
#include <functional>

#include "PEInfo.h"
#ifndef _PEEDIT_H
#define _PEEDIT_H

/* �̳� PEInfo */
class PEedit :public PEInfo {

public:
	/**
	 * @brief ��Ӹ������ε�PE�ļ���
	 * @param path PE�ļ�·��
	 * @param pOverlay ����ӵĸ������λ�����ָ��
	 * @param size ����ӵĸ������δ�С���ֽ�����
	 * @return DWORD ��ӵ��ֽ���������������󷵻�0
	 */
	static DWORD addOverlay(const char* path, LPBYTE pOverlay, DWORD size);
	/**
	 * @brief ���� PE �ļ�����ڵ�ַ RVA
	 * @param path PE �ļ�·��
	 * @param RVA �µ���ڵ�ַ RVA
	 * @return DWORD ���ؾɵ���ڵ�ַ RVA���������ʧ���򷵻� 0
	 */
	static DWORD setOepRva(const char * path,DWORD RVA);
	/**
	 * @brief ���� PE �ļ�����ڵ�ַ RVA
	 * @param pPeBuf PE �ļ�������ָ��
	 * @param RVA �µ���ڵ�ַ RVA
	 * @return DWORD ���ؾɵ���ڵ�ַ RVA���������ʧ���򷵻� 0
	*/
	static DWORD setOepRva(LPBYTE pPeBuf, DWORD RVA);
	/**
	 * @brief ��PE�ļ����ƶ��ض�λ�����ַ
	 * @param[in] pPeBuf PE�ļ�������ָ��
	 * @param[in] oldImageBase ԭʼӳ���ַ
	 * @param[in] newImageBase �µ�ӳ���ַ
	 * @param[in] offset �ƶ�ƫ����
	 * @param[in] bMemAlign �Ƿ�����ڴ���룬Ĭ��Ϊtrue
	 * @return DWORD �ƶ��ɹ����ض�λ����������ʧ�ܷ���0
	*/
	static DWORD shiftReloc(LPBYTE pPeBuf, size_t oldImageBase, size_t newImageBase, DWORD offset, bool bMemAlign = true);

	/**
	 * @brief ��PE�ļ�������RVAֵ�����Ƶ�ַƫ��ָ����ƫ����
	 * param pPeBuf PE�ļ�������ָ��
	 * @param offset ƫ����
	 * @param bMemAlign �Ƿ��ڴ����
	 * @param bResetFt �Ƿ�����FirstThunk����
	 * @return DWORD �޸ĵĺ�������
	*/
	static DWORD shiftOft(LPBYTE pPeBuf, DWORD offset, bool bMemAlign = true, bool bResetFt = true);
	/**
	 * @brief ��PE�ļ������һ���µĽ�
	 * @param[in] pPeBuf PE�ļ�������ָ��
	 * @param[in] newSectHeader �µĽڱ�ͷ
	 * @param[in] pNewSectBuf �µĽ����ݻ�����ָ��
	 * @param[in] newSectSize �µĽ����ݻ�������С
	 * @param[in] bMemAlign �Ƿ�����ڴ���룬Ĭ��Ϊtrue
	 * @return DWORD ��ӳɹ��ĽڵĴ�С��ʧ�ܷ���0
	*/
	static DWORD appendSection(LPBYTE pPeBuf, IMAGE_SECTION_HEADER newSectHeader,LPBYTE pNewSectBuf, DWORD newSectSize, bool bMemAlign = true);
	/**
	 * @brief ��PE�ļ���ɾ��ָ���Ľڵ�����
	 * @param[in] pPeBuf PE�ļ�������ָ��
	 * @param[in] removeNum Ҫɾ���Ľڵ�����
	 * @param[in] removeIdx Ҫɾ���Ľڵ���������
	 * @return DWORD ɾ�����ֽ�����ʧ�ܷ���0
	 */
	static DWORD removeSectionDatas(LPBYTE pPeBuf, int removeNum, int removeIdx[]);
	/**
	 * @brief ��PE�ļ����浽ָ��·��
	 * @param[in] path ����·��
	 * @param[in] pFileBuf PE�ļ�������ָ��
	 * @param[in] dwFileBufSize PE�ļ���������С
	 * @param[in] bMemAlign �Ƿ�����ڴ���룬Ĭ��Ϊfalse
	 * @param[in] bShrinkPe �Ƿ�ѹ��PE�ļ���С��Ĭ��Ϊtrue
	 * @param[in] pOverlayBuf Ҫ��ӵĸ������ݻ�����ָ�룬Ĭ��ΪNULL
	 * @param[in] OverlayBufSize Ҫ��ӵĸ������ݻ�������С��Ĭ��Ϊ0
	 * @return DWORD �ɹ�������ֽ�����ʧ�ܷ���0
	*/
	static DWORD savePeFile(const char* path, LPBYTE pFileBuf, DWORD dwFileBufSize,bool bMemAlign = false, bool bShrinkPe = true,LPBYTE pOverlayBuf = NULL, DWORD OverlayBufSize = 0);

public:
	/**
	* @brief ���ó�����ڵ��ַ��OEP���� RVA��
	* @param rva OEP �� RVA ֵ��
	* @return DWORD �������õ� RVA ֵ��
	*/
	DWORD setOepRva(DWORD rva);
	/**
	* @brief ���ض�λ���е� RVA ֵ�����¾ɾ����ַ��ֵ���е�����
	* @param oldImageBase �ɾ����ַ��
	* @param newImageBase �¾����ַ��
	* @param offset RVA ֵ�ĵ���ƫ������
	* @return DWORD �ƶ��ɹ����ض�λ����������ʧ�ܷ���0
	*/
	DWORD shiftReloc(size_t oldImageBase, size_t newImageBase, DWORD offset);
	/**
	* @brief ��������е� RVA ֵ����ƫ�������е�����
	* @param offset RVA ֵ�ĵ���ƫ������
	* @param bResetFt �Ƿ����� First Thunk �е� RVA ֵΪ��ֵ��
	* @return DWORD ���ص�����ĺ���������
	*/
	DWORD shiftOft(DWORD offset, bool bResetFt = true);
	/**
	* @brief �� PE �ļ�������µĽڡ�
	* @param newSectHeader �½ڵĽ�ͷ��
	* @param pNewSectBuf �½ڵ��������ݡ�
	* @param newSectSize �½ڵ����ݴ�С��
	* @return DWORD ��ӳɹ��ĽڵĴ�С��ʧ�ܷ���0
	*/
	DWORD appendSection(IMAGE_SECTION_HEADER newSectHeader,LPBYTE pNewSectBuf, DWORD newSectSize); 
	/**
	* @brief ɾ�� PE �ļ��е�ָ�������Ľڡ�
	* @param removeNum ��Ҫɾ���Ľڵ�������
	* @param removeIdx ��Ҫɾ���Ľڵ��������顣
	* @return DWORD ɾ�����ֽ�����ʧ�ܷ���0
	*/
	DWORD removeSectionDatas(int removeNum, int removeIdx[]); 
	/**
	* @brief ����ǰ PE �ļ����浽ָ��·����
	* @param path �����ļ���·����
	* @param bShrinkPe �Ƿ����� PE �ļ��ߴ硣
	* @return DWORD ���ر�����ֽ�����
	*/
	DWORD savePeFile(const char* path, bool bShrinkPe = true); 
};

#endif