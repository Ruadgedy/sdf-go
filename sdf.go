package sdf_go

/*
#cgo linux LDFLAGS: -ldasdf -ldtcsp -ldtrtl -lpthread -ldl
#cgo darwin LDFLAGS: -ldl
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <pthread.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/time.h>
#include <unistd.h>
#include <signal.h>
#include <math.h>
#include "dasdf_api.h"

//typedef unsigned char SGD_UCHAR;
typedef unsigned char* SGD_UCHAR_PRT;

int rv = 0;
void *phDev = NULL, *phSession = NULL;

// 1. 打开设备
int SDFOpenDevice(SGD_HANDLE *dH)
{
	rv = SDF_OpenDevice(dH);
	if(rv != SDR_OK){
		printf("Open device error rv = %d!\n",rv);
		return rv;
	}
	printf("Open device ok!\n");
	//dH = phDev;
	phDev = dH;
	return rv;
}

// 2. 关闭设备
int SDFCloseDevice(SGD_HANDLE phDeviceHandle)
{
	rv = SDF_CloseDevice(phDeviceHandle);
	if(rv != SDR_OK){
		printf("Close device error rv = %d!\n",rv);
		return rv;
	}
	printf("Close device ok!\n");
	return rv;
}

// 3. 创建会话
int SDFOpenSession(SGD_HANDLE hDeviceHandle, SGD_HANDLE *phSessionHandle)
{
	rv = SDF_OpenSession(hDeviceHandle, phSessionHandle);
	if(rv != SDR_OK){
		printf("Open session error rv = %d!\n",rv);
		return rv;
	}
	printf("Open session ok!\n");
	return rv;
}

// 4. 关闭会话
int SDFCloseSession(SGD_HANDLE sessionHandle)
{
	rv = SDF_CloseSession(sessionHandle);
	return rv;
}

//5. 获取设备信息
SGD_RV SDFGetDeviceInfo(SGD_HANDLE hSessionHandle, DEVICEINFO *pstDeviceInfo)
{
	return SDF_GetDeviceInfo(hSessionHandle, pstDeviceInfo);
}

//6. 产生随机数
SGD_RV SDFGenerateRandom(SGD_HANDLE hSessionHandle, SGD_UINT32  uiLength, SGD_UCHAR_PRT *pucRandom)
{
	*pucRandom = calloc(uiLength, sizeof(SGD_UCHAR));
	return SDF_GenerateRandom(hSessionHandle,uiLength,*pucRandom);
}

//7. 获取私钥使用权限
SGD_RV SDFGetPrivateKeyAccessRight(SGD_HANDLE hSessionHandle, SGD_UINT32 uiKeyIndex,SGD_UCHAR_PRT pucPassword, SGD_UINT32  uiPwdLength)
{
	return SDF_GetPrivateKeyAccessRight(hSessionHandle,uiKeyIndex,pucPassword,uiPwdLength);
}

//8. 释放私钥使用权限
SGD_RV SDFReleasePrivateKeyAccessRight(SGD_HANDLE hSessionHandle, SGD_UINT32  uiKeyIndex)
{
	return SDF_ReleasePrivateKeyAccessRight(hSessionHandle,uiKeyIndex);
}

//9. 导出RSA签名公钥
SGD_RV SDFExportSignPublicKey_RSA(SGD_HANDLE hSessionHandle, SGD_UINT32  uiKeyIndex,RSArefPublicKey *pucPublicKey)
{
	return SDF_ExportSignPublicKey_RSA(hSessionHandle,uiKeyIndex,pucPublicKey);
}

//10. 导出RSA加密公钥
SGD_RV SDFExportEncPublicKey_RSA(SGD_HANDLE hSessionHandle, SGD_UINT32  uiKeyIndex,RSArefPublicKey *pucPublicKey)
{
	return SDF_ExportEncPublicKey_RSA(hSessionHandle,uiKeyIndex,pucPublicKey);
}

//11. 产生RSA非对称密钥对并输出
SGD_RV SDFGenerateKeyPair_RSA(SGD_HANDLE hSessionHandle, SGD_UINT32  uiKeyBits,RSArefPublicKey *pucPublicKey,RSArefPrivateKey *pucPrivateKey)
{
	return SDF_GenerateKeyPair_RSA(hSessionHandle,uiKeyBits,pucPublicKey,pucPrivateKey);
}

//12. 生成会话密钥并用内部RSA公钥加密输出
SGD_RV SDFGenerateKeyWithIPK_RSA(SGD_HANDLE hSessionHandle, SGD_UINT32 uiIPKIndex,SGD_UINT32 uiKeyBits,SGD_UCHAR_PRT *pucKey,SGD_UINT32 *puiKeyLength,SGD_HANDLE *phKeyHandle)
{
	*pucKey = calloc(*puiKeyLength, sizeof(SGD_UCHAR));
	return SDF_GenerateKeyWithIPK_RSA(hSessionHandle,uiIPKIndex,uiKeyBits,*pucKey,puiKeyLength,phKeyHandle);
}

//13. 生成会话密钥并用外部RSA公钥加密输出
SGD_RV SDFGenerateKeyWithEPK_RSA(SGD_HANDLE hSessionHandle, SGD_UINT32 uiKeyBits,RSArefPublicKey *pucPublicKey,SGD_UCHAR_PRT *pucKey,SGD_UINT32 *puiKeyLength,SGD_HANDLE *phKeyHandle)
{
	*pucKey = calloc(*puiKeyLength, sizeof(SGD_UCHAR));
	return SDF_GenerateKeyWithEPK_RSA(hSessionHandle,uiKeyBits,pucPublicKey,*pucKey,puiKeyLength,phKeyHandle);
}

//14. 导入会话密钥并用内部RSA私钥解密
SGD_RV SDFImportKeyWithISK_RSA(SGD_HANDLE hSessionHandle, SGD_UINT32 uiISKIndex,SGD_UCHAR_PRT pucKey,SGD_UINT32 uiKeyLength,SGD_HANDLE *phKeyHandle)
{
	return SDF_ImportKeyWithISK_RSA(hSessionHandle,uiISKIndex,pucKey,uiKeyLength,phKeyHandle);
}

//15. 基于RSA算法的数字信封转换
SGD_RV SDFExchangeDigitEnvelopeBaseOnRSA(SGD_HANDLE hSessionHandle, SGD_UINT32  uiKeyIndex,RSArefPublicKey *pucPublicKey,SGD_UCHAR_PRT pucDEInput,SGD_UINT32  uiDELength,SGD_UCHAR_PRT *pucDEOutput,SGD_UINT32  *puiDELength)
{
	*pucDEOutput = calloc(*puiDELength, sizeof(SGD_UCHAR));
	return SDF_ExchangeDigitEnvelopeBaseOnRSA(hSessionHandle,uiKeyIndex,pucPublicKey,pucDEInput,uiDELength,*pucDEOutput,puiDELength);
}

//16. 导出ECC签名公钥
SGD_RV SDFExportSignPublicKey_ECC(SGD_HANDLE hSessionHandle, SGD_UINT32  uiKeyIndex,ECCrefPublicKey *pucPublicKey)
{
	return SDF_ExportSignPublicKey_ECC(hSessionHandle,uiKeyIndex,pucPublicKey);
}

//17. 导出ECC加密公钥
SGD_RV SDFExportEncPublicKey_ECC(SGD_HANDLE hSessionHandle, SGD_UINT32  uiKeyIndex,ECCrefPublicKey *pucPublicKey)
{
	return SDF_ExportEncPublicKey_ECC(hSessionHandle,uiKeyIndex,pucPublicKey);
}

//18. 产生ECC非对称密钥对并输出
SGD_RV SDFGenerateKeyPair_ECC(SGD_HANDLE hSessionHandle, SGD_UINT32  uiAlgID,SGD_UINT32  uiKeyBits,ECCrefPublicKey *pucPublicKey,ECCrefPrivateKey *pucPrivateKey)
{
	return SDF_GenerateKeyPair_ECC(hSessionHandle,uiAlgID,uiKeyBits,pucPublicKey,pucPrivateKey);
}

//19. 生成会话密钥并用内部ECC公钥加密输出
SGD_RV SDFGenerateKeyWithIPK_ECC (SGD_HANDLE hSessionHandle, SGD_UINT32 uiIPKIndex,SGD_UINT32 uiKeyBits,ECCCipher *pucKey,SGD_HANDLE *phKeyHandle)
{
	return SDF_GenerateKeyWithIPK_ECC(hSessionHandle,uiIPKIndex,uiKeyBits,pucKey,phKeyHandle);
}

//20. 生成会话密钥并用外部ECC公钥加密输出
SGD_RV SDFGenerateKeyWithEPK_ECC (SGD_HANDLE hSessionHandle, SGD_UINT32 uiKeyBits,SGD_UINT32  uiAlgID,ECCrefPublicKey *pucPublicKey,ECCCipher *pucKey,SGD_HANDLE *phKeyHandle)
{
	return SDF_GenerateKeyWithEPK_ECC(hSessionHandle,uiKeyBits,uiAlgID,pucPublicKey,pucKey,phKeyHandle);
}

//21. 导入会话密钥并用内部ECC私钥解密
SGD_RV SDFImportKeyWithISK_ECC (SGD_HANDLE hSessionHandle,SGD_UINT32 uiISKIndex,ECCCipher *pucKey,SGD_HANDLE *phKeyHandle)
{
	return SDF_ImportKeyWithISK_ECC(hSessionHandle,uiISKIndex,pucKey,phKeyHandle);
}

//22. 生成密钥协商参数并输出
SGD_RV SDFGenerateAgreementDataWithECC (SGD_HANDLE hSessionHandle, SGD_UINT32 uiISKIndex,SGD_UINT32 uiKeyBits,SGD_UCHAR_PRT pucSponsorID,SGD_UINT32 uiSponsorIDLength,ECCrefPublicKey  *pucSponsorPublicKey,ECCrefPublicKey  *pucSponsorTmpPublicKey,SGD_HANDLE *phAgreementHandle)
{
	return SDF_GenerateAgreementDataWithECC(hSessionHandle,uiISKIndex,uiKeyBits,pucSponsorID,uiSponsorIDLength,pucSponsorPublicKey,pucSponsorTmpPublicKey,phAgreementHandle);
}

//23. 计算会话密钥
SGD_RV SDFGenerateKeyWithECC (SGD_HANDLE hSessionHandle, SGD_UCHAR_PRT pucResponseID,SGD_UINT32 uiResponseIDLength,ECCrefPublicKey *pucResponsePublicKey,ECCrefPublicKey *pucResponseTmpPublicKey,SGD_HANDLE hAgreementHandle,SGD_HANDLE *phKeyHandle)
{
	return SDF_GenerateKeyWithECC(hSessionHandle,pucResponseID,uiResponseIDLength,pucResponsePublicKey,pucResponseTmpPublicKey,hAgreementHandle,phKeyHandle);
}

//24. 产生协商数据并计算会话密钥
SGD_RV SDFGenerateAgreementDataAndKeyWithECC (SGD_HANDLE hSessionHandle, SGD_UINT32 uiISKIndex,SGD_UINT32 uiKeyBits,SGD_UCHAR_PRT pucResponseID,SGD_UINT32 uiResponseIDLength,SGD_UCHAR_PRT pucSponsorID,SGD_UINT32 uiSponsorIDLength,ECCrefPublicKey *pucSponsorPublicKey,ECCrefPublicKey *pucSponsorTmpPublicKey,ECCrefPublicKey  *pucResponsePublicKey,	ECCrefPublicKey  *pucResponseTmpPublicKey,SGD_HANDLE *phKeyHandle)
{
	return SDF_GenerateAgreementDataAndKeyWithECC(hSessionHandle,uiISKIndex,uiKeyBits,pucResponseID,uiResponseIDLength,pucSponsorID,uiSponsorIDLength,pucSponsorPublicKey,pucSponsorTmpPublicKey,pucResponsePublicKey,pucResponseTmpPublicKey,phKeyHandle);
}

//25. 基于 ECC算法的数字信封转换
SGD_RV SDFExchangeDigitEnvelopeBaseOnECC(SGD_HANDLE hSessionHandle, SGD_UINT32  uiKeyIndex,SGD_UINT32  uiAlgID,ECCrefPublicKey *pucPublicKey,ECCCipher *pucEncDataIn,ECCCipher *pucEncDataOut)
{
	return SDF_ExchangeDigitEnvelopeBaseOnECC(hSessionHandle,uiKeyIndex,uiAlgID,pucPublicKey,pucEncDataIn,pucEncDataOut);
}

//26. 生成会话密钥并用密钥加密密钥加密输出
SGD_RV SDFGenerateKeyWithKEK(SGD_HANDLE hSessionHandle, SGD_UINT32 uiKeyBits,SGD_UINT32 uiAlgID,SGD_UINT32 uiKEKIndex, SGD_UCHAR_PRT pucKey, SGD_UINT32 *puiKeyLength, SGD_HANDLE *phKeyHandle)
{
	return SDF_GenerateKeyWithKEK(hSessionHandle,uiKeyBits,uiAlgID,uiKEKIndex,pucKey,puiKeyLength,phKeyHandle);
}

//27. 导入会话密钥并用密钥加密密钥解密
SGD_RV SDFImportKeyWithKEK(SGD_HANDLE hSessionHandle, SGD_UINT32  uiAlgID,SGD_UINT32 uiKEKIndex, SGD_UCHAR_PRT pucKey, SGD_UINT32 uiKeyLength, SGD_HANDLE *phKeyHandle)
{
	return SDF_ImportKeyWithKEK(hSessionHandle,uiAlgID,uiKEKIndex,pucKey,uiKeyLength,phKeyHandle);
}

//28. 导入明文会话密钥
SGD_RV SDFImportKey(SGD_HANDLE hSessionHandle, SGD_UCHAR_PRT pucKey, SGD_UINT32 uiKeyLength,SGD_HANDLE *phKeyHandle)
{
	return SDF_ImportKey(hSessionHandle,pucKey,uiKeyLength,phKeyHandle);
}

//29. 销毁会话密钥
SGD_RV SDFDestroyKey(SGD_HANDLE hSessionHandle, SGD_HANDLE hKeyHandle)
{
	return SDF_DestroyKey(hSessionHandle,hKeyHandle);
}

//34. 外部密钥ECC签名
SGD_RV SDFExternalSign_ECC(SGD_HANDLE hSessionHandle,SGD_UINT32 uiAlgID,ECCrefPrivateKey *pucPrivateKey,SGD_UCHAR_PRT pucData,SGD_UINT32  uiDataLength,ECCSignature *pucSignature)
{
	return SDF_ExternalSign_ECC(hSessionHandle,uiAlgID,pucPrivateKey,pucData,uiDataLength,pucSignature);
}

//35. 外部密钥ECC验证
SGD_RV SDFExternalVerify_ECC(SGD_HANDLE hSessionHandle,SGD_UINT32 uiAlgID,ECCrefPublicKey *pucPublicKey,SGD_UCHAR_PRT pucDataInput,SGD_UINT32  uiInputLength,ECCSignature *pucSignature)
{
	return SDF_ExternalVerify_ECC(hSessionHandle,uiAlgID,pucPublicKey,pucDataInput,uiInputLength,pucSignature);
}

//36. 内部密钥ECC签名
SGD_RV SDFInternalSign_ECC(SGD_HANDLE hSessionHandle,SGD_UINT32  uiISKIndex,SGD_UCHAR_PRT pucData,SGD_UINT32  uiDataLength,ECCSignature *pucSignature)
{
	return SDF_InternalSign_ECC(hSessionHandle,uiISKIndex,pucData,uiDataLength,pucSignature);
}

//37. 内部密钥ECC验证
SGD_RV SDFInternalVerify_ECC(SGD_HANDLE hSessionHandle,SGD_UINT32  uiISKIndex,SGD_UCHAR_PRT pucData,SGD_UINT32  uiDataLength,ECCSignature *pucSignature)
{
	return SDF_InternalVerify_ECC(hSessionHandle,uiISKIndex,pucData,uiDataLength,pucSignature);
}

//38. 外部密钥ECC加密
SGD_RV SDFExternalEncrypt_ECC(SGD_HANDLE hSessionHandle,SGD_UINT32 uiAlgID,ECCrefPublicKey *pucPublicKey,SGD_UCHAR_PRT pucData,SGD_UINT32  uiDataLength,ECCCipher *pucEncData)
{
	return SDF_ExternalEncrypt_ECC(hSessionHandle,uiAlgID,pucPublicKey,pucData,uiDataLength,pucEncData);
}

//39. 外部密钥ECC解密
SGD_RV SDFExternalDecrypt_ECC(SGD_HANDLE hSessionHandle,SGD_UINT32 uiAlgID,ECCrefPrivateKey *pucPrivateKey,ECCCipher *pucEncData,SGD_UCHAR_PRT *pucData,SGD_UINT32  *puiDataLength)
{
	*puiDataLength = 1024;
	*pucData = calloc(*puiDataLength, sizeof(SGD_UCHAR));
	return SDF_ExternalDecrypt_ECC(hSessionHandle,uiAlgID,pucPrivateKey,pucEncData,*pucData,puiDataLength);
}

//40. 对称加密
SGD_RV SDFEncrypt(SGD_HANDLE hSessionHandle,SGD_HANDLE hKeyHandle,SGD_UINT32 uiAlgID,SGD_UCHAR_PRT pucIV,SGD_UCHAR_PRT pucData,SGD_UINT32 uiDataLength,SGD_UCHAR_PRT *pucEncData,SGD_UINT32  *puiEncDataLength)
{
	*pucEncData = calloc(*puiEncDataLength, sizeof(SGD_UCHAR));
	return SDF_Encrypt(hSessionHandle,hKeyHandle,uiAlgID,pucIV,pucData,uiDataLength,*pucEncData,puiEncDataLength);
}

//41. 对称解密
SGD_RV SDFDecrypt (SGD_HANDLE hSessionHandle,SGD_HANDLE hKeyHandle,SGD_UINT32 uiAlgID,SGD_UCHAR_PRT pucIV,SGD_UCHAR_PRT pucEncData,SGD_UINT32  uiEncDataLength,SGD_UCHAR_PRT *pucData,SGD_UINT32 *puiDataLength)
{
	*pucData = calloc(*puiDataLength,sizeof(SGD_UCHAR));
	return SDF_Decrypt(hSessionHandle,hKeyHandle,uiAlgID,pucIV,pucEncData,uiEncDataLength,*pucData,puiDataLength);
}

//42. 计算ＭＡＣ
SGD_RV SDFCalculateMAC(SGD_HANDLE hSessionHandle,SGD_HANDLE hKeyHandle,SGD_UINT32 uiAlgID,SGD_UCHAR_PRT pucIV,SGD_UCHAR_PRT pucData,SGD_UINT32 uiDataLength,SGD_UCHAR_PRT *pucMAC,SGD_UINT32  *puiMACLength)
{
	*pucMAC = calloc(*puiMACLength, sizeof(SGD_UCHAR));
	return SDF_CalculateMAC(hSessionHandle,hKeyHandle,uiAlgID,pucIV,pucData,uiDataLength,*pucMAC,puiMACLength);
}

//43. 杂凑运算初始化
SGD_RV SDFHashInit(SGD_HANDLE hSessionHandle,SGD_UINT32 uiAlgID,ECCrefPublicKey *pucPublicKey,SGD_UCHAR_PRT pucID,SGD_UINT32 uiIDLength)
{
	return SDF_HashInit(hSessionHandle,uiAlgID,pucPublicKey,pucID,uiIDLength);
}

//44. 多包杂凑运算
SGD_RV SDFHashUpdate(SGD_HANDLE hSessionHandle,SGD_UCHAR_PRT pucData,SGD_UINT32  uiDataLength)
{
	return SDF_HashUpdate(hSessionHandle,pucData,uiDataLength);
}

//45. 杂凑运算结束
SGD_RV SDFHashFinal(SGD_HANDLE hSessionHandle,SGD_UCHAR_PRT *pucHash,SGD_UINT32  *puiHashLength)
{
	*puiHashLength = 32;
	*pucHash = calloc(*puiHashLength, sizeof(SGD_UCHAR));
	return SDF_HashFinal(hSessionHandle, *pucHash, puiHashLength);
}

//50. 获取对称句柄
//SGD_RV SDFGetSymmKeyHandle(SGD_HANDLE hSessionHandle, SGD_UINT32 uiKeyIndex, SGD_HANDLE *phKeyHandle)
//{
//
//}

//51. ECC方式的加密
SGD_RV SDFInternalEncrypt_ECC(SGD_HANDLE hSessionHandle, SGD_UINT32  uiISKIndex, SGD_UINT32 uiAlgID, SGD_UCHAR_PRT pucData, SGD_UINT32  uiDataLength, ECCCipher *pucEncData)
{
	return SDF_InternalEncrypt_ECC(hSessionHandle,uiISKIndex,pucData,uiDataLength,pucEncData);
}

//52. ECC方式的解密
SGD_RV SDFInternalDecrypt_ECC(SGD_HANDLE hSessionHandle,SGD_UINT32  uiISKIndex,SGD_UINT32 uiAlgID,ECCCipher *pucEncData,SGD_UCHAR_PRT *pucData,SGD_UINT32  *puiDataLength)
{
	*pucData = calloc(*puiDataLength, sizeof(SGD_UCHAR));
	return SDF_InternalDecrypt_ECC(hSessionHandle,uiISKIndex,pucEncData,*pucData,puiDataLength);
}


//30. 外部公钥RSA运算
SGD_RV SDFExternalPublicKeyOperation_RSA(SGD_HANDLE hSessionHandle, RSArefPublicKey *pucPublicKey,SGD_UCHAR_PRT pucDataInput,SGD_UINT32  uiInputLength,SGD_UCHAR_PRT *pucDataOutput,SGD_UINT32  *puiOutputLength)
{
	*pucDataOutput = calloc(*puiOutputLength, sizeof(SGD_UCHAR));
	return SDF_ExternalPublicKeyOperation_RSA(hSessionHandle, pucPublicKey, pucDataInput,uiInputLength,*pucDataOutput,puiOutputLength);
}

//31. 外部私钥RSA运算
SGD_RV SDFExternalPrivateKeyOperation_RSA(SGD_HANDLE hSessionHandle, RSArefPrivateKey *pucPrivateKey,SGD_UCHAR_PRT pucDataInput,SGD_UINT32  uiInputLength,SGD_UCHAR_PRT *pucDataOutput,SGD_UINT32  *puiOutputLength)
{
	*pucDataOutput = calloc(*puiOutputLength, sizeof(SGD_UCHAR));
	return SDF_ExternalPrivateKeyOperation_RSA(hSessionHandle,pucPrivateKey,pucDataInput,uiInputLength,*pucDataOutput,puiOutputLength);
}

//32. 内部公钥RSA运算
SGD_RV SDFInternalPublicKeyOperation_RSA(SGD_HANDLE hSessionHandle,SGD_UINT32  uiKeyIndex,SGD_UCHAR_PRT pucDataInput,SGD_UINT32  uiInputLength,SGD_UCHAR_PRT *pucDataOutput,SGD_UINT32  *puiOutputLength)
{
	*pucDataOutput = calloc(*puiOutputLength, sizeof(SGD_UCHAR));
	return SDF_InternalPublicKeyOperation_RSA(hSessionHandle,uiKeyIndex,pucDataInput,uiInputLength,*pucDataOutput,puiOutputLength);
}

//33. 内部私RSA运算
SGD_RV SDFInternalPrivateKeyOperation_RSA(SGD_HANDLE hSessionHandle,SGD_UINT32  uiKeyIndex,SGD_UCHAR_PRT pucDataInput,SGD_UINT32  uiInputLength,SGD_UCHAR_PRT *pucDataOutput,SGD_UINT32  *puiOutputLength)
{
	*pucDataOutput = calloc(*puiOutputLength, sizeof(SGD_UCHAR));
	return SDF_InternalPrivateKeyOperation_RSA(hSessionHandle, uiKeyIndex,pucDataInput,uiInputLength,*pucDataOutput,puiOutputLength);
}

//46. 创建文件
SGD_RV SDFCreateFile(SGD_HANDLE hSessionHandle,SGD_UCHAR_PRT pucFileName,SGD_UINT32 uiNameLen,SGD_UINT32 uiFileSize)
{
	return SDF_CreateFile(hSessionHandle,pucFileName,uiNameLen,uiFileSize);
}

//47. 读取文件
SGD_RV SDFReadFile(SGD_HANDLE hSessionHandle,SGD_UCHAR_PRT pucFileName,SGD_UINT32 uiNameLen,SGD_UINT32 uiOffset,SGD_UINT32 *puiReadLength,SGD_UCHAR_PRT *pucBuffer)
{
	*pucBuffer = calloc(*puiReadLength, sizeof(SGD_UCHAR));
	return SDF_ReadFile(hSessionHandle, pucFileName, uiNameLen, uiOffset, puiReadLength, *pucBuffer);
}

//48. 写文件
SGD_RV SDFWriteFile(SGD_HANDLE hSessionHandle,SGD_UCHAR_PRT pucFileName,SGD_UINT32 uiNameLen,SGD_UINT32 uiOffset,SGD_UINT32 uiWriteLength,SGD_UCHAR_PRT pucBuffer)
{
	return SDF_WriteFile(hSessionHandle, pucFileName,uiNameLen,uiOffset,uiWriteLength,pucBuffer);
}

//49. 删除文件
SGD_RV SDFDeleteFile(SGD_HANDLE hSessionHandle,SGD_UCHAR_PRT pucFileName,SGD_UINT32 uiNameLen)
{
	return SDF_DeleteFile(hSessionHandle, pucFileName,uiNameLen);
}
 */
import "C"
import "unsafe"

type Ctx struct {
}

type DeviceHandleType C.SGD_HANDLE
type SessionHandleType C.SGD_HANDLE
type KeyHandleType C.SGD_HANDLE
type AgreementHandleType C.SGD_HANDLE

var stubData = []byte{0}
func CMessage(data []byte) (dataPtr C.SGD_UCHAR_PRT) {
	l := len(data)
	if l == 0 {
		data = stubData
	}
	dataPtr = C.SGD_UCHAR_PRT(unsafe.Pointer(&data[0]))
	return dataPtr
}

// SDFOpenDevice 1.打开设备
func (c *Ctx) SDFOpenDevice() (deviceHandle DeviceHandleType, err error) {
	var err1 C.SGD_RV
	var dH C.SGD_HANDLE
	err1 = C.SDFOpenDevice(&dH)
	err = ToError(err1)
	deviceHandle = DeviceHandleType(dH)
	return
}

// SDFCloseDevice 2.关闭设备
func (c *Ctx) SDFCloseDevice(deviceHandle DeviceHandleType) (err error) {
	var err1 C.SGD_RV
	var dH C.SGD_HANDLE
	dH = C.SGD_HANDLE(deviceHandle)
	err1 = C.SDFCloseDevice(dH)
	return ToError(err1)
}

// SDFOpenSession 3.创建会话
func (c *Ctx) SDFOpenSession(deviceHandle DeviceHandleType) (sessionHandle SessionHandleType, err error) {
	var err1 C.SGD_RV
	var s C.SGD_HANDLE
	dH := C.SGD_HANDLE(deviceHandle)
	err1 = C.SDFOpenSession(dH, &s)
	sessionHandle = SessionHandleType(s)
	return sessionHandle, ToError(err1)
}

//SDFCloseSession 4.关闭会话
func (c *Ctx) SDFCloseSession(sessionHandle SessionHandleType) (err error) {
	var err1 C.SGD_RV
	err1 = C.SDFCloseSession(C.SGD_HANDLE(sessionHandle))
	return ToError(err1)
}

// SDFGetDeviceInfo 5.获取设备信息
func (c *Ctx) SDFGetDeviceInfo(sessionHandle SessionHandleType) (deviceInfo DeviceInfo, err error) {
	var deviceInfo1 C.DEVICEINFO
	var err1 C.SGD_RV
	err1 = C.SDFGetDeviceInfo(C.SGD_HANDLE(sessionHandle), &deviceInfo1)
	deviceInfo = ConvertToDeviceInfoGo(deviceInfo1)
	err = ToError(err1)
	return deviceInfo, err
}

// SDFGenerateRandom 6.产生随机数
func (c *Ctx) SDFGenerateRandom(sessionHandle SessionHandleType, length uint) (randomData []byte, err error) {
	var err1 C.SGD_RV
	var random C.SGD_UCHAR_PRT
	err1 = C.SDFGenerateRandom(C.SGD_HANDLE(sessionHandle), C.SGD_UINT32(length), &random)
	err = ToError(err1)
	randomData = C.GoBytes(unsafe.Pointer(random), C.int(length))
	C.free(unsafe.Pointer(random))
	return randomData, err
}

// SDFGetPrivateKeyAccessRight 7.获取私钥使用权限
func (c *Ctx) SDFGetPrivateKeyAccessRight(sessionHandle SessionHandleType, keyIndex uint, password []byte, pwdLength uint) (err error) {
	var err1 C.SGD_RV
	err1 = C.SDFGetPrivateKeyAccessRight(C.SGD_HANDLE(sessionHandle), C.SGD_UINT32(keyIndex), CMessage(password), C.SGD_UINT32(pwdLength))
	err = ToError(err1)
	return err
}

// SDFReleasePrivateKeyAccessRight 8.释放私钥使用权限
func (c *Ctx) SDFReleasePrivateKeyAccessRight(sessionHandle SessionHandleType, keyIndex uint) (err error) {
	var err1 C.SGD_RV
	err1 = C.SDFReleasePrivateKeyAccessRight(C.SGD_HANDLE(sessionHandle), C.SGD_UINT32(keyIndex))
	err = ToError(err1)
	return err
}

// SDFExportSignPublicKey_RSA 9.导出 RSA 签名公钥
func (c *Ctx) SDFExportSignPublicKey_RSA(sessionHandle SessionHandleType, keyIndex uint) (publicKey RSArefPublicKey, err error) {
	var err1 C.SGD_RV
	var pucPublicKey C.RSArefPublicKey
	err1 = C.SDFExportSignPublicKey_RSA(C.SGD_HANDLE(sessionHandle), C.SGD_UINT32(keyIndex), &pucPublicKey)
	publicKey = ConvertToRSArefPublicKeyGo(pucPublicKey)
	err = ToError(err1)
	return publicKey, err
}

// SDFExportEncPublicKey_RSA 10.导出 RSA 加密公钥
func (c *Ctx) SDFExportEncPublicKey_RSA(sessionHandle SessionHandleType, keyIndex uint) (publicKey RSArefPublicKey, err error) {
	var err1 C.SGD_RV
	var pucPublicKey C.RSArefPublicKey
	err1 = C.SDFExportEncPublicKey_RSA(C.SGD_HANDLE(sessionHandle), C.SGD_UINT32(keyIndex), &pucPublicKey)
	publicKey = ConvertToRSArefPublicKeyGo(pucPublicKey)
	err = ToError(err1)
	return publicKey, err
}

// SDFGenerateKeyPair_RSA 11.产生 RSA 非对称密钥对并输出
func (c *Ctx) SDFGenerateKeyPair_RSA(sessionHandle SessionHandleType, uiKeyBits uint) (publicKey RSArefPublicKey, privateKey RSArefPrivateKey, err error) {

	var err1 C.SGD_RV
	var pucPublicKey C.RSArefPublicKey
	var pucPrivateKey C.RSArefPrivateKey
	err1 = C.SDFGenerateKeyPair_RSA(C.SGD_HANDLE(sessionHandle), C.SGD_UINT32(uiKeyBits), &pucPublicKey, &pucPrivateKey)
	publicKey = ConvertToRSArefPublicKeyGo(pucPublicKey)
	privateKey = ConvertToRSArefPrivateKeyGo(pucPrivateKey)
	err = ToError(err1)
	return publicKey, privateKey, err
}

// SDFGenerateKeyWithIPK_RSA 12.生成会话密钥并用内部 RSA 公钥加密输出
func (c *Ctx) SDFGenerateKeyWithIPK_RSA(sessionHandle SessionHandleType, uiIPKIndex uint, uiKeyBits uint) (key []byte, keyLength uint, keyHandle KeyHandleType, err error) {
	var err1 C.SGD_RV
	var pucKey C.SGD_UCHAR_PRT
	var length C.SGD_UINT32
	var phKeyHandle C.SGD_HANDLE
	err1 = C.SDFGenerateKeyWithIPK_RSA(C.SGD_HANDLE(sessionHandle), C.SGD_UINT32(uiIPKIndex), C.SGD_UINT32(uiKeyBits), &pucKey, &length, &phKeyHandle)
	key = C.GoBytes(unsafe.Pointer(pucKey), C.int(length))
	C.free(unsafe.Pointer(pucKey))
	keyLength = uint(length)
	keyHandle = KeyHandleType(phKeyHandle)
	err = ToError(err1)
	return key, keyLength, keyHandle, err
}

// SDFGenerateKeyWithEPK_RSA 13.生成会话密钥并用外部 RSA 公钥加密输出
func (c *Ctx) SDFGenerateKeyWithEPK_RSA(sessionHandle SessionHandleType, uiKeyBits uint, publicKey RSArefPublicKey) (key []byte, keyLength uint, keyHandle KeyHandleType, err error) {
	var err1 C.SGD_RV
	var pucKey C.SGD_UCHAR_PRT
	var puiKeyLength C.SGD_UINT32
	var phKeyHandle C.SGD_HANDLE
	pubKey := ConvertToRSArefPublicKeyC(publicKey)
	err1 = C.SDFGenerateKeyWithEPK_RSA(C.SGD_HANDLE(sessionHandle), C.SGD_UINT32(uiKeyBits), &pubKey, &pucKey, &puiKeyLength, &phKeyHandle)
	key = C.GoBytes(unsafe.Pointer(pucKey), C.int(puiKeyLength))
	keyLength = uint(puiKeyLength)
	C.free(unsafe.Pointer(pucKey))
	keyHandle = KeyHandleType(phKeyHandle)
	err = ToError(err1)
	return key, keyLength, keyHandle, err
}

// SDFImportKeyWithISK_RSA 14.导入会话密钥并用内部 RSA 私钥解密
func (c *Ctx) SDFImportKeyWithISK_RSA(sessionHandle SessionHandleType, uiKeyBits uint, key []byte, uiKeyLength uint) (keyHandle KeyHandleType, err error) {
	var err1 C.SGD_RV
	var phKeyHandle C.SGD_HANDLE
	err1 = C.SDFImportKeyWithISK_RSA(C.SGD_HANDLE(sessionHandle), C.SGD_UINT32(uiKeyBits), CMessage(key), C.SGD_UINT32(uiKeyLength), &phKeyHandle)
	err = ToError(err1)
	keyHandle = KeyHandleType(phKeyHandle)
	return keyHandle, err
}

// SDFExchangeDigitEnvelopeBaseOnRSA 15.基于 RSA 算法的数字信封转换
func (c *Ctx) SDFExchangeDigitEnvelopeBaseOnRSA(sessionHandle SessionHandleType, keyIndex uint, publicKey RSArefPublicKey, deInput []byte, deLength uint) (deOutput []byte, deOutputLength uint, err error) {
	var err1 C.SGD_RV
	var pucDEOutput C.SGD_UCHAR_PRT
	var puiDELength C.SGD_UINT32
	pucPublicKey := ConvertToRSArefPublicKeyC(publicKey)
	err1 = C.SDFExchangeDigitEnvelopeBaseOnRSA(C.SGD_HANDLE(sessionHandle), C.SGD_UINT32(keyIndex), &pucPublicKey, CMessage(deInput), C.SGD_UINT32(deLength), &pucDEOutput, &puiDELength)
	deOutput = C.GoBytes(unsafe.Pointer(pucDEOutput), C.int(puiDELength))
	C.free(unsafe.Pointer(pucDEOutput))
	deOutputLength = uint(puiDELength)
	err = ToError(err1)
	return deOutput, deOutputLength, err
}

// SDFExportSignPublicKey_ECC 16.导出 ECC签名公钥
func (c *Ctx) SDFExportSignPublicKey_ECC(sessionHandle SessionHandleType, uiKeyIndex uint) (publicKey ECCrefPublicKey, err error) {
	var err1 C.SGD_RV
	var pucPublicKey C.ECCrefPublicKey
	err1 = C.SDFExportSignPublicKey_ECC(C.SGD_HANDLE(sessionHandle), C.SGD_UINT32(uiKeyIndex), &pucPublicKey)
	publicKey = ConvertToECCrefPublicKeyGo(pucPublicKey)
	err = ToError(err1)
	return publicKey, err
}

// SDFExportEncPublicKey_ECC 17.导出 ECC加密公钥
func (c *Ctx) SDFExportEncPublicKey_ECC(sessionHandle SessionHandleType, uiKeyIndex uint) (publicKey ECCrefPublicKey, err error) {
	var err1 C.SGD_RV
	var pucPublicKey C.ECCrefPublicKey
	err1 = C.SDFExportEncPublicKey_ECC(C.SGD_HANDLE(sessionHandle), C.SGD_UINT32(uiKeyIndex), &pucPublicKey)
	publicKey = ConvertToECCrefPublicKeyGo(pucPublicKey)
	err = ToError(err1)
	return publicKey, err
}

// SDFGenerateKeyPair_ECC 18.产生 ECC非对称密钥对并输出
func (c *Ctx) SDFGenerateKeyPair_ECC(sessionHandle SessionHandleType, uiAlgID uint, uiKeyBits uint) (publicKey ECCrefPublicKey, privateKey ECCrefPrivateKey, err error) {
	var err1 C.SGD_RV
	var pucPublicKey C.ECCrefPublicKey
	var pucPrivateKey C.ECCrefPrivateKey
	err1 = C.SDFGenerateKeyPair_ECC(C.SGD_HANDLE(sessionHandle), C.SGD_UINT32(uiAlgID), C.SGD_UINT32(uiKeyBits), &pucPublicKey, &pucPrivateKey)
	publicKey = ConvertToECCrefPublicKeyGo(pucPublicKey)
	privateKey = ConvertToECCrefPrivateKeyGo(pucPrivateKey)
	err = ToError(err1)
	return publicKey, privateKey, err
}

// SDFGenerateKeyWithIPK_ECC 19.生成会话密钥并用内部 ECC公钥加密输出
func (c *Ctx) SDFGenerateKeyWithIPK_ECC(sessionHandle SessionHandleType, uiIPKIndex uint, uiKeyBits uint) (key ECCCipher, keyHandle KeyHandleType, err error) {
	var err1 C.SGD_RV
	var pucKey C.ECCCipher
	var phKeyHandle C.SGD_HANDLE
	err1 = C.SDFGenerateKeyWithIPK_ECC(C.SGD_HANDLE(sessionHandle), C.SGD_UINT32(uiIPKIndex), C.SGD_UINT32(uiKeyBits), &pucKey, &phKeyHandle)
	key = ConvertToECCCipherGo(pucKey)
	keyHandle = KeyHandleType(phKeyHandle)
	err = ToError(err1)
	return key, keyHandle, err
}

// SDFGenerateKeyWithEPK_ECC 20.生成会话密钥并用外部 ECC公钥加密输出
func (c *Ctx) SDFGenerateKeyWithEPK_ECC(sessionHandle SessionHandleType, uiKeyBits uint, uiAlgID uint, publicKey ECCrefPublicKey) (key ECCCipher, keyHandle KeyHandleType, err error) {
	var err1 C.SGD_RV
	var pucPublicKey C.ECCrefPublicKey
	pucPublicKey.bits = C.SGD_UINT32(publicKey.Bits)
	for i := 0; i < len(publicKey.X); i++ {
		pucPublicKey.x[i] = C.SGD_UCHAR(publicKey.Y[i])
	}
	for i := 0; i < len(publicKey.Y); i++ {
		pucPublicKey.y[i] = C.SGD_UCHAR(publicKey.Y[i])
	}
	var pucKey C.ECCCipher
	var phKeyHandle C.SGD_HANDLE
	err1 = C.SDFGenerateKeyWithEPK_ECC(C.SGD_HANDLE(sessionHandle), C.SGD_UINT32(uiKeyBits), C.SGD_UINT32(uiAlgID), &pucPublicKey, &pucKey, &phKeyHandle)
	key = ConvertToECCCipherGo(pucKey)
	keyHandle = KeyHandleType(phKeyHandle)
	err = ToError(err1)
	return key, keyHandle, err
}

// SDFImportKeyWithISK_ECC 21.导入会话密钥并用内部 ECC私钥解密
func (c *Ctx) SDFImportKeyWithISK_ECC(sessionHandle SessionHandleType, uiISKIndex uint, key ECCCipher) (keyHandle KeyHandleType, err error) {
	var err1 C.SGD_RV
	var phKeyHandle C.SGD_HANDLE
	pucKey := ConvertToECCCipherC(key)
	err1 = C.SDFImportKeyWithISK_ECC(C.SGD_HANDLE(sessionHandle), C.SGD_UINT32(uiISKIndex), &pucKey, &phKeyHandle)
	err = ToError(err1)
	keyHandle = KeyHandleType(phKeyHandle)
	return keyHandle, err
}

// SDFGenerateAgreementDataWithECC 22.生成密钥协商参数并输出
func (c *Ctx) SDFGenerateAgreementDataWithECC(sessionHandle SessionHandleType, uiISKIndex uint, uiKeyBits uint, sponsorID []byte, sponsorIDLength uint) (sponsorPublicKey ECCrefPublicKey, sponsorTmpPublicKey ECCrefPublicKey, agreementHandle AgreementHandleType, err error) {
	var err1 C.SGD_RV
	var pucSponsorPublicKey C.ECCrefPublicKey
	var pucSponsorTmpPublicKey C.ECCrefPublicKey
	var phAgreementHandle C.SGD_HANDLE
	err1 = C.SDFGenerateAgreementDataWithECC(C.SGD_HANDLE(sessionHandle), C.SGD_UINT32(uiISKIndex), C.SGD_UINT32(uiKeyBits), CMessage(sponsorID), C.SGD_UINT32(sponsorIDLength), &pucSponsorPublicKey, &pucSponsorTmpPublicKey, &phAgreementHandle)
	sponsorPublicKey = ConvertToECCrefPublicKeyGo(pucSponsorPublicKey)
	sponsorTmpPublicKey = ConvertToECCrefPublicKeyGo(pucSponsorTmpPublicKey)
	agreementHandle = AgreementHandleType(phAgreementHandle)
	err = ToError(err1)
	return sponsorPublicKey, sponsorTmpPublicKey, agreementHandle, err
}

// SDFGenerateKeyWithECC 23.计算会话密钥
func (c *Ctx) SDFGenerateKeyWithECC(sessionHandle SessionHandleType, responseID []byte, responseIDLength uint, responsePublicKey ECCrefPublicKey, responseTmpPublicKey ECCrefPublicKey, hAgreementHandle AgreementHandleType) (keyHandle KeyHandleType, err error) {
	var err1 C.SGD_RV
	pucResponsePublicKey := ConvertToECCrefPublicKeyC(responsePublicKey)
	pucResponseTmpPublicKey := ConvertToECCrefPublicKeyC(responseTmpPublicKey)
	var phKeyHandle C.SGD_HANDLE
	err1 = C.SDFGenerateKeyWithECC(C.SGD_HANDLE(sessionHandle), CMessage(responseID), C.SGD_UINT32(responseIDLength), &pucResponsePublicKey, &pucResponseTmpPublicKey, C.SGD_HANDLE(hAgreementHandle), &phKeyHandle)
	keyHandle = KeyHandleType(phKeyHandle)
	err = ToError(err1)
	return keyHandle, err
}

// SDFGenerateAgreementDataAndKeyWithECC 24.产生协商数据并计算会话密钥
func (c *Ctx) SDFGenerateAgreementDataAndKeyWithECC(sessionHandle SessionHandleType, uiISKIndex uint, uiKeyBits uint, responseID []byte, responseIDLength uint, sponsorID []byte, sponsorIDLength uint, sponsorPublicKey ECCrefPublicKey, sponsorTmpPublicKey ECCrefPublicKey) (responsePublicKey ECCrefPublicKey, responseTmpPublicKey ECCrefPublicKey, keyHandle KeyHandleType, err error) {
	var err1 C.SGD_RV
	pucSponsorPublicKey := ConvertToECCrefPublicKeyC(sponsorPublicKey)
	pucSponsorTmpPublicKey := ConvertToECCrefPublicKeyC(sponsorTmpPublicKey)
	var pucResponsePublicKey C.ECCrefPublicKey
	var pucResponseTmpPublicKey C.ECCrefPublicKey
	var phKeyHandle C.SGD_HANDLE
	err1 = C.SDFGenerateAgreementDataAndKeyWithECC(C.SGD_HANDLE(sessionHandle), C.SGD_UINT32(uiISKIndex), C.SGD_UINT32(uiKeyBits), CMessage(responseID), C.SGD_UINT32(responseIDLength), CMessage(sponsorID), C.SGD_UINT32(sponsorIDLength), &pucSponsorPublicKey, &pucSponsorTmpPublicKey, &pucResponsePublicKey, &pucResponseTmpPublicKey, &phKeyHandle)
	responsePublicKey = ConvertToECCrefPublicKeyGo(pucResponsePublicKey)
	responseTmpPublicKey = ConvertToECCrefPublicKeyGo(pucResponseTmpPublicKey)
	keyHandle = KeyHandleType(phKeyHandle)
	err = ToError(err1)
	return responsePublicKey, responseTmpPublicKey, keyHandle, err
}

// SDFExchangeDigitEnvelopeBaseOnECC 25.基于 ECC算法的数字信封转换
func (c *Ctx) SDFExchangeDigitEnvelopeBaseOnECC(sessionHandle SessionHandleType, uiKeyIndex uint, uiAlgID uint, publicKey ECCrefPublicKey, encDataIn ECCCipher) (encDataOut ECCCipher, err error) {
	var err1 C.SGD_RV
	var pucEncDataOut C.ECCCipher
	pucPublicKey := ConvertToECCrefPublicKeyC(publicKey)
	pucEncDataIn := ConvertToECCCipherC(encDataIn)
	err1 = C.SDFExchangeDigitEnvelopeBaseOnECC(C.SGD_HANDLE(sessionHandle), C.SGD_UINT32(uiKeyIndex), C.SGD_UINT32(uiAlgID), &pucPublicKey, &pucEncDataIn, &pucEncDataOut)
	encDataOut = ConvertToECCCipherGo(pucEncDataOut)
	err = ToError(err1)
	return encDataOut, err
}

// SDFGenerateKeyWithKEK 26.生成会话密钥并用密钥加密密钥加密输出
func (c *Ctx) SDFGenerateKeyWithKEK(sessionHandle SessionHandleType, uiKeyBits uint, uiAlgID uint, uiKEKIndex uint) ([]byte, uint, KeyHandleType, error) {
	var err C.SGD_RV
	var pucKey C.SGD_UCHAR_PRT
	var keyLength C.SGD_UINT32
	var phKeyHandle C.SGD_HANDLE
	err = C.SDFGenerateKeyWithKEK(C.SGD_HANDLE(sessionHandle), C.SGD_UINT32(uiKeyBits), C.SGD_UINT32(uiAlgID), C.SGD_UINT32(uiKEKIndex), pucKey, &keyLength, &phKeyHandle)
	p := C.GoBytes(unsafe.Pointer(pucKey), C.int(keyLength))
	C.free(unsafe.Pointer(pucKey))
	return p, uint(keyLength), KeyHandleType(phKeyHandle), ToError(err)
}

// SDFImportKeyWithKEK 27.导入会话密钥并用密钥加密密钥解密
func (c *Ctx) SDFImportKeyWithKEK(sessionHandle SessionHandleType, uiAlgID uint, uiKEKIndex uint, key []byte, uiKeyLength uint) (keyHandle KeyHandleType, err error) {
	var err1 C.SGD_RV
	var phKeyHandle C.SGD_HANDLE
	err1 = C.SDFImportKeyWithKEK(C.SGD_HANDLE(sessionHandle), C.SGD_UINT32(uiAlgID), C.SGD_UINT32(uiKEKIndex), CMessage(key), C.SGD_UINT32(uiKeyLength), &phKeyHandle)
	keyHandle = KeyHandleType(phKeyHandle)
	err = ToError(err1)
	return keyHandle, err
}

// SDFImportKey 28.导入明文会话密钥
func (c *Ctx) SDFImportKey(sessionHandle SessionHandleType, pucKey []byte, uiKeyLength uint) (keyHandle KeyHandleType, err error) {
	var err1 C.SGD_RV
	var phKeyHandle C.SGD_HANDLE
	err1 = C.SDFImportKey(C.SGD_HANDLE(sessionHandle), CMessage(pucKey), C.SGD_UINT32(uiKeyLength), &phKeyHandle)
	keyHandle = KeyHandleType(phKeyHandle)
	err = ToError(err1)
	return keyHandle, err
}

// SDFDestroyKey 29.销毁会话密钥
func (c *Ctx) SDFDestroyKey(sessionHandle SessionHandleType, hKeyHandle KeyHandleType) (err error) {
	var err1 C.SGD_RV
	err1 = C.SDFDestroyKey(C.SGD_HANDLE(sessionHandle), C.SGD_HANDLE(hKeyHandle))
	err = ToError(err1)
	return err
}

// SDFExternalSign_ECC 34. 外部密钥ECC签名
func (c *Ctx) SDFExternalSign_ECC(sessionHandle SessionHandleType, uiAlgID uint, privateKey ECCrefPrivateKey, pucData []byte, uiDataLength uint) (signature ECCSignature, err error) {
	var err1 C.SGD_RV
	pucPrivateKey := ConvertToECCrefPrivateKeyC(privateKey)
	var pucSignature C.ECCSignature
	err1 = C.SDFExternalSign_ECC(C.SGD_HANDLE(sessionHandle), C.SGD_UINT32(uiAlgID), &pucPrivateKey, CMessage(pucData), C.SGD_UINT32(uiDataLength), &pucSignature)
	signature = ConvertToECCSignatureGo(pucSignature)
	err = ToError(err1)
	return signature, err
}

// SDFExternalVerify_ECC 35.外部密钥 ECC验证
func (c *Ctx) SDFExternalVerify_ECC(sessionHandle SessionHandleType, uiAlgID uint, publicKey ECCrefPublicKey, inputData []byte, uiInputLength uint, signature ECCSignature) (err error) {
	var err1 C.SGD_RV
	pucPublicKey := ConvertToECCrefPublicKeyC(publicKey)
	pucSignature := ConvertToECCSignatureC(signature)
	err1 = C.SDFExternalVerify_ECC(C.SGD_HANDLE(sessionHandle), C.SGD_UINT32(uiAlgID), &pucPublicKey, CMessage(inputData), C.SGD_UINT32(uiInputLength), &pucSignature)
	err = ToError(err1)
	return err
}

// SDFInternalSign_ECC 36.内部密钥 ECC签名
func (c *Ctx) SDFInternalSign_ECC(sessionHandle SessionHandleType, uiISKIndex uint, pucData []byte, uiDataLength uint) (signature ECCSignature, err error) {
	var err1 C.SGD_RV
	var pucSignature C.ECCSignature
	err1 = C.SDFInternalSign_ECC( C.SGD_HANDLE(sessionHandle), C.SGD_UINT32(uiISKIndex), CMessage(pucData), C.SGD_UINT32(uiDataLength), &pucSignature)
	signature = ConvertToECCSignatureGo(pucSignature)
	err = ToError(err1)
	return signature, err
}

// SDFInternalVerify_ECC 37.内部密钥 ECC验证
func (c *Ctx) SDFInternalVerify_ECC(sessionHandle SessionHandleType, uiISKIndex uint, pucData []byte, uiDataLength uint, signature ECCSignature) (err error) {
	var err1 C.SGD_RV
	var pucSignature C.ECCSignature
	for i := 0; i < len(signature.R); i++ {
		pucSignature.r[i] = C.SGD_UCHAR(signature.R[i])
	}
	for i := 0; i < len(signature.S); i++ {
		pucSignature.s[i] = C.SGD_UCHAR(signature.S[i])
	}
	err1 = C.SDFInternalVerify_ECC(C.SGD_HANDLE(sessionHandle), C.SGD_UINT32(uiISKIndex), CMessage(pucData), C.SGD_UINT32(uiDataLength), &pucSignature)
	err = ToError(err1)
	return err
}

// SDFExternalEncrypt_ECC 38.外部密钥 ECC加密
func (c *Ctx) SDFExternalEncrypt_ECC(sessionHandle SessionHandleType, uiAlgID uint, publicKey ECCrefPublicKey, data []byte, dataLength uint) (encData ECCCipher, err error) {
	var err1 C.SGD_RV
	pucPublicKey := ConvertToECCrefPublicKeyC(publicKey)
	var pucEncData C.ECCCipher
	err1 = C.SDFExternalEncrypt_ECC(C.SGD_HANDLE(sessionHandle), C.SGD_UINT32(uiAlgID), &pucPublicKey, CMessage(data), C.SGD_UINT32(dataLength), &pucEncData)
	encData = ConvertToECCCipherGo(pucEncData)
	err = ToError(err1)
	return encData, err
}

// SDFExternalDecrypt_ECC 39.外部密钥 ECC解密
func (c *Ctx) SDFExternalDecrypt_ECC(sessionHandle SessionHandleType, uiAlgID uint, privateKey ECCrefPrivateKey, encData ECCCipher) (data []byte, dataLength uint, err error) {
	var err1 C.SGD_RV
	pucPrivateKey := ConvertToECCrefPrivateKeyC(privateKey)
	pucEncData := ConvertToECCCipherC(encData)
	var pucData C.SGD_UCHAR_PRT
	var puiDataLength C.SGD_UINT32
	err1 = C.SDFExternalDecrypt_ECC(C.SGD_HANDLE(sessionHandle), C.SGD_UINT32(uiAlgID), &pucPrivateKey, &pucEncData, &pucData, &puiDataLength)
	data = C.GoBytes(unsafe.Pointer(pucData), C.int(puiDataLength))
	dataLength = uint(puiDataLength)
	C.free(unsafe.Pointer(pucData))
	err = ToError(err1)
	return data, dataLength, err
}

// SDFEncrypt 40.对称加密
func (c *Ctx) SDFEncrypt(sessionHandle SessionHandleType, keyHandle KeyHandleType, algID uint, iv []byte, data []byte, dataLength uint) (encData []byte, encDataLength uint, err error) {
	var err1 C.SGD_RV
	var pucEncData C.SGD_UCHAR_PRT
	var puiEncDataLength C.SGD_UINT32
	err1 = C.SDFEncrypt(C.SGD_HANDLE(sessionHandle), C.SGD_HANDLE(keyHandle), C.SGD_UINT32(algID), CMessage(iv), CMessage(data), C.SGD_UINT32(dataLength), &pucEncData, &puiEncDataLength)
	encData = C.GoBytes(unsafe.Pointer(pucEncData), C.int(puiEncDataLength))
	encDataLength = uint(puiEncDataLength)
	err = ToError(err1)
	C.free(unsafe.Pointer(pucEncData))
	return encData, uint(puiEncDataLength), err
}

// SDFDecrypt 41.对称解密
func (c *Ctx) SDFDecrypt(sessionHandle SessionHandleType, hKeyHandle KeyHandleType, uiAlgID uint, iv []byte, encData []byte, encDataLength uint) (data []byte, dataLength uint, err error) {
	var err1 C.SGD_RV
	var pucData C.SGD_UCHAR_PRT
	var puiDataLength C.SGD_UINT32
	err1 = C.SDFDecrypt(C.SGD_HANDLE(sessionHandle), C.SGD_HANDLE(hKeyHandle), C.SGD_UINT32(uiAlgID), CMessage(iv), CMessage(encData), C.SGD_UINT32(encDataLength), &pucData, &puiDataLength)
	data = C.GoBytes(unsafe.Pointer(pucData), C.int(puiDataLength))
	dataLength = uint(puiDataLength)
	C.free(unsafe.Pointer(pucData))
	err = ToError(err1)
	return data, dataLength, err
}

// SDFCalculateMAC 42.计算 MAC
func (c *Ctx) SDFCalculateMAC(sessionHandle SessionHandleType, hKeyHandle KeyHandleType, uiAlgID uint, iv []byte, data []byte, dataLength uint) (mac []byte, macLength uint, err error) {
	var err1 C.SGD_RV
	var pucMAC C.SGD_UCHAR_PRT
	var puiMACLength C.SGD_UINT32
	err1 = C.SDFCalculateMAC(C.SGD_HANDLE(sessionHandle), C.SGD_HANDLE(hKeyHandle), C.SGD_UINT32(uiAlgID), CMessage(iv), CMessage(data), C.SGD_UINT32(dataLength), &pucMAC, &puiMACLength)
	mac = C.GoBytes(unsafe.Pointer(pucMAC), C.int(puiMACLength))
	macLength = uint(puiMACLength)
	C.free(unsafe.Pointer(pucMAC))
	err = ToError(err1)
	return mac, macLength, err
}

// SDFHashInit 43.杂凑运算初始化
func (c *Ctx) SDFHashInit(sessionHandle SessionHandleType, uiAlgID uint, pucID []byte, uiIDLength uint) (publicKey ECCrefPublicKey, err error) {
	var err1 C.SGD_RV
	var pucPublicKey C.ECCrefPublicKey
	err1 = C.SDFHashInit(C.SGD_HANDLE(sessionHandle), C.SGD_UINT32(uiAlgID), &pucPublicKey, CMessage(pucID), C.SGD_UINT32(uiIDLength))
	publicKey = ConvertToECCrefPublicKeyGo(pucPublicKey)
	err = ToError(err1)
	return publicKey, err
}

// SDFHashUpdate 44.多包杂凑运算
func (c *Ctx) SDFHashUpdate(sessionHandle SessionHandleType, pucData []byte, uiDataLength uint) (err error) {
	var err1 C.SGD_RV
	err1 = C.SDFHashUpdate(C.SGD_HANDLE(sessionHandle), CMessage(pucData), C.SGD_UINT32(uiDataLength))
	err = ToError(err1)
	return err
}

// SDFHashFinal 45.杂凑运算结束
func (c *Ctx) SDFHashFinal(sessionHandle SessionHandleType) (hash []byte, hashLength uint, err error) {
	var err1 C.SGD_RV
	var pucData C.SGD_UCHAR_PRT
	var puiHashLength C.SGD_UINT32
	err1 = C.SDFHashFinal(C.SGD_HANDLE(sessionHandle), &pucData, &puiHashLength)
	hash = C.GoBytes(unsafe.Pointer(pucData), C.int(puiHashLength))
	hashLength = uint(puiHashLength)
	C.free(unsafe.Pointer(pucData))
	err = ToError(err1)
	return hash, hashLength, err
}

//// SDFGetSymmKeyHandle 50. 获取对称句柄
//func (c *Ctx) SDFGetSymmKeyHandle(sessionHandle SessionHandleType, uiKeyIndex uint) (keyHandle KeyHandleType, err error) {
//	var err1 C.SGD_RV
//	var phKeyHandle C.SGD_HANDLE
//	err1 = C.SDFGetSymmKeyHandle(C.SGD_HANDLE(sessionHandle), C.SGD_UINT32(uiKeyIndex), &phKeyHandle)
//	keyHandle = KeyHandleType(phKeyHandle)
//	err = ToError(err1)
//	return keyHandle, err
//}

// SDFInternalEncrypt_ECC 51. ECC方式的加密
func (c *Ctx) SDFInternalEncrypt_ECC(sessionHandle SessionHandleType, uiISKIndex uint, uiAlgID uint, pucData []byte, uiDataLength uint) (encData ECCCipher, err error) {
	var err1 C.SGD_RV
	var pucEncData C.ECCCipher
	err1 = C.SDFInternalEncrypt_ECC(C.SGD_HANDLE(sessionHandle), C.SGD_UINT32(uiISKIndex), C.SGD_UINT32(uiAlgID), CMessage(pucData), C.SGD_UINT32(uiDataLength), &pucEncData)
	encData = ConvertToECCCipherGo(pucEncData)
	err = ToError(err1)
	return encData, err
}

// SDFInternalDecrypt_ECC 52. ECC方式的解密
func (c *Ctx) SDFInternalDecrypt_ECC(sessionHandle SessionHandleType, uiISKIndex uint, uiAlgID uint, encData ECCCipher) (data []byte, dataLength uint, err error) {
	var err1 C.SGD_RV
	var pucEncData C.ECCCipher
	for i := 0; i < len(encData.X); i++ {
		pucEncData.x[i] = C.SGD_UCHAR(encData.X[i])
	}
	for i := 0; i < len(encData.Y); i++ {
		pucEncData.y[i] = C.SGD_UCHAR(encData.Y[i])
	}
	for i := 0; i < len(encData.M); i++ {
		pucEncData.M[i] = C.SGD_UCHAR(encData.M[i])
	}
	pucEncData.L = C.SGD_UINT32(encData.L)
	for i := 0; i < len(encData.C); i++ {
		pucEncData.C[i] = C.SGD_UCHAR(encData.C[i])
	}
	var pucData C.SGD_UCHAR_PRT
	var puiDataLength C.SGD_UINT32
	err1 = C.SDFInternalDecrypt_ECC(C.SGD_HANDLE(sessionHandle), C.SGD_UINT32(uiISKIndex), C.SGD_UINT32(uiAlgID), &pucEncData, &pucData, &puiDataLength)
	data = C.GoBytes(unsafe.Pointer(pucData), C.int(puiDataLength))
	C.free(unsafe.Pointer(pucData))
	dataLength = uint(puiDataLength)
	err = ToError(err1)
	return data, dataLength, err
}

// SDFExternalPublicKeyOperation_RSA 30.外部公钥 RSA 运算
func (c *Ctx) SDFExternalPublicKeyOperation_RSA(sessionHandle SessionHandleType, publicKey RSArefPublicKey, dataInput []byte, uiInputLength uint) (dataOutput []byte, err error) {
	var err1 C.SGD_RV
	var pucDataOutput C.SGD_UCHAR_PRT
	var puiOutputLength C.SGD_UINT32
	pucPublicKey := ConvertToRSArefPublicKeyC(publicKey)
	err1 = C.SDFExternalPublicKeyOperation_RSA(C.SGD_HANDLE(sessionHandle), &pucPublicKey, CMessage(dataInput), C.SGD_UINT32(uiInputLength), &pucDataOutput, &puiOutputLength)
	dataOutput = C.GoBytes(unsafe.Pointer(pucDataOutput), C.int(puiOutputLength))
	C.free(unsafe.Pointer(pucDataOutput))
	err = ToError(err1)
	return dataOutput, err
}

// SDFExternalPrivateKeyOperation_RSA 31. 外部私钥RSA运算
func (c *Ctx) SDFExternalPrivateKeyOperation_RSA(sessionHandle SessionHandleType, privateKey RSArefPrivateKey, dataInput []byte, uiInputLength uint) (dataOutput []byte, err error) {
	var err1 C.SGD_RV
	var pucDataOutput C.SGD_UCHAR_PRT
	var puiOutputLength C.SGD_UINT32
	pucPrivateKey := ConvertToRSArefPrivateKeyC(privateKey)
	err1 = C.SDFExternalPrivateKeyOperation_RSA(C.SGD_HANDLE(sessionHandle), &pucPrivateKey, CMessage(dataInput), C.SGD_UINT32(uiInputLength), &pucDataOutput, &puiOutputLength)
	dataOutput = C.GoBytes(unsafe.Pointer(pucDataOutput), C.int(puiOutputLength))
	C.free(unsafe.Pointer(pucDataOutput))
	err = ToError(err1)
	return dataOutput, err
}

// SDFInternalPublicKeyOperation_RSA 32.内部公钥 RSA 运算
func (c *Ctx) SDFInternalPublicKeyOperation_RSA(sessionHandle SessionHandleType, uiKeyIndex uint, pucDataInput []byte, uiInputLength uint) (dataOutput []byte, err error) {
	var err1 C.SGD_RV
	var pucDataOutput C.SGD_UCHAR_PRT
	var puiOutputLength C.SGD_UINT32
	err1 = C.SDFInternalPublicKeyOperation_RSA(C.SGD_HANDLE(sessionHandle), C.SGD_UINT32(uiKeyIndex), CMessage(pucDataInput), C.SGD_UINT32(uiInputLength), &pucDataOutput, &puiOutputLength)
	dataOutput = C.GoBytes(unsafe.Pointer(pucDataOutput), C.int(puiOutputLength))
	err = ToError(err1)
	C.free(unsafe.Pointer(pucDataOutput))
	return dataOutput, err
}

// SDFInternalPrivateKeyOperation_RSA 33.内部私钥 RSA 运算
func (c *Ctx) SDFInternalPrivateKeyOperation_RSA(sessionHandle SessionHandleType, uiKeyIndex uint, inData []byte, uiInputLength uint) (dataOutput []byte, err error) {
	var err1 C.SGD_RV
	var pucDataOutput C.SGD_UCHAR_PRT
	var puiOutputLength C.SGD_UINT32
	err1 = C.SDFInternalPrivateKeyOperation_RSA(C.SGD_HANDLE(sessionHandle), C.SGD_UINT32(uiKeyIndex), CMessage(inData), C.SGD_UINT32(uiInputLength), &pucDataOutput, &puiOutputLength)
	dataOutput1 := C.GoBytes(unsafe.Pointer(pucDataOutput), C.int(puiOutputLength))
	dataOutput = deepCopy(dataOutput1)
	C.free(unsafe.Pointer(pucDataOutput))
	err = ToError(err1)
	return dataOutput, err
}

// SDFCreateFile 46.创建文件
func (c *Ctx) SDFCreateFile(sessionHandle SessionHandleType, fileName []byte, uiFileSize uint) (err error) {
	var err1 C.SGD_RV
	err1 = C.SDFCreateFile(C.SGD_HANDLE(sessionHandle), CMessage(fileName), C.SGD_UINT32(len(fileName)), C.SGD_UINT32(uiFileSize))
	err = ToError(err1)
	return err
}

// SDFReadFile 47.读取文件
func (c *Ctx) SDFReadFile(sessionHandle SessionHandleType, fileName []byte, uiOffset uint, readLength uint) (buffer []byte, readLength1 uint, err error) {
	var err1 C.SGD_RV
	var puiReadLength C.SGD_UINT32
	var pucBuffer C.SGD_UCHAR_PRT
	puiReadLength = C.SGD_UINT32(readLength)
	err1 = C.SDFReadFile(C.SGD_HANDLE(sessionHandle), CMessage(fileName), C.SGD_UINT32(len(fileName)), C.SGD_UINT32(uiOffset), &puiReadLength, &pucBuffer)
	buffer = C.GoBytes(unsafe.Pointer(pucBuffer), C.int(puiReadLength))
	readLength1 = uint(puiReadLength)
	C.free(unsafe.Pointer(pucBuffer))
	err = ToError(err1)
	return buffer, readLength1, err
}

// SDFWriteFile 48.写文件
func (c *Ctx) SDFWriteFile(sessionHandle SessionHandleType, fileName []byte, uiOffset uint, buffer []byte, bufferLength uint) (err error) {
	var err1 C.SGD_RV
	err1 = C.SDFWriteFile(C.SGD_HANDLE(sessionHandle), CMessage(fileName), C.SGD_UINT32(len(fileName)), C.SGD_UINT32(uiOffset), C.SGD_UINT32(bufferLength), CMessage(buffer))
	err = ToError(err1)
	return err
}

// SDFDeleteFile 49.删除文件
func (c *Ctx) SDFDeleteFile(sessionHandle SessionHandleType, fileName []byte) (err error) {
	var err1 C.SGD_RV
	err1 = C.SDFDeleteFile( C.SGD_HANDLE(sessionHandle), CMessage(fileName), C.SGD_UINT32(len(fileName)))
	err = ToError(err1)
	return err
}