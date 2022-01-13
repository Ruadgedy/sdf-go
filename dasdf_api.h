#ifndef __DASDF_API_H__
#define __DASDF_API_H__

#ifdef __cplusplus
extern "C" {
#endif
//-----------------------------------------------------------------------------
//本接口遵循国密局制定的《公钥密码基础设施应用技术体系 密码设备应用接口规范》2010年8月版
//-----------------------------------------------------------------------------

/*数据类型定义*/
typedef char				SGD_CHAR;
typedef char				SGD_INT8;
typedef short				SGD_INT16;
typedef int					SGD_INT32;
typedef long long			SGD_INT64;
typedef unsigned char		SGD_UCHAR;
typedef unsigned char		SGD_UINT8;
typedef unsigned short		SGD_UINT16;
typedef unsigned int		SGD_UINT32;
typedef unsigned long long	SGD_UINT64;
typedef int		            SGD_RV;
typedef void*				SGD_OBJ;
typedef int					SGD_BOOL;
typedef void*				SGD_HANDLE;

//对称算法标识
#define SGD_SM1_ECB	    0x00000101	  //SM1算法ECB加密模式
#define SGD_SM1_CBC	    0x00000102	  //SM1算法CBC加密模式
#define SGD_SM1_CFB	    0x00000104	  //SM1算法CFB加密模式
#define SGD_SM1_OFB	    0x00000108	  //SM1算法OFB加密模式
#define SGD_SM1_MAC	    0x00000110	  //SM1算法MAC加密模式
#define SGD_SSF33_ECB	0x00000201	  //SSF33算法ECB加密模式
#define SGD_SSF33_CBC	0x00000202	  //SSF33算法CBC加密模式
#define SGD_SSF33_CFB	0x00000204	  //SSF33算法CFB加密模式
#define SGD_SSF33_OFB	0x00000208	  //SSF33算法OFB加密模式
#define SGD_SSF33_MAC	0x00000210	  //SSF33算法MAC加密模式
#define SGD_SM4_ECB		0x00000401	  //SM4算法ECB加密模式
#define SGD_SM4_CBC		0x00000402    //SM4算法CBC加密模式
#define SGD_SM4_CFB     0x00000404    //SM4算法CFB加密模式
#define SGD_SM4_OFB     0x00000408    //SM4算法OFB加密模式
#define SGD_SM4_MAC     0x00000410    //SM4算法MAC运算
#define SGD_ZUC_EEA3    0x00000801    //ZUC祖冲之机密性算法128-EEA3算法
#define SGD_ZUC_EIA3    0x00000802    //ZUC祖冲之完整性算法128-EIA3算法
//kxy add 2014.06.16
#define SGD_3DES_ECB	0x00002001	  //3DES算法ECB加密模式
#define SGD_3DES_CBC	0x00002002	  //3DES算法CBC加密模式
#define SGD_3DES_MAC	0x00002010	  //3DES算法MAC加密模式
#define SGD_AES_ECB     0x00004001	  //AES算法ECB加密模式
#define SGD_AES_CBC     0x00004002    //AES算法CBC加密模式
#define SGD_AES_MAC		0x00004010    //AES算法MAC加密模式
//0x00001000～0x800000FF  为其它对称算法预留


#define SGD_DES_ECB	    0x00003001	  //DES算法ECB加密模式
#define SGD_DES_CBC	    0x00003002	  //DES算法CBC加密模式
#define SGD_DES_CFB	    0x00003003	  //DES算法CFB加密模式
#define SGD_DES_OFB	    0x00003004	  //DES算法OFB加密模式

//非对称算法标识
#define SGD_RSA	        0x00010000	  //RSA算法
#define SGD_SM2_1	    0x00020100	  //椭圆曲线签名算法
#define SGD_SM2_2	    0x00020200	  //椭圆曲线密钥交换协议
#define SGD_SM2_3	    0x00020400	  //椭圆曲线加密算法
//#define SGD_ECC_n     0x00000400--0x800000xx  //为其它非对称算法预留
#define SGD_ECC_CV1_160 0x80000001    //1号曲线，160bit
#define SGD_ECC_CV2_192 0x80000002
#define SGD_ECC_CV3_224 0x80000003
#define SGD_ECC_CV4_256 0x80000004
#define SGD_ECC_CV5_192 0x80000005    //5号曲线，192bit
#define SGD_ECC_CV6_256 0x80000006
#define SGD_ECC_CV7_256 0x80000007    //7号曲线，256bit

//杂凑算法标识
#define SGD_SM3	        0x00000001	  //SM3杂凑算法
#define SGD_SHA1	    0x00000002	  //SHA1杂凑算法
#define SGD_SHA256	    0x00000004	  //SHA256杂凑算法
//0x00000040～0x00000080 为其它杂凑算法预留

//会话密钥存储在101-300位置
//#define _SESSIONKEY_STORE_IN_CARD_

//20090226 ECC加密机还是ECC加密卡
#define _ECC_SJK0814_   //MMK support SSF33/SM1/ECC
//#define _ECC_SJJ0929_    //JMJ support SS33/SM1/ECC

//20090423 为SM1高速卡修改本接口，屏蔽ECC算法
//#define _SJY05_B_     //JMJ support SSF33
//#define _SJY05_C_D_   //JMJ support SM1
//#define _SJY03_B_     //MMK support SSF33
//#define _SJY03_D_E_   //MMK support SM1

//20120702  DTCSP SM3是否软件实现
#define _SM3_SOFT_ 

#define ALGO_NOT_SUPPORT	-1

//-----------------------------------------------------------------------------
//set system environment
//#define __OS_WIN32__

#if defined(__OS_WIN32__)

#define DASDF_FUNC_EXPORT   __declspec(dllexport)
#define DASDF_FUNC_IMPORT    extern __declspec(dllimport)
#define DASDF_FUNC_IMPLEMENT  __declspec(dllexport)
#define DASDF_FUNC_STATIC    static

#else

#define DASDF_FUNC_EXPORT
#define DASDF_FUNC_IMPORT  extern
#define DASDF_FUNC_IMPLEMENT
#define DASDF_FUNC_STATIC  static

#endif

#define SYMM_KEY_LENGTH		16
#define KEY_ENC_KEY_LENGTH  16
#define SYMM_3DES_KEY_LENGTH 24

//-----------------------------------------------------------------------------
//RSA Public key and Private key structure
#define RSAref_MAX_BITS    2048
#define RSAref_MAX_LEN     ((RSAref_MAX_BITS + 7) / 8)
#define RSAref_MAX_PBITS   ((RSAref_MAX_BITS + 1) / 2)
#define RSAref_MAX_PLEN    ((RSAref_MAX_PBITS + 7)/ 8)

typedef struct RSArefPublicKey_st
{
	unsigned int  bits;
	unsigned char m[RSAref_MAX_LEN];
	unsigned char e[RSAref_MAX_LEN];
} RSArefPublicKey;

typedef struct RSArefPrivateKey_st
{
	unsigned int  bits;
	unsigned char m[RSAref_MAX_LEN];
	unsigned char e[RSAref_MAX_LEN];
	unsigned char d[RSAref_MAX_LEN];
	unsigned char prime[2][RSAref_MAX_PLEN];
	unsigned char pexp[2][RSAref_MAX_PLEN];
	unsigned char coef[RSAref_MAX_PLEN];
} RSArefPrivateKey;

//ECC Public key and Private key structure
#define ECCref_MAX_BITS			512                 //256->512
#define ECCref_MAX_LEN			((ECCref_MAX_BITS+7) / 8)

typedef struct ECCrefPublicKey_st
{
	unsigned int  bits;
	unsigned char x[ECCref_MAX_LEN]; 
	unsigned char y[ECCref_MAX_LEN]; 
} ECCrefPublicKey;

typedef struct ECCrefPrivateKey_st
{
	unsigned int  bits;
	unsigned char D[ECCref_MAX_LEN];
} ECCrefPrivateKey;

//ECC Cipher structure
typedef struct ECCCipher_st
{
	unsigned char x[ECCref_MAX_LEN]; 
	unsigned char y[ECCref_MAX_LEN]; 
	unsigned char M[32];
	unsigned int  L;                   //密文长度
	unsigned char C[1];   //密文数据 kxy 20140328
} ECCCipher;


//ECC Signature structure
typedef struct ECCSignature_st
{
	unsigned char r[ECCref_MAX_LEN];	
	unsigned char s[ECCref_MAX_LEN];	
} ECCSignature;

typedef struct DeviceInfo_st{
	unsigned char IssuerName[40];
	unsigned char DeviceName[16];
	unsigned char DeviceSerial[16];
	unsigned int  DeviceVersion;
	unsigned int  StandardVersion;
	unsigned int  AsymAlgAbility[2];
	unsigned int  SymAlgAbility;
	unsigned int  HashAlgAbility;
	unsigned int  BufferSize;
}DEVICEINFO;
//-----------------------------------------------------------------------------
//函数定义
DASDF_FUNC_EXPORT 
int SDF_OpenDevice(void **phDeviceHandle);
	/*
	*描述：	打开密码设备
	*参数：	phDeviceHandle[out]	返回设备句柄
	*返回值：	0	成功
	*		  非0	失败，返回错误代码
	*/

DASDF_FUNC_EXPORT 
int  SDF_OpenDeviceEx(void **phDeviceHandle,unsigned char *pucIpAddress,unsigned int  uiIpAddressLength);
/*
*描述：	自定义扩展函数，打开密码设备，用于打开指定IP的密码机设备
*参数：	phDeviceHandle[out]	    返回设备句柄
*       pucIpAddress[in]        要打开的密码机IP地址
*       uiIpAddressLength[in]   密码机IP地址长度
*返回值：	0	成功
*		  非0	失败，返回错误代码
*/

DASDF_FUNC_EXPORT 
int  SDF_CloseDevice(void *hDeviceHandle);
    /*
	*描述：	关闭密码设备，并释放相关资源
	*参数：	hDeviceHandle[in]	已打开的设备句柄
	*返回值：	0	成功
	*         非0	失败，返回错误代码
    */

DASDF_FUNC_EXPORT 
int SDF_OpenSession(void *hDeviceHandle, void **phSessionHandle);
    /*
	*描述：	创建与密码设备的会话
	*参数：	hDeviceHandle[in]	    已打开的设备句柄
	*       phSessionHandle[out]	返回与密码设备建立的新会话句柄
	*返回值：	0	成功
	*         非0	失败，返回错误代码
    */

DASDF_FUNC_EXPORT
int SDF_CloseSession(void *hSessionHandle);
    /*
	*描述：	关闭与密码设备已建立的会话，并释放相关资源
	*参数：	ulDeviceHandle[in]	与密码设备已建立的会话句柄
	*返回值：	0	成功
	*         非0	失败，返回错误代码
    */

DASDF_FUNC_EXPORT
int SDF_GetDeviceInfo(void *hSessionHandle,
					   DEVICEINFO *pstDeviceInfo);
    /*
	*描述：	获取密码设备能力描述
	*参数：	hSessionHandle[in]	与设备建立的会话句柄
	*       pstDeviceInfo [out]	设备能力描述信息，内容及格式见设备信息定义
	*返回值：	0	成功
	*         非0	失败，返回错误代码
    */

DASDF_FUNC_EXPORT
int SDF_GenerateRandom(void *hSessionHandle, 
						unsigned int  uiLength,
						unsigned char *pucRandom);
    /*
	*描述：	获取指定长度的随机数
	*参数：	hSessionHandle[in]	与设备建立的会话句柄
	*       uiLength[in]	    欲获取的随机数长度
	*       pucRandom[out]	    缓冲区指针，用于存放获取的随机数
	*返回值：	0	成功
	*         非0	失败，返回错误代码
    */

DASDF_FUNC_EXPORT
int SDF_GetPrivateKeyAccessRight(void *hSessionHandle, 
								  unsigned int  uiKeyIndex,
								  unsigned char *pucPassword,
								  unsigned int  uiPwdLength);
    /*
	*描述：	获取密码设备内部存储的指定索引私钥的使用授权
	*参数：	hSessionHandle[in]	与设备建立的会话句柄
	*		uiKeyIndex[in]		密码设备存储私钥的索引值
	*		pucPassword[in]		使用私钥权限的标识码
	*		uiPwdLength[in]		私钥权限标识码长度，不少于8字节
	*返回值：	0	成功
	*         非0	失败，返回错误代码
    */

DASDF_FUNC_EXPORT
int SDF_ReleasePrivateKeyAccessRight(  void *hSessionHandle, 
										unsigned int  uiKeyIndex);
    /*
	*描述：	释放密码设备存储的指定索引私钥的使用授权
	*参数：	hSessionHandle[in]	与设备建立的会话句柄
	*		uiKeyIndex[in]		密码设备存储私钥索引值
	*返回值：	0	成功
	*         非0	失败，返回错误代码
    */

DASDF_FUNC_EXPORT
int SDF_ExportSignPublicKey_RSA(void *hSessionHandle, 
								unsigned int  uiKeyIndex,
								RSArefPublicKey *pucPublicKey);
    /*
	*描述：	导出密码设备内部存储的指定索引位置的签名公钥
	*参数：	hSessionHandle[in]	与设备建立的会话句柄
	*		uiKeyIndex[in]		密码设备存储私钥索引值
	*		pucPublicKey[out]	RSA公钥结构
	*返回值：	0	成功
	*		  非0	失败，返回错误代码
    */

DASDF_FUNC_EXPORT
int SDF_ExportEncPublicKey_RSA(void *hSessionHandle, 
							   unsigned int  uiKeyIndex,
							   RSArefPublicKey *pucPublicKey);
    /*
	*描述：	导出密码设备内部存储的指定索引位置的加密公钥
	*参数：	hSessionHandle[in]	与设备建立的会话句柄
	*		uiKeyIndex[in]		密码设备存储私钥索引值
	*		pucPublicKey[out]	RSA公钥结构
	*返回值：	0	成功
	*		  非0	失败，返回错误代码
    */

DASDF_FUNC_EXPORT
int SDF_GenerateKeyPair_RSA(void *hSessionHandle, 
							unsigned int  uiKeyBits,
							RSArefPublicKey *pucPublicKey,
							RSArefPrivateKey *pucPrivateKey); 
    /*
	*描述：	请求密码设备产生指定模长的RSA密钥对
	*参数：	hSessionHandle[in]	与设备建立的会话句柄
	*		uiKeyBits [in]	    指定密钥模长
	*		pucPublicKey[out]	RSA公钥结构
	*		pucPrivateKey[out]	RSA私钥结构
	*返回值：	0	成功
	*         非0	失败，返回错误代码
    */

DASDF_FUNC_EXPORT
int SDF_GenerateKeyWithIPK_RSA(void *hSessionHandle, 
								unsigned int uiIPKIndex,
								unsigned int uiKeyBits,
								unsigned char *pucKey,
								unsigned int *puiKeyLength,
								void **phKeyHandle);
    /*
	*描述：	生成会话密钥并用指定索引的内部加密公钥加密输出，同时返回密钥句柄
	*参数：	hSessionHandle[in]	与设备建立的会话句柄
	*		uiIPKIndex[in]		密码设备内部存储公钥的索引值
	*       uiKeyBits[in]       指定产生的会话密钥长度
	*		pucKey[out]			缓冲区指针，用于存放返回的密钥密文
	*		puiKeyLength[out]	返回的密钥密文长度
	*		phKeyHandle[out]	返回的密钥句柄
	*返回值：	0	成功
	*		  非0	失败，返回错误代码
	*/

DASDF_FUNC_EXPORT
int SDF_GenerateKeyWithEPK_RSA(void *hSessionHandle, 
							   unsigned int uiKeyBits,
								RSArefPublicKey *pucPublicKey,
								unsigned char *pucKey,
								unsigned int *puiKeyLength,
								void **phKeyHandle);
    /*
	*描述：	生成会话密钥并用外部公钥加密输出，同时返回密钥句柄
	*参数：	hSessionHandle[in]	与设备建立的会话句柄
	*       uiKeyBits[in]       指定产生的会话密钥长度
	*		pucPublicKey[in]	输入的外部RSA公钥结构
	*		pucKey[out]			缓冲区指针，用于存放返回的密钥密文
	*		puiKeyLength[out]	返回的密钥密文长度
	*		phKeyHandle[out]	返回的密钥句柄
	*返回值：	0	成功
	*		  非0	失败，返回错误代码
	*/

DASDF_FUNC_EXPORT
int SDF_ImportKeyWithISK_RSA(void *hSessionHandle, 
							  unsigned int uiISKIndex,
							  unsigned char *pucKey,
							  unsigned int puiKeyLength,
							  void **phKeyHandle);
    /*
	*描述：	导入会话密钥并用内部私钥解密，同时返回密钥句柄
	*参数：	hSessionHandle[in]	与设备建立的会话句柄
	*		uiISKIndex[in]		密码设备内部存储加密私钥的索引值，对应于加密时的公钥
	*		pucKey[in]			缓冲区指针，用于存放输入的密钥密文
	*		puiKeyLength[in]	输入的密钥密文长度
	*		phKeyHandle[out]	返回的密钥句柄
	*返回值：	0	成功
	*		  非0	失败，返回错误代码
	*备注：	本函数既支持RSA算法,也支持ECC算法。
	*/

DASDF_FUNC_EXPORT
int SDF_ExchangeDigitEnvelopeBaseOnRSA(
									   void *hSessionHandle, 
									   unsigned int  uiKeyIndex,
									   RSArefPublicKey *pucPublicKey,
									   unsigned char *pucDEInput,
									   unsigned int  uiDELength,
									   unsigned char *pucDEOutput,
									   unsigned int  *puiDELength);
	/*
	*描述： 将由内部加密公钥加密的会话密钥转换为由外部指定的公钥加密，可用于数字信封转换
	*参数： hSessionHandle[in]	与设备建立的会话句柄
	*       uiKeyIndex[in]	    密码设备存储的内部RSA密钥对索引值
	*       pucPublicKey [in]	外部RSA公钥结构
	*	    pucDEInput [in]	    缓冲区指针，用于存放输入的会话密钥密文
	*		uiDELength[in]	    输入的会话密钥密文长度
	*		pucDEOutput[out]	缓冲区指针，用于存放输出的会话密钥密文
	*		puiDELength[out]	输出的会话密钥密文长度
	*返回值：  0	成功
	*        非0	失败，返回错误代码
	*/
DASDF_FUNC_EXPORT
int SDF_ExportSignPublicKey_ECC(void *hSessionHandle, 
								unsigned int  uiKeyIndex,
								ECCrefPublicKey *pucPublicKey);
    /*
	*描述：	导出密码设备内部存储的指定索引位置的签名公钥
	*参数：	hSessionHandle[in]	与设备建立的会话句柄
	*		uiKeyIndex[in]		密码设备存储私钥索引值
	*		pucPublicKey[out]	ECC公钥结构
	*返回值：	0	成功
	*		  非0	失败，返回错误代码
	*/

DASDF_FUNC_EXPORT
int SDF_ExportEncPublicKey_ECC(void *hSessionHandle, 
							   unsigned int  uiKeyIndex,
							   ECCrefPublicKey *pucPublicKey);
    /*
	*描述：	导出密码设备内部存储的指定索引位置的加密公钥
	*参数：	hSessionHandle[in]	与设备建立的会话句柄
	*		uiKeyIndex[in]		密码设备存储私钥索引值
	*		pucPublicKey[out]	ECC公钥结构
	*返回值：	0	成功
	*		  非0	失败，返回错误代码
	*/

DASDF_FUNC_EXPORT
int SDF_GenerateKeyPair_ECC(void *hSessionHandle, 
							unsigned int  uiAlgID,
							unsigned int  uiKeyBits,
							ECCrefPublicKey *pucPublicKey,
							ECCrefPrivateKey *pucPrivateKey);
    /*
	*描述：	请求密码设备产生指定类型和模长的Ecc密钥对
	*参数：	hSessionHandle[in]	与设备建立的会话句柄
	*		uiAlgID[in]			指定算法标识
	*		uiKeyBits [in]		指定密钥长度
	*		pucPublicKey[out]	ECC公钥结构
	*		pucPrivateKey[out]	ECC私钥结构
	*返回值：	0	成功
	*		  非0	失败，返回错误代码
	*/

DASDF_FUNC_EXPORT
int SDF_GenerateKeyWithIPK_ECC(void *hSessionHandle, 
								unsigned int uiIPKIndex,
								unsigned int uiKeyBits,
								ECCCipher *pucKey,
								void **phKeyHandle);
	/*
	*描述：	生成会话密钥并用指定索引的内部ECC加密公钥加密输出，同时返回密钥句柄
	*参数：	hSessionHandle[in]	与设备建立的会话句柄
	*		uiIPKIndex[in]		密码设备内部存储公钥的索引值
	*       uiKeyBits[in]	    指定产生的会话密钥长度
	*		pucKey[out]			缓冲区指针，用于存放返回的密钥密文
	*		phKeyHandle[out]	返回的密钥句柄
	*返回值：	0	成功
	*		  非0	失败，返回错误代码
	*/

DASDF_FUNC_EXPORT
int SDF_GenerateKeyWithEPK_ECC(void *hSessionHandle, 
							   unsigned int uiKeyBits,
							    unsigned int  uiAlgID,								
								ECCrefPublicKey *pucPublicKey,
								ECCCipher *pucKey,
								void **phKeyHandle);
    /*
	*描述：	生成会话密钥并用外部ECC公钥加密输出，同时返回密钥句柄
	*参数：	hSessionHandle[in]	与设备建立的会话句柄
	*       uiKeyBits[in]	    指定产生的会话密钥长度
	*       uiAlgID[in]	        外部ECC公钥的算法标识
	*		pucPublicKey[in]	输入的外部ECC公钥结构
	*		pucKey[out]			缓冲区指针，用于存放返回的密钥密文
	*		phKeyHandle[out]	返回的密钥句柄
	*返回值：	0	成功
	*		  非0	失败，返回错误代码
	*/

DASDF_FUNC_EXPORT
int SDF_ImportKeyWithISK_ECC(void *hSessionHandle,
							  unsigned int uiISKIndex,
							  ECCCipher *pucKey,
							  void **phKeyHandle);
    /*
	*描述：	导入会话密钥并用内部ECC加密私钥解密，同时返回密钥句柄
	*参数：	hSessionHandle[in]	与设备建立的会话句柄
	*		uiISKIndex[in]		密码设备内部存储加密私钥的索引值，对应于加密时的公钥
	*		pucKey[in]			缓冲区指针，用于存放输入的密钥密文
	*		phKeyHandle[out]	返回的密钥句柄
	*返回值：	0	成功
	*		  非0	失败，返回错误代码
	*/

/*
DASDF_FUNC_EXPORT
int SDF_GenerateKeyWithECC(void *hSessionHandle, 
							ECCrefPrivateKey *pucPrivateKey,
							ECCrefPublicKey *pucPublicKey,
							void **phKeyHandle);
*/
    /*ECDH密钥协商 20080512删除，换成下面的SCE密钥协商
	*描述：	使用自身ECC私钥和对方ECC公钥协商产生会话密钥，同时返回密钥句柄
	*参数：	hSessionHandle[in]	与设备建立的会话句柄
	*		pucPrivateKey[in]	外部输入的参与密钥协商的己方临时ECC私钥结构
	*		pucPublicKey[in]	外部输入的参与密钥协商的对方临时ECC公钥结构
	*		phKeyHandle[out]	返回的密钥句柄
	*返回值：	0	成功
	*		  非0	失败，返回错误代码
	*/
/*
DASDF_FUNC_EXPORT
int SDF_GenerateKeyWithECC (
							void *hSessionHandle, 
							unsigned int uiRole,
							unsigned int uiISKIndex,
							unsigned int uiKeyBits,
							ECCrefPrivateKey *pucSelfTmpPrivateKey,
							ECCrefPublicKey  *pucSelfTmpPublicKey,
							ECCrefPublicKey *pucOtherPublicKey,
							ECCrefPublicKey *pucOtherTmpPublicKey,
							unsigned char *pucSelfID,
							unsigned char *pucOtherID,
							void **phKeyHandle);
*/
	/*密钥协商20080623删除，换成3个函数实现密钥协商
	*描述：	使用自身ECC私钥和对方ECC公钥协商产生会话密钥，同时返回密钥句柄
	*参数：	hSessionHandle[in]	与设备建立的会话句柄
	*		uiRole[in]	    指明是密钥协商的发起方或是响应方
	*		uiISKIndex[in]	密码设备内部存储加密私钥的索引值，该私钥用于参与密钥协商
	*		uiKeyBits[in]	协商后要求输出的密钥长度
	*		pucSelfTmpPrivateKey[in]	外部输入的参与密钥协商的己方临时ECC私钥结构
	*		pucSelfTmpPublicKey[in]	    外部输入的参与密钥协商的己方临时ECC公钥结构
	*		pucOtherPublicKey[in]	    外部输入的参与密钥协商的对方ECC公钥结构
	*		pucOtherTmpPublicKey[in]	外部输入的参与密钥协商的对方临时ECC公钥结构
	*		pucSelfID[in]	参与密钥协商的己方ID值(长度ECCref_MAX_LEN)
	*		pucOtherID[in]	参与密钥协商的对方ID值(长度ECCref_MAX_LEN)
	*		phKeyHandle[out]	返回的密钥句柄
	*返回值：	0	成功
	*		  非0	失败，返回错误代码
	*备注：	1.如果在具体的应用中，协商双方没有统一分配的ID，可以将ID设定为常量
	*       2. uiRole为1时，表示是发起方；uiRole为2是，表示是响应方
	*/

DASDF_FUNC_EXPORT
int SDF_GenerateAgreementDataWithECC (
									  void *hSessionHandle, 
									  unsigned int uiISKIndex,
									  unsigned int uiKeyBits,
									  unsigned char *pucSponsorID,
									  unsigned int uiSponsorIDLength,
									  ECCrefPublicKey  *pucSponsorPublicKey,
									  ECCrefPublicKey  *pucSponsorTmpPublicKey,
									  void **phAgreementHandle);

	/*发起方 20080715修改
	描述：	使用ECC密钥协商算法，为计算会话密钥而产生协商参数，同时返回指定索引位置的ECC公钥、临时ECC密钥对的公钥及协商句柄。
	参数：	hSessionHandle[in]	与设备建立的会话句柄
			uiISKIndex[in]		密码设备内部存储加密私钥的索引值，该私钥用于参与密钥协商
			uiKeyBits[in]		要求协商的密钥长度
			pucSponsorID[in]	参与密钥协商的发起方ID值
			uiSponsorIDLength[in]		发起方ID长度
			pucSponsorPublicKey[out]	返回的发起方ECC公钥结构
			pucSponsorTmpPublicKey[out]	返回的发起方临时ECC公钥结构
			phAgreementHandle[out]		返回的协商句柄，用于计算协商密钥
			返回值：	0	成功
					  非0	失败，返回错误代码
			备注：	为协商会话密钥，协商的发起方应首先调用本函数。
				    如果在具体的应用中，协商双方没有统一分配的ID，可以将ID设定为常量。
    */

DASDF_FUNC_EXPORT
int SDF_GenerateKeyWithECC (
							void *hSessionHandle, 
							unsigned char *pucResponseID,
							unsigned int uiResponseIDLength,
							ECCrefPublicKey *pucResponsePublicKey,
							ECCrefPublicKey *pucResponseTmpPublicKey,
							void *hAgreementHandle,
							void **phKeyHandle);

	/*发起方 20080715修改
	描述：	使用ECC密钥协商算法，使用自身协商句柄和响应方的协商参数计算会话密钥，同时返回会话密钥句柄。
	参数：	hSessionHandle[in]	与设备建立的会话句柄
			pucResponseID[in]	外部输入的响应方ID值
			uiResponseIDLength[in]		外部输入的响应方ID长度
			pucResponsePublicKey[in]	外部输入的响应方ECC公钥结构
			pucResponseTmpPublicKey[in]	外部输入的响应方临时ECC公钥结构
			hAgreementHandle[in]		协商句柄，用于计算协商密钥
			phKeyHandle[out]	返回的密钥句柄
	返回值：	0	成功
			  非0	失败，返回错误代码
	备注：	协商的发起方获得响应方的协商参数后调用本函数，计算会话密钥。
			如果在具体的应用中，协商双方没有统一分配的ID，可以将ID设定为常量。
     */

DASDF_FUNC_EXPORT
int SDF_GenerateAgreementDataAndKeyWithECC (
						void *hSessionHandle, 
						unsigned int uiISKIndex,
						unsigned int uiKeyBits,
						unsigned char *pucResponseID,
						unsigned int uiResponseIDLength,
						unsigned char *pucSponsorID,
						unsigned int uiSponsorIDLength,
						ECCrefPublicKey *pucSponsorPublicKey,
						ECCrefPublicKey *pucSponsorTmpPublicKey,
						ECCrefPublicKey  *pucResponsePublicKey,
						ECCrefPublicKey  *pucResponseTmpPublicKey,
						void **phKeyHandle);

	/*响应方 20080715修改
	描述：	使用ECC密钥协商算法，产生协商参数并计算会话密钥，同时返回产生的协商参数和和密钥句柄。
	参数：	hSessionHandle[in]	与设备建立的会话句柄
			uiISKIndex[in]		密码设备内部存储加密私钥的索引值，该私钥用于参与密钥协商
			uiKeyBits[in]		协商后要求输出的密钥长度
			pucResponseID[in]	响应方ID值
			uiResponseIDLength[in]	响应方ID长度
			pucSponsorID[in]		发起方ID值
			uiSponsorIDLength[in]	发起方ID长度
			pucSponsorPublicKey[in]	外部输入的发起方ECC公钥结构
			pucSponsorTmpPublicKey[in]	外部输入的发起方临时ECC公钥结构
			pucResponsePublicKey[out]	返回的响应方ECC公钥结构
			pucResponseTmpPublicKey[out]	返回的响应方临时ECC公钥结构
			phKeyHandle[out]		返回的密钥句柄
	返回值：	0	成功
			  非0	失败，返回错误代码
	备注：	本函数由响应方调用。
			如果在具体的应用中，协商双方没有统一分配的ID，可以将ID设定为常量
    */


DASDF_FUNC_EXPORT
int SDF_ExchangeDigitEnvelopeBaseOnECC(
									   void *hSessionHandle, 
									   unsigned int  uiKeyIndex,
									   unsigned int  uiAlgID,
									   ECCrefPublicKey *pucPublicKey,
									   ECCCipher *pucEncDataIn,
									   ECCCipher *pucEncDataOut);
	/*
	描述：	将由内部加密公钥加密的会话密钥转换为由外部指定的公钥加密，可用于数字信封转换。
	参数：	hSessionHandle[in]	与设备建立的会话句柄
			uiKeyIndex[in]		密码设备存储的ECC密钥对索引值
			uiAlgID[in]			外部ECC公钥的算法标识
			pucPublicKey [in]	外部ECC公钥结构
			pucEncDataIn[in]	缓冲区指针，用于存放输入的会话密钥密文
			pucEncDataOut[out]	缓冲区指针，用于存放输出的会话密钥密文
	返回值：	0	成功
	非0	失败，返回错误代码
    */


DASDF_FUNC_EXPORT
int SDF_GenerateKeyWithKEK(void *hSessionHandle, 
						   unsigned int uiKeyBits,
							unsigned int  uiAlgID,
							unsigned int uiKEKIndex, 
							unsigned char *pucKey, 
							unsigned int *puiKeyLength, 
							void **phKeyHandle);
    /*
	*描述：	生成会话密钥并用密钥加密密钥加密输出，同时返回密钥句柄
	*参数：	hSessionHandle[in]	与设备建立的会话句柄
			uiKeyBits[in]		指定产生的会话密钥长度
	*		uiAlgID[in]			算法标识，指定对称加密算法
	*		uiKEKIndex[in]		密码设备内部存储密钥加密密钥的索引值
	*		pucKey[out]			缓冲区指针，用于存放返回的密钥密文
	*		puiKeyLength[out]	返回的密钥密文长度
	*		phKeyHandle[out]	返回的密钥句柄
	*返回值：	0	成功
	*		  非0	失败，返回错误代码
	*备注：	加密模式默认使用ECB模式
	*/

DASDF_FUNC_EXPORT
int SDF_ImportKeyWithKEK(void *hSessionHandle, 
						  unsigned int  uiAlgID,
						  unsigned int uiKEKIndex, 
						  unsigned char *pucKey, 
						  unsigned int puiKeyLength, 
						  void **phKeyHandle);
    /*
	*描述：	导入会话密钥并用密钥加密密钥解密，同时返回会话密钥句柄
	*参数：	hSessionHandle[in]	与设备建立的会话句柄
	*		uiAlgID[in]			算法标识，指定对称加密算法
	*		uiKEKIndex[in]		密码设备内部存储密钥加密密钥的索引值
	*		pucKey[in]			缓冲区指针，用于存放输入的密钥密文
	*		puiKeyLength[in]	输入的密钥密文长度
	*		phKeyHandle[out]	返回的密钥句柄
	*返回值：	0	成功
	*		  非0	失败，返回错误代码
	*备注：	加密模式默认使用ECB模式
	*/

DASDF_FUNC_EXPORT
int SDF_ImportKey(void *hSessionHandle, 
				   unsigned char *pucKey, 
				   unsigned int uiKeyLength,
				   void **phKeyHandle);
    /*
	*描述：	导入明文会话密钥，同时返回密钥句柄
	*参数：	hSessionHandle[in]	与设备建立的会话句柄
	*		pucKey[in]			缓冲区指针，用于存放输入的密钥明文
	*		puiKeyLength[in]	输入的密钥明文长度
	*		phKeyHandle[out]	返回的密钥句柄
	*返回值：	0	成功
	*		  非0	失败，返回错误代码
	*/

DASDF_FUNC_EXPORT
int SDF_DestroyKey(void *hSessionHandle, 
					void *hKeyHandle);
    /*
	*描述：	销毁会话密钥，并释放为密钥句柄分配的内存等资源。
	*参数：	hSessionHandle[in]	与设备建立的会话句柄
	*		hKeyHandle[in]		输入的密钥句柄
	*返回值：	0	成功
	*		  非0	失败，返回错误代码
	*备注：	备注：	在对称算法运算完成后，应调用本函数销毁会话密钥。
	*/

DASDF_FUNC_EXPORT
int SDF_ExternalPublicKeyOperation_RSA(
										void *hSessionHandle, 
										RSArefPublicKey *pucPublicKey,
										unsigned char *pucDataInput,
										unsigned int  uiInputLength,
										unsigned char *pucDataOutput,
										unsigned int  *puiOutputLength);
    /*
	*描述：	指定使用外部公钥对数据进行运算
	*参数：	hSessionHandle[in]	与设备建立的会话句柄
	*		pucPublicKey [in]	外部RSA公钥结构
	*		pucDataInput [in]	缓冲区指针，用于存放输入的数据
	*		uiInputLength[in]	输入的数据长度
	*		pucDataOutput[out]	缓冲区指针，用于存放输出的数据
	*		puiOutputLength[out]	输出的数据长度
	*返回值：	0	成功
	*		  非0	失败，返回错误代码
	*/

DASDF_FUNC_EXPORT
int SDF_ExternalPrivateKeyOperation_RSA(
										void *hSessionHandle, 
										RSArefPrivateKey *pucPrivateKey,
										unsigned char *pucDataInput,
										unsigned int  uiInputLength,
										unsigned char *pucDataOutput,
										unsigned int  *puiOutputLength);
	/*
	*描述：	指定使用外部私钥对数据进行运算
	*参数：	hSessionHandle[in]	与设备建立的会话句柄
	*		pucPrivateKey [in]	外部RSA私钥结构
	*		pucDataInput [in]	缓冲区指针，用于存放输入的数据
	*		uiInputLength [in]	输入的数据长度
	*		pucDataOutput [out]	缓冲区指针，用于存放输出的数据
	*		puiOutputLength [out]	输出的数据长度
	*返回值：	0	成功
	*		  非0	失败，返回错误代码
	*/

DASDF_FUNC_EXPORT
int SDF_InternalPublicKeyOperation_RSA(
										void *hSessionHandle,
										unsigned int  uiKeyIndex,
										unsigned char *pucDataInput,
										unsigned int  uiInputLength,
										unsigned char *pucDataOutput,
										unsigned int  *puiOutputLength);
	/*
	*描述：	使用内部指定索引的公钥对数据进行运算
	*参数：	hSessionHandle[in]	与设备建立的会话句柄
	*		uiKeyIndex[in]		密码设备内部存储公钥的索引值
	*		pucDataInput[in]	缓冲区指针，用于存放外部输入的数据
	*		uiInputLength[in]	输入的数据长度
	*		pucDataOutput[out]	缓冲区指针，用于存放输出的数据
	*		puiOutputLength[out]	输出的数据长度
	*返回值：	0	成功
	*		  非0	失败，返回错误代码
	*备注：	索引范围仅限于内部签名密钥对，数据格式由应用层封装
	*/

DASDF_FUNC_EXPORT
int SDF_InternalPrivateKeyOperation_RSA(
										void *hSessionHandle,
										unsigned int  uiKeyIndex,
										unsigned char *pucDataInput,
										unsigned int  uiInputLength,
										unsigned char *pucDataOutput,
										unsigned int  *puiOutputLength);
	/*
	*描述：	使用内部指定索引的私钥对数据进行运算
	*参数：	hSessionHandle[in]	与设备建立的会话句柄
	*		uiKeyIndex[in]		密码设备内部存储私钥的索引值
	*		pucDataInput[in]	缓冲区指针，用于存放外部输入的数据
	*		uiInputLength[in]	输入的数据长度
	*		pucDataOutput[out]	缓冲区指针，用于存放输出的数据
	*		puiOutputLength[out]	输出的数据长度
	*返回值：	0	成功
	*		  非0	失败，返回错误代码
	*备注：	索引范围仅限于内部签名密钥对，数据格式由应用层封装
	*/
DASDF_FUNC_EXPORT
int SDF_InternalPublicKeyOperation_RSA_Ex(
										void			*hSessionHandle, 
										unsigned int	uiKeyIndex,  
										unsigned int	uiKeyUsage,
										unsigned char	*pucDataInput, 
										unsigned int	uiInputLength, 
										unsigned char	*pucDataOutput, 
										unsigned int	*puiOutputLength); 

/************************************************************************/
/* 描述： 根据密钥用途，使用内部指定索引的公钥对数据进行运算 
参数：  hSessionHandle[in]		与设备建立的会话句柄 
		uiKeyIndex[in]			密码设备内部存储公钥的索引值 
		uiKeyUsage[in]			密钥用途
		pucDataInput[in]		缓冲区指针，用于存放外部输入的数据 
		uiInputLength[in]		输入的数据长度 
		pucDataOutput[out]		缓冲区指针，用于存放输出的数据 
		puiOutputLength[out]	输出的数据长度 
返回值： 
		0		成功 
		非0		失败，返回错误代码                                                 */
/************************************************************************/

DASDF_FUNC_EXPORT
int SDF_InternalPrivateKeyOperation_RSA_Ex(
										void			*hSessionHandle, 
										unsigned int	uiKeyIndex, 
										unsigned int	uiKeyUsage, 
										unsigned char	*pucDataInput, 
										unsigned int	uiInputLength, 
										unsigned char	*pucDataOutput, 
										unsigned int	*puiOutputLength);
/************************************************************************/
/* 描述： 根据密钥用途，使用内部指定索引的私钥对数据进行运算 
参数： 
		hSessionHandle[in]		与设备建立的会话句柄 
		uiKeyIndex[in]			密码设备内部存储私钥的索引值
		uiKeyUsage[in]			密钥用途
		pucDataInput[in]		缓冲区指针，用于存放外部输入的数据 
		uiInputLength[in]		输入的数据长度 
		pucDataOutput[out]		缓冲区指针，用于存放输出的数据 
		puiOutputLength[out]	输出的数据长度	
返回值：	
		0		成功 
		非0		失败，返回错误代码
                                                                     */
/************************************************************************/

DASDF_FUNC_EXPORT
int SDF_ExternalSign_ECC(
						 void *hSessionHandle,
						 unsigned int uiAlgID,
						 ECCrefPrivateKey *pucPrivateKey,
						 unsigned char *pucData,
						 unsigned int  uiDataLength,
						 ECCSignature *pucSignature);
	/*
	*描述：	使用ECC私钥对数据进行签名运算
	*参数：	hSessionHandle[in]	与设备建立的会话句柄
	*       uiAlgID[in]	        算法标识，指定使用的ECC算法
	*		pucPrivateKey[in]	外部ECC私钥结构
	*		pucData[in]			缓冲区指针，用于存放外部输入的数据
	*		uiDataLength[in]	输入的数据长度
	*		pucSignature[out]	缓冲区指针，用于存放输出的签名值数据
	*返回值：	0	成功
	*		  非0	失败，返回错误代码
	*备注：	对原文的杂凑运算，在函数外部完成。
	*/

DASDF_FUNC_EXPORT
int SDF_ExternalVerify_ECC(
						   void *hSessionHandle,
						   unsigned int uiAlgID,
						   ECCrefPublicKey *pucPublicKey,
						   unsigned char *pucDataInput,
						   unsigned int  uiInputLength,
						   ECCSignature *pucSignature);
	/*
	*描述：	使用ECC公钥对ECC签名值进行验证运算
	*参数：	hSessionHandle[in]	与设备建立的会话句柄
	*       uiAlgID[in]	        算法标识，指定使用的ECC算法
	*		pucPublicKey[in]	外部ECC公钥结构
	*		pucData[in]			缓冲区指针，用于存放外部输入的数据
	*		uiDataLength[in]	输入的数据长度
	*		pucSignature[in]	缓冲区指针，用于存放输入的签名值数据
	*返回值：	0	成功
	*		  非0	失败，返回错误代码
	*备注：	对原文的杂凑运算，在函数外部完成。
	*/

DASDF_FUNC_EXPORT
int SDF_InternalSign_ECC(
						 void *hSessionHandle,
						 unsigned int  uiISKIndex,
						 unsigned char *pucData,
						 unsigned int  uiDataLength,
						 ECCSignature *pucSignature);
	/*
	*描述：	使用ECC私钥对数据进行签名运算
	*参数：	hSessionHandle[in]	与设备建立的会话句柄
	*		uiISKIndex [in]		密码设备内部存储的ECC签名私钥的索引值
	*		pucData[in]			缓冲区指针，用于存放外部输入的数据
	*		uiDataLength[in]	输入的数据长度
	*		pucSignature [out]	缓冲区指针，用于存放输出的签名值数据
	*返回值：	0	成功
	*		  非0	失败，返回错误代码
	*备注：	对原文的杂凑运算，在函数外部完成。
	*/

DASDF_FUNC_EXPORT
int SDF_InternalVerify_ECC(
						   void *hSessionHandle,
						   unsigned int  uiISKIndex,
						   unsigned char *pucData,
						   unsigned int  uiDataLength,
						   ECCSignature *pucSignature);
	/*
	*描述：	使用ECC公钥对ECC签名值进行验证运算
	*参数：	hSessionHandle[in]	与设备建立的会话句柄
	*		uiISKIndex [in]		密码设备内部存储的ECC签名公钥的索引值
	*		pucData[in]			缓冲区指针，用于存放外部输入的数据
	*		uiDataLength[in]	输入的数据长度
	*		pucSignature[in]	缓冲区指针，用于存放输入的签名值数据
	*返回值：	0	成功
	*		  非0	失败，返回错误代码
	*备注：	对原文的杂凑运算，在函数外部完成。
	*/

DASDF_FUNC_EXPORT
int SDF_ExternalEncrypt_ECC(
							void *hSessionHandle,
							unsigned int uiAlgID,
							ECCrefPublicKey *pucPublicKey,
							unsigned char *pucData,
							unsigned int  uiDataLength,
							ECCCipher *pucEncData);
	/*
	*描述：	使用外部ECC公钥对数据进行加密运算
	*参数：	hSessionHandle[in]	与设备建立的会话句柄
	*       uiAlgID[in]	        算法标识，指定使用的ECC算法
	*		pucPublicKey[in]	外部ECC公钥结构
	*		pucData[in]			缓冲区指针，用于存放外部输入的数据
	*		uiDataLength[in]	输入的数据长度
	*		pucEncData[out]		缓冲区指针，用于存放输出的数据密文
	*返回值：	0	成功
	*		  非0	失败，返回错误代码
	*备注：	输入的数据长度uiDataLength不大于ECCref_MAX_LEN。
	*/

DASDF_FUNC_EXPORT
int SDF_ExternalDecrypt_ECC(
							void *hSessionHandle,
							unsigned int uiAlgID,
							ECCrefPrivateKey *pucPrivateKey,
							ECCCipher *pucEncData,
							unsigned char *pucData,
							unsigned int  *puiDataLength);
	/*
	*描述：	使用外部ECC私钥进行解密运算
	*参数：	hSessionHandle[in]	与设备建立的会话句柄
	*       uiAlgID[in]	        算法标识，指定使用的ECC算法
	*		pucPrivateKey[in]	外部ECC私钥结构
	*		pucEncData[in]		缓冲区指针，用于存放输入的数据密文
	*		pucData[out]		缓冲区指针，用于存放输出的数据明文
	*		puiDataLength[out]	输出的数据明文长度
	*返回值：	0	成功
	*		  非0	失败，返回错误代码
	*/

DASDF_FUNC_EXPORT
int SDF_InternalEncrypt_ECC(
							void *hSessionHandle,
							unsigned int uiISKIndex,
							unsigned char *pucData,
							unsigned int  uiDataLength,
							ECCCipher *pucEncData);
	/*
	*描述：	使用内部ECC公钥对数据进行加密运算
	*参数：	hSessionHandle[in]	与设备建立的会话句柄
	*       uiISKIndex [in]	    密码设备内部存储的ECC加密公钥的索引值
	*       pucData[in]	        缓冲区指针，用于存放外部输入的数据
	*       uiDataLength[in]	输入的数据长度
	*       pucEncData[out]	    缓冲区指针，用于存放输出的数据密文
	*返回值：	0	成功
	*         非0	失败，返回错误代码
	*备注：	输入的数据长度uiDataLength不大于ECCref_MAX_LEN。
	*/

DASDF_FUNC_EXPORT
int SDF_InternalDecrypt_ECC(
							void *hSessionHandle,
							unsigned int uiISKIndex,
							ECCCipher *pucEncData,
							unsigned char *pucData,
							unsigned int  *puiDataLength);
/*
*描述：	使用内部ECC私钥进行解密运算
*参数：	hSessionHandle[in]	与设备建立的会话句柄
*       uiISKIndex [in]	    密码设备内部存储的ECC加密私钥的索引值
*       pucEncData[in]	    缓冲区指针，用于存放输入的数据密文
*       pucData[out]	    缓冲区指针，用于存放输出的数据明文
*       puiDataLength[out]	输出的数据明文长度
*返回值：	0	成功
*         非0	失败，返回错误代码
*/

DASDF_FUNC_EXPORT
int SDF_Encrypt(
				void *hSessionHandle,
				void *hKeyHandle,
				unsigned int uiAlgID,
				unsigned char *pucIV,
				unsigned char *pucData,
				unsigned int uiDataLength,
				unsigned char *pucEncData,
				unsigned int  *puiEncDataLength);
	/*
	*描述：	使用指定的密钥句柄和IV对数据进行对称加密运算
	*参数：	hSessionHandle[in]	与设备建立的会话句柄
	*		hKeyHandle[in]		指定的密钥句柄
	*		uiAlgID[in]			算法标识，指定对称加密算法
	*		pucIV[in|out]		缓冲区指针，用于存放输入和返回的IV数据
	*		pucData[in]			缓冲区指针，用于存放输入的数据明文
	*		uiDataLength[in]	输入的数据明文长度
	*		pucEncData[out]		缓冲区指针，用于存放输出的数据密文
	*		puiEncDataLength[out]	输出的数据密文长度
	*返回值：	0	成功
	*		  非0	失败，返回错误代码
	*备注：	此函数不对数据进行填充处理，输入的数据必须是指定算法分组长度的整数倍。
	*/

DASDF_FUNC_EXPORT
int SDF_Decrypt(
				 void *hSessionHandle,
				 void *hKeyHandle,
				 unsigned int uiAlgID,
				 unsigned char *pucIV,
				 unsigned char *pucEncData,
				 unsigned int  uiEncDataLength,
				 unsigned char *pucData,
				 unsigned int *puiDataLength);
	/*
	*描述：	使用指定的密钥句柄和IV对数据进行对称解密运算
	*参数：	hSessionHandle[in]	与设备建立的会话句柄
	*		hKeyHandle[in]		指定的密钥句柄
	*		uiAlgID[in]			算法标识，指定对称加密算法
	*		pucIV[in|out]		缓冲区指针，用于存放输入和返回的IV数据
	*		pucEncData[in]		缓冲区指针，用于存放输入的数据密文
	*		uiEncDataLength[in]	输入的数据密文长度
	*		pucData[out]		缓冲区指针，用于存放输出的数据明文
	*		puiDataLength[out]	输出的数据明文长度
	*返回值：	0	成功
	*		  非0	失败，返回错误代码
	*备注：	此函数不对数据进行填充处理，输入的数据必须是指定算法分组长度的整数倍。
	*/

DASDF_FUNC_EXPORT
int SDF_CalculateMAC(
					 void *hSessionHandle,
					 void *hKeyHandle,
					 unsigned int uiAlgID,
					 unsigned char *pucIV,
					 unsigned char *pucData,
					 unsigned int uiDataLength,
					 unsigned char *pucMAC,
					 unsigned int  *puiMACLength);
	/*
	*描述：	使用指定的密钥句柄和IV对数据进行MAC运算
	*参数：	hSessionHandle[in]	与设备建立的会话句柄
	*		hKeyHandle[in]		指定的密钥句柄
	*		uiAlgID[in]			算法标识，指定MAC加密算法
	*		pucIV[in|out]		缓冲区指针，用于存放输入和返回的IV数据
	*		pucData[in]			缓冲区指针，用于存放输出的数据明文
	*		uiDataLength[in]	输出的数据明文长度
	*		pucMAC[out]			缓冲区指针，用于存放输出的MAC值
	*		puiMACLength[out]	输出的MAC值长度
	*返回值：	0	成功
	*		  非0	失败，返回错误代码
	*备注：	此函数不对数据进行分包处理，多包数据MAC运算由IV控制最后的MAC值。
	*/


DASDF_FUNC_EXPORT
int SDF_HashInit(
				 void *hSessionHandle,
				 unsigned int uiAlgID,
				 ECCrefPublicKey *pucPublicKey,
				 unsigned char *pucID,
				 unsigned int uiIDLength);

	/*
	描述：	三步式数据杂凑运算第一步。
	参数：	hSessionHandle[in]	与设备建立的会话句柄
			uiAlgID[in]			指定杂凑算法标识
			pucPublicKey[in]	签名者的ECC公钥，产生用于ECC签名的杂凑值时有效
			pucID[in]			签名者的ID值，产生用于ECC签名的杂凑值时有效
			uiIDLength[in]		签名者的ID长度
	返回值：	0	成功
				非0	失败，返回错误代码
	备注：	如果在具体的应用中，协商双方没有统一分配的ID，可以将ID设定为常量。
    */

DASDF_FUNC_EXPORT
int SDF_HashUpdate(
				   void *hSessionHandle,
				   unsigned char *pucData,
				   unsigned int  uiDataLength);
	/*
	*描述：	三步式数据杂凑运算第二步，对输入的明文进行杂凑运算
	*参数：	hSessionHandle[in]	与设备建立的会话句柄
	*		pucData[in]			缓冲区指针，用于存放输入的数据明文
	*		uiDataLength[in]	输入的数据明文长度
	*返回值：	0	成功
	*		  非0	失败，返回错误代码
	*/

DASDF_FUNC_EXPORT
int SDF_HashFinal(
				  void *hSessionHandle,
				  unsigned char *pucHash,
				  unsigned int  *puiHashLength);
	/*
	*描述：	三步式数据杂凑运算第三步，杂凑运算结束返回杂凑数据并清除中间数据
	*参数：	hSessionHandle[in]	与设备建立的会话句柄
	*		pucHash[out]		缓冲区指针，用于存放输出的杂凑数据
	*		puiHashLength[out]	返回的杂凑数据长度
	*返回值：	0	成功
	*		  非0	失败，返回错误代码
	*/

DASDF_FUNC_EXPORT
int SDF_CreateFile(
				   void *hSessionHandle,
				   unsigned char *pucFileName,
				   unsigned int uiNameLen,
				   unsigned int uiFileSize);
	/*
	*描述：	在密码设备内部创建用于存储用户数据的文件
	*参数：	hSessionHandle[in]	与设备建立的会话句柄
	*		pucFileName[in]		缓冲区指针，用于存放输入的文件名，最大长度128字节
	*		uiNameLen[in]		文件名长度
	*		uiFileSize[in]		文件所占存储空间的长度
	*返回值：	0	成功
	*	      非0	失败，返回错误代码
	*/

DASDF_FUNC_EXPORT
int SDF_ReadFile(
				 void *hSessionHandle,
				 unsigned char *pucFileName,
				 unsigned int uiNameLen,
				 unsigned int uiOffset,
				 unsigned int *puiFileLength,
				 unsigned char *pucBuffer);
	/*
	*描述：	读取在密码设备内部存储用户数据的文件的内容
	*参数：	hSessionHandle[in]	与设备建立的会话句柄
	*		pucFileName[in]		缓冲区指针，用于存放输入的文件名，最大长度128字节
	*		uiNameLen[in]		文件名长度
	*       uiOffset[in]	    指定读取文件时的偏移值
	*		puiFileLength[in|out]	入参时指定读取文件内容的长度；出参时返回实际读取文件内容的长度
	*		pucBuffer[out]		缓冲区指针，用于存放读取的文件数据
	*返回值：	0	成功
	*		  非0	失败，返回错误代码
	*/

DASDF_FUNC_EXPORT
int SDF_WriteFile(
				  void *hSessionHandle,
				  unsigned char *pucFileName,
				  unsigned int uiNameLen,
				  unsigned int uiOffset,
				  unsigned int uiFileLength,
				  unsigned char *pucBuffer);
	/*
	*描述：	向密码设备内部存储用户数据的文件中写入内容
	*参数：	hSessionHandle[in]	与设备建立的会话句柄
	*		pucFileName[in]		缓冲区指针，用于存放输入的文件名，最大长度128字节
	*		uiNameLen[in]		文件名长度
	*	    uiOffset[in]	    指定写入文件时的偏移值
	*		uiFileLength[in]	指定写入文件内容的长度
	*		pucBuffer[in]		缓冲区指针，用于存放输入的写文件数据
	*返回值：	0	成功
	*		  非0	失败，返回错误代码
	*/

DASDF_FUNC_EXPORT
int SDF_DeleteFile(
				   void *hSessionHandle,
				   unsigned char *pucFileName,
				   unsigned int uiNameLen);
	/*
	*描述：	删除指定文件名的密码设备内部存储用户数据的文件
	*参数：	hSessionHandle[in]	与设备建立的会话句柄
	*		pucFileName[in]		缓冲区指针，用于存放输入的文件名，最大长度128字节
	*		uiNameLen[in]		文件名长度
	*返回值：	0	成功
	*		  非0	失败，返回错误代码
	*/
//-----------------------------------------------------------------------------
/////// 20110816 金税三期身份认证系统项目 增加函数
/******************************************************************* 
描述：		从外部导入RSA或ECC密钥对
参数：		hSessionHandle[in]	与设备建立的会话句柄
			Mechanism[in]		算法标识
			KeyId[in]			密钥存放的id号，此处即密钥索引号Index
			PrivateKeyDerBuf[in]私钥DER缓冲区指针
			prikeyDerLen[in]	私钥DER缓冲区长度
			PublicKeyDerBuf[in]	公钥DER缓冲区指针
			PublicDerLen[in]	公钥DER缓冲区长度
返回值：	0	成功
			非0	失败，返回错误代码

备注：		对于RSA算法来说，私钥指PKCS1格式的DER编码私钥，公钥同理；
			对于ECC算法来说，目前私钥指D，公钥指xy。
            本函数调用时，设备端需要满足管理员权限。
*/
DASDF_FUNC_EXPORT
int SDF_ImportKeyPair(void             *hSessionHandle, 
						  unsigned  int    Mechanism,		   
						  unsigned  int    KeyId,
						  unsigned  char   *PrivateKeyDerBuf,
						  unsigned  int    prikeyDerLen,
						  unsigned  char   *PublicKeyDerBuf,
						  unsigned  int    PublicDerLen);



/******************************************************************* 
描述：		产生RSA密钥对并保存至密钥表 
参数：		hSessionHandle[in]	与设备建立的会话句柄
			Mechanism[in]		算法标识
			KeySize[in]			密钥长度
			keyid[in]			密钥ID，此处即密钥索引号Index
返回值：	0	成功
			非0	失败，返回错误代码
备注：      本函数调用时，设备端需要满足管理员权限。
*/
DASDF_FUNC_EXPORT
int SDF_GenerateKeyPairEx_RSA(void *hSessionHandle, 
								  unsigned  int Mechanism,
								  unsigned  int KeySize,
								  unsigned  int keyid);


/******************************************************************* 
描述：		产生ECC密钥对并保存至密钥表 
参数：		hSessionHandle[in]	与设备建立的会话句柄
			Mechanism[in]		算法标识
			uiAlgID[in]			ECC算法标识
			keyid[in]			密钥ID，此处即密钥索引号Index
返回值：	0		成功
			非0		失败，返回错误代码
备注：      本函数调用时，设备端需要满足管理员权限。
*/

DASDF_FUNC_EXPORT
int SDF_GenerateKeyPairEx_ECC(void *hSessionHandle, 
								  unsigned  int Mechanism,
								  unsigned int  uiAlgID,
								  unsigned  int keyid);
//-----------------------------------------------------------------------------
//错误代码标识
#define SDR_OK	                0x0	                    //操作成功
#define SDR_BASE	            0x01000000	            //错误码基础值
#define SDR_UNKNOWERR			SDR_BASE + 0x00000001	//未知错误
#define SDR_NOTSUPPORT			SDR_BASE + 0x00000002	//不支持的接口调用
#define SDR_COMMFAIL			SDR_BASE + 0x00000003	//与设备通信失败
#define SDR_HARDFAIL			SDR_BASE + 0x00000004	//运算模块无响应
#define SDR_OPENDEVICE			SDR_BASE + 0x00000005	//打开设备失败
#define SDR_OPENSESSION			SDR_BASE + 0x00000006	//创建会话失败
#define SDR_PARDENY				SDR_BASE + 0x00000007	//无私钥使用权限
#define SDR_KEYNOTEXIST			SDR_BASE + 0x00000008	//不存在的密钥调用
#define SDR_ALGNOTSUPPORT		SDR_BASE + 0x00000009	//不支持的算法调用
#define SDR_ALGMODNOTSUPPORT	SDR_BASE + 0x0000000A	//不支持的算法模式调用
#define SDR_PKOPERR				SDR_BASE + 0x0000000B	//公钥运算失败
#define SDR_SKOPERR				SDR_BASE + 0x0000000C	//私钥运算失败
#define SDR_SIGNERR				SDR_BASE + 0x0000000D	//签名运算失败
#define SDR_VERIFYERR			SDR_BASE + 0x0000000E	//验证签名失败
#define SDR_SYMOPERR			SDR_BASE + 0x0000000F	//对称算法运算失败
#define SDR_STEPERR				SDR_BASE + 0x00000010	//多步运算步骤错误
#define SDR_FILESIZEERR			SDR_BASE + 0x00000011	//文件长度超出限制
#define SDR_FILENOEXIST			SDR_BASE + 0x00000012	//指定的文件不存在
#define SDR_FILEOFSERR			SDR_BASE + 0x00000013	//文件起始位置错误
#define SDR_KEYTYPEERR			SDR_BASE + 0x00000014	//密钥类型错误
#define SDR_KEYERR				SDR_BASE + 0x00000015	//密钥错误
#define SDR_ENCDATAERR          SDR_BASE + 0x00000016   //ECC加密数据错误
//… …	SDR_BASE + 0x00000016至 SDR_BASE + 0x00FFFFFF	预留

#define SDR_CLOSEDEVICE	         SDR_BASE + 0x00000090	    //关闭设备失败  (由于标准增加了一个错误码，本错误码进行了调整,20110324)
#define SDR_CLOSESESSION	     SDR_BASE + 0x00000017	    //关闭会话失败
#define SDR_DATA_LENGTH_ERR      SDR_BASE + 0x00000018      //数据长度错误
#define SDR_BUFFER_TOO_SMALL     SDR_BASE + 0x00000019      //接受buffer大小不够
#define SDR_GEN_RSA_KEY_ERR		 SDR_BASE + 0x0000001A		//产生RSA密钥错误
#define SDR_GEN_ECC_KEY_ERR		 SDR_BASE + 0x0000001B		//产生ECC密钥错误
#define SDR_GEN_SYMM_KEY_ERR	 SDR_BASE + 0x0000001C      //产生对称密钥错误
#define SDR_GEN_RADOM_ERR		 SDR_BASE + 0x0000001D		//产生随机数错误
#define SDR_ENC_SYMM_KEY_ERR	 SDR_BASE + 0x0000001E		//加密SYMMKEY错误
#define SDR_MEMORY_ERR			 SDR_BASE + 0x0000001F		//内存错误
#define SDR_KEY_EXH_ERR			 SDR_BASE + 0x00000020		//密钥转换错误
#define SDR_ENC_ERROR			 SDR_BASE + 0x00000021		//加密失败
#define SDR_DEC_ERROR			 SDR_BASE + 0x00000022		//解密失败
#define SDR_SM3_INIT_ERR		 SDR_BASE + 0x00000023		//SM3算法初始化失败
#define SDR_SHA1_INIT_ERR		 SDR_BASE + 0x00000024		//SHA1算法初始化失败
#define SDR_SHA256_INIT_ERR		 SDR_BASE + 0x00000025		//SHA256算法初始化失败
#define SDR_SM3_UPDATE_ERR		 SDR_BASE + 0x00000026		//SM3算法杂凑运算失败
#define SDR_SHA1_UPDATE_ERR		 SDR_BASE + 0x00000027		//SHA1算法杂凑运算失败
#define SDR_SHA256_UPDATE_ERR	 SDR_BASE + 0x00000028		//SHA256算法杂凑运算失败
#define SDR_SM3_FINAL_ERR		 SDR_BASE + 0x00000029		//SM3算法杂凑运算输出失败
#define SDR_SHA1_FINAL_ERR		 SDR_BASE + 0x0000002A		//SHA1算法杂凑运算输出失败
#define SDR_SHA256_FINAL_ERR	 SDR_BASE + 0x0000002B		//SHA256算法杂凑运算输出失败
#define SDR_URFBC_ERR			 SDR_BASE + 0x0000002C		//从FLUSH区读数据错误
#define SDR_UWFBC_ERR			 SDR_BASE + 0x0000002D		//向FLUSH区写数据错误
#define SDR_URFBC_ERR_ReadIndex	 SDR_BASE + 0x0000002E		//从FLUSH区读数据索引错误
#define SDR_UWFBC_ERR_Create	 SDR_BASE + 0x0000002F		//创建文件[写入FLUSH错误
#define SDR_UNKNOWFile_ERR		 SDR_BASE + 0x00000030		//文件已存在
#define SDR_URFBC_Number_ERR	 SDR_BASE + 0x00000031		//从FLUSH区读文件个数错误
#define SDR_KEY_LENGTH_ERR       SDR_BASE + 0x00000032      //密钥长度错误
#define SDR_INSERTLIST_ERR		 SDR_BASE + 0x00000033		//插入链表错误；
#define SDF_OFFSET_ERROR		 SDR_BASE + 0x00000034		//偏移量错误，不能超过文件大小
#define SDF_SESSIONHANDLE_ERR    SDR_BASE + 0x00000035      //会话句柄错误
#define SDF_KEYHANDLE_ERR        SDR_BASE + 0x00000036      //密钥句柄错误
#define SDF_PARAMETER_ERR        SDR_BASE + 0x00000037      //参数输入错误
#define SDF_FILEINDEX_TOO_LONG   SDR_BASE + 0x00000038      //文件索引越界
#define SDF_DER_DECODE_ERR       SDR_BASE + 0x00000039      //Der解码密钥错误
#define SDF_MANAGEMENT_DENY_ERR  SDR_BASE + 0x0000003A      //管理权限不满足
#define SDF_IMPORTKEYPAIR_ERR    SDR_BASE + 0x0000003B      //导入密钥对错误

//kxy add 20140619
#define KEY_USAGE_ENCRYPT	1
#define KEY_USAGE_SIGN		2
#ifdef __cplusplus
}
#endif

#endif
