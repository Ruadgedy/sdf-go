#ifndef __DASDF_API_H__
#define __DASDF_API_H__

#ifdef __cplusplus
extern "C" {
#endif
//-----------------------------------------------------------------------------
//���ӿ���ѭ���ܾ��ƶ��ġ���Կ���������ʩӦ�ü�����ϵ �����豸Ӧ�ýӿڹ淶��2010��8�°�
//-----------------------------------------------------------------------------

/*�������Ͷ���*/
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

//�Գ��㷨��ʶ
#define SGD_SM1_ECB	    0x00000101	  //SM1�㷨ECB����ģʽ
#define SGD_SM1_CBC	    0x00000102	  //SM1�㷨CBC����ģʽ
#define SGD_SM1_CFB	    0x00000104	  //SM1�㷨CFB����ģʽ
#define SGD_SM1_OFB	    0x00000108	  //SM1�㷨OFB����ģʽ
#define SGD_SM1_MAC	    0x00000110	  //SM1�㷨MAC����ģʽ
#define SGD_SSF33_ECB	0x00000201	  //SSF33�㷨ECB����ģʽ
#define SGD_SSF33_CBC	0x00000202	  //SSF33�㷨CBC����ģʽ
#define SGD_SSF33_CFB	0x00000204	  //SSF33�㷨CFB����ģʽ
#define SGD_SSF33_OFB	0x00000208	  //SSF33�㷨OFB����ģʽ
#define SGD_SSF33_MAC	0x00000210	  //SSF33�㷨MAC����ģʽ
#define SGD_SM4_ECB		0x00000401	  //SM4�㷨ECB����ģʽ
#define SGD_SM4_CBC		0x00000402    //SM4�㷨CBC����ģʽ
#define SGD_SM4_CFB     0x00000404    //SM4�㷨CFB����ģʽ
#define SGD_SM4_OFB     0x00000408    //SM4�㷨OFB����ģʽ
#define SGD_SM4_MAC     0x00000410    //SM4�㷨MAC����
#define SGD_ZUC_EEA3    0x00000801    //ZUC���֮�������㷨128-EEA3�㷨
#define SGD_ZUC_EIA3    0x00000802    //ZUC���֮�������㷨128-EIA3�㷨
//kxy add 2014.06.16
#define SGD_3DES_ECB	0x00002001	  //3DES�㷨ECB����ģʽ
#define SGD_3DES_CBC	0x00002002	  //3DES�㷨CBC����ģʽ
#define SGD_3DES_MAC	0x00002010	  //3DES�㷨MAC����ģʽ
#define SGD_AES_ECB     0x00004001	  //AES�㷨ECB����ģʽ
#define SGD_AES_CBC     0x00004002    //AES�㷨CBC����ģʽ
#define SGD_AES_MAC		0x00004010    //AES�㷨MAC����ģʽ
//0x00001000��0x800000FF  Ϊ�����Գ��㷨Ԥ��


#define SGD_DES_ECB	    0x00003001	  //DES�㷨ECB����ģʽ
#define SGD_DES_CBC	    0x00003002	  //DES�㷨CBC����ģʽ
#define SGD_DES_CFB	    0x00003003	  //DES�㷨CFB����ģʽ
#define SGD_DES_OFB	    0x00003004	  //DES�㷨OFB����ģʽ

//�ǶԳ��㷨��ʶ
#define SGD_RSA	        0x00010000	  //RSA�㷨
#define SGD_SM2_1	    0x00020100	  //��Բ����ǩ���㷨
#define SGD_SM2_2	    0x00020200	  //��Բ������Կ����Э��
#define SGD_SM2_3	    0x00020400	  //��Բ���߼����㷨
//#define SGD_ECC_n     0x00000400--0x800000xx  //Ϊ�����ǶԳ��㷨Ԥ��
#define SGD_ECC_CV1_160 0x80000001    //1�����ߣ�160bit
#define SGD_ECC_CV2_192 0x80000002
#define SGD_ECC_CV3_224 0x80000003
#define SGD_ECC_CV4_256 0x80000004
#define SGD_ECC_CV5_192 0x80000005    //5�����ߣ�192bit
#define SGD_ECC_CV6_256 0x80000006
#define SGD_ECC_CV7_256 0x80000007    //7�����ߣ�256bit

//�Ӵ��㷨��ʶ
#define SGD_SM3	        0x00000001	  //SM3�Ӵ��㷨
#define SGD_SHA1	    0x00000002	  //SHA1�Ӵ��㷨
#define SGD_SHA256	    0x00000004	  //SHA256�Ӵ��㷨
//0x00000040��0x00000080 Ϊ�����Ӵ��㷨Ԥ��

//�Ự��Կ�洢��101-300λ��
//#define _SESSIONKEY_STORE_IN_CARD_

//20090226 ECC���ܻ�����ECC���ܿ�
#define _ECC_SJK0814_   //MMK support SSF33/SM1/ECC
//#define _ECC_SJJ0929_    //JMJ support SS33/SM1/ECC

//20090423 ΪSM1���ٿ��޸ı��ӿڣ�����ECC�㷨
//#define _SJY05_B_     //JMJ support SSF33
//#define _SJY05_C_D_   //JMJ support SM1
//#define _SJY03_B_     //MMK support SSF33
//#define _SJY03_D_E_   //MMK support SM1

//20120702  DTCSP SM3�Ƿ����ʵ��
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
	unsigned int  L;                   //���ĳ���
	unsigned char C[1];   //�������� kxy 20140328
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
//��������
DASDF_FUNC_EXPORT 
int SDF_OpenDevice(void **phDeviceHandle);
	/*
	*������	�������豸
	*������	phDeviceHandle[out]	�����豸���
	*����ֵ��	0	�ɹ�
	*		  ��0	ʧ�ܣ����ش������
	*/

DASDF_FUNC_EXPORT 
int  SDF_OpenDeviceEx(void **phDeviceHandle,unsigned char *pucIpAddress,unsigned int  uiIpAddressLength);
/*
*������	�Զ�����չ�������������豸�����ڴ�ָ��IP��������豸
*������	phDeviceHandle[out]	    �����豸���
*       pucIpAddress[in]        Ҫ�򿪵������IP��ַ
*       uiIpAddressLength[in]   �����IP��ַ����
*����ֵ��	0	�ɹ�
*		  ��0	ʧ�ܣ����ش������
*/

DASDF_FUNC_EXPORT 
int  SDF_CloseDevice(void *hDeviceHandle);
    /*
	*������	�ر������豸�����ͷ������Դ
	*������	hDeviceHandle[in]	�Ѵ򿪵��豸���
	*����ֵ��	0	�ɹ�
	*         ��0	ʧ�ܣ����ش������
    */

DASDF_FUNC_EXPORT 
int SDF_OpenSession(void *hDeviceHandle, void **phSessionHandle);
    /*
	*������	�����������豸�ĻỰ
	*������	hDeviceHandle[in]	    �Ѵ򿪵��豸���
	*       phSessionHandle[out]	�����������豸�������»Ự���
	*����ֵ��	0	�ɹ�
	*         ��0	ʧ�ܣ����ش������
    */

DASDF_FUNC_EXPORT
int SDF_CloseSession(void *hSessionHandle);
    /*
	*������	�ر��������豸�ѽ����ĻỰ�����ͷ������Դ
	*������	ulDeviceHandle[in]	�������豸�ѽ����ĻỰ���
	*����ֵ��	0	�ɹ�
	*         ��0	ʧ�ܣ����ش������
    */

DASDF_FUNC_EXPORT
int SDF_GetDeviceInfo(void *hSessionHandle,
					   DEVICEINFO *pstDeviceInfo);
    /*
	*������	��ȡ�����豸��������
	*������	hSessionHandle[in]	���豸�����ĻỰ���
	*       pstDeviceInfo [out]	�豸����������Ϣ�����ݼ���ʽ���豸��Ϣ����
	*����ֵ��	0	�ɹ�
	*         ��0	ʧ�ܣ����ش������
    */

DASDF_FUNC_EXPORT
int SDF_GenerateRandom(void *hSessionHandle, 
						unsigned int  uiLength,
						unsigned char *pucRandom);
    /*
	*������	��ȡָ�����ȵ������
	*������	hSessionHandle[in]	���豸�����ĻỰ���
	*       uiLength[in]	    ����ȡ�����������
	*       pucRandom[out]	    ������ָ�룬���ڴ�Ż�ȡ�������
	*����ֵ��	0	�ɹ�
	*         ��0	ʧ�ܣ����ش������
    */

DASDF_FUNC_EXPORT
int SDF_GetPrivateKeyAccessRight(void *hSessionHandle, 
								  unsigned int  uiKeyIndex,
								  unsigned char *pucPassword,
								  unsigned int  uiPwdLength);
    /*
	*������	��ȡ�����豸�ڲ��洢��ָ������˽Կ��ʹ����Ȩ
	*������	hSessionHandle[in]	���豸�����ĻỰ���
	*		uiKeyIndex[in]		�����豸�洢˽Կ������ֵ
	*		pucPassword[in]		ʹ��˽ԿȨ�޵ı�ʶ��
	*		uiPwdLength[in]		˽ԿȨ�ޱ�ʶ�볤�ȣ�������8�ֽ�
	*����ֵ��	0	�ɹ�
	*         ��0	ʧ�ܣ����ش������
    */

DASDF_FUNC_EXPORT
int SDF_ReleasePrivateKeyAccessRight(  void *hSessionHandle, 
										unsigned int  uiKeyIndex);
    /*
	*������	�ͷ������豸�洢��ָ������˽Կ��ʹ����Ȩ
	*������	hSessionHandle[in]	���豸�����ĻỰ���
	*		uiKeyIndex[in]		�����豸�洢˽Կ����ֵ
	*����ֵ��	0	�ɹ�
	*         ��0	ʧ�ܣ����ش������
    */

DASDF_FUNC_EXPORT
int SDF_ExportSignPublicKey_RSA(void *hSessionHandle, 
								unsigned int  uiKeyIndex,
								RSArefPublicKey *pucPublicKey);
    /*
	*������	���������豸�ڲ��洢��ָ������λ�õ�ǩ����Կ
	*������	hSessionHandle[in]	���豸�����ĻỰ���
	*		uiKeyIndex[in]		�����豸�洢˽Կ����ֵ
	*		pucPublicKey[out]	RSA��Կ�ṹ
	*����ֵ��	0	�ɹ�
	*		  ��0	ʧ�ܣ����ش������
    */

DASDF_FUNC_EXPORT
int SDF_ExportEncPublicKey_RSA(void *hSessionHandle, 
							   unsigned int  uiKeyIndex,
							   RSArefPublicKey *pucPublicKey);
    /*
	*������	���������豸�ڲ��洢��ָ������λ�õļ��ܹ�Կ
	*������	hSessionHandle[in]	���豸�����ĻỰ���
	*		uiKeyIndex[in]		�����豸�洢˽Կ����ֵ
	*		pucPublicKey[out]	RSA��Կ�ṹ
	*����ֵ��	0	�ɹ�
	*		  ��0	ʧ�ܣ����ش������
    */

DASDF_FUNC_EXPORT
int SDF_GenerateKeyPair_RSA(void *hSessionHandle, 
							unsigned int  uiKeyBits,
							RSArefPublicKey *pucPublicKey,
							RSArefPrivateKey *pucPrivateKey); 
    /*
	*������	���������豸����ָ��ģ����RSA��Կ��
	*������	hSessionHandle[in]	���豸�����ĻỰ���
	*		uiKeyBits [in]	    ָ����Կģ��
	*		pucPublicKey[out]	RSA��Կ�ṹ
	*		pucPrivateKey[out]	RSA˽Կ�ṹ
	*����ֵ��	0	�ɹ�
	*         ��0	ʧ�ܣ����ش������
    */

DASDF_FUNC_EXPORT
int SDF_GenerateKeyWithIPK_RSA(void *hSessionHandle, 
								unsigned int uiIPKIndex,
								unsigned int uiKeyBits,
								unsigned char *pucKey,
								unsigned int *puiKeyLength,
								void **phKeyHandle);
    /*
	*������	���ɻỰ��Կ����ָ���������ڲ����ܹ�Կ���������ͬʱ������Կ���
	*������	hSessionHandle[in]	���豸�����ĻỰ���
	*		uiIPKIndex[in]		�����豸�ڲ��洢��Կ������ֵ
	*       uiKeyBits[in]       ָ�������ĻỰ��Կ����
	*		pucKey[out]			������ָ�룬���ڴ�ŷ��ص���Կ����
	*		puiKeyLength[out]	���ص���Կ���ĳ���
	*		phKeyHandle[out]	���ص���Կ���
	*����ֵ��	0	�ɹ�
	*		  ��0	ʧ�ܣ����ش������
	*/

DASDF_FUNC_EXPORT
int SDF_GenerateKeyWithEPK_RSA(void *hSessionHandle, 
							   unsigned int uiKeyBits,
								RSArefPublicKey *pucPublicKey,
								unsigned char *pucKey,
								unsigned int *puiKeyLength,
								void **phKeyHandle);
    /*
	*������	���ɻỰ��Կ�����ⲿ��Կ���������ͬʱ������Կ���
	*������	hSessionHandle[in]	���豸�����ĻỰ���
	*       uiKeyBits[in]       ָ�������ĻỰ��Կ����
	*		pucPublicKey[in]	������ⲿRSA��Կ�ṹ
	*		pucKey[out]			������ָ�룬���ڴ�ŷ��ص���Կ����
	*		puiKeyLength[out]	���ص���Կ���ĳ���
	*		phKeyHandle[out]	���ص���Կ���
	*����ֵ��	0	�ɹ�
	*		  ��0	ʧ�ܣ����ش������
	*/

DASDF_FUNC_EXPORT
int SDF_ImportKeyWithISK_RSA(void *hSessionHandle, 
							  unsigned int uiISKIndex,
							  unsigned char *pucKey,
							  unsigned int puiKeyLength,
							  void **phKeyHandle);
    /*
	*������	����Ự��Կ�����ڲ�˽Կ���ܣ�ͬʱ������Կ���
	*������	hSessionHandle[in]	���豸�����ĻỰ���
	*		uiISKIndex[in]		�����豸�ڲ��洢����˽Կ������ֵ����Ӧ�ڼ���ʱ�Ĺ�Կ
	*		pucKey[in]			������ָ�룬���ڴ���������Կ����
	*		puiKeyLength[in]	�������Կ���ĳ���
	*		phKeyHandle[out]	���ص���Կ���
	*����ֵ��	0	�ɹ�
	*		  ��0	ʧ�ܣ����ش������
	*��ע��	��������֧��RSA�㷨,Ҳ֧��ECC�㷨��
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
	*������ �����ڲ����ܹ�Կ���ܵĻỰ��Կת��Ϊ���ⲿָ���Ĺ�Կ���ܣ������������ŷ�ת��
	*������ hSessionHandle[in]	���豸�����ĻỰ���
	*       uiKeyIndex[in]	    �����豸�洢���ڲ�RSA��Կ������ֵ
	*       pucPublicKey [in]	�ⲿRSA��Կ�ṹ
	*	    pucDEInput [in]	    ������ָ�룬���ڴ������ĻỰ��Կ����
	*		uiDELength[in]	    ����ĻỰ��Կ���ĳ���
	*		pucDEOutput[out]	������ָ�룬���ڴ������ĻỰ��Կ����
	*		puiDELength[out]	����ĻỰ��Կ���ĳ���
	*����ֵ��  0	�ɹ�
	*        ��0	ʧ�ܣ����ش������
	*/
DASDF_FUNC_EXPORT
int SDF_ExportSignPublicKey_ECC(void *hSessionHandle, 
								unsigned int  uiKeyIndex,
								ECCrefPublicKey *pucPublicKey);
    /*
	*������	���������豸�ڲ��洢��ָ������λ�õ�ǩ����Կ
	*������	hSessionHandle[in]	���豸�����ĻỰ���
	*		uiKeyIndex[in]		�����豸�洢˽Կ����ֵ
	*		pucPublicKey[out]	ECC��Կ�ṹ
	*����ֵ��	0	�ɹ�
	*		  ��0	ʧ�ܣ����ش������
	*/

DASDF_FUNC_EXPORT
int SDF_ExportEncPublicKey_ECC(void *hSessionHandle, 
							   unsigned int  uiKeyIndex,
							   ECCrefPublicKey *pucPublicKey);
    /*
	*������	���������豸�ڲ��洢��ָ������λ�õļ��ܹ�Կ
	*������	hSessionHandle[in]	���豸�����ĻỰ���
	*		uiKeyIndex[in]		�����豸�洢˽Կ����ֵ
	*		pucPublicKey[out]	ECC��Կ�ṹ
	*����ֵ��	0	�ɹ�
	*		  ��0	ʧ�ܣ����ش������
	*/

DASDF_FUNC_EXPORT
int SDF_GenerateKeyPair_ECC(void *hSessionHandle, 
							unsigned int  uiAlgID,
							unsigned int  uiKeyBits,
							ECCrefPublicKey *pucPublicKey,
							ECCrefPrivateKey *pucPrivateKey);
    /*
	*������	���������豸����ָ�����ͺ�ģ����Ecc��Կ��
	*������	hSessionHandle[in]	���豸�����ĻỰ���
	*		uiAlgID[in]			ָ���㷨��ʶ
	*		uiKeyBits [in]		ָ����Կ����
	*		pucPublicKey[out]	ECC��Կ�ṹ
	*		pucPrivateKey[out]	ECC˽Կ�ṹ
	*����ֵ��	0	�ɹ�
	*		  ��0	ʧ�ܣ����ش������
	*/

DASDF_FUNC_EXPORT
int SDF_GenerateKeyWithIPK_ECC(void *hSessionHandle, 
								unsigned int uiIPKIndex,
								unsigned int uiKeyBits,
								ECCCipher *pucKey,
								void **phKeyHandle);
	/*
	*������	���ɻỰ��Կ����ָ���������ڲ�ECC���ܹ�Կ���������ͬʱ������Կ���
	*������	hSessionHandle[in]	���豸�����ĻỰ���
	*		uiIPKIndex[in]		�����豸�ڲ��洢��Կ������ֵ
	*       uiKeyBits[in]	    ָ�������ĻỰ��Կ����
	*		pucKey[out]			������ָ�룬���ڴ�ŷ��ص���Կ����
	*		phKeyHandle[out]	���ص���Կ���
	*����ֵ��	0	�ɹ�
	*		  ��0	ʧ�ܣ����ش������
	*/

DASDF_FUNC_EXPORT
int SDF_GenerateKeyWithEPK_ECC(void *hSessionHandle, 
							   unsigned int uiKeyBits,
							    unsigned int  uiAlgID,								
								ECCrefPublicKey *pucPublicKey,
								ECCCipher *pucKey,
								void **phKeyHandle);
    /*
	*������	���ɻỰ��Կ�����ⲿECC��Կ���������ͬʱ������Կ���
	*������	hSessionHandle[in]	���豸�����ĻỰ���
	*       uiKeyBits[in]	    ָ�������ĻỰ��Կ����
	*       uiAlgID[in]	        �ⲿECC��Կ���㷨��ʶ
	*		pucPublicKey[in]	������ⲿECC��Կ�ṹ
	*		pucKey[out]			������ָ�룬���ڴ�ŷ��ص���Կ����
	*		phKeyHandle[out]	���ص���Կ���
	*����ֵ��	0	�ɹ�
	*		  ��0	ʧ�ܣ����ش������
	*/

DASDF_FUNC_EXPORT
int SDF_ImportKeyWithISK_ECC(void *hSessionHandle,
							  unsigned int uiISKIndex,
							  ECCCipher *pucKey,
							  void **phKeyHandle);
    /*
	*������	����Ự��Կ�����ڲ�ECC����˽Կ���ܣ�ͬʱ������Կ���
	*������	hSessionHandle[in]	���豸�����ĻỰ���
	*		uiISKIndex[in]		�����豸�ڲ��洢����˽Կ������ֵ����Ӧ�ڼ���ʱ�Ĺ�Կ
	*		pucKey[in]			������ָ�룬���ڴ���������Կ����
	*		phKeyHandle[out]	���ص���Կ���
	*����ֵ��	0	�ɹ�
	*		  ��0	ʧ�ܣ����ش������
	*/

/*
DASDF_FUNC_EXPORT
int SDF_GenerateKeyWithECC(void *hSessionHandle, 
							ECCrefPrivateKey *pucPrivateKey,
							ECCrefPublicKey *pucPublicKey,
							void **phKeyHandle);
*/
    /*ECDH��ԿЭ�� 20080512ɾ�������������SCE��ԿЭ��
	*������	ʹ������ECC˽Կ�ͶԷ�ECC��ԿЭ�̲����Ự��Կ��ͬʱ������Կ���
	*������	hSessionHandle[in]	���豸�����ĻỰ���
	*		pucPrivateKey[in]	�ⲿ����Ĳ�����ԿЭ�̵ļ�����ʱECC˽Կ�ṹ
	*		pucPublicKey[in]	�ⲿ����Ĳ�����ԿЭ�̵ĶԷ���ʱECC��Կ�ṹ
	*		phKeyHandle[out]	���ص���Կ���
	*����ֵ��	0	�ɹ�
	*		  ��0	ʧ�ܣ����ش������
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
	/*��ԿЭ��20080623ɾ��������3������ʵ����ԿЭ��
	*������	ʹ������ECC˽Կ�ͶԷ�ECC��ԿЭ�̲����Ự��Կ��ͬʱ������Կ���
	*������	hSessionHandle[in]	���豸�����ĻỰ���
	*		uiRole[in]	    ָ������ԿЭ�̵ķ��𷽻�����Ӧ��
	*		uiISKIndex[in]	�����豸�ڲ��洢����˽Կ������ֵ����˽Կ���ڲ�����ԿЭ��
	*		uiKeyBits[in]	Э�̺�Ҫ���������Կ����
	*		pucSelfTmpPrivateKey[in]	�ⲿ����Ĳ�����ԿЭ�̵ļ�����ʱECC˽Կ�ṹ
	*		pucSelfTmpPublicKey[in]	    �ⲿ����Ĳ�����ԿЭ�̵ļ�����ʱECC��Կ�ṹ
	*		pucOtherPublicKey[in]	    �ⲿ����Ĳ�����ԿЭ�̵ĶԷ�ECC��Կ�ṹ
	*		pucOtherTmpPublicKey[in]	�ⲿ����Ĳ�����ԿЭ�̵ĶԷ���ʱECC��Կ�ṹ
	*		pucSelfID[in]	������ԿЭ�̵ļ���IDֵ(����ECCref_MAX_LEN)
	*		pucOtherID[in]	������ԿЭ�̵ĶԷ�IDֵ(����ECCref_MAX_LEN)
	*		phKeyHandle[out]	���ص���Կ���
	*����ֵ��	0	�ɹ�
	*		  ��0	ʧ�ܣ����ش������
	*��ע��	1.����ھ����Ӧ���У�Э��˫��û��ͳһ�����ID�����Խ�ID�趨Ϊ����
	*       2. uiRoleΪ1ʱ����ʾ�Ƿ��𷽣�uiRoleΪ2�ǣ���ʾ����Ӧ��
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

	/*���� 20080715�޸�
	������	ʹ��ECC��ԿЭ���㷨��Ϊ����Ự��Կ������Э�̲�����ͬʱ����ָ������λ�õ�ECC��Կ����ʱECC��Կ�ԵĹ�Կ��Э�̾����
	������	hSessionHandle[in]	���豸�����ĻỰ���
			uiISKIndex[in]		�����豸�ڲ��洢����˽Կ������ֵ����˽Կ���ڲ�����ԿЭ��
			uiKeyBits[in]		Ҫ��Э�̵���Կ����
			pucSponsorID[in]	������ԿЭ�̵ķ���IDֵ
			uiSponsorIDLength[in]		����ID����
			pucSponsorPublicKey[out]	���صķ���ECC��Կ�ṹ
			pucSponsorTmpPublicKey[out]	���صķ�����ʱECC��Կ�ṹ
			phAgreementHandle[out]		���ص�Э�̾�������ڼ���Э����Կ
			����ֵ��	0	�ɹ�
					  ��0	ʧ�ܣ����ش������
			��ע��	ΪЭ�̻Ự��Կ��Э�̵ķ���Ӧ���ȵ��ñ�������
				    ����ھ����Ӧ���У�Э��˫��û��ͳһ�����ID�����Խ�ID�趨Ϊ������
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

	/*���� 20080715�޸�
	������	ʹ��ECC��ԿЭ���㷨��ʹ������Э�̾������Ӧ����Э�̲�������Ự��Կ��ͬʱ���ػỰ��Կ�����
	������	hSessionHandle[in]	���豸�����ĻỰ���
			pucResponseID[in]	�ⲿ�������Ӧ��IDֵ
			uiResponseIDLength[in]		�ⲿ�������Ӧ��ID����
			pucResponsePublicKey[in]	�ⲿ�������Ӧ��ECC��Կ�ṹ
			pucResponseTmpPublicKey[in]	�ⲿ�������Ӧ����ʱECC��Կ�ṹ
			hAgreementHandle[in]		Э�̾�������ڼ���Э����Կ
			phKeyHandle[out]	���ص���Կ���
	����ֵ��	0	�ɹ�
			  ��0	ʧ�ܣ����ش������
	��ע��	Э�̵ķ��𷽻����Ӧ����Э�̲�������ñ�����������Ự��Կ��
			����ھ����Ӧ���У�Э��˫��û��ͳһ�����ID�����Խ�ID�趨Ϊ������
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

	/*��Ӧ�� 20080715�޸�
	������	ʹ��ECC��ԿЭ���㷨������Э�̲���������Ự��Կ��ͬʱ���ز�����Э�̲����ͺ���Կ�����
	������	hSessionHandle[in]	���豸�����ĻỰ���
			uiISKIndex[in]		�����豸�ڲ��洢����˽Կ������ֵ����˽Կ���ڲ�����ԿЭ��
			uiKeyBits[in]		Э�̺�Ҫ���������Կ����
			pucResponseID[in]	��Ӧ��IDֵ
			uiResponseIDLength[in]	��Ӧ��ID����
			pucSponsorID[in]		����IDֵ
			uiSponsorIDLength[in]	����ID����
			pucSponsorPublicKey[in]	�ⲿ����ķ���ECC��Կ�ṹ
			pucSponsorTmpPublicKey[in]	�ⲿ����ķ�����ʱECC��Կ�ṹ
			pucResponsePublicKey[out]	���ص���Ӧ��ECC��Կ�ṹ
			pucResponseTmpPublicKey[out]	���ص���Ӧ����ʱECC��Կ�ṹ
			phKeyHandle[out]		���ص���Կ���
	����ֵ��	0	�ɹ�
			  ��0	ʧ�ܣ����ش������
	��ע��	����������Ӧ�����á�
			����ھ����Ӧ���У�Э��˫��û��ͳһ�����ID�����Խ�ID�趨Ϊ����
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
	������	�����ڲ����ܹ�Կ���ܵĻỰ��Կת��Ϊ���ⲿָ���Ĺ�Կ���ܣ������������ŷ�ת����
	������	hSessionHandle[in]	���豸�����ĻỰ���
			uiKeyIndex[in]		�����豸�洢��ECC��Կ������ֵ
			uiAlgID[in]			�ⲿECC��Կ���㷨��ʶ
			pucPublicKey [in]	�ⲿECC��Կ�ṹ
			pucEncDataIn[in]	������ָ�룬���ڴ������ĻỰ��Կ����
			pucEncDataOut[out]	������ָ�룬���ڴ������ĻỰ��Կ����
	����ֵ��	0	�ɹ�
	��0	ʧ�ܣ����ش������
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
	*������	���ɻỰ��Կ������Կ������Կ���������ͬʱ������Կ���
	*������	hSessionHandle[in]	���豸�����ĻỰ���
			uiKeyBits[in]		ָ�������ĻỰ��Կ����
	*		uiAlgID[in]			�㷨��ʶ��ָ���ԳƼ����㷨
	*		uiKEKIndex[in]		�����豸�ڲ��洢��Կ������Կ������ֵ
	*		pucKey[out]			������ָ�룬���ڴ�ŷ��ص���Կ����
	*		puiKeyLength[out]	���ص���Կ���ĳ���
	*		phKeyHandle[out]	���ص���Կ���
	*����ֵ��	0	�ɹ�
	*		  ��0	ʧ�ܣ����ش������
	*��ע��	����ģʽĬ��ʹ��ECBģʽ
	*/

DASDF_FUNC_EXPORT
int SDF_ImportKeyWithKEK(void *hSessionHandle, 
						  unsigned int  uiAlgID,
						  unsigned int uiKEKIndex, 
						  unsigned char *pucKey, 
						  unsigned int puiKeyLength, 
						  void **phKeyHandle);
    /*
	*������	����Ự��Կ������Կ������Կ���ܣ�ͬʱ���ػỰ��Կ���
	*������	hSessionHandle[in]	���豸�����ĻỰ���
	*		uiAlgID[in]			�㷨��ʶ��ָ���ԳƼ����㷨
	*		uiKEKIndex[in]		�����豸�ڲ��洢��Կ������Կ������ֵ
	*		pucKey[in]			������ָ�룬���ڴ���������Կ����
	*		puiKeyLength[in]	�������Կ���ĳ���
	*		phKeyHandle[out]	���ص���Կ���
	*����ֵ��	0	�ɹ�
	*		  ��0	ʧ�ܣ����ش������
	*��ע��	����ģʽĬ��ʹ��ECBģʽ
	*/

DASDF_FUNC_EXPORT
int SDF_ImportKey(void *hSessionHandle, 
				   unsigned char *pucKey, 
				   unsigned int uiKeyLength,
				   void **phKeyHandle);
    /*
	*������	�������ĻỰ��Կ��ͬʱ������Կ���
	*������	hSessionHandle[in]	���豸�����ĻỰ���
	*		pucKey[in]			������ָ�룬���ڴ���������Կ����
	*		puiKeyLength[in]	�������Կ���ĳ���
	*		phKeyHandle[out]	���ص���Կ���
	*����ֵ��	0	�ɹ�
	*		  ��0	ʧ�ܣ����ش������
	*/

DASDF_FUNC_EXPORT
int SDF_DestroyKey(void *hSessionHandle, 
					void *hKeyHandle);
    /*
	*������	���ٻỰ��Կ�����ͷ�Ϊ��Կ���������ڴ����Դ��
	*������	hSessionHandle[in]	���豸�����ĻỰ���
	*		hKeyHandle[in]		�������Կ���
	*����ֵ��	0	�ɹ�
	*		  ��0	ʧ�ܣ����ش������
	*��ע��	��ע��	�ڶԳ��㷨������ɺ�Ӧ���ñ��������ٻỰ��Կ��
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
	*������	ָ��ʹ���ⲿ��Կ�����ݽ�������
	*������	hSessionHandle[in]	���豸�����ĻỰ���
	*		pucPublicKey [in]	�ⲿRSA��Կ�ṹ
	*		pucDataInput [in]	������ָ�룬���ڴ�����������
	*		uiInputLength[in]	��������ݳ���
	*		pucDataOutput[out]	������ָ�룬���ڴ�����������
	*		puiOutputLength[out]	��������ݳ���
	*����ֵ��	0	�ɹ�
	*		  ��0	ʧ�ܣ����ش������
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
	*������	ָ��ʹ���ⲿ˽Կ�����ݽ�������
	*������	hSessionHandle[in]	���豸�����ĻỰ���
	*		pucPrivateKey [in]	�ⲿRSA˽Կ�ṹ
	*		pucDataInput [in]	������ָ�룬���ڴ�����������
	*		uiInputLength [in]	��������ݳ���
	*		pucDataOutput [out]	������ָ�룬���ڴ�����������
	*		puiOutputLength [out]	��������ݳ���
	*����ֵ��	0	�ɹ�
	*		  ��0	ʧ�ܣ����ش������
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
	*������	ʹ���ڲ�ָ�������Ĺ�Կ�����ݽ�������
	*������	hSessionHandle[in]	���豸�����ĻỰ���
	*		uiKeyIndex[in]		�����豸�ڲ��洢��Կ������ֵ
	*		pucDataInput[in]	������ָ�룬���ڴ���ⲿ���������
	*		uiInputLength[in]	��������ݳ���
	*		pucDataOutput[out]	������ָ�룬���ڴ�����������
	*		puiOutputLength[out]	��������ݳ���
	*����ֵ��	0	�ɹ�
	*		  ��0	ʧ�ܣ����ش������
	*��ע��	������Χ�������ڲ�ǩ����Կ�ԣ����ݸ�ʽ��Ӧ�ò��װ
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
	*������	ʹ���ڲ�ָ��������˽Կ�����ݽ�������
	*������	hSessionHandle[in]	���豸�����ĻỰ���
	*		uiKeyIndex[in]		�����豸�ڲ��洢˽Կ������ֵ
	*		pucDataInput[in]	������ָ�룬���ڴ���ⲿ���������
	*		uiInputLength[in]	��������ݳ���
	*		pucDataOutput[out]	������ָ�룬���ڴ�����������
	*		puiOutputLength[out]	��������ݳ���
	*����ֵ��	0	�ɹ�
	*		  ��0	ʧ�ܣ����ش������
	*��ע��	������Χ�������ڲ�ǩ����Կ�ԣ����ݸ�ʽ��Ӧ�ò��װ
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
/* ������ ������Կ��;��ʹ���ڲ�ָ�������Ĺ�Կ�����ݽ������� 
������  hSessionHandle[in]		���豸�����ĻỰ��� 
		uiKeyIndex[in]			�����豸�ڲ��洢��Կ������ֵ 
		uiKeyUsage[in]			��Կ��;
		pucDataInput[in]		������ָ�룬���ڴ���ⲿ��������� 
		uiInputLength[in]		��������ݳ��� 
		pucDataOutput[out]		������ָ�룬���ڴ����������� 
		puiOutputLength[out]	��������ݳ��� 
����ֵ�� 
		0		�ɹ� 
		��0		ʧ�ܣ����ش������                                                 */
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
/* ������ ������Կ��;��ʹ���ڲ�ָ��������˽Կ�����ݽ������� 
������ 
		hSessionHandle[in]		���豸�����ĻỰ��� 
		uiKeyIndex[in]			�����豸�ڲ��洢˽Կ������ֵ
		uiKeyUsage[in]			��Կ��;
		pucDataInput[in]		������ָ�룬���ڴ���ⲿ��������� 
		uiInputLength[in]		��������ݳ��� 
		pucDataOutput[out]		������ָ�룬���ڴ����������� 
		puiOutputLength[out]	��������ݳ���	
����ֵ��	
		0		�ɹ� 
		��0		ʧ�ܣ����ش������
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
	*������	ʹ��ECC˽Կ�����ݽ���ǩ������
	*������	hSessionHandle[in]	���豸�����ĻỰ���
	*       uiAlgID[in]	        �㷨��ʶ��ָ��ʹ�õ�ECC�㷨
	*		pucPrivateKey[in]	�ⲿECC˽Կ�ṹ
	*		pucData[in]			������ָ�룬���ڴ���ⲿ���������
	*		uiDataLength[in]	��������ݳ���
	*		pucSignature[out]	������ָ�룬���ڴ�������ǩ��ֵ����
	*����ֵ��	0	�ɹ�
	*		  ��0	ʧ�ܣ����ش������
	*��ע��	��ԭ�ĵ��Ӵ����㣬�ں����ⲿ��ɡ�
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
	*������	ʹ��ECC��Կ��ECCǩ��ֵ������֤����
	*������	hSessionHandle[in]	���豸�����ĻỰ���
	*       uiAlgID[in]	        �㷨��ʶ��ָ��ʹ�õ�ECC�㷨
	*		pucPublicKey[in]	�ⲿECC��Կ�ṹ
	*		pucData[in]			������ָ�룬���ڴ���ⲿ���������
	*		uiDataLength[in]	��������ݳ���
	*		pucSignature[in]	������ָ�룬���ڴ�������ǩ��ֵ����
	*����ֵ��	0	�ɹ�
	*		  ��0	ʧ�ܣ����ش������
	*��ע��	��ԭ�ĵ��Ӵ����㣬�ں����ⲿ��ɡ�
	*/

DASDF_FUNC_EXPORT
int SDF_InternalSign_ECC(
						 void *hSessionHandle,
						 unsigned int  uiISKIndex,
						 unsigned char *pucData,
						 unsigned int  uiDataLength,
						 ECCSignature *pucSignature);
	/*
	*������	ʹ��ECC˽Կ�����ݽ���ǩ������
	*������	hSessionHandle[in]	���豸�����ĻỰ���
	*		uiISKIndex [in]		�����豸�ڲ��洢��ECCǩ��˽Կ������ֵ
	*		pucData[in]			������ָ�룬���ڴ���ⲿ���������
	*		uiDataLength[in]	��������ݳ���
	*		pucSignature [out]	������ָ�룬���ڴ�������ǩ��ֵ����
	*����ֵ��	0	�ɹ�
	*		  ��0	ʧ�ܣ����ش������
	*��ע��	��ԭ�ĵ��Ӵ����㣬�ں����ⲿ��ɡ�
	*/

DASDF_FUNC_EXPORT
int SDF_InternalVerify_ECC(
						   void *hSessionHandle,
						   unsigned int  uiISKIndex,
						   unsigned char *pucData,
						   unsigned int  uiDataLength,
						   ECCSignature *pucSignature);
	/*
	*������	ʹ��ECC��Կ��ECCǩ��ֵ������֤����
	*������	hSessionHandle[in]	���豸�����ĻỰ���
	*		uiISKIndex [in]		�����豸�ڲ��洢��ECCǩ����Կ������ֵ
	*		pucData[in]			������ָ�룬���ڴ���ⲿ���������
	*		uiDataLength[in]	��������ݳ���
	*		pucSignature[in]	������ָ�룬���ڴ�������ǩ��ֵ����
	*����ֵ��	0	�ɹ�
	*		  ��0	ʧ�ܣ����ش������
	*��ע��	��ԭ�ĵ��Ӵ����㣬�ں����ⲿ��ɡ�
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
	*������	ʹ���ⲿECC��Կ�����ݽ��м�������
	*������	hSessionHandle[in]	���豸�����ĻỰ���
	*       uiAlgID[in]	        �㷨��ʶ��ָ��ʹ�õ�ECC�㷨
	*		pucPublicKey[in]	�ⲿECC��Կ�ṹ
	*		pucData[in]			������ָ�룬���ڴ���ⲿ���������
	*		uiDataLength[in]	��������ݳ���
	*		pucEncData[out]		������ָ�룬���ڴ���������������
	*����ֵ��	0	�ɹ�
	*		  ��0	ʧ�ܣ����ش������
	*��ע��	��������ݳ���uiDataLength������ECCref_MAX_LEN��
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
	*������	ʹ���ⲿECC˽Կ���н�������
	*������	hSessionHandle[in]	���豸�����ĻỰ���
	*       uiAlgID[in]	        �㷨��ʶ��ָ��ʹ�õ�ECC�㷨
	*		pucPrivateKey[in]	�ⲿECC˽Կ�ṹ
	*		pucEncData[in]		������ָ�룬���ڴ���������������
	*		pucData[out]		������ָ�룬���ڴ���������������
	*		puiDataLength[out]	������������ĳ���
	*����ֵ��	0	�ɹ�
	*		  ��0	ʧ�ܣ����ش������
	*/

DASDF_FUNC_EXPORT
int SDF_InternalEncrypt_ECC(
							void *hSessionHandle,
							unsigned int uiISKIndex,
							unsigned char *pucData,
							unsigned int  uiDataLength,
							ECCCipher *pucEncData);
	/*
	*������	ʹ���ڲ�ECC��Կ�����ݽ��м�������
	*������	hSessionHandle[in]	���豸�����ĻỰ���
	*       uiISKIndex [in]	    �����豸�ڲ��洢��ECC���ܹ�Կ������ֵ
	*       pucData[in]	        ������ָ�룬���ڴ���ⲿ���������
	*       uiDataLength[in]	��������ݳ���
	*       pucEncData[out]	    ������ָ�룬���ڴ���������������
	*����ֵ��	0	�ɹ�
	*         ��0	ʧ�ܣ����ش������
	*��ע��	��������ݳ���uiDataLength������ECCref_MAX_LEN��
	*/

DASDF_FUNC_EXPORT
int SDF_InternalDecrypt_ECC(
							void *hSessionHandle,
							unsigned int uiISKIndex,
							ECCCipher *pucEncData,
							unsigned char *pucData,
							unsigned int  *puiDataLength);
/*
*������	ʹ���ڲ�ECC˽Կ���н�������
*������	hSessionHandle[in]	���豸�����ĻỰ���
*       uiISKIndex [in]	    �����豸�ڲ��洢��ECC����˽Կ������ֵ
*       pucEncData[in]	    ������ָ�룬���ڴ���������������
*       pucData[out]	    ������ָ�룬���ڴ���������������
*       puiDataLength[out]	������������ĳ���
*����ֵ��	0	�ɹ�
*         ��0	ʧ�ܣ����ش������
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
	*������	ʹ��ָ������Կ�����IV�����ݽ��жԳƼ�������
	*������	hSessionHandle[in]	���豸�����ĻỰ���
	*		hKeyHandle[in]		ָ������Կ���
	*		uiAlgID[in]			�㷨��ʶ��ָ���ԳƼ����㷨
	*		pucIV[in|out]		������ָ�룬���ڴ������ͷ��ص�IV����
	*		pucData[in]			������ָ�룬���ڴ���������������
	*		uiDataLength[in]	������������ĳ���
	*		pucEncData[out]		������ָ�룬���ڴ���������������
	*		puiEncDataLength[out]	������������ĳ���
	*����ֵ��	0	�ɹ�
	*		  ��0	ʧ�ܣ����ش������
	*��ע��	�˺����������ݽ�����䴦����������ݱ�����ָ���㷨���鳤�ȵ���������
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
	*������	ʹ��ָ������Կ�����IV�����ݽ��жԳƽ�������
	*������	hSessionHandle[in]	���豸�����ĻỰ���
	*		hKeyHandle[in]		ָ������Կ���
	*		uiAlgID[in]			�㷨��ʶ��ָ���ԳƼ����㷨
	*		pucIV[in|out]		������ָ�룬���ڴ������ͷ��ص�IV����
	*		pucEncData[in]		������ָ�룬���ڴ���������������
	*		uiEncDataLength[in]	������������ĳ���
	*		pucData[out]		������ָ�룬���ڴ���������������
	*		puiDataLength[out]	������������ĳ���
	*����ֵ��	0	�ɹ�
	*		  ��0	ʧ�ܣ����ش������
	*��ע��	�˺����������ݽ�����䴦����������ݱ�����ָ���㷨���鳤�ȵ���������
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
	*������	ʹ��ָ������Կ�����IV�����ݽ���MAC����
	*������	hSessionHandle[in]	���豸�����ĻỰ���
	*		hKeyHandle[in]		ָ������Կ���
	*		uiAlgID[in]			�㷨��ʶ��ָ��MAC�����㷨
	*		pucIV[in|out]		������ָ�룬���ڴ������ͷ��ص�IV����
	*		pucData[in]			������ָ�룬���ڴ���������������
	*		uiDataLength[in]	������������ĳ���
	*		pucMAC[out]			������ָ�룬���ڴ�������MACֵ
	*		puiMACLength[out]	�����MACֵ����
	*����ֵ��	0	�ɹ�
	*		  ��0	ʧ�ܣ����ش������
	*��ע��	�˺����������ݽ��зְ������������MAC������IV��������MACֵ��
	*/


DASDF_FUNC_EXPORT
int SDF_HashInit(
				 void *hSessionHandle,
				 unsigned int uiAlgID,
				 ECCrefPublicKey *pucPublicKey,
				 unsigned char *pucID,
				 unsigned int uiIDLength);

	/*
	������	����ʽ�����Ӵ������һ����
	������	hSessionHandle[in]	���豸�����ĻỰ���
			uiAlgID[in]			ָ���Ӵ��㷨��ʶ
			pucPublicKey[in]	ǩ���ߵ�ECC��Կ����������ECCǩ�����Ӵ�ֵʱ��Ч
			pucID[in]			ǩ���ߵ�IDֵ����������ECCǩ�����Ӵ�ֵʱ��Ч
			uiIDLength[in]		ǩ���ߵ�ID����
	����ֵ��	0	�ɹ�
				��0	ʧ�ܣ����ش������
	��ע��	����ھ����Ӧ���У�Э��˫��û��ͳһ�����ID�����Խ�ID�趨Ϊ������
    */

DASDF_FUNC_EXPORT
int SDF_HashUpdate(
				   void *hSessionHandle,
				   unsigned char *pucData,
				   unsigned int  uiDataLength);
	/*
	*������	����ʽ�����Ӵ�����ڶ���������������Ľ����Ӵ�����
	*������	hSessionHandle[in]	���豸�����ĻỰ���
	*		pucData[in]			������ָ�룬���ڴ���������������
	*		uiDataLength[in]	������������ĳ���
	*����ֵ��	0	�ɹ�
	*		  ��0	ʧ�ܣ����ش������
	*/

DASDF_FUNC_EXPORT
int SDF_HashFinal(
				  void *hSessionHandle,
				  unsigned char *pucHash,
				  unsigned int  *puiHashLength);
	/*
	*������	����ʽ�����Ӵ�������������Ӵ�������������Ӵ����ݲ�����м�����
	*������	hSessionHandle[in]	���豸�����ĻỰ���
	*		pucHash[out]		������ָ�룬���ڴ��������Ӵ�����
	*		puiHashLength[out]	���ص��Ӵ����ݳ���
	*����ֵ��	0	�ɹ�
	*		  ��0	ʧ�ܣ����ش������
	*/

DASDF_FUNC_EXPORT
int SDF_CreateFile(
				   void *hSessionHandle,
				   unsigned char *pucFileName,
				   unsigned int uiNameLen,
				   unsigned int uiFileSize);
	/*
	*������	�������豸�ڲ��������ڴ洢�û����ݵ��ļ�
	*������	hSessionHandle[in]	���豸�����ĻỰ���
	*		pucFileName[in]		������ָ�룬���ڴ��������ļ�������󳤶�128�ֽ�
	*		uiNameLen[in]		�ļ�������
	*		uiFileSize[in]		�ļ���ռ�洢�ռ�ĳ���
	*����ֵ��	0	�ɹ�
	*	      ��0	ʧ�ܣ����ش������
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
	*������	��ȡ�������豸�ڲ��洢�û����ݵ��ļ�������
	*������	hSessionHandle[in]	���豸�����ĻỰ���
	*		pucFileName[in]		������ָ�룬���ڴ��������ļ�������󳤶�128�ֽ�
	*		uiNameLen[in]		�ļ�������
	*       uiOffset[in]	    ָ����ȡ�ļ�ʱ��ƫ��ֵ
	*		puiFileLength[in|out]	���ʱָ����ȡ�ļ����ݵĳ��ȣ�����ʱ����ʵ�ʶ�ȡ�ļ����ݵĳ���
	*		pucBuffer[out]		������ָ�룬���ڴ�Ŷ�ȡ���ļ�����
	*����ֵ��	0	�ɹ�
	*		  ��0	ʧ�ܣ����ش������
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
	*������	�������豸�ڲ��洢�û����ݵ��ļ���д������
	*������	hSessionHandle[in]	���豸�����ĻỰ���
	*		pucFileName[in]		������ָ�룬���ڴ��������ļ�������󳤶�128�ֽ�
	*		uiNameLen[in]		�ļ�������
	*	    uiOffset[in]	    ָ��д���ļ�ʱ��ƫ��ֵ
	*		uiFileLength[in]	ָ��д���ļ����ݵĳ���
	*		pucBuffer[in]		������ָ�룬���ڴ�������д�ļ�����
	*����ֵ��	0	�ɹ�
	*		  ��0	ʧ�ܣ����ش������
	*/

DASDF_FUNC_EXPORT
int SDF_DeleteFile(
				   void *hSessionHandle,
				   unsigned char *pucFileName,
				   unsigned int uiNameLen);
	/*
	*������	ɾ��ָ���ļ����������豸�ڲ��洢�û����ݵ��ļ�
	*������	hSessionHandle[in]	���豸�����ĻỰ���
	*		pucFileName[in]		������ָ�룬���ڴ��������ļ�������󳤶�128�ֽ�
	*		uiNameLen[in]		�ļ�������
	*����ֵ��	0	�ɹ�
	*		  ��0	ʧ�ܣ����ش������
	*/
//-----------------------------------------------------------------------------
/////// 20110816 ��˰���������֤ϵͳ��Ŀ ���Ӻ���
/******************************************************************* 
������		���ⲿ����RSA��ECC��Կ��
������		hSessionHandle[in]	���豸�����ĻỰ���
			Mechanism[in]		�㷨��ʶ
			KeyId[in]			��Կ��ŵ�id�ţ��˴�����Կ������Index
			PrivateKeyDerBuf[in]˽ԿDER������ָ��
			prikeyDerLen[in]	˽ԿDER����������
			PublicKeyDerBuf[in]	��ԿDER������ָ��
			PublicDerLen[in]	��ԿDER����������
����ֵ��	0	�ɹ�
			��0	ʧ�ܣ����ش������

��ע��		����RSA�㷨��˵��˽ԿָPKCS1��ʽ��DER����˽Կ����Կͬ��
			����ECC�㷨��˵��Ŀǰ˽ԿָD����Կָxy��
            ����������ʱ���豸����Ҫ�������ԱȨ�ޡ�
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
������		����RSA��Կ�Բ���������Կ�� 
������		hSessionHandle[in]	���豸�����ĻỰ���
			Mechanism[in]		�㷨��ʶ
			KeySize[in]			��Կ����
			keyid[in]			��ԿID���˴�����Կ������Index
����ֵ��	0	�ɹ�
			��0	ʧ�ܣ����ش������
��ע��      ����������ʱ���豸����Ҫ�������ԱȨ�ޡ�
*/
DASDF_FUNC_EXPORT
int SDF_GenerateKeyPairEx_RSA(void *hSessionHandle, 
								  unsigned  int Mechanism,
								  unsigned  int KeySize,
								  unsigned  int keyid);


/******************************************************************* 
������		����ECC��Կ�Բ���������Կ�� 
������		hSessionHandle[in]	���豸�����ĻỰ���
			Mechanism[in]		�㷨��ʶ
			uiAlgID[in]			ECC�㷨��ʶ
			keyid[in]			��ԿID���˴�����Կ������Index
����ֵ��	0		�ɹ�
			��0		ʧ�ܣ����ش������
��ע��      ����������ʱ���豸����Ҫ�������ԱȨ�ޡ�
*/

DASDF_FUNC_EXPORT
int SDF_GenerateKeyPairEx_ECC(void *hSessionHandle, 
								  unsigned  int Mechanism,
								  unsigned int  uiAlgID,
								  unsigned  int keyid);
//-----------------------------------------------------------------------------
//��������ʶ
#define SDR_OK	                0x0	                    //�����ɹ�
#define SDR_BASE	            0x01000000	            //���������ֵ
#define SDR_UNKNOWERR			SDR_BASE + 0x00000001	//δ֪����
#define SDR_NOTSUPPORT			SDR_BASE + 0x00000002	//��֧�ֵĽӿڵ���
#define SDR_COMMFAIL			SDR_BASE + 0x00000003	//���豸ͨ��ʧ��
#define SDR_HARDFAIL			SDR_BASE + 0x00000004	//����ģ������Ӧ
#define SDR_OPENDEVICE			SDR_BASE + 0x00000005	//���豸ʧ��
#define SDR_OPENSESSION			SDR_BASE + 0x00000006	//�����Ựʧ��
#define SDR_PARDENY				SDR_BASE + 0x00000007	//��˽Կʹ��Ȩ��
#define SDR_KEYNOTEXIST			SDR_BASE + 0x00000008	//�����ڵ���Կ����
#define SDR_ALGNOTSUPPORT		SDR_BASE + 0x00000009	//��֧�ֵ��㷨����
#define SDR_ALGMODNOTSUPPORT	SDR_BASE + 0x0000000A	//��֧�ֵ��㷨ģʽ����
#define SDR_PKOPERR				SDR_BASE + 0x0000000B	//��Կ����ʧ��
#define SDR_SKOPERR				SDR_BASE + 0x0000000C	//˽Կ����ʧ��
#define SDR_SIGNERR				SDR_BASE + 0x0000000D	//ǩ������ʧ��
#define SDR_VERIFYERR			SDR_BASE + 0x0000000E	//��֤ǩ��ʧ��
#define SDR_SYMOPERR			SDR_BASE + 0x0000000F	//�Գ��㷨����ʧ��
#define SDR_STEPERR				SDR_BASE + 0x00000010	//�ಽ���㲽�����
#define SDR_FILESIZEERR			SDR_BASE + 0x00000011	//�ļ����ȳ�������
#define SDR_FILENOEXIST			SDR_BASE + 0x00000012	//ָ�����ļ�������
#define SDR_FILEOFSERR			SDR_BASE + 0x00000013	//�ļ���ʼλ�ô���
#define SDR_KEYTYPEERR			SDR_BASE + 0x00000014	//��Կ���ʹ���
#define SDR_KEYERR				SDR_BASE + 0x00000015	//��Կ����
#define SDR_ENCDATAERR          SDR_BASE + 0x00000016   //ECC�������ݴ���
//�� ��	SDR_BASE + 0x00000016�� SDR_BASE + 0x00FFFFFF	Ԥ��

#define SDR_CLOSEDEVICE	         SDR_BASE + 0x00000090	    //�ر��豸ʧ��  (���ڱ�׼������һ�������룬������������˵���,20110324)
#define SDR_CLOSESESSION	     SDR_BASE + 0x00000017	    //�رջỰʧ��
#define SDR_DATA_LENGTH_ERR      SDR_BASE + 0x00000018      //���ݳ��ȴ���
#define SDR_BUFFER_TOO_SMALL     SDR_BASE + 0x00000019      //����buffer��С����
#define SDR_GEN_RSA_KEY_ERR		 SDR_BASE + 0x0000001A		//����RSA��Կ����
#define SDR_GEN_ECC_KEY_ERR		 SDR_BASE + 0x0000001B		//����ECC��Կ����
#define SDR_GEN_SYMM_KEY_ERR	 SDR_BASE + 0x0000001C      //�����Գ���Կ����
#define SDR_GEN_RADOM_ERR		 SDR_BASE + 0x0000001D		//�������������
#define SDR_ENC_SYMM_KEY_ERR	 SDR_BASE + 0x0000001E		//����SYMMKEY����
#define SDR_MEMORY_ERR			 SDR_BASE + 0x0000001F		//�ڴ����
#define SDR_KEY_EXH_ERR			 SDR_BASE + 0x00000020		//��Կת������
#define SDR_ENC_ERROR			 SDR_BASE + 0x00000021		//����ʧ��
#define SDR_DEC_ERROR			 SDR_BASE + 0x00000022		//����ʧ��
#define SDR_SM3_INIT_ERR		 SDR_BASE + 0x00000023		//SM3�㷨��ʼ��ʧ��
#define SDR_SHA1_INIT_ERR		 SDR_BASE + 0x00000024		//SHA1�㷨��ʼ��ʧ��
#define SDR_SHA256_INIT_ERR		 SDR_BASE + 0x00000025		//SHA256�㷨��ʼ��ʧ��
#define SDR_SM3_UPDATE_ERR		 SDR_BASE + 0x00000026		//SM3�㷨�Ӵ�����ʧ��
#define SDR_SHA1_UPDATE_ERR		 SDR_BASE + 0x00000027		//SHA1�㷨�Ӵ�����ʧ��
#define SDR_SHA256_UPDATE_ERR	 SDR_BASE + 0x00000028		//SHA256�㷨�Ӵ�����ʧ��
#define SDR_SM3_FINAL_ERR		 SDR_BASE + 0x00000029		//SM3�㷨�Ӵ��������ʧ��
#define SDR_SHA1_FINAL_ERR		 SDR_BASE + 0x0000002A		//SHA1�㷨�Ӵ��������ʧ��
#define SDR_SHA256_FINAL_ERR	 SDR_BASE + 0x0000002B		//SHA256�㷨�Ӵ��������ʧ��
#define SDR_URFBC_ERR			 SDR_BASE + 0x0000002C		//��FLUSH�������ݴ���
#define SDR_UWFBC_ERR			 SDR_BASE + 0x0000002D		//��FLUSH��д���ݴ���
#define SDR_URFBC_ERR_ReadIndex	 SDR_BASE + 0x0000002E		//��FLUSH����������������
#define SDR_UWFBC_ERR_Create	 SDR_BASE + 0x0000002F		//�����ļ�[д��FLUSH����
#define SDR_UNKNOWFile_ERR		 SDR_BASE + 0x00000030		//�ļ��Ѵ���
#define SDR_URFBC_Number_ERR	 SDR_BASE + 0x00000031		//��FLUSH�����ļ���������
#define SDR_KEY_LENGTH_ERR       SDR_BASE + 0x00000032      //��Կ���ȴ���
#define SDR_INSERTLIST_ERR		 SDR_BASE + 0x00000033		//�����������
#define SDF_OFFSET_ERROR		 SDR_BASE + 0x00000034		//ƫ�������󣬲��ܳ����ļ���С
#define SDF_SESSIONHANDLE_ERR    SDR_BASE + 0x00000035      //�Ự�������
#define SDF_KEYHANDLE_ERR        SDR_BASE + 0x00000036      //��Կ�������
#define SDF_PARAMETER_ERR        SDR_BASE + 0x00000037      //�����������
#define SDF_FILEINDEX_TOO_LONG   SDR_BASE + 0x00000038      //�ļ�����Խ��
#define SDF_DER_DECODE_ERR       SDR_BASE + 0x00000039      //Der������Կ����
#define SDF_MANAGEMENT_DENY_ERR  SDR_BASE + 0x0000003A      //����Ȩ�޲�����
#define SDF_IMPORTKEYPAIR_ERR    SDR_BASE + 0x0000003B      //������Կ�Դ���

//kxy add 20140619
#define KEY_USAGE_ENCRYPT	1
#define KEY_USAGE_SIGN		2
#ifdef __cplusplus
}
#endif

#endif
