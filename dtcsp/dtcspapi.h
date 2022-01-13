#ifndef _DTCSP_API_H_
#define _DTCSP_API_H_

#ifdef __cplusplus
extern "C" {
#endif

typedef unsigned int	DTCSP_UINT32;

#ifdef _WIN32
typedef __int64         DTCSP_INT64;
#else
typedef long long       DTCSP_INT64;
#endif

typedef unsigned short	DTCSP_UINT16;
typedef unsigned char	DTCSP_UCHAR;
typedef char			DTCSP_CHAR;
typedef int				DTCSP_INT32;
typedef short			DTCSP_INT16;
typedef void			DTCSP_VOID;
typedef long			DTCSP_LONG;
typedef unsigned long	DTCSP_ULONG;
typedef DTCSP_UINT32*	DTCSP_UINT32_PTR;
typedef DTCSP_UINT16*	DTCSP_UINT16_PTR;
typedef DTCSP_UCHAR*	DTCSP_UCHAR_PTR;
typedef DTCSP_CHAR*		DTCSP_CHAR_PTR;
typedef DTCSP_INT32*	DTCSP_INT32_PTR;
typedef DTCSP_INT16*	DTCSP_INT16_PTR;
typedef DTCSP_VOID*		DTCSP_VOID_PTR;
typedef DTCSP_INT32		DTCSP_HANDLE;
typedef DTCSP_LONG *	DTCSP_LONG_PTR;
typedef DTCSP_ULONG *	DTCSP_ULONG_PTR;

#define MAX_SYM_KEY_NUM     500
#define MAX_SESSION_KEY_NUM 500
#define MAX_ECC_KEY_NUM     500
//#define MAX_ECC_KEY_NUM     1000 //sj-20180517-azt-twoCard
#define MAX_RSA_KEY_NUM     100

#define MAX_RSA_MODULUS_LEN			256
#define MAX_RSA_PRIME_LEN			128

#ifdef _SUPPORT_RSA_4096_
#define MAX_RSA_MODULUS_LEN_EX		512		
#define MAX_RSA_PRIME_LEN_EX		256
#else 
#define MAX_RSA_MODULUS_LEN_EX		256	
#define MAX_RSA_PRIME_LEN_EX		128
#endif

#define	DTCSP_MAX_DEV_NUM			5
#define	DTCSP_MAX_ARI_NUM			10

#define SM1_ECB	    				0x00000101	
#define SM4_ECB						0x00000401
#define	MAX_ECC_HASH_LEN			32
#define MAX_ECC_PRIME_LEN			32


typedef struct
{
	DTCSP_INT32  DeviceCount;
	DTCSP_HANDLE MultiCardHandle[DTCSP_MAX_DEV_NUM];
	DTCSP_VOID_PTR hBalanceHandle;	
	DTCSP_INT32  WaitIdleTimeOut;
	DTCSP_INT32  DeviceInitType;
	DTCSP_INT32  HashTimeOut;
	DTCSP_INT32  PrivateFlagType;
	DTCSP_INT32  SysMasterKeyType;
	DTCSP_INT32  CardVersion;
	DTCSP_INT16  ArithMeticHandle[DTCSP_MAX_ARI_NUM];
}DTCSP_CONTEXT, *DTCSP_CONTEXT_PTR;

typedef struct
{
  unsigned int  bits;                 		
  unsigned char modulus[MAX_RSA_MODULUS_LEN];  	
  unsigned char exponent[MAX_RSA_MODULUS_LEN]; 
} DTCSP_RSA_PUBLIC_KEY;

typedef struct 
{
  unsigned int  bits;                           	
  unsigned char modulus[MAX_RSA_MODULUS_LEN];       	
  unsigned char publicExponent[MAX_RSA_MODULUS_LEN];	
  unsigned char exponent[MAX_RSA_MODULUS_LEN];      	
  unsigned char prime[2][MAX_RSA_PRIME_LEN];        	
  unsigned char primeExponent[2][MAX_RSA_PRIME_LEN];	
  unsigned char coefficient[MAX_RSA_PRIME_LEN];
} DTCSP_RSA_PRIVATE_KEY;

typedef struct
{
  unsigned int  bits;                 		
  unsigned char modulus[MAX_RSA_MODULUS_LEN];  	
  unsigned char publicExponent[MAX_RSA_MODULUS_LEN];
  unsigned char cipherPrivateKey[MAX_RSA_PRIME_LEN*7];
} DTCSP_RSA_CIPHER_PRIVATE_KEY;

typedef struct{
	DTCSP_UINT32			InitFlag; 	
	DTCSP_UINT32			Flag; 		
	DTCSP_UCHAR 			ID[64];    	
	DTCSP_UINT32   		nIDLen;  
	DTCSP_UINT32			CardIndex;
	DTCSP_UCHAR 			MidValue[32]; 
	DTCSP_UCHAR 			RemData[64];
	DTCSP_UINT32   		nRemDataLen;
	DTCSP_UINT32     	nTotalDataLen;
}DTCSP_SM3_CONTEXT,*DTCSP_SM3_CONTEXT_PTR;

typedef struct
{ 
	unsigned 	char 		primep[MAX_ECC_PRIME_LEN];
	unsigned 	char 		a[MAX_ECC_PRIME_LEN];	
	unsigned 	char 		b[MAX_ECC_PRIME_LEN];
	unsigned 	char 		gx[MAX_ECC_PRIME_LEN];
	unsigned 	char 		gy[MAX_ECC_PRIME_LEN];
	unsigned 	char 		n[MAX_ECC_PRIME_LEN];
	unsigned  short  	len;
	unsigned  short  	type;
} DTCSP_ECC_CURVE, *DTCSP_ECC_CURVE_PTR;

typedef struct
{
	DTCSP_ECC_CURVE	curve;
	unsigned char	qx[MAX_ECC_PRIME_LEN];
	unsigned char	qy[MAX_ECC_PRIME_LEN];
} DTCSP_ECC_PUBLIC_KEY, *DTCSP_ECC_PUBLIC_KEY_PTR;

typedef struct
{
	DTCSP_ECC_CURVE  curve; 
	unsigned char qx[MAX_ECC_PRIME_LEN];
	unsigned char qy[MAX_ECC_PRIME_LEN];
	unsigned char d[MAX_ECC_PRIME_LEN];
}DTCSP_ECC_PRIVATE_KEY, *DTCSP_ECC_PRIVATE_KEY_PTR;

typedef  struct { 
	unsigned char  Rdata[32];
	unsigned char  Sdata[32];
}DTCSP_ECC_SIG,*DTCSP_ECC_SIG_PTR;

typedef struct  
{
	unsigned short	nCipherLen;
	unsigned char	c1[64];
	unsigned char	c2[4096];
	unsigned char	c3[32];
}DTCSP_ECC_CIPHER,*DTCSP_ECC_CIPHER_PTR;

typedef struct 
{
	unsigned int	BitLen;
	unsigned char	X[64];
	unsigned char	Y[64];
}DTCSP_PUBLICKEYBLOB, *DTCSP_PUBLICKEYBLOB_PTR;

typedef struct 
{
	unsigned char	X[64];
	unsigned char	Y[64];
	unsigned char	HASH[32];
	unsigned int    CipherLen;
	unsigned char	Cipher[1];	
} DTCSP_CIPHERBLOB, *DTCSP_CIPHERBLOB_PTR;

typedef struct 
{
    unsigned int  	Version; 
    unsigned int  	SymmAlgID;
    unsigned int  	Bits;
    unsigned char 	cbEncryptedPriKey[64]; 
    DTCSP_PUBLICKEYBLOB PubKey; 
    DTCSP_CIPHERBLOB CipherBlob;
}DTCSP_ENVELOPEDKEYBLOB, *DTCSP_ENVELOPEDKEYBLOB_PTR;

typedef struct
{
	unsigned char IssuerName[40];
	unsigned char DeviceName[16];
	unsigned char DeviceSerial[16];
	unsigned int  DeviceVersion;
	unsigned int  StandardVersion;
	unsigned int  AsymAlgAbility[2];
	unsigned int  SymAlgAbility;
	unsigned int  HashAlgAbility;
	unsigned int  BufferSize;
}DTCSP_DEVICEINFO,*DTCSP_DEVICEINFO_PTR;

DTCSP_INT32	DTCSP_Init(
		DTCSP_VOID_PTR* pContext,
		DTCSP_CHAR_PTR 	pConfigureFileName,
		DTCSP_UCHAR_PTR pPassword);

DTCSP_INT32 DTCSP_End(DTCSP_VOID_PTR *pContext);

DTCSP_INT32 DTCSP_GetDTCSPVersion(DTCSP_UCHAR_PTR pVersion);

DTCSP_INT32 DTCSP_GetCardVersion(
		DTCSP_VOID_PTR	pContext,
		DTCSP_UCHAR_PTR	pCardVersion);
		
DTCSP_INT32 DTCSP_GetKeyStatus(
		DTCSP_VOID_PTR		pContext,
		DTCSP_UINT32    	nKeyType,
		DTCSP_UINT32        nKeyNum,
		DTCSP_UINT32_PTR	pKeyTag);
		
DTCSP_INT32 DTCSP_GetCardStatus(
		DTCSP_VOID_PTR		pContext,
		DTCSP_INT32_PTR		pRunStatus);

DTCSP_INT32 DTCSP_GetDevCardFlashBlockSum(
		DTCSP_VOID_PTR		pContext,
		DTCSP_INT32_PTR		pBlockSum);

DTCSP_INT32 DTCSP_SetKeyProtectKey(
		DTCSP_VOID_PTR		pContext);

DTCSP_INT32 DTCSP_SetKeyProtectKeyAlg(
				DTCSP_VOID_PTR pContext,
				DTCSP_UINT32   nAlgType);

DTCSP_INT32 DTCSP_GenDevSignKeyPair(
		DTCSP_VOID_PTR		pContext);

DTCSP_INT32 DTCSP_GenDevCipherEncKeyPair(
		DTCSP_VOID_PTR				pContext,
		DTCSP_INT32					nSymAlg,
		DTCSP_ENVELOPEDKEYBLOB_PTR  pENVELOPEDKEYBLOB);

DTCSP_INT32 DTCSP_ImportDevCipherEncKeyPair(
		DTCSP_VOID_PTR				pContext,
		DTCSP_ENVELOPEDKEYBLOB_PTR  pENVELOPEDKEYBLOB);

DTCSP_INT32 DTCSP_GetDevPubKey(
		DTCSP_VOID_PTR		pContext,
		DTCSP_UINT32        nKeyType,
		DTCSP_ECC_PUBLIC_KEY_PTR pSM2PublicKey);

DTCSP_INT32 DTCSP_SetDevInfo(
		DTCSP_VOID_PTR		pContext,
		DTCSP_DEVICEINFO    DevInfo);

DTCSP_INT32 DTCSP_GetDevInfo(
		DTCSP_VOID_PTR		pContext,
		DTCSP_DEVICEINFO_PTR pDevInfo);
				
DTCSP_INT32 DTCSP_InitFlash(DTCSP_VOID_PTR pContext);

DTCSP_INT32 DTCSP_InitFlashParameter(DTCSP_VOID_PTR pContext,DTCSP_INT32 nBlockNumber);

DTCSP_INT32 DTCSP_DisableAllInit(DTCSP_VOID_PTR pContext);

DTCSP_INT32 DTCSP_ClearDisableAllInit(DTCSP_VOID_PTR pContext);

DTCSP_INT32 DTCSP_SetPrivateAccessFlag(DTCSP_VOID_PTR pContext);

DTCSP_INT32 DTCSP_ClearPrivateAccessFlag(DTCSP_VOID_PTR pContext);

DTCSP_INT32 DTCSP_InitManagerBegin(
		DTCSP_VOID_PTR 	pContext,
		DTCSP_INT32  		nManagerCount);
		
DTCSP_INT32 DTCSP_InitManagerKey(
		DTCSP_VOID_PTR	pContext,
		DTCSP_INT32			nManagerNumber);
		
DTCSP_INT32 DTCSP_InitManagerEnd(DTCSP_VOID_PTR pContext);

DTCSP_INT32 DTCSP_GetManagerCount(
		DTCSP_VOID_PTR	 pContext,
		DTCSP_INT32_PTR  pManagerCount);
		
DTCSP_INT32 DTCSP_AddOneManager(
		DTCSP_VOID_PTR		pContext,
		DTCSP_INT32				nManagerNumber);
		
DTCSP_INT32 DTCSP_DelOneManager(
      	DTCSP_VOID_PTR  pContext,
				DTCSP_INT32			nManagerNumber);
		
DTCSP_INT32 DTCSP_ManagerLogin(
		DTCSP_VOID_PTR  	pContext,
		DTCSP_INT32_PTR  	pManagerNumber);
		
DTCSP_INT32 DTCSP_ManagerLogout(DTCSP_VOID_PTR pContext);

DTCSP_INT32 DTCSP_ChangeManagerKey(DTCSP_VOID_PTR 	pContext,DTCSP_INT32_PTR pManagerNumber);
		
DTCSP_INT32 DTCSP_AddOneOperator(DTCSP_VOID_PTR  pContext,DTCSP_INT32 nOperatorNumber);
DTCSP_INT32 DTCSP_DelOneOperator(DTCSP_VOID_PTR	pContext,DTCSP_INT32 nOperatorNumber);
DTCSP_INT32 DTCSP_OperatorLogin(DTCSP_VOID_PTR  pContext,DTCSP_INT32_PTR pOperatorNumber);
DTCSP_INT32 DTCSP_OperatorLogout(DTCSP_VOID_PTR  pContext);
DTCSP_INT32 DTCSP_ChangeOperatorKey(DTCSP_VOID_PTR pContext,DTCSP_INT32_PTR pOperatorNumber);

DTCSP_INT32 DTCSP_SMCCreate(
		DTCSP_VOID_PTR		pContext,
		DTCSP_UCHAR_PTR		pSMCUserName,
		DTCSP_INT32				nSMCUserNameLen,
		DTCSP_UCHAR_PTR		pSMCAuthPwd,
		DTCSP_INT32				nSMCAuthPwdLen,
		DTCSP_UCHAR_PTR		pSMCUnlockPwd,
		DTCSP_INT32				nSMCUnlockPwdLen);

DTCSP_INT32 DTCSP_SMCVerifyAuthPwd(
		DTCSP_VOID_PTR	pContext,
		DTCSP_UCHAR_PTR	pSMCUserName,
		DTCSP_INT32			nSMCUserNameLen,
		DTCSP_UCHAR_PTR	pSMCAuthPwd,
		DTCSP_INT32 		nSMCAuthPwdLen);

DTCSP_INT32 DTCSP_ModifySMCAuthPwd(
		   DTCSP_VOID_PTR		pContext,
		   DTCSP_UCHAR_PTR	pSMCUserName, 
		   DTCSP_INT32			nSMCUserNameLen,
		   DTCSP_UCHAR_PTR	pSMCAuthPwd,
		   DTCSP_INT32     	nSMCAuthPwdLen,
		   DTCSP_UCHAR_PTR	pSMCNewAuthPwd,
		   DTCSP_INT32      nSMCNewAuthPwdLen);

DTCSP_INT32 DTCSP_SMCUnlock(
			DTCSP_VOID_PTR	pContext,
			DTCSP_UCHAR_PTR	pSMCUserName, 
			DTCSP_INT32			nSMCUserNameLen, 
			DTCSP_UCHAR_PTR	pSMCUnlockPwd,
			DTCSP_INT32 		nSMCUnlockPwdLen, 
			DTCSP_UCHAR_PTR	pSMCNewAuthPwd,
			DTCSP_INT32			nSMCNewAuthPwdLen);

DTCSP_INT32 DTCSP_GenSymmetricKey(
			DTCSP_VOID_PTR	pContext,
			DTCSP_INT32     nSymKeyNum,
			DTCSP_INT32     nSymKeyLen);

DTCSP_INT32 DTCSP_PutSymmetricKey(
			DTCSP_VOID_PTR	pContext,
			DTCSP_INT32     nSymKeyNum,
			DTCSP_UCHAR_PTR pSymKey,
			DTCSP_INT32     nSymKeyLen);
			
DTCSP_INT32 DTCSP_GetSymmetricKey(
				DTCSP_VOID_PTR  pContext,
				DTCSP_INT32     nSymKeyNum,
				DTCSP_UCHAR_PTR pSymKey,
				DTCSP_INT32_PTR pSymKeyLen);
				
DTCSP_INT32 DTCSP_DelSymmetricKey(
				DTCSP_VOID_PTR  pContext,
				DTCSP_INT32     nSymKeyNum);

DTCSP_INT32 DTCSP_GenerateTrueRandData(
		DTCSP_VOID_PTR	pContext,
		DTCSP_INT32			nRandomDataLen,
		DTCSP_UCHAR_PTR	pRandomData);

DTCSP_INT32 DTCSP_StartRandSingleDetection(
			DTCSP_VOID_PTR	pContext,
			DTCSP_INT32     nDetectionLength);

DTCSP_INT32 DTCSP_StartRandCycleDetection(
			DTCSP_VOID_PTR	pContext);

DTCSP_INT32 DTCSP_SetRandCycleDetection(
			DTCSP_VOID_PTR	pContext,
			DTCSP_INT32     nGroup,
			DTCSP_INT32     nIntervalTime);

DTCSP_INT32 DTCSP_GetRandDetectionStatus(
			DTCSP_VOID_PTR	pContext,
			DTCSP_INT32_PTR nDetectionStatus);

DTCSP_INT32 DTCSP_GetRandCycleDetectionStatus(
			DTCSP_VOID_PTR	pContext,
			DTCSP_INT32_PTR nDetectionStatus);//0��ͨ����1����ͨ��2�����ڼ��

DTCSP_INT32 DTCSP_GetRandSingleDetectionStatus(
			DTCSP_VOID_PTR	pContext,
			DTCSP_INT32_PTR nDetectionStatus);//0����ͨ����δ�����ɣ�1��ͨ��

DTCSP_INT32 DTCSP_SymmetricKeyEncrypt(
		DTCSP_VOID_PTR		pContext,
		DTCSP_UINT32			nAlgorithm,
		DTCSP_INT32				nKeyNumber,
		DTCSP_UCHAR_PTR		pSymmetricKey,
		DTCSP_INT32				nSymmetricKeyLen,
		DTCSP_UCHAR_PTR		pInData,
		DTCSP_INT32				nInDataLen,
		DTCSP_UCHAR_PTR		pOutData,
		DTCSP_INT32 *			pOutDataLen);

DTCSP_INT32 DTCSP_SymmetricKeyDecrypt(
		DTCSP_VOID_PTR 		pContext,
		DTCSP_UINT32			nAlgorithm,
		DTCSP_INT32				nKeyNumber,
		DTCSP_UCHAR_PTR		pSymmetricKey,
		DTCSP_INT32				nSymmetricKeyLen,
		DTCSP_UCHAR_PTR		pInData,
		DTCSP_INT32				nInDataLen,
		DTCSP_UCHAR_PTR		pOutData,
		DTCSP_INT32_PTR		pOutDataLen);

DTCSP_INT32 DTCSP_SSF33EncryptStd(
		DTCSP_VOID_PTR	pContext,
		DTCSP_INT32			bKeyChangeFlag,
		DTCSP_UCHAR_PTR	pKey33,
		DTCSP_INT32			nKeyLen,
		DTCSP_UCHAR_PTR	pInData,
		DTCSP_INT32			nInDataLen,
		DTCSP_UCHAR_PTR	pOutData,
		DTCSP_INT32_PTR	pOutDataLen);

DTCSP_INT32 DTCSP_SSF33DecryptStd(
		DTCSP_VOID_PTR	pContext,
		DTCSP_INT32			bKeyChangeFlag,
		DTCSP_UCHAR_PTR	pKey33,
		DTCSP_INT32			nKeyLen,
		DTCSP_UCHAR_PTR	pInData,
		DTCSP_INT32			nInDataLen,
		DTCSP_UCHAR_PTR	pOutData,
		DTCSP_INT32_PTR	pOutDataLen);

DTCSP_INT32	DTCSP_BackupCardInfoBeginEx(
				DTCSP_VOID_PTR	pContext);

DTCSP_INT32	DTCSP_BackupCardInfoExportSecretKeyPartEx(
				DTCSP_VOID_PTR	pContext,
				DTCSP_INT32			nICCardNumber);

DTCSP_INT32 DTCSP_BackupCardInfoEndEx(
		DTCSP_VOID_PTR	pContext,
		DTCSP_INT32     nBakRstType,
		DTCSP_INT32			nBakRstAlg,	
		DTCSP_INT32     nKEKBeginNumber,		
		DTCSP_INT32     nKEKEndNumber,		
		DTCSP_INT32			nUserBeginNumber,		
		DTCSP_INT32     nUserEndNumber,	
		DTCSP_UCHAR_PTR	pBackupFileName);

DTCSP_INT32 DTCSP_BackupCardInfoEndEx_RSA(
		DTCSP_VOID_PTR	pContext,
		DTCSP_INT32     nBakRstType,
		DTCSP_INT32			nBakRstAlg,	
		DTCSP_INT32     nKEKBeginNumber,		
		DTCSP_INT32     nKEKEndNumber,		
		DTCSP_INT32			nUserBeginNumber,		
		DTCSP_INT32     nUserEndNumber,		
		DTCSP_INT32			nRSABeginNumber,		
		DTCSP_INT32     nRSAEndNumber,
		DTCSP_UCHAR_PTR	pBackupFileName);

DTCSP_INT32	DTCSP_RestoreCardInfoBeginEx(
				DTCSP_VOID_PTR	pContext);

DTCSP_INT32	DTCSP_RestoreCardInfoImportSecretKeyPartEx(DTCSP_VOID_PTR  pContext, 
													   			  DTCSP_INT32_PTR pICCardNumber);

DTCSP_INT32	DTCSP_RestoreImportCardInfoEx(
				DTCSP_VOID_PTR	pContext,
				DTCSP_UCHAR_PTR	pRestoreFileName);
				
DTCSP_INT32	DTCSP_RestoreImportCardInfoEx_RSA(
				DTCSP_VOID_PTR	pContext,
				DTCSP_UCHAR_PTR	pRestoreFileName);

DTCSP_INT32	DTCSP_RestoreCardInfoEndEx(DTCSP_VOID_PTR pContext);


DTCSP_INT32 DTCSP_UserReadFlashByChar(
		DTCSP_VOID_PTR	pContext,
		DTCSP_INT32			nOffset,
		DTCSP_UCHAR_PTR	pOutdata,
		DTCSP_INT32			nOutdataLen);

DTCSP_INT32 DTCSP_UserWriteFlashByChar(
		DTCSP_VOID_PTR	pContext,
		DTCSP_INT32			nOffset,
		DTCSP_UCHAR_PTR	pIndata,
		DTCSP_INT32			nIndataLen);

DTCSP_INT32 DTCSP_UserReadFlash(
		DTCSP_VOID_PTR	pContext,
		DTCSP_INT32			nFlashOffsetLong,
		DTCSP_ULONG_PTR	pOutdata,
		DTCSP_INT32			nOutdataLenLong);

DTCSP_INT32 DTCSP_UserWriteFlash(
		DTCSP_VOID_PTR	pContext,
		DTCSP_INT32			nFlashOffsetLong,
		DTCSP_ULONG_PTR	pIndata,
		DTCSP_INT32			nIndataLenLong);
					
DTCSP_INT32 DTCSP_SCB2ECBEncrypt(
								 DTCSP_VOID_PTR		pContext,
								 DTCSP_INT32			nKeynum,
								 DTCSP_UCHAR_PTR	pKey,
								 DTCSP_INT32			nKeyLen,
								 DTCSP_UCHAR_PTR	pInData,
								 DTCSP_INT32			nInDataLen,
								 DTCSP_UCHAR_PTR	pOutData,
								 DTCSP_INT32_PTR	pOutDataLen);

DTCSP_INT32 DTCSP_SCB2ECBDecrypt(
								 DTCSP_VOID_PTR		pContext,
								 DTCSP_INT32			nKeynum,
								 DTCSP_UCHAR_PTR	pKey,
								 DTCSP_INT32			nKeyLen,
								 DTCSP_UCHAR_PTR	pInData,
								 DTCSP_INT32			nInDataLen,
								 DTCSP_UCHAR_PTR	pOutData,
								 DTCSP_INT32_PTR	pOutDataLen);

DTCSP_INT32 DTCSP_SCB2CBCEncrypt(
								 DTCSP_VOID_PTR		pContext,
								 DTCSP_INT32			nKeynum,
								 DTCSP_UCHAR_PTR	pKey,
								 DTCSP_INT32			nKeyLen,
								 DTCSP_UCHAR_PTR 	pIv,
								 DTCSP_UCHAR_PTR	pInData,
								 DTCSP_INT32			nInDataLen,
								 DTCSP_UCHAR_PTR	pOutData,
								 DTCSP_INT32_PTR	pOutDataLen);

DTCSP_INT32 DTCSP_SCB2CBCDecrypt(
								 DTCSP_VOID_PTR		pContext,
								 DTCSP_INT32			nKeynum,
								 DTCSP_UCHAR_PTR	pKey,
								 DTCSP_INT32			nKeyLen,
								 DTCSP_UCHAR_PTR 	pIv,
								 DTCSP_UCHAR_PTR	pInData,
								 DTCSP_INT32			nInDataLen,
								 DTCSP_UCHAR_PTR	pOutData,
								 DTCSP_INT32_PTR	pOutDataLen);
								 	
DTCSP_INT32 DTCSP_SM1ECBEncrypt(
									   DTCSP_VOID_PTR		pContext,
									   DTCSP_INT32			nKeynum,
									   DTCSP_UCHAR_PTR	pKey,
									   DTCSP_INT32			nKeyLen,
									   DTCSP_UCHAR_PTR	pInData,
									   DTCSP_INT32			nInDataLen,
									   DTCSP_UCHAR_PTR	pOutData,
									   DTCSP_INT32_PTR	pOutDataLen);

DTCSP_INT32 DTCSP_SM1ECBDecrypt(
								DTCSP_VOID_PTR	pContext,
								DTCSP_INT32			nKeynum,
								DTCSP_UCHAR_PTR	pKey,
								DTCSP_INT32			nKeyLen,
								DTCSP_UCHAR_PTR	pInData,
								DTCSP_INT32			nInDataLen,
								DTCSP_UCHAR_PTR	pOutData,
								DTCSP_INT32_PTR	pOutDataLen);

DTCSP_INT32 DTCSP_SM1CBCEncrypt(
							DTCSP_VOID_PTR	pContext,
							DTCSP_INT32			nKeynum,
							DTCSP_UCHAR_PTR	pKey,
							DTCSP_INT32			nKeyLen,
							DTCSP_UCHAR_PTR pIv,
							DTCSP_UCHAR_PTR	pInData,
							DTCSP_INT32			nInDataLen,
							DTCSP_UCHAR_PTR	pOutData,
							DTCSP_INT32_PTR	pOutDataLen);

DTCSP_INT32 DTCSP_SM1CBCDecrypt(
							DTCSP_VOID_PTR	pContext,
							DTCSP_INT32			nKeynum,
							DTCSP_UCHAR_PTR	pKey,
							DTCSP_INT32			nKeyLen,
							DTCSP_UCHAR_PTR pIv,
							DTCSP_UCHAR_PTR	pInData,
							DTCSP_INT32			nInDataLen,
							DTCSP_UCHAR_PTR	pOutData,
							DTCSP_INT32_PTR	pOutDataLen);

DTCSP_INT32 DTCSP_SM1OFBEncrypt(
							DTCSP_VOID_PTR	pContext,
							DTCSP_INT32			nKeynum,
							DTCSP_UCHAR_PTR	pKey,
							DTCSP_INT32			nKeyLen,
							DTCSP_UCHAR_PTR pIv,
							DTCSP_UCHAR_PTR	pInData,
							DTCSP_INT32			nInDataLen,
							DTCSP_UCHAR_PTR	pOutData,
							DTCSP_INT32_PTR	pOutDataLen);

DTCSP_INT32 DTCSP_SM1OFBDecrypt(
							DTCSP_VOID_PTR	pContext,
							DTCSP_INT32			nKeynum,
							DTCSP_UCHAR_PTR	pKey,
							DTCSP_INT32			nKeyLen,
							DTCSP_UCHAR_PTR pIv,
							DTCSP_UCHAR_PTR	pInData,
							DTCSP_INT32			nInDataLen,
							DTCSP_UCHAR_PTR	pOutData,
							DTCSP_INT32_PTR	pOutDataLen);

DTCSP_INT32 DTCSP_SM1MAC(
		DTCSP_VOID_PTR		pContext,
		DTCSP_INT32		  	nKeynum,
		DTCSP_UCHAR_PTR		pKey,
		DTCSP_INT32		  	nKeyLen,
		DTCSP_UCHAR_PTR 	pIv,
		DTCSP_UCHAR_PTR		pInData,
		DTCSP_INT32		  	nInDataLen,
		DTCSP_UCHAR_PTR		pOutData,
		DTCSP_INT32_PTR		pOutDataLen);

DTCSP_INT32 DTCSP_FPGA_SM4ECBEncrypt(
									   DTCSP_VOID_PTR		pContext,
									   DTCSP_INT32			nKeynum,
									   DTCSP_UCHAR_PTR	pKey,
									   DTCSP_INT32			nKeyLen,
									   DTCSP_UCHAR_PTR	pInData,
									   DTCSP_INT32			nInDataLen,
									   DTCSP_UCHAR_PTR	pOutData,
									   DTCSP_INT32_PTR	pOutDataLen);

DTCSP_INT32 DTCSP_FPGA_SM4ECBDecrypt(
								DTCSP_VOID_PTR	pContext,
								DTCSP_INT32			nKeynum,
								DTCSP_UCHAR_PTR	pKey,
								DTCSP_INT32			nKeyLen,
								DTCSP_UCHAR_PTR	pInData,
								DTCSP_INT32			nInDataLen,
								DTCSP_UCHAR_PTR	pOutData,
								DTCSP_INT32_PTR	pOutDataLen);

DTCSP_INT32 DTCSP_FPGA_SM4CBCEncrypt(
							DTCSP_VOID_PTR	pContext,
							DTCSP_INT32			nKeynum,
							DTCSP_UCHAR_PTR	pKey,
							DTCSP_INT32			nKeyLen,
							DTCSP_UCHAR_PTR pIv,
							DTCSP_UCHAR_PTR	pInData,
							DTCSP_INT32			nInDataLen,
							DTCSP_UCHAR_PTR	pOutData,
							DTCSP_INT32_PTR	pOutDataLen);

DTCSP_INT32 DTCSP_FPGA_SM4CBCDecrypt(
							DTCSP_VOID_PTR	pContext,
							DTCSP_INT32			nKeynum,
							DTCSP_UCHAR_PTR	pKey,
							DTCSP_INT32			nKeyLen,
							DTCSP_UCHAR_PTR pIv,
							DTCSP_UCHAR_PTR	pInData,
							DTCSP_INT32			nInDataLen,
							DTCSP_UCHAR_PTR	pOutData,
							DTCSP_INT32_PTR	pOutDataLen);

DTCSP_INT32 DTCSP_FPGA_SM4OFBEncrypt(
							DTCSP_VOID_PTR	pContext,
							DTCSP_INT32			nKeynum,
							DTCSP_UCHAR_PTR	pKey,
							DTCSP_INT32			nKeyLen,
							DTCSP_UCHAR_PTR pIv,
							DTCSP_UCHAR_PTR	pInData,
							DTCSP_INT32			nInDataLen,
							DTCSP_UCHAR_PTR	pOutData,
							DTCSP_INT32_PTR	pOutDataLen);

DTCSP_INT32 DTCSP_FPGA_SM4OFBDecrypt(
							DTCSP_VOID_PTR	pContext,
							DTCSP_INT32			nKeynum,
							DTCSP_UCHAR_PTR	pKey,
							DTCSP_INT32			nKeyLen,
							DTCSP_UCHAR_PTR pIv,
							DTCSP_UCHAR_PTR	pInData,
							DTCSP_INT32			nInDataLen,
							DTCSP_UCHAR_PTR	pOutData,
							DTCSP_INT32_PTR	pOutDataLen);

DTCSP_INT32 DTCSP_FPGA_SM4MAC(
		DTCSP_VOID_PTR		pContext,
		DTCSP_INT32		  	nKeynum,
		DTCSP_UCHAR_PTR		pKey,
		DTCSP_INT32		  	nKeyLen,
		DTCSP_UCHAR_PTR 	pIv,
		DTCSP_UCHAR_PTR		pInData,
		DTCSP_INT32		  	nInDataLen,
		DTCSP_UCHAR_PTR		pOutData,
		DTCSP_INT32_PTR		pOutDataLen);

DTCSP_INT32 DTCSP_SSF33Encrypt_NoLLimit(
		DTCSP_VOID_PTR	pContext,
		DTCSP_INT32			bKeyChangeFlag,
		DTCSP_UCHAR_PTR	Key33,
		DTCSP_INT32			KeyLen,
		DTCSP_UCHAR_PTR	InData,
		DTCSP_INT32			InDataLen,
		DTCSP_UCHAR_PTR	OutData,
		DTCSP_INT32_PTR	OutDataLen);

DTCSP_INT32 DTCSP_SSF33Decrypt_NoLLimit(
		DTCSP_VOID_PTR	pContext,
		DTCSP_INT32			bKeyChangeFlag,
		DTCSP_UCHAR_PTR	Key33,
		DTCSP_INT32			KeyLen,
		DTCSP_UCHAR_PTR	InData,
		DTCSP_INT32			InDataLen,
		DTCSP_UCHAR_PTR	OutData,
		DTCSP_INT32_PTR	OutDataLen);

DTCSP_INT32 DTCSP_SSF33Encrypt(
		DTCSP_VOID_PTR	pContext,
		DTCSP_INT32			bKeyChangeFlag,
		DTCSP_UCHAR_PTR	pKey33,
		DTCSP_INT32			nKeyLen,
		DTCSP_UCHAR_PTR	pInData,
		DTCSP_INT32			nInDataLen,
		DTCSP_UCHAR_PTR	pOutData,
		DTCSP_INT32_PTR	pOutDataLen);

DTCSP_INT32 DTCSP_SSF33Decrypt(
		DTCSP_VOID_PTR	pContext,
		DTCSP_INT32			bKeyChangeFlag,
		DTCSP_UCHAR_PTR	pKey33,
		DTCSP_INT32			nKeyLen,
		DTCSP_UCHAR_PTR	pInData,
		DTCSP_INT32			nInDataLen,
		DTCSP_UCHAR_PTR	pOutData,
		DTCSP_INT32_PTR	pOutDataLen);
		
DTCSP_INT32 DTCSP_3DESEncrypt(
		DTCSP_VOID_PTR   pContext,
		DTCSP_INT32      nKeyNum,
		DTCSP_UCHAR_PTR  pDesKey,
		DTCSP_ULONG      nDesKeyLen,
		DTCSP_UCHAR_PTR  pInData,
		DTCSP_ULONG      nInDataLen,
		DTCSP_UCHAR_PTR  pOutData,
		DTCSP_ULONG_PTR  pOutDataLen);
		
DTCSP_INT32 DTCSP_3DESDecrypt(
		DTCSP_VOID_PTR      pContext,
		DTCSP_INT32         nKeyNum,
		DTCSP_UCHAR_PTR 		pDesKey,
		DTCSP_ULONG  				nDesKeyLen,
		DTCSP_UCHAR_PTR 		pInData,
		DTCSP_ULONG  				nInDataLen,
		DTCSP_UCHAR_PTR 		pOutData,
		DTCSP_ULONG_PTR 		pOutDataLen);
		
DTCSP_INT32 DTCSP_DESEncrypt(
		DTCSP_VOID_PTR   pContext,
		DTCSP_INT32      nKeyNum,
		DTCSP_UCHAR_PTR  pDesKey,
		DTCSP_INT32      nDesKeyLen,
		DTCSP_UCHAR_PTR  pInData,
		DTCSP_INT32      nInDataLen,
		DTCSP_UCHAR_PTR  pOutData,
		DTCSP_INT32_PTR  pOutDataLen);
		
DTCSP_INT32 DTCSP_DESDecrypt(
		DTCSP_VOID_PTR         pContext,
		DTCSP_INT32            nKeyNum,
		DTCSP_UCHAR_PTR		 		 pDesKey,
		DTCSP_INT32            nDesKeyLen,
		DTCSP_UCHAR_PTR		     pInData,
		DTCSP_INT32            nInDataLen,
		DTCSP_UCHAR_PTR		     pOutData,
		DTCSP_INT32_PTR        pOutDataLen);

DTCSP_INT32 DTCSP_HASH(
		  DTCSP_VOID_PTR   pContext,
		  DTCSP_UINT32     nAlgorithm,
		  DTCSP_UCHAR_PTR  pInData,
		  DTCSP_INT32      nInDataLen,
		  DTCSP_UCHAR_PTR  pOutData,
		  DTCSP_INT32_PTR  pOutDataLen);

DTCSP_INT32 DTCSP_HASHInit (
		  DTCSP_VOID_PTR   pContext,
		  DTCSP_UINT32     nAlgorithm,
		  DTCSP_ULONG_PTR  hashHandle);

DTCSP_INT32 DTCSP_HASHUpdate(
		  DTCSP_VOID_PTR   pContext,
		  DTCSP_ULONG      hashHandle,
		  DTCSP_UCHAR_PTR  pInData,
		  DTCSP_INT32      nInDataLen);	

DTCSP_INT32 DTCSP_HASHFinal (
		  DTCSP_VOID_PTR   pContext,
		  DTCSP_ULONG      hashHandle,
		  DTCSP_UCHAR_PTR  pOutData,
		  DTCSP_INT32_PTR  pOutDataLen);

DTCSP_INT32 DTCSP_ECC_GenKeyPair(
			DTCSP_VOID_PTR						pContext,
			DTCSP_INT32								nStoreLocation,
			DTCSP_ECC_PUBLIC_KEY_PTR	pEccPublicKey,
			DTCSP_ECC_PRIVATE_KEY_PTR	pEccPrivateKey);

DTCSP_INT32	DTCSP_ECC_PutKeyPair(
			DTCSP_VOID_PTR	pContext,
			DTCSP_INT32			nDstKeyNumber,
			DTCSP_INT32			nKeyType,
			DTCSP_ECC_PUBLIC_KEY	pPublicKey,
			DTCSP_ECC_PRIVATE_KEY	pPrivateKey);
								  
DTCSP_INT32 DTCSP_ECC_DestroyKeyPair(
			DTCSP_VOID_PTR	pContext,
			DTCSP_INT32			nStoreLocation,
			DTCSP_INT32			nKeyType);

DTCSP_INT32 DTCSP_ECC_GetPubKey(
			DTCSP_VOID_PTR		  pContext,
			DTCSP_INT32					nStoreLocation,
			DTCSP_INT32					nKeyType,
			DTCSP_ECC_PUBLIC_KEY_PTR	pEccPublicKey);

DTCSP_INT32 DTCSP_ECC_GetPriKey(
			DTCSP_VOID_PTR				pContext,
			DTCSP_INT32						nStoreLocation,
			DTCSP_INT32						nKeyType,
			DTCSP_ECC_PRIVATE_KEY_PTR	pEccPrivateKey);

DTCSP_INT32 DTCSP_ECC_GenCipherEncKeyPair(
				DTCSP_VOID_PTR				pContext,
				DTCSP_INT32						nStoreLocation,
				DTCSP_INT32						nSymAlg,
				DTCSP_ENVELOPEDKEYBLOB_PTR  pENVELOPEDKEYBLOB);

DTCSP_INT32 DTCSP_ECC_ImportCipherEncKeyPair(
				DTCSP_VOID_PTR				pContext,
				DTCSP_INT32						nStoreLocation,
				DTCSP_ENVELOPEDKEYBLOB_PTR  pENVELOPEDKEYBLOB);

DTCSP_INT32 DTCSP_ECC_ExchangeDigitEnvelope(
			DTCSP_VOID_PTR				pContext,
			DTCSP_INT32						nStoreLocation,
			DTCSP_ECC_PRIVATE_KEY_PTR	pEccPrivateKey,
			DTCSP_ECC_PUBLIC_KEY_PTR	pEccPublicKey,
			DTCSP_ECC_CIPHER_PTR		pInData,
			DTCSP_ECC_CIPHER_PTR		pOutData);

DTCSP_INT32 DTCSP_PutPrivateKeyAccessData(
			DTCSP_VOID_PTR  pContext,
			DTCSP_INT32     keynumber,
			DTCSP_UCHAR_PTR pAccessData,
			DTCSP_INT32     nAccessDataLen);
								  
DTCSP_INT32 DTCSP_GetPrivateKeyAccessData(
			DTCSP_VOID_PTR      pContext,
			DTCSP_INT32         keynumber,
			DTCSP_UCHAR_PTR     pAccessData,
			DTCSP_INT32_PTR     pAccessDataLen);

DTCSP_INT32 DTCSP_GetPrivateKeyAccessRight(
		    DTCSP_VOID_PTR	 		pContext,
		    DTCSP_INT32         keynumber,
		    DTCSP_UCHAR_PTR	    pAccessData,     
		    DTCSP_INT32     		nAccessDataLen);

DTCSP_INT32	DTCSP_ReleasePrivateKeyAccessRight(
		    DTCSP_VOID_PTR	    pContext,
		    DTCSP_INT32         keynumber);  

DTCSP_INT32 DTCSP_SCE_Sign(
			DTCSP_VOID_PTR				pContext,
			DTCSP_INT32						nStoreLocation,
			DTCSP_ECC_PRIVATE_KEY_PTR	pEccPrivateKey,
			DTCSP_UCHAR_PTR				pInDataMes,
			DTCSP_INT32						nInDataMesLen,
			DTCSP_ECC_SIG_PTR			pOutDataSign);

DTCSP_INT32 DTCSP_SCE_Verify(
			DTCSP_VOID_PTR				pContext,
			DTCSP_INT32						nStoreLocation,
			DTCSP_ECC_PUBLIC_KEY_PTR	pEccPublicKey,
			DTCSP_UCHAR_PTR				pInDataMes,
			DTCSP_INT32						nInDataMesLen,
			DTCSP_ECC_SIG_PTR			pInDataSign,
			DTCSP_INT32_PTR				result);
			
DTCSP_INT32 DTCSP_SCE_Encrypt(
			DTCSP_VOID_PTR				pContext,
			DTCSP_INT32						nStoreLocation,
			DTCSP_ECC_PUBLIC_KEY_PTR	pEccPublicKey,
			DTCSP_UCHAR_PTR				pInData,
			DTCSP_INT32						nInDataLen,  
			DTCSP_ECC_CIPHER_PTR  pOutData);

DTCSP_INT32 DTCSP_SCE_Decrypt(
			DTCSP_VOID_PTR				pContext,
			DTCSP_INT32						nStoreLocation,
			DTCSP_ECC_PRIVATE_KEY_PTR	pEccPrivateKey,
			DTCSP_ECC_CIPHER_PTR  pInData,
			DTCSP_UCHAR_PTR				pOutData,
			DTCSP_INT32*					nOutDataLen);

DTCSP_INT32 DTCSP_SM2_1_Sign(
			DTCSP_VOID_PTR				pContext,
			DTCSP_INT32						nStoreLocation,
			DTCSP_ECC_PRIVATE_KEY_PTR	pEccPrivateKey,
			DTCSP_UCHAR_PTR				pInDataMes,
			DTCSP_INT32						nInDataMesLen,
			DTCSP_ECC_SIG_PTR			pOutDataSign);
			
DTCSP_INT32 DTCSP_SM2_1_Verify(
			DTCSP_VOID_PTR				pContext,
			DTCSP_INT32						nStoreLocation,
			DTCSP_ECC_PUBLIC_KEY_PTR	pEccPublicKey,
			DTCSP_UCHAR_PTR				pInDataMes,
			DTCSP_INT32						nInDataMesLen,
			DTCSP_ECC_SIG_PTR			pInDataSign,
			DTCSP_INT32_PTR				result);
						
DTCSP_INT32 DTCSP_SM2_3_Encrypt(
			DTCSP_VOID_PTR				pContext,
			DTCSP_INT32						nStoreLocation,
			DTCSP_ECC_PUBLIC_KEY_PTR	pEccPublicKey,
			DTCSP_UCHAR_PTR				pInData,
			DTCSP_INT32						nInDataLen,  
			DTCSP_ECC_CIPHER_PTR  pOutData);
			
DTCSP_INT32 DTCSP_SM2_3_Decrypt(
			DTCSP_VOID_PTR				pContext,
			DTCSP_INT32						nStoreLocation,
			DTCSP_ECC_PRIVATE_KEY_PTR	pEccPrivateKey,
			DTCSP_ECC_CIPHER_PTR  pInData,
			DTCSP_UCHAR_PTR				pOutData,
			DTCSP_INT32*					nOutDataLen);			

DTCSP_INT32 DTCSP_SCE_KeyAgreement (
			DTCSP_VOID_PTR				pContext,
			DTCSP_INT32  					nStoreLocation,
			DTCSP_ECC_PRIVATE_KEY_PTR	pOrgPriKey,
			DTCSP_ECC_PRIVATE_KEY_PTR	pOrgTempPriKey,
			DTCSP_ECC_PUBLIC_KEY_PTR	pRespoPubKey,
			DTCSP_ECC_PUBLIC_KEY_PTR	pRespoTempPubKey,
			DTCSP_INT32                 nflag,
			DTCSP_INT32					nKeyLen,
			DTCSP_UCHAR_PTR	    pOrgID,
			DTCSP_INT32					nOrgIDLen,
			DTCSP_UCHAR_PTR		  pRespoID,
			DTCSP_INT32					nRespoIDLen,
			DTCSP_UCHAR_PTR		  pOutKey);

DTCSP_INT32 DTCSP_SM2_2_KeyAgreement (
			DTCSP_VOID_PTR				pContext,
			DTCSP_INT32  					nStoreLocation,
			DTCSP_ECC_PRIVATE_KEY_PTR	pOrgPriKey,
			DTCSP_ECC_PRIVATE_KEY_PTR	pOrgTempPriKey,
			DTCSP_ECC_PUBLIC_KEY_PTR	pRespoPubKey,
			DTCSP_ECC_PUBLIC_KEY_PTR	pRespoTempPubKey,
			DTCSP_INT32               nflag,
			DTCSP_INT32					nKeyLen,
			DTCSP_UCHAR_PTR		  pOrgID,
			DTCSP_INT32					nOrgIDLen,
			DTCSP_UCHAR_PTR		  pRespoID,
			DTCSP_INT32					nRespoIDLen,
			DTCSP_UCHAR_PTR		  pOutKey);

DTCSP_INT32 DTCSP_SCE_KeyAgreement_Ex(
			DTCSP_VOID_PTR		  pContext,
			DTCSP_INT32  				nStoreLocation,
			DTCSP_ECC_PRIVATE_KEY_PTR	pOrgPriKey,
			DTCSP_ECC_PRIVATE_KEY_PTR	pOrgTempPriKey,
			DTCSP_ECC_PUBLIC_KEY_PTR	pRespoPubKey,
			DTCSP_ECC_PUBLIC_KEY_PTR	pRespoTempPubKey,
			DTCSP_INT32               nflag,
			DTCSP_INT32					nKeyLen,
			DTCSP_UCHAR_PTR		  pOrgID,
			DTCSP_INT32					nOrgIDLen,
			DTCSP_UCHAR_PTR		  pRespoID,
			DTCSP_INT32					nRespoIDLen,
			DTCSP_UCHAR_PTR		  pOutKey);

DTCSP_INT32 DTCSP_SM2_2_KeyAgreement_Ex(
			DTCSP_VOID_PTR	    pContext,
			DTCSP_INT32  				nStoreLocation,
			DTCSP_ECC_PRIVATE_KEY_PTR	pOrgPriKey,
			DTCSP_ECC_PRIVATE_KEY_PTR	pOrgTempPriKey,
			DTCSP_ECC_PUBLIC_KEY_PTR	pRespoPubKey,
			DTCSP_ECC_PUBLIC_KEY_PTR	pRespoTempPubKey,
			DTCSP_INT32               nflag,
			DTCSP_INT32					nKeyLen,
			DTCSP_UCHAR_PTR		  pOrgID,
			DTCSP_INT32					nOrgIDLen,
			DTCSP_UCHAR_PTR		  pRespoID,
			DTCSP_INT32					nRespoIDLen,
			DTCSP_UCHAR_PTR		  pOutKey);

DTCSP_INT32 DTCSP_SM3 (
			DTCSP_VOID_PTR			pContext,
			DTCSP_UCHAR_PTR 		pInData,       	
			DTCSP_INT32     		nInDataLen,
			DTCSP_UCHAR_PTR 		pOutData,
			DTCSP_INT32_PTR  	 	pOutDataLen);

DTCSP_INT32  DTCSP_SM3_Initialize(
		   DTCSP_VOID_PTR			 pContext, 
		   DTCSP_SM3_CONTEXT_PTR	 pSCHContext,
		   DTCSP_INT32				 	nFlag,      
		   DTCSP_UCHAR_PTR 			pID, 
		   DTCSP_INT32         	nIDLen,
		   DTCSP_INT32         	nStoreLocation,
		   DTCSP_INT32  			 	nEccCurveFlag,
		   DTCSP_ECC_PUBLIC_KEY_PTR	 pEccPublicKey);

DTCSP_INT32 DTCSP_SM3_Update(
			DTCSP_VOID_PTR			pContext,
			DTCSP_SM3_CONTEXT_PTR	pSCHContext,
			DTCSP_UCHAR_PTR 		pInData,       	
			DTCSP_INT32      		nInDataLen);

DTCSP_INT32 DTCSP_SM3_Finalize(
			DTCSP_VOID_PTR 			pContext, 
			DTCSP_SM3_CONTEXT_PTR	pSCHContext,
			DTCSP_UCHAR_PTR			pOutData,
			DTCSP_INT32_PTR  		pOutDataLen);

DTCSP_INT32 DTCSP_GetSessionKey(
				DTCSP_VOID_PTR  pContext,
				DTCSP_INT32     nSessionKeyNum,
				DTCSP_UCHAR_PTR pSessionKey,
				DTCSP_INT32_PTR pSessionKeyLen);

DTCSP_INT32 DTCSP_DelSessionKey(
				DTCSP_VOID_PTR  pContext,
				DTCSP_INT32     nSessionKeyNum);

DTCSP_INT32 DTCSP_GenSessionKey_ECC(
			DTCSP_VOID_PTR			pContext,
			DTCSP_INT32					nStoreLocation,
			DTCSP_ECC_PUBLIC_KEY_PTR	pEccPublicKey,
			DTCSP_INT32							nKeyLen,  
			DTCSP_ECC_CIPHER_PTR		pOutKeyData,
			DTCSP_VOID_PTR       		pKeyHandle);

DTCSP_INT32 DTCSP_ImportSessionKey_ECC(
			DTCSP_VOID_PTR				pContext,
			DTCSP_INT32						nStoreLocation,
			DTCSP_ECC_PRIVATE_KEY_PTR	pEccPrivateKey,
			DTCSP_ECC_CIPHER_PTR	pInKeyData,
			DTCSP_VOID_PTR       	pKeyHandle);

DTCSP_INT32 DTCSP_GenSessionKey_KEK(
			DTCSP_VOID_PTR			pContext,
			DTCSP_INT32					nStoreLocation,
			DTCSP_INT32					nKeyLen,
			DTCSP_INT32					nAlgID,
			DTCSP_UCHAR_PTR			pOutKeyData,
			DTCSP_INT32_PTR   	pOutKeyDataLen,
			DTCSP_VOID_PTR     	pKeyHandle);

DTCSP_INT32 DTCSP_ImportSessionKey_KEK(
			DTCSP_VOID_PTR			pContext,
			DTCSP_INT32					nStoreLocation,
			DTCSP_INT32					nAlgID,
			DTCSP_UCHAR_PTR			pInKeyData,
			DTCSP_INT32    			nInKeyDataLen,
			DTCSP_VOID_PTR     	pKeyHandle);

DTCSP_INT32 DTCSP_ImportSessionKey(
			DTCSP_VOID_PTR				pContext,
			DTCSP_UCHAR_PTR				pInKeyData,
			DTCSP_INT32    		  	nInKeyDataLen,
			DTCSP_VOID_PTR      	pKeyHandle);
		
//sj-2016-9-14			
DTCSP_INT32	DTCSP_Restore3CardKey(DTCSP_VOID_PTR	pContext, 
													        DTCSP_UCHAR_PTR  pKey);	
													        
//sj-2017-6-5
DTCSP_INT32	DTCSP_Restore0347KeyTo0602Card_RSA(DTCSP_VOID_PTR	  pContext, 
													                     DTCSP_UCHAR_PTR	pRestoreFileName);
													                     
DTCSP_INT32	DTCSP_Restore0347KeyTo0602Card_RSA_flashAndFile(DTCSP_VOID_PTR	pContext,                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               
													                                  DTCSP_UCHAR_PTR	pRestoreFileName);                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 													                     													        												        
													        
//sj-2017-7-7
DTCSP_INT32 DTCSP_PutCurSystemKey_only(
				DTCSP_VOID_PTR	pContext,
				DTCSP_CHAR_PTR	pCurSystemKey);
				
DTCSP_INT32 DTCSP_PutCurSystemKey(
				DTCSP_VOID_PTR	pContext,
				DTCSP_CHAR_PTR	pCurSystemKey);
				
DTCSP_INT32 DTCSP_PutOldSystemKey(
				DTCSP_VOID_PTR	pContext,
				DTCSP_CHAR_PTR	pCurSystemKey);																					        
													        
DTCSP_INT32 DTCSP_GetCurSystemKey(
								  DTCSP_VOID_PTR  pContext,
								  DTCSP_UCHAR_PTR pCurSystemKey,
								  DTCSP_INT32 *   nCurSystemKeyLen);
								  
DTCSP_INT32 DTCSP_GetOldSystemKey(
								  DTCSP_VOID_PTR  pContext,
								  DTCSP_UCHAR_PTR pOldSystemKey,
								  DTCSP_INT32 *   nOldSystemKeyLen);								  													        
												        		
//lz 2019-02-19
DTCSP_INT32	DTCSP_PutDevAccessData(
				DTCSP_VOID_PTR			pContext,
				DTCSP_UCHAR_PTR			pAccessData,
				DTCSP_INT32			    nAccessDataLen);



DTCSP_INT32 DTCSP_GetDevKeyAccessData(
				DTCSP_VOID_PTR			pContext,
				DTCSP_UCHAR_PTR			pAccessData,
				DTCSP_INT32_PTR    		pAccessDataLen);


DTCSP_INT32 DTCSP_GetDevKeyAccessRight(
				DTCSP_VOID_PTR			pContext,
				DTCSP_UCHAR_PTR			pAccessData,
				DTCSP_INT32				nAccessDataLen);


DTCSP_INT32 DTCSP_ReleaseDevKeyAccessRight(
				DTCSP_VOID_PTR 			pContext);	
////////////////////Out of card error code//////////////////////////////////////
#define DTCSP_SUCCESS					0x0000
#define DTCSP_ERR_COMMAND_CODE			0xEEEE
#define DTCSP_ERR_FAILED				0xFFFF
#define	NO_SUPPORT_FUNC                 0xEFFF  
#define DTCSP_ERR_LOADBALANCE_INIT		0xEE01
#define DTCSP_ERR_LOADBALANCE_GET		0xEE02
#define DTCSP_ERR_LOADBALANCE_REL		0xEE03
#define DTCSP_ERR_LOADBALANCE_GETALL	0xEE04
#define DTCSP_ERR_LOADBALANCE_RELALL	0xEE05

//	communication
#define DTCSP_ERR_PARAMENT			0xEE20
#define	DTCSP_ERR_OPEN_FILE			0xEE21

//	For Config File
#define	DTCSP_ERR_CONFIG_FILE		0xEE30
#define	DTCSP_ERR_CONFIG_KEY		0xEE31

/* Management & operation */
#define ERR_MANAGEMENT_DENY         0xE000  // ����Ȩ�޲�����
#define ERR_OPERATION_DENY          0xE001  // ����Ȩ�޲�����
#define ERR_PRI_KEY_ACCESS_RIGHT    0xE002  // ˽ԿȨ�޲�����     //4
#define ERR_PRI_KEY_ACCESS_DATA     0xE003  // ��֤˽ԿȨ�����   //3
#define ERR_AUDITOR_DENY            0xE004  // ���Ȩ�޲����� //sj-20180917-add
 
/* transfer */
#define ERR_USB_TRANSFER_BAG        0xE010  // Only For USB Device
#define ERR_USB_TRANSFER_MAXLEN     0xE011  // Only For USB Device
#define ERR_TRANSFER_LENGTH         0xE011  // Only For PCI Device

#define ERR_MNG_NOT_INITIALIZED     0xE050  // ����Աδ��ʼ��     //2
#define ERR_MNG_NUM_LIMIT           0xE051  // ����Ա��Ŀ�Ѽ���,�������ӻ�ɾ��
#define ERR_MNG_NOT_EXIST           0xE052  // �ù���Ա������
#define ERR_OPR_NOT_EXIST           0xE055	 // �����ڲ���Ա
#define ERR_MNG_ALREADY_EXIST       0xE057  // �ù���Ա�Ѵ���
#define ERR_FLASH_INIT_FORBID       0xE060  // ��ֹ��ʼ��FLASH
#define ERR_CONFIGKEY_NOT_EXIST     0xE063  // ϵͳ/(��ǰ������)�豸����Կ������
#define ERR_OPRPASS_NOT_EXIST       0xE064	 // δ��ʼ������Ա����
#define ERR_MNG_NUMBER_ILLEGAL      0xE065  // ����Ա��Ŀ/���벻�Ϸ�
#define ERR_OPR_NUM_LIMIT           0xE066  // ����Ա��Ŀ�Ѽ���  //1
#define ERR_OPR_ALREADY_EXIST       0xE068  // �ò���Ա�Ѵ���

//sj-20180817-add
#define ERR_AUDITOR_NUMBER_ILLEGAL  0xE069  // ���Ա��Ŀ/���벻�Ϸ�    
#define ERR_AUDITOR_NUM_LIMIT       0xE072  // ���Ա��Ŀ�Ѽ���,�������ӻ�ɾ��
#define ERR_AUDITOR_STATUS          0xE073  // ��������Ա״̬               
#define ERR_AUDITOR_ALREADY_EXIST   0xE074  // �����Ա�Ѵ���                
#define ERR_AUDITOR_NOT_EXIST       0xE075  // �����Ա������   

#define ERR_PASSWD_VERIFY           0xE070  // ����/������֤ʧ��
#define ERR_ID_VERIFY               0xE071  // ID��֤ʧ��

#define ERR_DEVIVE_STATUS           0xE080  // ��ǰ�豸״̬���������в���

/* for Algorithm */
#define ERR_KEY_NUMBER              0xE100  // ָ������Կ�Ŵ���
#define ERR_RSA_MODULUSLENGTH       0xE101  // RSA��Կģ������������������ģ������
#define ERR_KEY_NOT_EXIST           0xE102  // ָ������Կ������
#define ERR_SYMC_KEY_LENGTH         0xE103  // �Գ���Կ���ȳ���/�����������
    
/* IC Card Read/Write */
#define ERR_IC_READER_STATUS        0xE501  // δ��װ������/����������ʧ��
#define ERR_NO_IC_CARD              0xE502  // ��������δ����IC��
#define ERR_DSP_MPU_COMM_CHECK      0xE503  // DSP<->MPUͨ������У��ʧ��
#define ERR_IC_CARD_STATUS          0xE504  // ��IC�����ܶ�д/ʹ���˷Ƿ���
#define ERR_MNG_IC_CARD             0xE511  // ����Ĺ���Ա��
#define ERR_OPR_IC_CARD             0xE512  // ����Ĳ���Ա��
#define ERR_AUDITOR_IC_CARD         0xE513  // ��������Ա�� //sj-20180918-add

/* OTHERS */
#define ERR_CHECK_SUM               0xE700  // У��ͳ���

#define ERR_SHA1_UNINIT       		0xE701  //SHA1δִ�г�ʼ��
#define ERR_SHA1_UPDATE      		0xE702  //SHA1���´�
#define ERR_SHA256_UNINIT        	0xE703  //SHA256δִ�г�ʼ��
#define ERR_SHA256_UPDATE       	0xE704  //SHA256���´�
#define ERR_SCH_UNINIT			    0xE705  //SCHδִ�г�ʼ��
#define ERR_SCH_UPDATE			    0xE706  //SCH���´�
#define ERR_SET_CHIPID          	0xE707  //�����û�ID��
#define ERR_GET_CHIPID          	0xE708  //��ȡ�û�ID���û������
#define ERR_HASH_TIME_OUT           0xE709  //hash������ʱ091125

#define ERR_ECC_AUTHDATA        	0xE710  //�û���֤��Ϣ����
#define ERR_ECC_NOAUTHPASS    	    0xE711  //û��ͨ����Ȩ��֤

#define ERR_ECC_CURVE		        0xE720  //��Ч���߲���
#define ERR_ECC_UNINIT			    0xE721  //ECCδ���г�ʼ��
#define ERR_ECC_KEY			        0xE722  //�����ECC��Կ��
#define ERR_ECC_UNLOADPUBKEY		0xE723  //ECCδ���ع�Կ
#define ERR_ECC_UNLOADPRIKEY		0xE724  //ECCδ����˽Կ
#define ERR_ECC_SIGNATURE		    0xE725  //ECC��֤��ͨ������Чǩ��
#define ERR_ECC_CIPHER		        0xE726  //ECC���ܲ��ɹ����Ƿ�����

/* Backup restore */
#define ERR_BR_IC_NUMBER            0xE800  // �������Կ�����Ų���
#define ERR_BR_BAK_BEGIN            0xE801  // Backup Begin���ɹ���û��
#define ERR_BR_EXPORT_KEY           0xE802  // ��Կ����û��ȫ�����
#define ERR_BR_BLOCK_NO             0xE803  // ��Ų���
#define ERR_BR_IMPORT_KEY           0xE804  // �������Կ�������Ի���Ŀ����
#define ERR_BR_RST_BEGIN            0xE805  // Restore Begin���ɹ���û��
#define ERR_BR_KEY_EXIST            0xE806  // ��Կ������
#define ERR_KEY_NO                  0xE807  // ��Կ�Ŵ�

//RSA PKCS#1 pad
#define DTCSP_ERR_PKCS1_BTERR		0xE030
#define DTCSP_ERR_PKCS1_BLOCKTYPE	0xE031
#define DTCSP_ERR_DATA_TOO_LONG		0xE032
#define DTCSP_ERR_NOERROR			0xE033
#define DTCSP_ERR_IVALID_PKCS1BLOCK	0xE034
#define DTCSP_ERR_PSERROR			0xE035
#define DTCSP_ERR_SPERROR			0xE036
#define DTCSP_ERR_DATA_LENGTH		0xE038		
	
//	flash
//#define	DTCSP_ERR_FLASH_ADDRESS	  0xEE10

//////////////////////////////////////////Inside of card error number//////////
#define ERR_SUCCESS                  0x0000
#define ERR_COMMAND_CODE             0xEEEE
#define ERR_PARAMENT                 0xEE20
#define ERR_ARIC_NOT_SUPPORT         0xEE22  

#define ERR_FORMAT_CARD              0xE105  //��ʼ�����ܿ��� 
#define ERR_ERASE_CARD				 0xE106  //�������ܿ���
#define ERR_WRITE_USER_INFO          0xE107  //д�û���Ϣ��
#define ERR_WRITE_Serial			 0xE107  //д���ܿ����кŴ�	
#define ERR_EXT_AUTHKEY              0xE108  //д�ⲿ��֤��Կ��
#define ERR_AUTHKEY                  0xE109  //д�û������
#define ERR_UNLOCKKEY				 0xE110  //�������������
#define ERR_READ_Serial				 0xE111  //�����ܿ����кŴ�	
#define ERR_READ_USERNAME			 0xE112  //�����ܿ��û������
#define ERR_OLD_AUTHPASSWD			 0xE113  //�û��������
#define ERRO_UNLOCK_PASSWD           0xE114  //����Ľ�������
#define ERRO_VERIFY_ONCE_PASSWD      0xE115  //��֤/�޸Ŀ���ʧ��,�������λ��� 
#define ERRO_VERIFY_TWICE_PASSWD     0xE116  //��֤/�޸Ŀ���ʧ��,����һ�λ���
#define ERRO_VERIFY_THRICE_PASSWD    0xE117  //��֤/�޸Ŀ���ʧ��,�ٴ�ʧ�ܽ�������
#define ERRO_LOCK_PASSWD             0xE118  //������
#define ERRO_VERIFY_PASSWD           0xE119  //��֤�������ʧ��
#define ERRO_SMCU_NLOCK              0xE120  //��������ʧ��
#define ERRO_SMCU_NLOCKPWD           0xE121  //��֤�����������
#define ERRO_MODIFY_SMC_UNLOCKPWD    0xE122  //�޸Ľ����������
#define ERRO_SMC_EXT_AUTH_PWD        0xE123  //������ⲿ��֤����
#define ERRO_CREAT_FILE              0xE124  //�����ļ�����
#define ERRO_IC_CREATE_RSA_KEY       0xE125  //�������ܿ�RSA��Կ����
#define ERRO_IC_PRI_KEY_RAW          0xE126  //���ܿ�˽Կ�������
#define ERR_BACK_CPU_CARD_BEGIN      0xE127  //�������ܿ���ʼ��

#define ERR_DEV_NOT_PERMIT           0xE207  //������˲���
//#define ERR_KEY_NUMBER               0xE250  //ָ������Կ�Ŵ���
#define ERR_SYMC_ARITH               0xE301  //���㷨��֧��

#define ERR_Device_NoInit            0xE200  // Device is��not init
#define ERR_Device_NoReady           0xE201  // Device is��not ready
#define ERR_DEV_SIGN_KEY_NOT_EXIST   0xE202  // �豸ǩ����Կ�Բ�����
#define ERR_SAFEKEY_NOT_EXIST		 0xE203  // ��Կ������Կ������
#define ERR_DEV_SIGN_KEY_EXIST       0xE204  // �豸ǩ����Կ���Ѵ���
#define ERR_SAFEKEY_EXIST			 0xE205  // ��Կ������Կ���Ѵ���
#define ERR_DEV_ENC_KEY_EXIST        0xE206  // �豸������Կ���Ѵ���


//DTRTL
#define ERR_SUCCESS					0x0000
#define ERR_SYSDIR					0xE901
#define ERR_WR_RD_FILE				0xE902
#define ERR_OPEN_CLOSE_DEV			0xE903
#define ERR_WR_RD_DEV				0xE905
#define ERR_CREATE_DEL_SEM			0xE907
#define ERR_CREATE_DEL_SHAREMEM		0xE909
#define ERR_V_P						0xE911
#define ERR_MAP_UNMAP_MEM			0xE913
#define ERR_FindPCI					0xE915
#define ERR_LoadBalance				0xE916
#define ERR_REBOOT					0xE917																


#ifdef __cplusplus
}
#endif

#endif
