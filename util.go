package sdf_go
/*
#include "dasdf_api.h"

//void MallocCipher(ECCCipher *cipher,unsigned int length)
//{
//	//cipher = (ECCCipher*)malloc(sizeof(ECCCipher)+length);
//	cipher->C = (unsigned char *)calloc(length, sizeof(unsigned char));
//}
*/
import "C"
import (
	"fmt"
	"strings"
	"unsafe"
)

func ConvertToDeviceInfoGo(deviceInfo1 C.DEVICEINFO) (deviceInfo DeviceInfo) {
	deviceInfo = DeviceInfo{
		IssuerName:      strings.TrimRight(string(C.GoBytes(unsafe.Pointer(&deviceInfo1.IssuerName[0]), 40)), " "),
		DeviceName:      strings.TrimRight(string(C.GoBytes(unsafe.Pointer(&deviceInfo1.DeviceName[0]), 16)), " "),
		DeviceSerial:    strings.TrimRight(string(C.GoBytes(unsafe.Pointer(&deviceInfo1.DeviceSerial[0]), 16)), " "),
		DeviceVersion:   uint(deviceInfo1.DeviceVersion),
		StandardVersion: uint(deviceInfo1.StandardVersion),
		SymAlgAbility:   uint(deviceInfo1.SymAlgAbility),
		HashAlgAbility:  uint(deviceInfo1.HashAlgAbility),
		BufferSize:      uint(deviceInfo1.BufferSize),
	}
	temp1 := C.GoBytes(unsafe.Pointer(&deviceInfo1.AsymAlgAbility[0]), 2)
	temp2 := C.GoBytes(unsafe.Pointer(&deviceInfo1.AsymAlgAbility[1]), 2)
	deviceInfo.AsymAlgAbility[0] = uint(temp1[0])
	deviceInfo.AsymAlgAbility[1] = uint(temp2[0])
	return deviceInfo
}

func ConvertToRSArefPrivateKeyC(privateKey RSArefPrivateKey) (pucPrivateKey C.RSArefPrivateKey) {
	pucPrivateKey.bits = C.SGD_UINT32(privateKey.Bits)
	for i := 0; i < len(privateKey.M); i++ {
		pucPrivateKey.m[i] = C.SGD_UCHAR(privateKey.M[i])
	}
	for i := 0; i < len(privateKey.E); i++ {
		pucPrivateKey.e[i] = C.SGD_UCHAR(privateKey.E[i])
	}
	for i := 0; i < len(privateKey.D); i++ {
		pucPrivateKey.d[i] = C.SGD_UCHAR(privateKey.D[i])
	}
	for i := 0; i < len(privateKey.Coef); i++ {
		pucPrivateKey.coef[i] = C.SGD_UCHAR(privateKey.Coef[i])
	}

	for i := 0; i < len(privateKey.Prime[0]); i++ {
		pucPrivateKey.prime[0][i] = C.SGD_UCHAR(privateKey.Prime[0][i])
	}
	for i := 0; i < len(privateKey.Prime[0]); i++ {
		pucPrivateKey.prime[1][i] = C.SGD_UCHAR(privateKey.Prime[1][i])
	}

	for i := 0; i < len(privateKey.Pexp[0]); i++ {
		pucPrivateKey.pexp[0][i] = C.SGD_UCHAR(privateKey.Pexp[0][i])
	}
	for i := 0; i < len(privateKey.Pexp[0]); i++ {
		pucPrivateKey.pexp[1][i] = C.SGD_UCHAR(privateKey.Pexp[1][i])
	}
	return pucPrivateKey
}

func ConvertToRSArefPrivateKeyGo(pucPrivateKey C.RSArefPrivateKey) (privateKey RSArefPrivateKey) {
	privateKey = RSArefPrivateKey{
		Bits: uint(pucPrivateKey.bits),
		M:    strings.TrimRight(string(C.GoBytes(unsafe.Pointer(&pucPrivateKey.m[0]), 256)), " "),
		E:    strings.TrimRight(string(C.GoBytes(unsafe.Pointer(&pucPrivateKey.e[0]), 256)), " "),
		D:    strings.TrimRight(string(C.GoBytes(unsafe.Pointer(&pucPrivateKey.d[0]), 256)), " "),
		Coef: strings.TrimRight(string(C.GoBytes(unsafe.Pointer(&pucPrivateKey.coef[0]), 128)), " "),
	}
	privateKey.Prime[0] = strings.TrimRight(string(C.GoBytes(unsafe.Pointer(&pucPrivateKey.prime[0]), 128)), " ")
	privateKey.Prime[1] = strings.TrimRight(string(C.GoBytes(unsafe.Pointer(&pucPrivateKey.prime[1]), 128)), " ")
	privateKey.Pexp[0] = strings.TrimRight(string(C.GoBytes(unsafe.Pointer(&pucPrivateKey.pexp[0]), 128)), " ")
	privateKey.Pexp[1] = strings.TrimRight(string(C.GoBytes(unsafe.Pointer(&pucPrivateKey.pexp[1]), 128)), " ")
	return privateKey
}

func ConvertToRSArefPublicKeyC(publicKey RSArefPublicKey) (pucPublicKey C.RSArefPublicKey) {
	pucPublicKey.bits = C.SGD_UINT32(publicKey.Bits)
	for i := 0; i < len(publicKey.M); i++ {
		pucPublicKey.m[i] = C.SGD_UCHAR(publicKey.M[i])
	}
	for i := 0; i < len(publicKey.E); i++ {
		pucPublicKey.e[i] = C.SGD_UCHAR(publicKey.E[i])
	}
	return pucPublicKey
}

func ConvertToRSArefPublicKeyGo(pucPublicKey C.RSArefPublicKey) (publicKey RSArefPublicKey) {
	publicKey = RSArefPublicKey{
		Bits: uint(pucPublicKey.bits),
		M:    strings.TrimRight(string(C.GoBytes(unsafe.Pointer(&pucPublicKey.m[0]), 256)), " "),
		E:    strings.TrimRight(string(C.GoBytes(unsafe.Pointer(&pucPublicKey.e[0]), 256)), " "),
	}
	return publicKey
}

func ConvertToECCrefPublicKeyC(publicKey ECCrefPublicKey) (pucPublicKey C.ECCrefPublicKey) {

	pucPublicKey.bits = C.SGD_UINT32(publicKey.Bits)
	for i := 0; i < len(publicKey.X); i++ {
		pucPublicKey.x[i] = C.SGD_UCHAR(publicKey.X[i])
	}
	for i := 0; i < len(publicKey.Y); i++ {
		pucPublicKey.y[i] = C.SGD_UCHAR(publicKey.Y[i])
	}
	return pucPublicKey
}

func ConvertToECCrefPublicKeyGo(pucPublicKey C.ECCrefPublicKey) (publicKey ECCrefPublicKey) {
	publicKey = ECCrefPublicKey{
		Bits: uint(pucPublicKey.bits),
		X:    strings.TrimRight(string(C.GoBytes(unsafe.Pointer(&pucPublicKey.x[0]), 64)), " "),
		Y:    strings.TrimRight(string(C.GoBytes(unsafe.Pointer(&pucPublicKey.y[0]), 64)), " "),
	}
	return publicKey
}

func ConvertToECCrefPrivateKeyC(privateKey ECCrefPrivateKey) (pucPrivateKey C.ECCrefPrivateKey) {
	pucPrivateKey.bits = C.SGD_UINT32(privateKey.Bits)
	for i := 0; i < len(privateKey.K); i++ {
		pucPrivateKey.D[i] = C.SGD_UCHAR(privateKey.K[i])
	}
	return pucPrivateKey
}

func ConvertToECCrefPrivateKeyGo(pucPrivateKey C.ECCrefPrivateKey) (privateKey ECCrefPrivateKey) {
	privateKey = ECCrefPrivateKey{
		Bits: uint(pucPrivateKey.bits),
		K:    strings.TrimRight(string(C.GoBytes(unsafe.Pointer(&pucPrivateKey.D[0]),64)), " "),
	}
	return privateKey
}

func ConvertToECCCipherC(encData ECCCipher) (pucEncData C.ECCCipher) {
	//C.MallocCipher(&pucEncData,C.uint(encData.L))
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
	return pucEncData
}
func ConvertToECCCipherGo(pucKey C.ECCCipher) (key ECCCipher) {
	key = ECCCipher{
		X: strings.TrimRight(string(C.GoBytes(unsafe.Pointer(&pucKey.x[0]), 64)), " "),
		Y: strings.TrimRight(string(C.GoBytes(unsafe.Pointer(&pucKey.y[0]), 64)), " "),
		M: strings.TrimRight(string(C.GoBytes(unsafe.Pointer(&pucKey.M[0]), 32)), " "),
		L: uint(pucKey.L),
		C: strings.TrimRight(string(C.GoBytes(unsafe.Pointer(&pucKey.C[0]), C.int(pucKey.L))), " "),
	}
	return key
}

func ConvertToECCSignatureC(signature ECCSignature) (pSignature C.ECCSignature) {
	for i := 0; i < len(signature.R); i++ {
		pSignature.r[i] = C.SGD_UCHAR(signature.R[i])
	}
	for i := 0; i < len(signature.S); i++ {
		pSignature.s[i] = C.SGD_UCHAR(signature.S[i])
	}
	return pSignature
}

func ConvertToECCSignatureGo(pucSignature C.ECCSignature) (signature ECCSignature) {
	signature = ECCSignature{
		R: strings.TrimRight(string(C.GoBytes(unsafe.Pointer(&pucSignature.r[0]), 64)), " "),
		S: strings.TrimRight(string(C.GoBytes(unsafe.Pointer(&pucSignature.s[0]), 64)), " "),
	}
	return signature
}

func ToError(e C.SGD_RV) error {
	if e == C.SDR_OK {
		return nil
	}
	err_code := int(e)
	str := fmt.Sprintf("sdf: 0x%X:%s",err_code, StrErrors[err_code])
	return fmt.Errorf(str)
}

func deepCopy(src []byte) (dst []byte) {
	dst = make([]byte, len(src))
	for i, v := range src {
		dst[i] = v
	}
	return
}