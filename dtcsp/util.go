package dtcsp

/*
#include "dtcspapi.h"
 */
import "C"
import (
	"strings"
	"unsafe"
)

func ConvertUcharPtrToString(ptr C.DTCSP_UCHAR_PTR) string {
	return strings.TrimRight(string(C.GoBytes(unsafe.Pointer(ptr),40))," ")
}

func ToError()  {

}