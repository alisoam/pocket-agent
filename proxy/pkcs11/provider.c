/* PKCS#11 Provider for PocketSSHAgent
 * Exposes Android Keystore keys over BLE as a PKCS#11 token
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>

/* PKCS#11 type definitions */
typedef unsigned char CK_BYTE;
typedef unsigned char CK_UTF8CHAR;
typedef unsigned long CK_ULONG;
typedef unsigned long CK_RV;
typedef unsigned long CK_SESSION_HANDLE;
typedef unsigned long CK_OBJECT_HANDLE;
typedef unsigned long CK_SLOT_ID;
typedef unsigned long CK_FLAGS;
typedef unsigned long CK_STATE;
typedef unsigned long CK_USER_TYPE;
typedef void *CK_VOID_PTR;
typedef unsigned char CK_BBOOL;
typedef unsigned char *CK_BYTE_PTR;
typedef CK_BYTE *CK_UTF8CHAR_PTR;
typedef CK_ULONG *CK_ULONG_PTR;
typedef CK_SESSION_HANDLE *CK_SESSION_HANDLE_PTR;
typedef CK_OBJECT_HANDLE *CK_OBJECT_HANDLE_PTR;
typedef CK_SLOT_ID *CK_SLOT_ID_PTR;

/* PKCS#11 structures */
typedef struct CK_VERSION {
    CK_BYTE major;
    CK_BYTE minor;
} CK_VERSION;

typedef struct CK_INFO {
    CK_VERSION cryptokiVersion;
    CK_UTF8CHAR manufacturerID[32];
    CK_FLAGS flags;
    CK_UTF8CHAR libraryDescription[32];
    CK_VERSION libraryVersion;
} CK_INFO;

typedef CK_INFO *CK_INFO_PTR;

typedef struct CK_SLOT_INFO {
    CK_UTF8CHAR slotDescription[64];
    CK_UTF8CHAR manufacturerID[32];
    CK_FLAGS flags;
    CK_VERSION hardwareVersion;
    CK_VERSION firmwareVersion;
} CK_SLOT_INFO;

typedef CK_SLOT_INFO *CK_SLOT_INFO_PTR;

typedef struct CK_TOKEN_INFO {
    CK_UTF8CHAR label[32];
    CK_UTF8CHAR manufacturerID[32];
    CK_UTF8CHAR model[16];
    CK_UTF8CHAR serialNumber[16];
    CK_FLAGS flags;
    CK_ULONG ulMaxSessionCount;
    CK_ULONG ulSessionCount;
    CK_ULONG ulMaxRwSessionCount;
    CK_ULONG ulRwSessionCount;
    CK_ULONG ulMaxPinLen;
    CK_ULONG ulMinPinLen;
    CK_ULONG ulTotalPublicMemory;
    CK_ULONG ulFreePublicMemory;
    CK_ULONG ulTotalPrivateMemory;
    CK_ULONG ulFreePrivateMemory;
    CK_VERSION hardwareVersion;
    CK_VERSION firmwareVersion;
    CK_UTF8CHAR utcTime[16];
} CK_TOKEN_INFO;

typedef CK_TOKEN_INFO *CK_TOKEN_INFO_PTR;

typedef struct CK_SESSION_INFO {
    CK_SLOT_ID slotID;
    CK_STATE state;
    CK_FLAGS flags;
    CK_ULONG ulDeviceError;
} CK_SESSION_INFO;

typedef CK_SESSION_INFO *CK_SESSION_INFO_PTR;

typedef struct CK_ATTRIBUTE {
    CK_ULONG type;
    CK_VOID_PTR pValue;
    CK_ULONG ulValueLen;
} CK_ATTRIBUTE;

typedef CK_ATTRIBUTE *CK_ATTRIBUTE_PTR;

typedef struct CK_MECHANISM {
    CK_ULONG mechanism;
    CK_VOID_PTR pParameter;
    CK_ULONG ulParameterLen;
} CK_MECHANISM;

typedef CK_MECHANISM *CK_MECHANISM_PTR;

typedef CK_RV (*CK_NOTIFY)(CK_SESSION_HANDLE hSession, CK_ULONG event, CK_VOID_PTR pApplication);

/* PKCS#11 Function List Structure */
typedef struct CK_FUNCTION_LIST {
    CK_VERSION version;
    CK_RV (*C_Initialize)(CK_VOID_PTR pInitArgs);
    CK_RV (*C_Finalize)(CK_VOID_PTR pReserved);
    CK_RV (*C_GetInfo)(CK_INFO_PTR pInfo);
    CK_RV (*C_GetFunctionList)(struct CK_FUNCTION_LIST **ppFunctionList);
    CK_RV (*C_GetSlotList)(CK_BBOOL tokenPresent, CK_SLOT_ID_PTR pSlotList, CK_ULONG_PTR pulCount);
    CK_RV (*C_GetSlotInfo)(CK_SLOT_ID slotID, CK_SLOT_INFO_PTR pInfo);
    CK_RV (*C_GetTokenInfo)(CK_SLOT_ID slotID, CK_TOKEN_INFO_PTR pInfo);
    CK_RV (*C_GetMechanismList)(CK_SLOT_ID slotID, CK_VOID_PTR pMechanismList, CK_ULONG_PTR pulCount);
    CK_RV (*C_GetMechanismInfo)(CK_SLOT_ID slotID, CK_ULONG type, CK_VOID_PTR pInfo);
    CK_RV (*C_InitToken)(CK_SLOT_ID slotID, CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen, CK_UTF8CHAR_PTR pLabel);
    CK_RV (*C_InitPIN)(CK_SESSION_HANDLE hSession, CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen);
    CK_RV (*C_SetPIN)(CK_SESSION_HANDLE hSession, CK_UTF8CHAR_PTR pOldPin, CK_ULONG ulOldLen, CK_UTF8CHAR_PTR pNewPin, CK_ULONG ulNewLen);
    CK_RV (*C_OpenSession)(CK_SLOT_ID slotID, CK_FLAGS flags, CK_VOID_PTR pApplication, CK_NOTIFY Notify, CK_SESSION_HANDLE_PTR phSession);
    CK_RV (*C_CloseSession)(CK_SESSION_HANDLE hSession);
    CK_RV (*C_CloseAllSessions)(CK_SLOT_ID slotID);
    CK_RV (*C_GetSessionInfo)(CK_SESSION_HANDLE hSession, CK_SESSION_INFO_PTR pInfo);
    CK_RV (*C_GetOperationState)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pOperationState, CK_ULONG_PTR pulOperationStateLen);
    CK_RV (*C_SetOperationState)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pOperationState, CK_ULONG ulOperationStateLen, CK_OBJECT_HANDLE hEncryptionKey, CK_OBJECT_HANDLE hAuthenticationKey);
    CK_RV (*C_Login)(CK_SESSION_HANDLE hSession, CK_USER_TYPE userType, CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen);
    CK_RV (*C_Logout)(CK_SESSION_HANDLE hSession);
    CK_RV (*C_CreateObject)(CK_SESSION_HANDLE hSession, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount, CK_OBJECT_HANDLE_PTR phObject);
    CK_RV (*C_CopyObject)(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount, CK_OBJECT_HANDLE_PTR phNewObject);
    CK_RV (*C_DestroyObject)(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject);
    CK_RV (*C_GetObjectSize)(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ULONG_PTR pulSize);
    CK_RV (*C_GetAttributeValue)(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount);
    CK_RV (*C_SetAttributeValue)(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount);
    CK_RV (*C_FindObjectsInit)(CK_SESSION_HANDLE hSession, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount);
    CK_RV (*C_FindObjects)(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE_PTR phObject, CK_ULONG ulMaxObjectCount, CK_ULONG_PTR pulObjectCount);
    CK_RV (*C_FindObjectsFinal)(CK_SESSION_HANDLE hSession);
    CK_RV (*C_EncryptInit)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey);
    CK_RV (*C_Encrypt)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pEncryptedData, CK_ULONG_PTR pulEncryptedDataLen);
    CK_RV (*C_EncryptUpdate)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen, CK_BYTE_PTR pEncryptedPart, CK_ULONG_PTR pulEncryptedPartLen);
    CK_RV (*C_EncryptFinal)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pLastEncryptedPart, CK_ULONG_PTR pulLastEncryptedPartLen);
    CK_RV (*C_DecryptInit)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey);
    CK_RV (*C_Decrypt)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedData, CK_ULONG ulEncryptedDataLen, CK_BYTE_PTR pData, CK_ULONG_PTR pulDataLen);
    CK_RV (*C_DecryptUpdate)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedPart, CK_ULONG ulEncryptedPartLen, CK_BYTE_PTR pPart, CK_ULONG_PTR pulPartLen);
    CK_RV (*C_DecryptFinal)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pLastPart, CK_ULONG_PTR pulLastPartLen);
    CK_RV (*C_DigestInit)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism);
    CK_RV (*C_Digest)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pDigest, CK_ULONG_PTR pulDigestLen);
    CK_RV (*C_DigestUpdate)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen);
    CK_RV (*C_DigestKey)(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hKey);
    CK_RV (*C_DigestFinal)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pDigest, CK_ULONG_PTR pulDigestLen);
    CK_RV (*C_SignInit)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey);
    CK_RV (*C_Sign)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen);
    CK_RV (*C_SignUpdate)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen);
    CK_RV (*C_SignFinal)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen);
    CK_RV (*C_SignRecoverInit)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey);
    CK_RV (*C_SignRecover)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen);
    CK_RV (*C_VerifyInit)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey);
    CK_RV (*C_Verify)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pSignature, CK_ULONG ulSignatureLen);
    CK_RV (*C_VerifyUpdate)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen);
    CK_RV (*C_VerifyFinal)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSignature, CK_ULONG ulSignatureLen);
    CK_RV (*C_VerifyRecoverInit)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey);
    CK_RV (*C_VerifyRecover)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSignature, CK_ULONG ulSignatureLen, CK_BYTE_PTR pData, CK_ULONG_PTR pulDataLen);
    CK_RV (*C_DigestEncryptUpdate)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen, CK_BYTE_PTR pEncryptedPart, CK_ULONG_PTR pulEncryptedPartLen);
    CK_RV (*C_DecryptDigestUpdate)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedPart, CK_ULONG ulEncryptedPartLen, CK_BYTE_PTR pPart, CK_ULONG_PTR pulPartLen);
    CK_RV (*C_SignEncryptUpdate)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen, CK_BYTE_PTR pEncryptedPart, CK_ULONG_PTR pulEncryptedPartLen);
    CK_RV (*C_DecryptVerifyUpdate)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedPart, CK_ULONG ulEncryptedPartLen, CK_BYTE_PTR pPart, CK_ULONG_PTR pulPartLen);
    CK_RV (*C_GenerateKey)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount, CK_OBJECT_HANDLE_PTR phKey);
    CK_RV (*C_GenerateKeyPair)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_ATTRIBUTE_PTR pPublicKeyTemplate, CK_ULONG ulPublicKeyAttributeCount, CK_ATTRIBUTE_PTR pPrivateKeyTemplate, CK_ULONG ulPrivateKeyAttributeCount, CK_OBJECT_HANDLE_PTR phPublicKey, CK_OBJECT_HANDLE_PTR phPrivateKey);
    CK_RV (*C_WrapKey)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hWrappingKey, CK_OBJECT_HANDLE hKey, CK_BYTE_PTR pWrappedKey, CK_ULONG_PTR pulWrappedKeyLen);
    CK_RV (*C_UnwrapKey)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hUnwrappingKey, CK_BYTE_PTR pWrappedKey, CK_ULONG ulWrappedKeyLen, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulAttributeCount, CK_OBJECT_HANDLE_PTR phKey);
    CK_RV (*C_DeriveKey)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hBaseKey, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulAttributeCount, CK_OBJECT_HANDLE_PTR phKey);
    CK_RV (*C_SeedRandom)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSeed, CK_ULONG ulSeedLen);
    CK_RV (*C_GenerateRandom)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR RandomData, CK_ULONG ulRandomLen);
    CK_RV (*C_GetFunctionStatus)(CK_SESSION_HANDLE hSession);
    CK_RV (*C_CancelFunction)(CK_SESSION_HANDLE hSession);
    CK_RV (*C_WaitForSlotEvent)(CK_FLAGS flags, CK_SLOT_ID_PTR pSlot, CK_VOID_PTR pReserved);
} CK_FUNCTION_LIST;

typedef CK_FUNCTION_LIST *CK_FUNCTION_LIST_PTR;
typedef CK_FUNCTION_LIST_PTR *CK_FUNCTION_LIST_PTR_PTR;

/* Forward declarations of all C functions (required for function_list initialization) */
CK_RV C_Initialize(CK_VOID_PTR pInitArgs);
CK_RV C_Finalize(CK_VOID_PTR pReserved);
CK_RV C_GetInfo(CK_INFO_PTR pInfo);
CK_RV C_GetFunctionList(CK_FUNCTION_LIST_PTR_PTR ppFunctionList);
CK_RV C_GetSlotList(CK_BBOOL tokenPresent, CK_SLOT_ID_PTR pSlotList, CK_ULONG_PTR pulCount);
CK_RV C_GetSlotInfo(CK_SLOT_ID slotID, CK_SLOT_INFO_PTR pInfo);
CK_RV C_GetTokenInfo(CK_SLOT_ID slotID, CK_TOKEN_INFO_PTR pInfo);
CK_RV C_GetMechanismList(CK_SLOT_ID slotID, CK_VOID_PTR pMechanismList, CK_ULONG_PTR pulCount);
CK_RV C_GetMechanismInfo(CK_SLOT_ID slotID, CK_ULONG type, CK_VOID_PTR pInfo);
CK_RV C_InitToken(CK_SLOT_ID slotID, CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen, CK_UTF8CHAR_PTR pLabel);
CK_RV C_InitPIN(CK_SESSION_HANDLE hSession, CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen);
CK_RV C_SetPIN(CK_SESSION_HANDLE hSession, CK_UTF8CHAR_PTR pOldPin, CK_ULONG ulOldLen, CK_UTF8CHAR_PTR pNewPin, CK_ULONG ulNewLen);
CK_RV C_OpenSession(CK_SLOT_ID slotID, CK_FLAGS flags, CK_VOID_PTR pApplication, CK_NOTIFY Notify, CK_SESSION_HANDLE_PTR phSession);
CK_RV C_CloseSession(CK_SESSION_HANDLE hSession);
CK_RV C_CloseAllSessions(CK_SLOT_ID slotID);
CK_RV C_GetSessionInfo(CK_SESSION_HANDLE hSession, CK_SESSION_INFO_PTR pInfo);
CK_RV C_GetOperationState(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pOperationState, CK_ULONG_PTR pulOperationStateLen);
CK_RV C_SetOperationState(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pOperationState, CK_ULONG ulOperationStateLen, CK_OBJECT_HANDLE hEncryptionKey, CK_OBJECT_HANDLE hAuthenticationKey);
CK_RV C_Login(CK_SESSION_HANDLE hSession, CK_USER_TYPE userType, CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen);
CK_RV C_Logout(CK_SESSION_HANDLE hSession);
CK_RV C_CreateObject(CK_SESSION_HANDLE hSession, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount, CK_OBJECT_HANDLE_PTR phObject);
CK_RV C_CopyObject(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount, CK_OBJECT_HANDLE_PTR phNewObject);
CK_RV C_DestroyObject(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject);
CK_RV C_GetObjectSize(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ULONG_PTR pulSize);
CK_RV C_GetAttributeValue(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount);
CK_RV C_SetAttributeValue(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount);
CK_RV C_FindObjectsInit(CK_SESSION_HANDLE hSession, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount);
CK_RV C_FindObjects(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE_PTR phObject, CK_ULONG ulMaxObjectCount, CK_ULONG_PTR pulObjectCount);
CK_RV C_FindObjectsFinal(CK_SESSION_HANDLE hSession);
CK_RV C_EncryptInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey);
CK_RV C_Encrypt(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pEncryptedData, CK_ULONG_PTR pulEncryptedDataLen);
CK_RV C_EncryptUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen, CK_BYTE_PTR pEncryptedPart, CK_ULONG_PTR pulEncryptedPartLen);
CK_RV C_EncryptFinal(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pLastEncryptedPart, CK_ULONG_PTR pulLastEncryptedPartLen);
CK_RV C_DecryptInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey);
CK_RV C_Decrypt(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedData, CK_ULONG ulEncryptedDataLen, CK_BYTE_PTR pData, CK_ULONG_PTR pulDataLen);
CK_RV C_DecryptUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedPart, CK_ULONG ulEncryptedPartLen, CK_BYTE_PTR pPart, CK_ULONG_PTR pulPartLen);
CK_RV C_DecryptFinal(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pLastPart, CK_ULONG_PTR pulLastPartLen);
CK_RV C_DigestInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism);
CK_RV C_Digest(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pDigest, CK_ULONG_PTR pulDigestLen);
CK_RV C_DigestUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen);
CK_RV C_DigestKey(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hKey);
CK_RV C_DigestFinal(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pDigest, CK_ULONG_PTR pulDigestLen);
CK_RV C_SignInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey);
CK_RV C_Sign(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen);
CK_RV C_SignUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen);
CK_RV C_SignFinal(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen);
CK_RV C_SignRecoverInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey);
CK_RV C_SignRecover(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen);
CK_RV C_VerifyInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey);
CK_RV C_Verify(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pSignature, CK_ULONG ulSignatureLen);
CK_RV C_VerifyUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen);
CK_RV C_VerifyFinal(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSignature, CK_ULONG ulSignatureLen);
CK_RV C_VerifyRecoverInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey);
CK_RV C_VerifyRecover(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSignature, CK_ULONG ulSignatureLen, CK_BYTE_PTR pData, CK_ULONG_PTR pulDataLen);
CK_RV C_DigestEncryptUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen, CK_BYTE_PTR pEncryptedPart, CK_ULONG_PTR pulEncryptedPartLen);
CK_RV C_DecryptDigestUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedPart, CK_ULONG ulEncryptedPartLen, CK_BYTE_PTR pPart, CK_ULONG_PTR pulPartLen);
CK_RV C_SignEncryptUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen, CK_BYTE_PTR pEncryptedPart, CK_ULONG_PTR pulEncryptedPartLen);
CK_RV C_DecryptVerifyUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedPart, CK_ULONG ulEncryptedPartLen, CK_BYTE_PTR pPart, CK_ULONG_PTR pulPartLen);
CK_RV C_GenerateKey(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount, CK_OBJECT_HANDLE_PTR phKey);
CK_RV C_GenerateKeyPair(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_ATTRIBUTE_PTR pPublicKeyTemplate, CK_ULONG ulPublicKeyAttributeCount, CK_ATTRIBUTE_PTR pPrivateKeyTemplate, CK_ULONG ulPrivateKeyAttributeCount, CK_OBJECT_HANDLE_PTR phPublicKey, CK_OBJECT_HANDLE_PTR phPrivateKey);
CK_RV C_WrapKey(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hWrappingKey, CK_OBJECT_HANDLE hKey, CK_BYTE_PTR pWrappedKey, CK_ULONG_PTR pulWrappedKeyLen);
CK_RV C_UnwrapKey(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hUnwrappingKey, CK_BYTE_PTR pWrappedKey, CK_ULONG ulWrappedKeyLen, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulAttributeCount, CK_OBJECT_HANDLE_PTR phKey);
CK_RV C_DeriveKey(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hBaseKey, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulAttributeCount, CK_OBJECT_HANDLE_PTR phKey);
CK_RV C_SeedRandom(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSeed, CK_ULONG ulSeedLen);
CK_RV C_GenerateRandom(CK_SESSION_HANDLE hSession, CK_BYTE_PTR RandomData, CK_ULONG ulRandomLen);
CK_RV C_GetFunctionStatus(CK_SESSION_HANDLE hSession);
CK_RV C_CancelFunction(CK_SESSION_HANDLE hSession);
CK_RV C_WaitForSlotEvent(CK_FLAGS flags, CK_SLOT_ID_PTR pSlot, CK_VOID_PTR pReserved);

/* Global function list populated below */
static CK_FUNCTION_LIST function_list;

/* Forward declarations for Go functions */
extern CK_RV GoInitialize();
extern CK_RV GoFinalize();
extern CK_RV GoOpenSession(CK_SLOT_ID slotID, CK_FLAGS flags, CK_SESSION_HANDLE_PTR phSession);
extern CK_RV GoCloseSession(CK_SESSION_HANDLE hSession);
extern CK_RV GoLogin(CK_SESSION_HANDLE hSession, CK_USER_TYPE userType);
extern CK_RV GoLogout(CK_SESSION_HANDLE hSession);
extern CK_RV GoFindObjectsInit(CK_SESSION_HANDLE hSession, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount);
extern CK_RV GoFindObjects(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE_PTR phObject, CK_ULONG ulMaxObjectCount, CK_ULONG_PTR pulObjectCount);
extern CK_RV GoFindObjectsFinal(CK_SESSION_HANDLE hSession);
extern CK_RV GoGetAttributeValue(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount);
extern CK_RV GoSignInit(CK_SESSION_HANDLE hSession, CK_ULONG mechanism, CK_OBJECT_HANDLE hKey);
extern CK_RV GoSign(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hKey, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen);

/* PKCS#11 return codes */
#define CKR_OK                            0x00000000
#define CKR_ARGUMENTS_BAD                 0x00000007
#define CKR_FUNCTION_NOT_SUPPORTED        0x00000054
#define CKR_SESSION_HANDLE_INVALID        0x000000B3
#define CKR_OPERATION_NOT_INITIALIZED     0x00000091

/* Token flags */
#define CKF_TOKEN_PRESENT                 0x00000001
#define CKF_HW_SLOT                       0x00000004
#define CKF_LOGIN_REQUIRED                0x00000004
#define CKF_USER_PIN_INITIALIZED          0x00000008
#define CKF_PROTECTED_AUTHENTICATION_PATH 0x00000100
#define CKF_TOKEN_INITIALIZED             0x00000400

/* Session flags */
#define CKF_SERIAL_SESSION                0x00000004
#define CKF_RW_SESSION                    0x00000002

/* Session state */
#define CKS_RO_PUBLIC_SESSION             0
#define CKS_RO_USER_FUNCTIONS             1
#define CKS_RW_PUBLIC_SESSION             2
#define CKS_RW_USER_FUNCTIONS             3

/* User types */
#define CKU_USER                          1

/* (no per-process sign-key global; key handle is stored per-session in the Go backend) */

/* Helper to pad string with spaces */
static void pad_string(CK_UTF8CHAR *dest, const char *src, size_t len) {
    size_t i;
    size_t src_len = strlen(src);
    
    for (i = 0; i < len; i++) {
        if (i < src_len) {
            dest[i] = src[i];
        } else {
            dest[i] = ' ';
        }
    }
}

/* C_Initialize */
CK_RV C_Initialize(CK_VOID_PTR pInitArgs) {
    (void)pInitArgs;
    /* Prevent dlclose from unmapping us — Go runtime goroutines crash if the
       text segment disappears while they're still running. */
    Dl_info info;
    if (dladdr((void*)C_Initialize, &info) && info.dli_fname) {
        dlopen(info.dli_fname, RTLD_NOW | RTLD_NODELETE);
    }
    return GoInitialize();
}

/* C_Finalize */
CK_RV C_Finalize(CK_VOID_PTR pReserved) {
    (void)pReserved; /* Unused */
    return GoFinalize();
}

/* C_GetInfo */
CK_RV C_GetInfo(CK_INFO_PTR pInfo) {
    if (pInfo == NULL) {
        return CKR_ARGUMENTS_BAD;
    }
    
    memset(pInfo, 0, sizeof(CK_INFO));
    
    pInfo->cryptokiVersion.major = 2;
    pInfo->cryptokiVersion.minor = 40;
    
    pad_string(pInfo->manufacturerID, "PocketSSHAgent", 32);
    pad_string(pInfo->libraryDescription, "Android Keystore PKCS11 Provider", 32);
    
    pInfo->libraryVersion.major = 1;
    pInfo->libraryVersion.minor = 0;
    
    return CKR_OK;
}

/* C_GetFunctionList - Primary PKCS#11 entry point */
CK_RV C_GetFunctionList(CK_FUNCTION_LIST_PTR_PTR ppFunctionList) {
    if (ppFunctionList == NULL) {
        return CKR_ARGUMENTS_BAD;
    }
    
    /* Initialize function list once */
    static int initialized = 0;
    if (!initialized) {
        function_list.version.major = 2;
        function_list.version.minor = 40;
        function_list.C_Initialize = C_Initialize;
        function_list.C_Finalize = C_Finalize;
        function_list.C_GetInfo = C_GetInfo;
        function_list.C_GetFunctionList = C_GetFunctionList;
        function_list.C_GetSlotList = C_GetSlotList;
        function_list.C_GetSlotInfo = C_GetSlotInfo;
        function_list.C_GetTokenInfo = C_GetTokenInfo;
        function_list.C_GetMechanismList = C_GetMechanismList;
        function_list.C_GetMechanismInfo = C_GetMechanismInfo;
        function_list.C_InitToken = C_InitToken;
        function_list.C_InitPIN = C_InitPIN;
        function_list.C_SetPIN = C_SetPIN;
        function_list.C_OpenSession = C_OpenSession;
        function_list.C_CloseSession = C_CloseSession;
        function_list.C_CloseAllSessions = C_CloseAllSessions;
        function_list.C_GetSessionInfo = C_GetSessionInfo;
        function_list.C_GetOperationState = C_GetOperationState;
        function_list.C_SetOperationState = C_SetOperationState;
        function_list.C_Login = C_Login;
        function_list.C_Logout = C_Logout;
        function_list.C_CreateObject = C_CreateObject;
        function_list.C_CopyObject = C_CopyObject;
        function_list.C_DestroyObject = C_DestroyObject;
        function_list.C_GetObjectSize = C_GetObjectSize;
        function_list.C_GetAttributeValue = C_GetAttributeValue;
        function_list.C_SetAttributeValue = C_SetAttributeValue;
        function_list.C_FindObjectsInit = C_FindObjectsInit;
        function_list.C_FindObjects = C_FindObjects;
        function_list.C_FindObjectsFinal = C_FindObjectsFinal;
        function_list.C_EncryptInit = C_EncryptInit;
        function_list.C_Encrypt = C_Encrypt;
        function_list.C_EncryptUpdate = C_EncryptUpdate;
        function_list.C_EncryptFinal = C_EncryptFinal;
        function_list.C_DecryptInit = C_DecryptInit;
        function_list.C_Decrypt = C_Decrypt;
        function_list.C_DecryptUpdate = C_DecryptUpdate;
        function_list.C_DecryptFinal = C_DecryptFinal;
        function_list.C_DigestInit = C_DigestInit;
        function_list.C_Digest = C_Digest;
        function_list.C_DigestUpdate = C_DigestUpdate;
        function_list.C_DigestKey = C_DigestKey;
        function_list.C_DigestFinal = C_DigestFinal;
        function_list.C_SignInit = C_SignInit;
        function_list.C_Sign = C_Sign;
        function_list.C_SignUpdate = C_SignUpdate;
        function_list.C_SignFinal = C_SignFinal;
        function_list.C_SignRecoverInit = C_SignRecoverInit;
        function_list.C_SignRecover = C_SignRecover;
        function_list.C_VerifyInit = C_VerifyInit;
        function_list.C_Verify = C_Verify;
        function_list.C_VerifyUpdate = C_VerifyUpdate;
        function_list.C_VerifyFinal = C_VerifyFinal;
        function_list.C_VerifyRecoverInit = C_VerifyRecoverInit;
        function_list.C_VerifyRecover = C_VerifyRecover;
        function_list.C_DigestEncryptUpdate = C_DigestEncryptUpdate;
        function_list.C_DecryptDigestUpdate = C_DecryptDigestUpdate;
        function_list.C_SignEncryptUpdate = C_SignEncryptUpdate;
        function_list.C_DecryptVerifyUpdate = C_DecryptVerifyUpdate;
        function_list.C_GenerateKey = C_GenerateKey;
        function_list.C_GenerateKeyPair = C_GenerateKeyPair;
        function_list.C_WrapKey = C_WrapKey;
        function_list.C_UnwrapKey = C_UnwrapKey;
        function_list.C_DeriveKey = C_DeriveKey;
        function_list.C_SeedRandom = C_SeedRandom;
        function_list.C_GenerateRandom = C_GenerateRandom;
        function_list.C_GetFunctionStatus = C_GetFunctionStatus;
        function_list.C_CancelFunction = C_CancelFunction;
        function_list.C_WaitForSlotEvent = C_WaitForSlotEvent;
        initialized = 1;
    }
    
    *ppFunctionList = &function_list;
    return CKR_OK;
}

/* C_GetSlotList */
CK_RV C_GetSlotList(CK_BBOOL tokenPresent, CK_SLOT_ID_PTR pSlotList, CK_ULONG_PTR pulCount) {
    (void)tokenPresent; /* Always have token present */
    
    if (pulCount == NULL) {
        return CKR_ARGUMENTS_BAD;
    }
    
    if (pSlotList == NULL) {
        /* Query slot count */
        *pulCount = 1;
        return CKR_OK;
    }
    
    if (*pulCount < 1) {
        *pulCount = 1;
        return CKR_ARGUMENTS_BAD;
    }
    
    pSlotList[0] = 0;
    *pulCount = 1;
    
    return CKR_OK;
}

/* C_GetSlotInfo */
CK_RV C_GetSlotInfo(CK_SLOT_ID slotID, CK_SLOT_INFO_PTR pInfo) {
    if (slotID != 0) {
        return CKR_ARGUMENTS_BAD;
    }
    
    if (pInfo == NULL) {
        return CKR_ARGUMENTS_BAD;
    }
    
    memset(pInfo, 0, sizeof(CK_SLOT_INFO));
    
    pad_string(pInfo->slotDescription, "PocketSSHAgent Slot", 64);
    pad_string(pInfo->manufacturerID, "PocketSSHAgent", 32);
    
    pInfo->flags = CKF_TOKEN_PRESENT | CKF_HW_SLOT;
    pInfo->hardwareVersion.major = 1;
    pInfo->hardwareVersion.minor = 0;
    pInfo->firmwareVersion.major = 1;
    pInfo->firmwareVersion.minor = 0;
    
    return CKR_OK;
}

/* C_GetTokenInfo */
CK_RV C_GetTokenInfo(CK_SLOT_ID slotID, CK_TOKEN_INFO_PTR pInfo) {
    if (slotID != 0) {
        return CKR_ARGUMENTS_BAD;
    }
    
    if (pInfo == NULL) {
        return CKR_ARGUMENTS_BAD;
    }
    
    memset(pInfo, 0, sizeof(CK_TOKEN_INFO));
    
    pad_string(pInfo->label, "PocketSSHAgent Token", 32);
    pad_string(pInfo->manufacturerID, "PocketSSHAgent", 32);
    pad_string(pInfo->model, "v1.0", 16);
    pad_string(pInfo->serialNumber, "0000000001", 16);
    
    pInfo->flags = CKF_TOKEN_INITIALIZED | CKF_USER_PIN_INITIALIZED |
                   CKF_PROTECTED_AUTHENTICATION_PATH;
    
    pInfo->ulMaxSessionCount = 0; /* Unlimited */
    pInfo->ulMaxRwSessionCount = 0; /* Unlimited */
    pInfo->ulMaxPinLen = 0; /* No PIN (biometric) */
    pInfo->ulMinPinLen = 0;
    
    pInfo->hardwareVersion.major = 1;
    pInfo->hardwareVersion.minor = 0;
    pInfo->firmwareVersion.major = 1;
    pInfo->firmwareVersion.minor = 0;
    
    return CKR_OK;
}

/* C_OpenSession */
CK_RV C_OpenSession(CK_SLOT_ID slotID, CK_FLAGS flags, CK_VOID_PTR pApplication, CK_NOTIFY Notify, CK_SESSION_HANDLE_PTR phSession) {
    (void)pApplication; /* Unused */
    (void)Notify; /* Unused */
    
    if (phSession == NULL) {
        return CKR_ARGUMENTS_BAD;
    }
    
    return GoOpenSession(slotID, flags, phSession);
}

/* C_CloseSession */
CK_RV C_CloseSession(CK_SESSION_HANDLE hSession) {
    return GoCloseSession(hSession);
}

/* C_CloseAllSessions */
CK_RV C_CloseAllSessions(CK_SLOT_ID slotID) {
    (void)slotID;
    /* Not implemented - single session model */
    return CKR_OK;
}

/* C_GetSessionInfo */
CK_RV C_GetSessionInfo(CK_SESSION_HANDLE hSession, CK_SESSION_INFO_PTR pInfo) {
    (void)hSession;
    
    if (pInfo == NULL) {
        return CKR_ARGUMENTS_BAD;
    }
    
    pInfo->slotID = 0;
    pInfo->state = CKS_RO_PUBLIC_SESSION;
    pInfo->flags = CKF_SERIAL_SESSION;
    pInfo->ulDeviceError = 0;
    
    return CKR_OK;
}

/* C_Login */
CK_RV C_Login(CK_SESSION_HANDLE hSession, CK_USER_TYPE userType, CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen) {
    (void)pPin; /* Unused - biometric auth */
    (void)ulPinLen;
    
    return GoLogin(hSession, userType);
}

/* C_Logout */
CK_RV C_Logout(CK_SESSION_HANDLE hSession) {
    return GoLogout(hSession);
}

/* C_FindObjectsInit */
CK_RV C_FindObjectsInit(CK_SESSION_HANDLE hSession, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount) {
    return GoFindObjectsInit(hSession, pTemplate, ulCount);
}

/* C_FindObjects */
CK_RV C_FindObjects(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE_PTR phObject, CK_ULONG ulMaxObjectCount, CK_ULONG_PTR pulObjectCount) {
    return GoFindObjects(hSession, phObject, ulMaxObjectCount, pulObjectCount);
}

/* C_FindObjectsFinal */
CK_RV C_FindObjectsFinal(CK_SESSION_HANDLE hSession) {
    return GoFindObjectsFinal(hSession);
}

/* C_GetAttributeValue */
CK_RV C_GetAttributeValue(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount) {
    return GoGetAttributeValue(hSession, hObject, pTemplate, ulCount);
}

/* C_SignInit */
CK_RV C_SignInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey) {
    if (pMechanism == NULL) {
        return CKR_ARGUMENTS_BAD;
    }
    return GoSignInit(hSession, pMechanism->mechanism, hKey);
}

/* C_Sign */
CK_RV C_Sign(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen) {
    if (pData == NULL || pulSignatureLen == NULL) {
        return CKR_ARGUMENTS_BAD;
    }
    /* Pass hKey=0; GoSign resolves the key from the session's SignKeyHandle. */
    return GoSign(hSession, 0, pData, ulDataLen, pSignature, pulSignatureLen);
}

/* Unsupported functions - return not supported */
CK_RV C_GetMechanismList(CK_SLOT_ID slotID, CK_VOID_PTR pMechanismList, CK_ULONG_PTR pulCount) {
    (void)slotID; (void)pMechanismList; (void)pulCount;
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_GetMechanismInfo(CK_SLOT_ID slotID, CK_ULONG type, CK_VOID_PTR pInfo) {
    (void)slotID; (void)type; (void)pInfo;
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_InitToken(CK_SLOT_ID slotID, CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen, CK_UTF8CHAR_PTR pLabel) {
    (void)slotID; (void)pPin; (void)ulPinLen; (void)pLabel;
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_InitPIN(CK_SESSION_HANDLE hSession, CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen) {
    (void)hSession; (void)pPin; (void)ulPinLen;
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_SetPIN(CK_SESSION_HANDLE hSession, CK_UTF8CHAR_PTR pOldPin, CK_ULONG ulOldLen, CK_UTF8CHAR_PTR pNewPin, CK_ULONG ulNewLen) {
    (void)hSession; (void)pOldPin; (void)ulOldLen; (void)pNewPin; (void)ulNewLen;
    return CKR_FUNCTION_NOT_SUPPORTED;
}

/* Stub implementations for other required functions */
CK_RV C_GetOperationState(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pOperationState, CK_ULONG_PTR pulOperationStateLen) {
    (void)hSession; (void)pOperationState; (void)pulOperationStateLen;
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_SetOperationState(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pOperationState, CK_ULONG ulOperationStateLen, CK_OBJECT_HANDLE hEncryptionKey, CK_OBJECT_HANDLE hAuthenticationKey) {
    (void)hSession; (void)pOperationState; (void)ulOperationStateLen; (void)hEncryptionKey; (void)hAuthenticationKey;
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_CreateObject(CK_SESSION_HANDLE hSession, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount, CK_OBJECT_HANDLE_PTR phObject) {
    (void)hSession; (void)pTemplate; (void)ulCount; (void)phObject;
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_CopyObject(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount, CK_OBJECT_HANDLE_PTR phNewObject) {
    (void)hSession; (void)hObject; (void)pTemplate; (void)ulCount; (void)phNewObject;
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_DestroyObject(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject) {
    (void)hSession; (void)hObject;
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_GetObjectSize(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ULONG_PTR pulSize) {
    (void)hSession; (void)hObject; (void)pulSize;
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_SetAttributeValue(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount) {
    (void)hSession; (void)hObject; (void)pTemplate; (void)ulCount;
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_EncryptInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey) {
    (void)hSession; (void)pMechanism; (void)hKey;
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_Encrypt(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pEncryptedData, CK_ULONG_PTR pulEncryptedDataLen) {
    (void)hSession; (void)pData; (void)ulDataLen; (void)pEncryptedData; (void)pulEncryptedDataLen;
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_EncryptUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen, CK_BYTE_PTR pEncryptedPart, CK_ULONG_PTR pulEncryptedPartLen) {
    (void)hSession; (void)pPart; (void)ulPartLen; (void)pEncryptedPart; (void)pulEncryptedPartLen;
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_EncryptFinal(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pLastEncryptedPart, CK_ULONG_PTR pulLastEncryptedPartLen) {
    (void)hSession; (void)pLastEncryptedPart; (void)pulLastEncryptedPartLen;
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_DecryptInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey) {
    (void)hSession; (void)pMechanism; (void)hKey;
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_Decrypt(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedData, CK_ULONG ulEncryptedDataLen, CK_BYTE_PTR pData, CK_ULONG_PTR pulDataLen) {
    (void)hSession; (void)pEncryptedData; (void)ulEncryptedDataLen; (void)pData; (void)pulDataLen;
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_DecryptUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedPart, CK_ULONG ulEncryptedPartLen, CK_BYTE_PTR pPart, CK_ULONG_PTR pulPartLen) {
    (void)hSession; (void)pEncryptedPart; (void)ulEncryptedPartLen; (void)pPart; (void)pulPartLen;
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_DecryptFinal(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pLastPart, CK_ULONG_PTR pulLastPartLen) {
    (void)hSession; (void)pLastPart; (void)pulLastPartLen;
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_DigestInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism) {
    (void)hSession; (void)pMechanism;
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_Digest(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pDigest, CK_ULONG_PTR pulDigestLen) {
    (void)hSession; (void)pData; (void)ulDataLen; (void)pDigest; (void)pulDigestLen;
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_DigestUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen) {
    (void)hSession; (void)pPart; (void)ulPartLen;
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_DigestKey(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hKey) {
    (void)hSession; (void)hKey;
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_DigestFinal(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pDigest, CK_ULONG_PTR pulDigestLen) {
    (void)hSession; (void)pDigest; (void)pulDigestLen;
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_SignUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen) {
    (void)hSession; (void)pPart; (void)ulPartLen;
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_SignFinal(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen) {
    (void)hSession; (void)pSignature; (void)pulSignatureLen;
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_SignRecoverInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey) {
    (void)hSession; (void)pMechanism; (void)hKey;
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_SignRecover(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen) {
    (void)hSession; (void)pData; (void)ulDataLen; (void)pSignature; (void)pulSignatureLen;
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_VerifyInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey) {
    (void)hSession; (void)pMechanism; (void)hKey;
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_Verify(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pSignature, CK_ULONG ulSignatureLen) {
    (void)hSession; (void)pData; (void)ulDataLen; (void)pSignature; (void)ulSignatureLen;
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_VerifyUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen) {
    (void)hSession; (void)pPart; (void)ulPartLen;
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_VerifyFinal(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSignature, CK_ULONG ulSignatureLen) {
    (void)hSession; (void)pSignature; (void)ulSignatureLen;
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_VerifyRecoverInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey) {
    (void)hSession; (void)pMechanism; (void)hKey;
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_VerifyRecover(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSignature, CK_ULONG ulSignatureLen, CK_BYTE_PTR pData, CK_ULONG_PTR pulDataLen) {
    (void)hSession; (void)pSignature; (void)ulSignatureLen; (void)pData; (void)pulDataLen;
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_DigestEncryptUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen, CK_BYTE_PTR pEncryptedPart, CK_ULONG_PTR pulEncryptedPartLen) {
    (void)hSession; (void)pPart; (void)ulPartLen; (void)pEncryptedPart; (void)pulEncryptedPartLen;
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_DecryptDigestUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedPart, CK_ULONG ulEncryptedPartLen, CK_BYTE_PTR pPart, CK_ULONG_PTR pulPartLen) {
    (void)hSession; (void)pEncryptedPart; (void)ulEncryptedPartLen; (void)pPart; (void)pulPartLen;
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_SignEncryptUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen, CK_BYTE_PTR pEncryptedPart, CK_ULONG_PTR pulEncryptedPartLen) {
    (void)hSession; (void)pPart; (void)ulPartLen; (void)pEncryptedPart; (void)pulEncryptedPartLen;
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_DecryptVerifyUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedPart, CK_ULONG ulEncryptedPartLen, CK_BYTE_PTR pPart, CK_ULONG_PTR pulPartLen) {
    (void)hSession; (void)pEncryptedPart; (void)ulEncryptedPartLen; (void)pPart; (void)pulPartLen;
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_GenerateKey(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount, CK_OBJECT_HANDLE_PTR phKey) {
    (void)hSession; (void)pMechanism; (void)pTemplate; (void)ulCount; (void)phKey;
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_GenerateKeyPair(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_ATTRIBUTE_PTR pPublicKeyTemplate, CK_ULONG ulPublicKeyAttributeCount, CK_ATTRIBUTE_PTR pPrivateKeyTemplate, CK_ULONG ulPrivateKeyAttributeCount, CK_OBJECT_HANDLE_PTR phPublicKey, CK_OBJECT_HANDLE_PTR phPrivateKey) {
    (void)hSession; (void)pMechanism; (void)pPublicKeyTemplate; (void)ulPublicKeyAttributeCount;
    (void)pPrivateKeyTemplate; (void)ulPrivateKeyAttributeCount; (void)phPublicKey; (void)phPrivateKey;
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_WrapKey(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hWrappingKey, CK_OBJECT_HANDLE hKey, CK_BYTE_PTR pWrappedKey, CK_ULONG_PTR pulWrappedKeyLen) {
    (void)hSession; (void)pMechanism; (void)hWrappingKey; (void)hKey; (void)pWrappedKey; (void)pulWrappedKeyLen;
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_UnwrapKey(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hUnwrappingKey, CK_BYTE_PTR pWrappedKey, CK_ULONG ulWrappedKeyLen, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulAttributeCount, CK_OBJECT_HANDLE_PTR phKey) {
    (void)hSession; (void)pMechanism; (void)hUnwrappingKey; (void)pWrappedKey; (void)ulWrappedKeyLen;
    (void)pTemplate; (void)ulAttributeCount; (void)phKey;
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_DeriveKey(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hBaseKey, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulAttributeCount, CK_OBJECT_HANDLE_PTR phKey) {
    (void)hSession; (void)pMechanism; (void)hBaseKey; (void)pTemplate; (void)ulAttributeCount; (void)phKey;
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_SeedRandom(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSeed, CK_ULONG ulSeedLen) {
    (void)hSession; (void)pSeed; (void)ulSeedLen;
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_GenerateRandom(CK_SESSION_HANDLE hSession, CK_BYTE_PTR RandomData, CK_ULONG ulRandomLen) {
    (void)hSession; (void)RandomData; (void)ulRandomLen;
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_GetFunctionStatus(CK_SESSION_HANDLE hSession) {
    (void)hSession;
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_CancelFunction(CK_SESSION_HANDLE hSession) {
    (void)hSession;
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_WaitForSlotEvent(CK_FLAGS flags, CK_SLOT_ID_PTR pSlot, CK_VOID_PTR pReserved) {
    (void)flags; (void)pSlot; (void)pReserved;
    return CKR_FUNCTION_NOT_SUPPORTED;
}
