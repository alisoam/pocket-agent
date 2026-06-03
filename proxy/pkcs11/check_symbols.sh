#!/bin/bash
# Check if all required PKCS#11 symbols are exported

REQUIRED_SYMBOLS=(
    "C_Initialize"
    "C_Finalize"
    "C_GetInfo"
    "C_GetFunctionList"
    "C_GetSlotList"
    "C_GetSlotInfo"
    "C_GetTokenInfo"
    "C_OpenSession"
    "C_CloseSession"
    "C_Login"
    "C_Logout"
    "C_FindObjectsInit"
    "C_FindObjects"
    "C_FindObjectsFinal"
    "C_GetAttributeValue"
    "C_SignInit"
    "C_Sign"
)

echo "Checking for required PKCS#11 symbols in libpocket-pkcs11.so..."
echo ""

MISSING=0
for sym in "${REQUIRED_SYMBOLS[@]}"; do
    if nm -D libpocket-pkcs11.so | grep -q " T $sym\$"; then
        echo "✓ $sym"
    else
        echo "✗ $sym (MISSING)"
        MISSING=$((MISSING + 1))
    fi
done

echo ""
if [ $MISSING -eq 0 ]; then
    echo "✅ All required symbols present!"
    exit 0
else
    echo "❌ $MISSING symbols missing"
    exit 1
fi
