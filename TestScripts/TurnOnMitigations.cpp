#include <windows.h>
#include <stdio.h>
#include <tchar.h>
#include <Processthreadsapi.h>
#pragma comment(lib, "Advapi32.lib")
#include <cstdio>

static void add_mitigations(HANDLE hProc)
{

    //

    printf(" ProcessASLRPolicy:::: \n");

    PROCESS_MITIGATION_ASLR_POLICY aslrPolicy = { 0 };   
    GetProcessMitigationPolicy(hProc, ProcessASLRPolicy, &aslrPolicy, sizeof(aslrPolicy));

    aslrPolicy.EnableBottomUpRandomization = 1;
    aslrPolicy.EnableForceRelocateImages = 1;
    aslrPolicy.EnableHighEntropy = 1;
    aslrPolicy.DisallowStrippedImages = 1;

    SetProcessMitigationPolicy(ProcessASLRPolicy, &aslrPolicy, sizeof(aslrPolicy));

    PROCESS_MITIGATION_ASLR_POLICY aslrPolicyReturned = { 0 };


    GetProcessMitigationPolicy(hProc, ProcessASLRPolicy, &aslrPolicyReturned, sizeof(aslrPolicyReturned));
    printf(" EnableBottomUpRandomization: %u\n", aslrPolicyReturned.EnableBottomUpRandomization);
    printf(" EnableForceRelocateImages: %u\n", aslrPolicyReturned.EnableForceRelocateImages);
    printf(" EnableHighEntropy: %u\n", aslrPolicyReturned.EnableHighEntropy);
    printf(" DisallowStrippedImages: %u\n", aslrPolicyReturned.DisallowStrippedImages);

    //

    printf(" ProcessDynamicCodePolicy:::: \n");

    PROCESS_MITIGATION_DYNAMIC_CODE_POLICY dynamicCodePolicy = { 0 };
    GetProcessMitigationPolicy(hProc, ProcessDynamicCodePolicy, &dynamicCodePolicy, sizeof(dynamicCodePolicy));

    dynamicCodePolicy.ProhibitDynamicCode = 1;
    dynamicCodePolicy.AllowThreadOptOut = 1;
    dynamicCodePolicy.AllowRemoteDowngrade = 1;

    SetProcessMitigationPolicy(ProcessDynamicCodePolicy, &dynamicCodePolicy, sizeof(dynamicCodePolicy));

    PROCESS_MITIGATION_DYNAMIC_CODE_POLICY dynamicCodePolicyReturned = { 0 };


    GetProcessMitigationPolicy(hProc, ProcessDynamicCodePolicy, &dynamicCodePolicyReturned, sizeof(dynamicCodePolicyReturned));
    printf(" ProhibitDynamicCode: %u\n", dynamicCodePolicyReturned.ProhibitDynamicCode);
    printf(" AllowThreadOptOut: %u\n", dynamicCodePolicyReturned.AllowThreadOptOut);
    printf(" AllowRemoteDowngrade: %u\n", dynamicCodePolicyReturned.AllowRemoteDowngrade);

    //

    printf(" ProcessStrictHandleCheckPolicy:::: \n");

    PROCESS_MITIGATION_STRICT_HANDLE_CHECK_POLICY strictHandlePolicy = { 0 };
    GetProcessMitigationPolicy(hProc, ProcessStrictHandleCheckPolicy, &strictHandlePolicy, sizeof(strictHandlePolicy));

    strictHandlePolicy.RaiseExceptionOnInvalidHandleReference = 1;
    strictHandlePolicy.HandleExceptionsPermanentlyEnabled = 1;

    SetProcessMitigationPolicy(ProcessStrictHandleCheckPolicy, &strictHandlePolicy, sizeof(strictHandlePolicy));

    PROCESS_MITIGATION_STRICT_HANDLE_CHECK_POLICY strictHandlePolicyReturned = { 0 };


    GetProcessMitigationPolicy(hProc, ProcessStrictHandleCheckPolicy, &strictHandlePolicyReturned, sizeof(strictHandlePolicyReturned));
    printf(" RaiseExceptionOnInvalidHandleReference: %u\n", strictHandlePolicyReturned.RaiseExceptionOnInvalidHandleReference);
    printf(" HandleExceptionsPermanentlyEnabled: %u\n", strictHandlePolicyReturned.HandleExceptionsPermanentlyEnabled);

    //

    printf(" ProcessExtensionPointDisablePolicy:::: \n");

    PROCESS_MITIGATION_EXTENSION_POINT_DISABLE_POLICY extensionPointPolicy = { 0 };
    GetProcessMitigationPolicy(hProc, ProcessExtensionPointDisablePolicy, &extensionPointPolicy, sizeof(extensionPointPolicy));

    extensionPointPolicy.DisableExtensionPoints = 1;

    SetProcessMitigationPolicy(ProcessExtensionPointDisablePolicy, &extensionPointPolicy, sizeof(extensionPointPolicy));

    PROCESS_MITIGATION_EXTENSION_POINT_DISABLE_POLICY extensionPointPolicyReturned = { 0 };


    GetProcessMitigationPolicy(hProc, ProcessExtensionPointDisablePolicy, &extensionPointPolicyReturned, sizeof(extensionPointPolicyReturned));
    printf(" DisableExtensionPoints: %u\n", extensionPointPolicyReturned.DisableExtensionPoints);


    //

    printf(" ProcessControlFlowGuardPolicy:::: \n");

    PROCESS_MITIGATION_CONTROL_FLOW_GUARD_POLICY controlFlowGuardPolicy = { 0 };
    GetProcessMitigationPolicy(hProc, ProcessControlFlowGuardPolicy, &controlFlowGuardPolicy, sizeof(controlFlowGuardPolicy));

    controlFlowGuardPolicy.EnableControlFlowGuard = 1;
    controlFlowGuardPolicy.EnableExportSuppression = 1;
    controlFlowGuardPolicy.StrictMode = 1;

    SetProcessMitigationPolicy(ProcessControlFlowGuardPolicy, &controlFlowGuardPolicy, sizeof(controlFlowGuardPolicy));

    PROCESS_MITIGATION_CONTROL_FLOW_GUARD_POLICY controlFlowGuardPolicyReturned = { 0 };


    GetProcessMitigationPolicy(hProc, ProcessControlFlowGuardPolicy, &controlFlowGuardPolicyReturned, sizeof(controlFlowGuardPolicyReturned));
    printf(" EnableControlFlowGuard: %u\n", controlFlowGuardPolicyReturned.EnableControlFlowGuard);
    printf(" EnableExportSuppression: %u\n", controlFlowGuardPolicyReturned.EnableExportSuppression);
    printf(" StrictMode: %u\n", controlFlowGuardPolicyReturned.StrictMode);


    //

    printf(" ProcessSignaturePolicy:::: \n");

    PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY binarySignaturePolicy = { 0 };
    GetProcessMitigationPolicy(hProc, ProcessSignaturePolicy, &binarySignaturePolicy, sizeof(binarySignaturePolicy));

    binarySignaturePolicy.MicrosoftSignedOnly = 1;
    binarySignaturePolicy.StoreSignedOnly = 1;
    binarySignaturePolicy.MitigationOptIn = 1;

    SetProcessMitigationPolicy(ProcessSignaturePolicy, &binarySignaturePolicy, sizeof(binarySignaturePolicy));

    PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY binarySignaturePolicyReturned = { 0 };


    GetProcessMitigationPolicy(hProc, ProcessSignaturePolicy, &binarySignaturePolicyReturned, sizeof(binarySignaturePolicyReturned));
    printf(" MicrosoftSignedOnly: %u\n", binarySignaturePolicyReturned.MicrosoftSignedOnly);
    printf(" StoreSignedOnly: %u\n", binarySignaturePolicyReturned.StoreSignedOnly);
    printf(" MitigationOptIn: %u\n", binarySignaturePolicyReturned.MitigationOptIn);


    //

    printf(" ProcessImageLoadPolicy:::: \n");

    PROCESS_MITIGATION_IMAGE_LOAD_POLICY imageLoadPolicy = { 0 };
    GetProcessMitigationPolicy(hProc, ProcessImageLoadPolicy, &imageLoadPolicy, sizeof(imageLoadPolicy));

    imageLoadPolicy.NoRemoteImages = 1;
    imageLoadPolicy.NoLowMandatoryLabelImages = 1;
    imageLoadPolicy.PreferSystem32Images = 1;

    SetProcessMitigationPolicy(ProcessImageLoadPolicy, &imageLoadPolicy, sizeof(imageLoadPolicy));

    PROCESS_MITIGATION_IMAGE_LOAD_POLICY imageLoadPolicyReturned = { 0 };


    GetProcessMitigationPolicy(hProc, ProcessImageLoadPolicy, &imageLoadPolicyReturned, sizeof(imageLoadPolicyReturned));
    printf(" NoRemoteImages: %u\n", imageLoadPolicyReturned.NoRemoteImages);
    printf(" NoLowMandatoryLabelImages: %u\n", imageLoadPolicyReturned.NoLowMandatoryLabelImages);
    printf(" PreferSystem32Images: %u\n", imageLoadPolicyReturned.PreferSystem32Images);

    //

    printf(" ProcessFontDisablePolicy:::: \n");

    PROCESS_MITIGATION_FONT_DISABLE_POLICY fontDisablePolicy = { 0 };
    GetProcessMitigationPolicy(hProc, ProcessFontDisablePolicy, &fontDisablePolicy, sizeof(fontDisablePolicy));

    fontDisablePolicy.DisableNonSystemFonts = 1;
    fontDisablePolicy.AuditNonSystemFontLoading = 1;

    SetProcessMitigationPolicy(ProcessFontDisablePolicy, &fontDisablePolicy, sizeof(fontDisablePolicy));

    PROCESS_MITIGATION_FONT_DISABLE_POLICY fontDisablePolicyReturned = { 0 };


    GetProcessMitigationPolicy(hProc, ProcessFontDisablePolicy, &fontDisablePolicyReturned, sizeof(fontDisablePolicyReturned));
    printf(" DisableNonSystemFonts: %u\n", fontDisablePolicyReturned.DisableNonSystemFonts);
    printf(" AuditNonSystemFontLoading: %u\n", fontDisablePolicyReturned.AuditNonSystemFontLoading);


    //

    printf(" ProcessSystemCallDisablePolicy:::: \n");

    PROCESS_MITIGATION_SYSTEM_CALL_DISABLE_POLICY systemCallDisablePolicy = { 0 };
    GetProcessMitigationPolicy(hProc, ProcessSystemCallDisablePolicy, &systemCallDisablePolicy, sizeof(systemCallDisablePolicy));

    systemCallDisablePolicy.DisallowWin32kSystemCalls = 1;

    SetProcessMitigationPolicy(ProcessSystemCallDisablePolicy, &systemCallDisablePolicy, sizeof(systemCallDisablePolicy));

    PROCESS_MITIGATION_SYSTEM_CALL_DISABLE_POLICY systemCallDisablePolicyRetuerned = { 0 };


    GetProcessMitigationPolicy(hProc, ProcessSystemCallDisablePolicy, &systemCallDisablePolicyRetuerned, sizeof(systemCallDisablePolicyRetuerned));
    printf(" DisallowWin32kSystemCalls: %u\n", systemCallDisablePolicyRetuerned.DisallowWin32kSystemCalls);

}

void _tmain(int argc, TCHAR* argv[])
{

    HANDLE hProcess = GetCurrentProcess();
    add_mitigations(hProcess);

    STARTUPINFO si;
    PROCESS_INFORMATION pi;

    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    ZeroMemory(&pi, sizeof(pi));

    //if (argc != 2)
    //{
    //    printf("Usage: %s [cmdline]\n", argv[0]);
    //    return;
    //}

    TCHAR lpszClientPath[500] = TEXT("c:\\Test\\notepad.exe");

    // Start the child process. 
    if (!CreateProcess(NULL,   // No module name (use command line)
        lpszClientPath,        // Command line
        NULL,           // Process handle not inheritable
        NULL,           // Thread handle not inheritable
        FALSE,          // Set handle inheritance to FALSE
        NORMAL_PRIORITY_CLASS | CREATE_NEW_CONSOLE | CREATE_UNICODE_ENVIRONMENT,              // No creation flags
        NULL,           // Use parent's environment block
        NULL,           // Use parent's starting directory 
        &si,            // Pointer to STARTUPINFO structure
        &pi)           // Pointer to PROCESS_INFORMATION structure
        )
    {
        printf("CreateProcess failed (%d).\n", GetLastError());

        std::getchar();
        return;
    }

    // Wait until child process exits.
    WaitForSingleObject(pi.hProcess, INFINITE);

    // Close process and thread handles. 
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    std::getchar();
}