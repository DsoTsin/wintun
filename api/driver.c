/* SPDX-License-Identifier: GPL-2.0
 *
 * Copyright (C) 2018-2021 WireGuard LLC. All Rights Reserved.
 */

#include <Windows.h>
#include <winternl.h>
#include <cfgmgr32.h>
#include <SetupAPI.h>
#include <devguid.h>
#include <ndisguid.h>
#include <Shlwapi.h>
#include <shellapi.h>
#include <wchar.h>
#include <strsafe.h>

#include "driver.h"
#include "adapter.h"
#include "logger.h"
#include "namespace.h"
#include "resource.h"
#include "registry.h"
#include "ntdll.h"
#include "rundll32.h"
#include "wintun-inf.h"

#pragma warning(disable : 4221) /* nonstandard: address of automatic in initializer */

struct _SP_DEVINFO_DATA_LIST
{
    SP_DEVINFO_DATA Data;
    struct _SP_DEVINFO_DATA_LIST *Next;
};

static _Return_type_success_(return != FALSE)
BOOL
DisableAllOurAdapters(_In_ HDEVINFO DevInfo, _Inout_ SP_DEVINFO_DATA_LIST **DisabledAdapters)
{
    DWORD LastError = ERROR_SUCCESS;
    for (DWORD EnumIndex = 0;; ++EnumIndex)
    {
        SP_DEVINFO_DATA_LIST *DeviceNode = Zalloc(sizeof(*DeviceNode));
        if (!DeviceNode)
            return FALSE;
        DeviceNode->Data.cbSize = sizeof(SP_DEVINFO_DATA);
        if (!SetupDiEnumDeviceInfo(DevInfo, EnumIndex, &DeviceNode->Data))
        {
            if (GetLastError() == ERROR_NO_MORE_ITEMS)
            {
                Free(DeviceNode);
                break;
            }
            goto cleanupDeviceNode;
        }

        DEVPROPTYPE PropType;
        WCHAR Name[MAX_ADAPTER_NAME] = L"<unknown>";
        SetupDiGetDevicePropertyW(
            DevInfo,
            &DeviceNode->Data,
            &DEVPKEY_Wintun_Name,
            &PropType,
            (PBYTE)Name,
            MAX_ADAPTER_NAME * sizeof(Name[0]),
            NULL,
            0);

        ULONG Status, ProblemCode;
        if (CM_Get_DevNode_Status(&Status, &ProblemCode, DeviceNode->Data.DevInst, 0) != CR_SUCCESS ||
            ((Status & DN_HAS_PROBLEM) && ProblemCode == CM_PROB_DISABLED))
            goto cleanupDeviceNode;

        LOG(WINTUN_LOG_INFO, L"Disabling adapter \"%s\"", Name);
        if (!AdapterDisableInstance(DevInfo, &DeviceNode->Data))
        {
            LOG_LAST_ERROR(L"Failed to disable adapter \"%s\"", Name);
            LastError = LastError != ERROR_SUCCESS ? LastError : GetLastError();
            goto cleanupDeviceNode;
        }

        DeviceNode->Next = *DisabledAdapters;
        *DisabledAdapters = DeviceNode;
        continue;

    cleanupDeviceNode:
        Free(DeviceNode);
    }
    return RET_ERROR(TRUE, LastError);
}

static _Return_type_success_(return != FALSE)
BOOL
EnableAllOurAdapters(_In_ HDEVINFO DevInfo, _In_ SP_DEVINFO_DATA_LIST *AdaptersToEnable)
{
    DWORD LastError = ERROR_SUCCESS;
    for (SP_DEVINFO_DATA_LIST *DeviceNode = AdaptersToEnable; DeviceNode; DeviceNode = DeviceNode->Next)
    {
        DEVPROPTYPE PropType;
        WCHAR Name[MAX_ADAPTER_NAME] = L"<unknown>";
        SetupDiGetDevicePropertyW(
            DevInfo,
            &DeviceNode->Data,
            &DEVPKEY_Wintun_Name,
            &PropType,
            (PBYTE)Name,
            MAX_ADAPTER_NAME * sizeof(Name[0]),
            NULL,
            0);

        LOG(WINTUN_LOG_INFO, L"Enabling adapter \"%s\"", Name);
        if (!AdapterEnableInstance(DevInfo, &DeviceNode->Data))
        {
            LOG_LAST_ERROR(L"Failed to enable adapter \"%s\"", Name);
            LastError = LastError != ERROR_SUCCESS ? LastError : GetLastError();
        }
    }
    return RET_ERROR(TRUE, LastError);
}

static BOOL
IsNewer(
    _In_ const FILETIME *DriverDate1,
    _In_ DWORDLONG DriverVersion1,
    _In_ const FILETIME *DriverDate2,
    _In_ DWORDLONG DriverVersion2)
{
    if (DriverDate1->dwHighDateTime > DriverDate2->dwHighDateTime)
        return TRUE;
    if (DriverDate1->dwHighDateTime < DriverDate2->dwHighDateTime)
        return FALSE;

    if (DriverDate1->dwLowDateTime > DriverDate2->dwLowDateTime)
        return TRUE;
    if (DriverDate1->dwLowDateTime < DriverDate2->dwLowDateTime)
        return FALSE;

    if (DriverVersion1 > DriverVersion2)
        return TRUE;
    if (DriverVersion1 < DriverVersion2)
        return FALSE;

    return FALSE;
}

static _Return_type_success_(return != 0)
DWORD
VersionOfFile(_In_z_ LPCWSTR Filename)
{
    DWORD Zero;
    DWORD Len = GetFileVersionInfoSizeW(Filename, &Zero);
    if (!Len)
    {
        LOG_LAST_ERROR(L"Failed to query %s version info size", Filename);
        return 0;
    }
    VOID *VersionInfo = Alloc(Len);
    if (!VersionInfo)
        return 0;
    DWORD LastError = ERROR_SUCCESS, Version = 0;
    VS_FIXEDFILEINFO *FixedInfo;
    UINT FixedInfoLen = sizeof(*FixedInfo);
    if (!GetFileVersionInfoW(Filename, 0, Len, VersionInfo))
    {
        LastError = LOG_LAST_ERROR(L"Failed to get %s version info", Filename);
        goto out;
    }
    if (!VerQueryValueW(VersionInfo, L"\\", &FixedInfo, &FixedInfoLen))
    {
        LastError = LOG_LAST_ERROR(L"Failed to get %s version info root", Filename);
        goto out;
    }
    Version = FixedInfo->dwFileVersionMS;
    if (!Version)
    {
        LOG(WINTUN_LOG_WARN, L"Determined version of %s, but was v0.0, so returning failure", Filename);
        LastError = ERROR_VERSION_PARSE_ERROR;
    }
out:
    Free(VersionInfo);
    return RET_ERROR(Version, LastError);
}

static DWORD WINAPI
MaybeGetRunningDriverVersion(BOOL ReturnOneIfRunningInsteadOfVersion)
{
    PRTL_PROCESS_MODULES Modules;
    ULONG BufferSize = 128 * 1024;
    for (;;)
    {
        Modules = Alloc(BufferSize);
        if (!Modules)
            return 0;
        NTSTATUS Status = NtQuerySystemInformation(SystemModuleInformation, Modules, BufferSize, &BufferSize);
        if (NT_SUCCESS(Status))
            break;
        Free(Modules);
        if (Status == STATUS_INFO_LENGTH_MISMATCH)
            continue;
        LOG(WINTUN_LOG_ERR, L"Failed to enumerate drivers (status: 0x%x)", Status);
        SetLastError(RtlNtStatusToDosError(Status));
        return 0;
    }
    DWORD LastError = ERROR_SUCCESS, Version = 0;
    for (ULONG i = Modules->NumberOfModules; i-- > 0;)
    {
        LPCSTR NtPath = (LPCSTR)Modules->Modules[i].FullPathName;
        if (!_stricmp(&NtPath[Modules->Modules[i].OffsetToFileName], "wintun.sys"))
        {
            if (ReturnOneIfRunningInsteadOfVersion)
            {
                Version = 1;
                goto cleanupModules;
            }
            WCHAR FilePath[MAX_PATH * 3 + 15];
            if (_snwprintf_s(FilePath, _countof(FilePath), _TRUNCATE, L"\\\\?\\GLOBALROOT%S", NtPath) == -1)
                continue;
            Version = VersionOfFile(FilePath);
            if (!Version)
                LastError = GetLastError();
            goto cleanupModules;
        }
    }
    LastError = ERROR_FILE_NOT_FOUND;
cleanupModules:
    Free(Modules);
    return RET_ERROR(Version, LastError);
}

_Use_decl_annotations_
DWORD WINAPI WintunGetRunningDriverVersion(VOID)
{
    return MaybeGetRunningDriverVersion(FALSE);
}

static BOOL EnsureWintunUnloaded(VOID)
{
    BOOL Loaded;
    for (DWORD Tries = 0; Tries < 1500; ++Tries)
    {
        if (Tries)
            Sleep(50);
        Loaded = MaybeGetRunningDriverVersion(TRUE) != 0;
        if (!Loaded)
            break;
    }
    return !Loaded;
}

_Use_decl_annotations_
VOID
DriverInstallDeferredCleanup(HDEVINFO DevInfoExistingAdapters, SP_DEVINFO_DATA_LIST *ExistingAdapters)
{
    if (ExistingAdapters)
    {
        EnableAllOurAdapters(DevInfoExistingAdapters, ExistingAdapters);
        while (ExistingAdapters)
        {
            SP_DEVINFO_DATA_LIST *Next = ExistingAdapters->Next;
            Free(ExistingAdapters);
            ExistingAdapters = Next;
        }
    }
    if (DevInfoExistingAdapters != INVALID_HANDLE_VALUE)
        SetupDiDestroyDeviceInfoList(DevInfoExistingAdapters);
}

// Driver Version
#define INFSTR_DRIVERVERSION_SECTION    L"DriverVer"
#define INFSTR_KEY_CATALOGFILE          L"CatalogFile"
#define INFSTR_SECT_VERSION             L"Version"

BOOL CheckOEMDriverExist(int Count, LPCWSTR DriverNames[], LPCWSTR Versions[], BOOL bExpired[], BOOL bExists[], BOOL bUninstall)
{
    WCHAR FindName[MAX_PATH];
    HANDLE hFind = INVALID_HANDLE_VALUE;
    WIN32_FIND_DATAW wfd;
    if (!GetWindowsDirectoryW(FindName, ARRAYSIZE(FindName)) ||
        FAILED(StringCchCatW(FindName, ARRAYSIZE(FindName), L"\\INF\\OEM*.INF"))) {
        goto final;
    }
    hFind = FindFirstFileW(FindName, &wfd);
    if (hFind == INVALID_HANDLE_VALUE) {
        goto final;
    }
    do {
        HINF hInf = INVALID_HANDLE_VALUE;
        UINT ErrorLine;
        INFCONTEXT Context;
        WCHAR InfData[MAX_INF_STRING_LENGTH];
        hInf = SetupOpenInfFileW(wfd.cFileName, NULL, INF_STYLE_WIN4, &ErrorLine);
        if (hInf == INVALID_HANDLE_VALUE) {
            continue;
        }
        if (SetupFindFirstLineW(hInf, INFSTR_SECT_VERSION, INFSTR_KEY_CATALOGFILE, &Context)
            && SetupGetStringFieldW(&Context, 1, InfData, ARRAYSIZE(InfData), NULL))
        {
            for (int i = 0; i < Count; i++)
            {
                WCHAR TestCatName[64] = { 0 };
                StringCchPrintfW(TestCatName, 64, L"%s.cat", DriverNames[i]);
                if (_wcsicmp(TestCatName, InfData) == 0)
                {
                    if (bUninstall)
                    {
                        STARTUPINFO start_info = { 0 };
                        start_info.cb = sizeof(STARTUPINFO);
                        start_info.dwFlags = STARTF_USESHOWWINDOW;
                        start_info.wShowWindow = SW_HIDE;
                        start_info.dwFlags = 0;
                        PROCESS_INFORMATION temp_process_info = { 0 };
                        WCHAR commandLine[1024];
                        wnsprintfW(commandLine, 1024, L"pnputil.exe /delete-driver %s /force", wfd.cFileName);
                        if (!CreateProcessW(NULL, (LPWSTR)commandLine, NULL, NULL,
                            TRUE, // Handles are inherited.
                            NORMAL_PRIORITY_CLASS | CREATE_NO_WINDOW, NULL,
                            NULL, &start_info,
                            &temp_process_info)) {
                            LOG(WINTUN_LOG_ERR, L"Could not uninstall driver %s, %s", wfd.cFileName, DriverNames[i]);
                            continue;
                        }
                        WaitForSingleObject(temp_process_info.hProcess, INFINITE);
                        DWORD dw_exit_code = 0;
                        GetExitCodeProcess(temp_process_info.hProcess, &dw_exit_code);
                        CloseHandle(temp_process_info.hProcess);
                        LOG(WINTUN_LOG_INFO, L"Finish uninstall %s, exit: %u", DriverNames[i], dw_exit_code);
                    }
                    else
                    {
                        if (SetupFindFirstLineW(hInf, INFSTR_SECT_VERSION, INFSTR_DRIVERVERSION_SECTION, &Context))
                        {
                            bExists[i] = TRUE;
                            if (SetupGetStringFieldW(&Context, 1, InfData, ARRAYSIZE(InfData), NULL)) { // Test date
                            }
                            else
                            {
                                LOG(WINTUN_LOG_WARN, L"Unknown driver date: %s", DriverNames[i]);
                                continue;
                            }
                            if (SetupGetStringFieldW(&Context, 2, InfData, ARRAYSIZE(InfData), NULL)) { // test version
                                int Ret = _wcsicmp(Versions[i], InfData);
                                bExpired[i] = Ret > 0 ? TRUE : FALSE;
                                if (bExpired[i])
                                {
                                    LOG(WINTUN_LOG_WARN, L"%s driver version: %s (current) is expired (new: %s), need to install", DriverNames[i], InfData, Versions[i]);
                                }
                                else
                                {
                                    LOG(WINTUN_LOG_INFO, L"%s driver use current version: %s, [%s] tested.", DriverNames[i], InfData, Versions[i]);
                                }
                            }
                            else {
                                LOG(WINTUN_LOG_WARN, L"Unknown driver version: %s", DriverNames[i]);
                                continue;
                            }
                        }
                    }
                }
            }
        }
        else {
            continue;
        }

        if (hInf != INVALID_HANDLE_VALUE) {
            SetupCloseInfFile(hInf);
        }
    } while (FindNextFileW(hFind, &wfd));
    FindClose(hFind);
final:
    return TRUE;
}

static LPCWSTR DriverExts[3] = { L"sys", L"cat", L"inf", };

_Use_decl_annotations_
BOOL
SimpleDriverInstall(LPCWSTR TempDir, LPCWSTR ResourceNamePrefix, LPCWSTR FileNamePrefix) {
    LOG(WINTUN_LOG_INFO, L"Installing %s driver", ResourceNamePrefix);
    DWORD LastError = 0;
    WCHAR ExtractPath[MAX_PATH] = { 0 };
    for (int i = 0; i < 3; i++) {
        WCHAR FileName[64] = { 0 };
        wnsprintfW(FileName, 64, L"%s.%s", FileNamePrefix, DriverExts[i]);
        if (wcscmp(L"cat", DriverExts[i]) == 0)
        {
            _wcslwr(FileName);
        }
        WCHAR ResourceName[64] = { 0 };
        wnsprintfW(ResourceName, 64, L"%s.%s", ResourceNamePrefix, DriverExts[i]);
        if (!PathCombineW(ExtractPath, TempDir, FileName)) {
            // TODO: log error
            return FALSE;
        }
        if (!ResourceCopyToFile(ExtractPath, ResourceName)) {
            // TODO: log error
            return FALSE;
        }

    }
    //if (!SetupCopyOEMInfW(ExtractPath, NULL, SPOST_NONE, 0, NULL, 0, NULL, NULL)) {    
    //    LastError = LOG_LAST_ERROR(L"Could not install driver %s to store", ExtractPath);
    //}
    STARTUPINFO start_info = {0};
    start_info.cb = sizeof(STARTUPINFO);
    start_info.dwFlags = STARTF_USESHOWWINDOW;
    start_info.wShowWindow = SW_HIDE;
    start_info.dwFlags = 0;
    PROCESS_INFORMATION temp_process_info = {0};
    WCHAR commandLine[1024];
    wnsprintfW(commandLine, 1024, L"pnputil.exe /add-driver %s /install", ExtractPath);
    if (!CreateProcessW(NULL, (LPWSTR)commandLine, NULL, NULL,
        TRUE, // Handles are inherited.
        NORMAL_PRIORITY_CLASS | CREATE_NO_WINDOW, NULL,
        TempDir, &start_info,
        &temp_process_info)) {
        LastError = LOG_LAST_ERROR(L"Could not install driver %s to store", ExtractPath);
        return FALSE;
    }
    WaitForSingleObject(temp_process_info.hProcess, INFINITE);
    DWORD dw_exit_code = 0;
    GetExitCodeProcess(temp_process_info.hProcess, &dw_exit_code);
    CloseHandle(temp_process_info.hProcess);
    LOG(WINTUN_LOG_INFO, L"Install %s completely, exit: %u", ResourceNamePrefix, dw_exit_code);
    return TRUE;
}

_Use_decl_annotations_
BOOL
DriverInstall(HDEVINFO *DevInfoExistingAdaptersForCleanup, SP_DEVINFO_DATA_LIST **ExistingAdaptersForCleanup)
{
    static const FILETIME OurDriverDate = WINTUN_INF_FILETIME;
    static const DWORDLONG OurDriverVersion = WINTUN_INF_VERSION;
    HANDLE DriverInstallationLock = NamespaceTakeDriverInstallationMutex();
    if (!DriverInstallationLock)
    {
        LOG(WINTUN_LOG_ERR, L"Failed to take driver installation mutex");
        return FALSE;
    }
    DWORD LastError = ERROR_SUCCESS;
    HDEVINFO DevInfo = SetupDiCreateDeviceInfoListExW(&GUID_DEVCLASS_NET, NULL, NULL, NULL);
    if (DevInfo == INVALID_HANDLE_VALUE)
    {
        LastError = LOG_LAST_ERROR(L"Failed to create empty device information set");
        goto cleanupDriverInstallationLock;
    }
    SP_DEVINFO_DATA DevInfoData = { .cbSize = sizeof(DevInfoData) };
    if (!SetupDiCreateDeviceInfoW(DevInfo, WINTUN_HWID, &GUID_DEVCLASS_NET, NULL, NULL, DICD_GENERATE_ID, &DevInfoData))
    {
        LastError = LOG_LAST_ERROR(L"Failed to create new device information element");
        goto cleanupDevInfo;
    }
    static const WCHAR Hwids[_countof(WINTUN_HWID) + 1 /*Multi-string terminator*/] = WINTUN_HWID;
    if (!SetupDiSetDeviceRegistryPropertyW(DevInfo, &DevInfoData, SPDRP_HARDWAREID, (const BYTE *)Hwids, sizeof(Hwids)))
    {
        LastError = LOG_LAST_ERROR(L"Failed to set adapter hardware ID");
        goto cleanupDevInfo;
    }
    if (!SetupDiBuildDriverInfoList(DevInfo, &DevInfoData, SPDIT_COMPATDRIVER))
    {
        LastError = LOG_LAST_ERROR(L"Failed building adapter driver info list");
        goto cleanupDevInfo;
    }
    FILETIME DriverDate = { 0 };
    DWORDLONG DriverVersion = 0;
    HDEVINFO DevInfoExistingAdapters = INVALID_HANDLE_VALUE;
    SP_DEVINFO_DATA_LIST *ExistingAdapters = NULL;
    for (DWORD EnumIndex = 0;; ++EnumIndex)
    {
        SP_DRVINFO_DATA_W DrvInfoData = { .cbSize = sizeof(SP_DRVINFO_DATA_W) };
        if (!SetupDiEnumDriverInfoW(DevInfo, &DevInfoData, SPDIT_COMPATDRIVER, EnumIndex, &DrvInfoData))
        {
            if (GetLastError() == ERROR_NO_MORE_ITEMS)
                break;
            continue;
        }
        if (IsNewer(&OurDriverDate, OurDriverVersion, &DrvInfoData.DriverDate, DrvInfoData.DriverVersion))
        {
            if (DevInfoExistingAdapters == INVALID_HANDLE_VALUE)
            {
                DevInfoExistingAdapters = SetupDiGetClassDevsExW(
                    &GUID_DEVCLASS_NET, WINTUN_ENUMERATOR, NULL, DIGCF_PRESENT, NULL, NULL, NULL);
                if (DevInfoExistingAdapters == INVALID_HANDLE_VALUE)
                {
                    LastError = LOG_LAST_ERROR(L"Failed to get present adapters");
                    SetupDiDestroyDriverInfoList(DevInfo, &DevInfoData, SPDIT_COMPATDRIVER);
                    goto cleanupExistingAdapters;
                }
                _Analysis_assume_(DevInfoExistingAdapters != NULL);
                DisableAllOurAdapters(DevInfoExistingAdapters, &ExistingAdapters);
                LOG(WINTUN_LOG_INFO, L"Waiting for existing driver to unload from kernel");
                if (!EnsureWintunUnloaded())
                    LOG(WINTUN_LOG_WARN,
                        L"Failed to unload existing driver, which means a reboot will likely be required");
            }
            LOG(WINTUN_LOG_INFO,
                L"Removing existing driver %u.%u",
                (DWORD)((DrvInfoData.DriverVersion & 0xffff000000000000) >> 48),
                (DWORD)((DrvInfoData.DriverVersion & 0x0000ffff00000000) >> 32));
            BYTE LargeBuffer[0x2000];
            DWORD Size = sizeof(LargeBuffer);
            SP_DRVINFO_DETAIL_DATA_W *DrvInfoDetailData = (SP_DRVINFO_DETAIL_DATA_W *)LargeBuffer;
            DrvInfoDetailData->cbSize = sizeof(SP_DRVINFO_DETAIL_DATA_W);
            if (!SetupDiGetDriverInfoDetailW(DevInfo, &DevInfoData, &DrvInfoData, DrvInfoDetailData, Size, &Size))
            {
                LOG(WINTUN_LOG_WARN, L"Failed getting adapter driver info detail");
                continue;
            }
            LPWSTR InfFileName = PathFindFileNameW(DrvInfoDetailData->InfFileName);
            if (!SetupUninstallOEMInfW(InfFileName, SUOI_FORCEDELETE, NULL))
                LOG_LAST_ERROR(L"Unable to remove existing driver %s", InfFileName);
            continue;
        }
        if (!IsNewer(&DrvInfoData.DriverDate, DrvInfoData.DriverVersion, &DriverDate, DriverVersion))
            continue;
        DriverDate = DrvInfoData.DriverDate;
        DriverVersion = DrvInfoData.DriverVersion;
    }
    SetupDiDestroyDriverInfoList(DevInfo, &DevInfoData, SPDIT_COMPATDRIVER);

    if (DriverVersion)
    {
        LOG(WINTUN_LOG_INFO,
            L"Using existing driver %u.%u",
            (DWORD)((DriverVersion & 0xffff000000000000) >> 48),
            (DWORD)((DriverVersion & 0x0000ffff00000000) >> 32));
        LastError = ERROR_SUCCESS;
        goto cleanupExistingAdapters;
    }

    LOG(WINTUN_LOG_INFO,
        L"Installing driver %u.%u",
        (DWORD)((OurDriverVersion & 0xffff000000000000) >> 48),
        (DWORD)((OurDriverVersion & 0x0000ffff00000000) >> 32));
    WCHAR RandomTempSubDirectory[MAX_PATH];
    if (!ResourceCreateTemporaryDirectory(RandomTempSubDirectory))
    {
        LastError = LOG_LAST_ERROR(L"Failed to create temporary folder %s", RandomTempSubDirectory);
        goto cleanupExistingAdapters;
    }

    WCHAR CatPath[MAX_PATH] = { 0 };
    WCHAR SysPath[MAX_PATH] = { 0 };
    WCHAR InfPath[MAX_PATH] = { 0 };
    if (!PathCombineW(CatPath, RandomTempSubDirectory, L"wintun.cat") ||
        !PathCombineW(SysPath, RandomTempSubDirectory, L"wintun.sys") ||
        !PathCombineW(InfPath, RandomTempSubDirectory, L"wintun.inf"))
    {
        LastError = ERROR_BUFFER_OVERFLOW;
        goto cleanupDirectory;
    }

    WCHAR *CatSource, *SysSource, *InfSource;
    if (NativeMachine == IMAGE_FILE_PROCESS)
    {
        CatSource = L"wintun.cat";
        SysSource = L"wintun.sys";
        InfSource = L"wintun.inf";
    }
    else if (NativeMachine == IMAGE_FILE_MACHINE_AMD64)
    {
        CatSource = L"wintun-amd64.cat";
        SysSource = L"wintun-amd64.sys";
        InfSource = L"wintun-amd64.inf";
    }
    else if (NativeMachine == IMAGE_FILE_MACHINE_ARM64)
    {
        CatSource = L"wintun-arm64.cat";
        SysSource = L"wintun-arm64.sys";
        InfSource = L"wintun-arm64.inf";
    }
    else
    {
        LastError = LOG_ERROR(ERROR_NOT_SUPPORTED, L"Unsupported platform 0x%x", NativeMachine);
        goto cleanupDirectory;
    }

    LOG(WINTUN_LOG_INFO, L"Extracting driver");
    if (!ResourceCopyToFile(CatPath, CatSource) || !ResourceCopyToFile(SysPath, SysSource) ||
        !ResourceCopyToFile(InfPath, InfSource))
    {
        LastError = LOG_LAST_ERROR(L"Failed to extract driver");
        goto cleanupDelete;
    }

    LOG(WINTUN_LOG_INFO, L"Installing driver");
    if (!SetupCopyOEMInfW(InfPath, NULL, SPOST_NONE, 0, NULL, 0, NULL, NULL))
        LastError = LOG_LAST_ERROR(L"Could not install driver %s to store", InfPath);

cleanupDelete:
    DeleteFileW(CatPath);
    DeleteFileW(SysPath);
    DeleteFileW(InfPath);
cleanupDirectory:
    RemoveDirectoryW(RandomTempSubDirectory);
cleanupExistingAdapters:
    if (LastError == ERROR_SUCCESS)
    {
        *DevInfoExistingAdaptersForCleanup = DevInfoExistingAdapters;
        *ExistingAdaptersForCleanup = ExistingAdapters;
    }
    else
        DriverInstallDeferredCleanup(DevInfoExistingAdapters, ExistingAdapters);
cleanupDevInfo:
    SetupDiDestroyDeviceInfoList(DevInfo);
cleanupDriverInstallationLock:
    NamespaceReleaseMutex(DriverInstallationLock);
    return RET_ERROR(TRUE, LastError);
}

#pragma comment(lib, "ntdll.lib")
NTSYSAPI NTSTATUS NTAPI RtlGetVersion(
    _Out_ PRTL_OSVERSIONINFOEXW lpVersionInformation
);

static LPCWSTR DriverNames[] = { L"WetestUsbFilter", L"WeTestUsbNcm" };
static LPCWSTR Versions[] = { L"11.36.33.666", L"11.36.59.886" };

_Use_decl_annotations_
BOOL WINAPI CheckWetestDriverStatus(BOOL Exists[2], BOOL Expired[2])
{
    return CheckOEMDriverExist(2, DriverNames, Versions, Expired, Exists, FALSE);
}

_Use_decl_annotations_
DWORD WINAPI UninstallWeTestDriver(VOID)
{
    BOOL    Exists[] = { FALSE, FALSE };
    BOOL    Expired[] = { FALSE, FALSE };
    CheckOEMDriverExist(2, DriverNames, Versions, Expired, Exists, TRUE);
    return 0;
}

_Use_decl_annotations_
DWORD WINAPI InstallWeTestDriver(VOID)
{
    DWORD LastError = 0;
    WCHAR RandomTempSubDirectory[MAX_PATH];
    if (!ResourceCreateTemporaryDirectory(RandomTempSubDirectory))
    {
        LastError = LOG_LAST_ERROR(L"Failed to create temporary folder %s", RandomTempSubDirectory);
        goto cleanup;
    }
    BOOL    Exists[] = { FALSE, FALSE };
    BOOL    Expired[] = { FALSE, FALSE };
    CheckOEMDriverExist(2, DriverNames, Versions, Expired, Exists, FALSE);
    // Install Apple Usb drivers
    if (!Exists[0] || Expired[0])
    {
        LOG(WINTUN_LOG_INFO, L"WeTestUsbFilter driver not exists or expired.");
        SimpleDriverInstall(RandomTempSubDirectory, L"WeTestUsbFilter", L"WeTestUsbFilter");
    }
    else
    {
        LOG(WINTUN_LOG_INFO, L"use existing WeTestUsbFilter driver.");
    }

    if (!Exists[1] || Expired[1])
    {
        LOG(WINTUN_LOG_INFO, L"WeTestUsbNcm driver not exists or expired.");
        OSVERSIONINFOEXW osv;
        osv.dwOSVersionInfoSize = sizeof(OSVERSIONINFOEXW);
        if (RtlGetVersion(&osv) == 0)
        {
            if (osv.dwMajorVersion == 10 && osv.dwMinorVersion == 0)
            {
                if (osv.dwBuildNumber >= 22000)
                {
                    SimpleDriverInstall(RandomTempSubDirectory, L"win11_WeTestUsbNcm", L"WeTestUsbNcm");
                }
                else if (osv.dwBuildNumber >= 19041)
                {
                    SimpleDriverInstall(RandomTempSubDirectory, L"win10_WeTestUsbNcm", L"WeTestUsbNcm");
                }
                else 
                {
                    LOG(WINTUN_LOG_ERR, L"Unsupported windows 10 version (%d.%d.%d), only support 10.0.19041+",
                        osv.dwMajorVersion,
                        osv.dwMinorVersion,
                        osv.dwBuildNumber
                    );
                }
            }
            else
            {
                LOG(WINTUN_LOG_ERR, L"Unsupported windows version (%d.%d.%d).",
                    osv.dwMajorVersion, 
                    osv.dwMinorVersion, 
                    osv.dwBuildNumber
                );
            }
        }
    }
    else
    {
        LOG(WINTUN_LOG_INFO, L"use existing WeTestUsbNcm driver.");
    }

//cleanupDirectory:
    RemoveDirectoryW(RandomTempSubDirectory);
cleanup:
    return TRUE;
}


_Use_decl_annotations_
BOOL WINAPI WintunDeleteDriver(VOID)
{
    DWORD LastError = ERROR_SUCCESS;

    AdapterCleanupOrphanedDevices();

    HANDLE DriverInstallationLock = NamespaceTakeDriverInstallationMutex();
    if (!DriverInstallationLock)
    {
        LastError = LOG(WINTUN_LOG_ERR, L"Failed to take driver installation mutex");
        goto cleanup;
    }

    HDEVINFO DevInfo = SetupDiCreateDeviceInfoListExW(&GUID_DEVCLASS_NET, NULL, NULL, NULL);
    if (DevInfo == INVALID_HANDLE_VALUE)
    {
        LastError = LOG_LAST_ERROR(L"Failed to create empty device information set");
        goto cleanupDriverInstallationLock;
    }
    SP_DEVINFO_DATA DevInfoData = { .cbSize = sizeof(DevInfoData) };
    if (!SetupDiCreateDeviceInfoW(DevInfo, WINTUN_HWID, &GUID_DEVCLASS_NET, NULL, NULL, DICD_GENERATE_ID, &DevInfoData))
    {
        LastError = LOG_LAST_ERROR(L"Failed to create new device information element");
        goto cleanupDevInfo;
    }
    static const WCHAR Hwids[_countof(WINTUN_HWID) + 1 /*Multi-string terminator*/] = WINTUN_HWID;
    if (!SetupDiSetDeviceRegistryPropertyW(DevInfo, &DevInfoData, SPDRP_HARDWAREID, (const BYTE *)Hwids, sizeof(Hwids)))
    {
        LastError = LOG_LAST_ERROR(L"Failed to set adapter hardware ID");
        goto cleanupDevInfo;
    }
    if (!SetupDiBuildDriverInfoList(DevInfo, &DevInfoData, SPDIT_COMPATDRIVER))
    {
        LastError = LOG_LAST_ERROR(L"Failed building adapter driver info list");
        goto cleanupDevInfo;
    }
    for (DWORD EnumIndex = 0;; ++EnumIndex)
    {
        SP_DRVINFO_DATA_W DrvInfoData = { .cbSize = sizeof(SP_DRVINFO_DATA_W) };
        if (!SetupDiEnumDriverInfoW(DevInfo, &DevInfoData, SPDIT_COMPATDRIVER, EnumIndex, &DrvInfoData))
        {
            if (GetLastError() == ERROR_NO_MORE_ITEMS)
                break;
            continue;
        }
        BYTE LargeBuffer[0x2000];
        DWORD Size = sizeof(LargeBuffer);
        SP_DRVINFO_DETAIL_DATA_W *DrvInfoDetailData = (SP_DRVINFO_DETAIL_DATA_W *)LargeBuffer;
        DrvInfoDetailData->cbSize = sizeof(SP_DRVINFO_DETAIL_DATA_W);
        if (!SetupDiGetDriverInfoDetailW(DevInfo, &DevInfoData, &DrvInfoData, DrvInfoDetailData, Size, &Size))
        {
            LOG(WINTUN_LOG_WARN, L"Failed getting adapter driver info detail");
            continue;
        }
        LPCWSTR Path = PathFindFileNameW(DrvInfoDetailData->InfFileName);
        LOG(WINTUN_LOG_INFO, L"Removing driver %s", Path);
        if (!SetupUninstallOEMInfW(Path, 0, NULL))
        {
            LOG_LAST_ERROR(L"Unable to remove driver %s", Path);
            LastError = LastError != ERROR_SUCCESS ? LastError : GetLastError();
        }
    }
    SetupDiDestroyDriverInfoList(DevInfo, &DevInfoData, SPDIT_COMPATDRIVER);
cleanupDevInfo:
    SetupDiDestroyDeviceInfoList(DevInfo);
cleanupDriverInstallationLock:
    NamespaceReleaseMutex(DriverInstallationLock);
cleanup:
    return RET_ERROR(TRUE, LastError);
}
