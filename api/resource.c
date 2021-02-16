/* SPDX-License-Identifier: GPL-2.0
 *
 * Copyright (C) 2018-2021 WireGuard LLC. All Rights Reserved.
 */

#include "entry.h"
#include "logger.h"
#include "resource.h"
#include <Windows.h>

_Return_type_success_(return != NULL) _Ret_bytecount_(*Size) const
    void *ResourceGetAddress(_In_z_ const WCHAR *ResourceName, _Out_ DWORD *Size)
{
    HRSRC FoundResource = FindResourceW(ResourceModule, ResourceName, RT_RCDATA);
    if (!FoundResource)
    {
        LOG_LAST_ERROR(L"Failed to find resource %s", ResourceName);
        return NULL;
    }
    *Size = SizeofResource(ResourceModule, FoundResource);
    if (!*Size)
    {
        LOG_LAST_ERROR(L"Failed to query resource %s size", ResourceName);
        return NULL;
    }
    HGLOBAL LoadedResource = LoadResource(ResourceModule, FoundResource);
    if (!LoadedResource)
    {
        LOG_LAST_ERROR(L"Failed to load resource %s", ResourceName);
        return NULL;
    }
    BYTE *Address = LockResource(LoadedResource);
    if (!Address)
    {
        LOG(WINTUN_LOG_ERR, L"Failed to lock resource %s", ResourceName);
        SetLastError(ERROR_LOCK_FAILED);
        return NULL;
    }
    return Address;
}

_Return_type_success_(return != FALSE) BOOL
    ResourceCopyToFile(_In_z_ const WCHAR *DestinationPath, _In_z_ const WCHAR *ResourceName)
{
    DWORD SizeResource;
    const void *LockedResource = ResourceGetAddress(ResourceName, &SizeResource);
    if (!LockedResource)
    {
        LOG(WINTUN_LOG_ERR, L"Failed to locate resource %s", ResourceName);
        return FALSE;
    }
    HANDLE DestinationHandle = CreateFileW(
        DestinationPath,
        GENERIC_WRITE,
        0,
        &SecurityAttributes,
        CREATE_NEW,
        FILE_ATTRIBUTE_NORMAL | FILE_ATTRIBUTE_TEMPORARY,
        NULL);
    if (DestinationHandle == INVALID_HANDLE_VALUE)
    {
        LOG_LAST_ERROR(L"Failed to create file %s", DestinationPath);
        return FALSE;
    }
    DWORD BytesWritten;
    DWORD LastError;
    if (!WriteFile(DestinationHandle, LockedResource, SizeResource, &BytesWritten, NULL))
    {
        LastError = LOG_LAST_ERROR(L"Failed to write file %s", DestinationPath);
        goto cleanupDestinationHandle;
    }
    if (BytesWritten != SizeResource)
    {
        LOG(WINTUN_LOG_ERR,
            L"Incomplete write to %s (written: %u, expected: %u)",
            DestinationPath,
            BytesWritten,
            SizeResource);
        LastError = ERROR_WRITE_FAULT;
        goto cleanupDestinationHandle;
    }
    LastError = ERROR_SUCCESS;
cleanupDestinationHandle:
    CloseHandle(DestinationHandle);
    return RET_ERROR(TRUE, LastError);
}
