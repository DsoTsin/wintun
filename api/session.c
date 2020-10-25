/* SPDX-License-Identifier: GPL-2.0
 *
 * Copyright (C) 2018-2020 WireGuard LLC. All Rights Reserved.
 */

#include "pch.h"

#pragma warning(disable : 4200) /* nonstandard: zero-sized array in struct/union */

#define TUN_ALIGNMENT sizeof(ULONG)
#define TUN_ALIGN(Size) (((ULONG)(Size) + ((ULONG)TUN_ALIGNMENT - 1)) & ~((ULONG)TUN_ALIGNMENT - 1))
#define TUN_IS_ALIGNED(Size) (!((ULONG)(Size) & ((ULONG)TUN_ALIGNMENT - 1)))
#define TUN_MAX_PACKET_SIZE TUN_ALIGN(sizeof(TUN_PACKET) + WINTUN_MAX_IP_PACKET_SIZE)
#define TUN_RING_CAPACITY(Size) ((Size) - sizeof(TUN_RING) - (TUN_MAX_PACKET_SIZE - TUN_ALIGNMENT))
#define TUN_RING_SIZE(Capacity) (sizeof(TUN_RING) + (Capacity) + (TUN_MAX_PACKET_SIZE - TUN_ALIGNMENT))
#define TUN_RING_WRAP(Value, Capacity) ((Value) & (Capacity - 1))
#define LOCK_SPIN_COUNT 0x10000
#define TUN_PACKET_RELEASE ((DWORD)0x80000000)

typedef struct _TUN_PACKET
{
    ULONG Size;
    UCHAR Data[];
} TUN_PACKET;

typedef struct _TUN_RING
{
    volatile ULONG Head;
    volatile ULONG Tail;
    volatile LONG Alertable;
    UCHAR Data[];
} TUN_RING;

#define TUN_IOCTL_REGISTER_RINGS CTL_CODE(51820U, 0x970U, METHOD_BUFFERED, FILE_READ_DATA | FILE_WRITE_DATA)

typedef struct _TUN_REGISTER_RINGS
{
    struct
    {
        ULONG RingSize;
        TUN_RING *Ring;
        HANDLE TailMoved;
    } Send, Receive;
} TUN_REGISTER_RINGS;

typedef struct _TUN_SESSION
{
    ULONG Capacity;
    struct
    {
        ULONG Tail;
        ULONG TailRelease;
        ULONG PacketsToRelease;
        CRITICAL_SECTION Lock;
    } Receive;
    struct
    {
        ULONG Head;
        ULONG HeadRelease;
        ULONG PacketsToRelease;
        CRITICAL_SECTION Lock;
    } Send;
    TUN_REGISTER_RINGS Descriptor;
    HANDLE Handle;
} TUN_SESSION;

WINTUN_STATUS WINAPI
WintunStartSession(_In_ const WINTUN_ADAPTER *Adapter, _In_ DWORD Capacity, _Out_ TUN_SESSION **Session)
{
    *Session = HeapAlloc(ModuleHeap, HEAP_ZERO_MEMORY, sizeof(TUN_SESSION));
    if (!*Session)
        return LOG(WINTUN_LOG_ERR, L"Out of memory"), ERROR_OUTOFMEMORY;
    const ULONG RingSize = TUN_RING_SIZE(Capacity);
    DWORD Result;
    BYTE *AllocatedRegion = VirtualAlloc(0, (size_t)RingSize * 2, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!AllocatedRegion)
    {
        Result = LOG_LAST_ERROR(L"Failed to allocate ring memory");
        goto cleanupRings;
    }
    (*Session)->Descriptor.Send.RingSize = RingSize;
    (*Session)->Descriptor.Send.Ring = (TUN_RING *)AllocatedRegion;
    (*Session)->Descriptor.Send.TailMoved = CreateEventW(SecurityAttributes, FALSE, FALSE, NULL);
    if (!(*Session)->Descriptor.Send.TailMoved)
    {
        Result = LOG_LAST_ERROR(L"Failed to create send event");
        goto cleanupAllocatedRegion;
    }

    (*Session)->Descriptor.Receive.RingSize = RingSize;
    (*Session)->Descriptor.Receive.Ring = (TUN_RING *)(AllocatedRegion + RingSize);
    (*Session)->Descriptor.Receive.TailMoved = CreateEvent(SecurityAttributes, FALSE, FALSE, NULL);
    if (!(*Session)->Descriptor.Receive.TailMoved)
    {
        Result = LOG_LAST_ERROR(L"Failed to create receive event");
        goto cleanupSendTailMoved;
    }

    Result = WintunGetAdapterDeviceObject(Adapter, &(*Session)->Handle);
    if (Result != ERROR_SUCCESS)
    {
        LOG(WINTUN_LOG_ERR, L"Failed to open adapter device object");
        goto cleanupReceiveTailMoved;
    }
    DWORD BytesReturned;
    if (!DeviceIoControl(
            (*Session)->Handle,
            TUN_IOCTL_REGISTER_RINGS,
            &(*Session)->Descriptor,
            sizeof(TUN_REGISTER_RINGS),
            NULL,
            0,
            &BytesReturned,
            NULL))
    {
        Result = LOG_LAST_ERROR(L"Failed to perform ioctl");
        goto cleanupHandle;
    }
    (*Session)->Capacity = Capacity;
    (void)InitializeCriticalSectionAndSpinCount(&(*Session)->Receive.Lock, LOCK_SPIN_COUNT);
    (void)InitializeCriticalSectionAndSpinCount(&(*Session)->Send.Lock, LOCK_SPIN_COUNT);
    return ERROR_SUCCESS;
cleanupHandle:
    CloseHandle((*Session)->Handle);
cleanupReceiveTailMoved:
    CloseHandle((*Session)->Descriptor.Receive.TailMoved);
cleanupSendTailMoved:
    CloseHandle((*Session)->Descriptor.Send.TailMoved);
cleanupAllocatedRegion:
    VirtualFree(AllocatedRegion, 0, MEM_RELEASE);
cleanupRings:
    HeapFree(ModuleHeap, 0, *Session);
    *Session = NULL;
    return Result;
}

void WINAPI
WintunEndSession(_In_ TUN_SESSION *Session)
{
    SetEvent(Session->Descriptor.Send.TailMoved); // wake the reader if it's sleeping
    DeleteCriticalSection(&Session->Send.Lock);
    DeleteCriticalSection(&Session->Receive.Lock);
    CloseHandle(Session->Handle);
    CloseHandle(Session->Descriptor.Send.TailMoved);
    CloseHandle(Session->Descriptor.Receive.TailMoved);
    VirtualFree(Session->Descriptor.Send.Ring, 0, MEM_RELEASE);
    HeapFree(ModuleHeap, 0, Session);
}

BOOL WINAPI
WintunIsPacketAvailable(_In_ TUN_SESSION *Session)
{
    return Session->Send.Head != InterlockedGetU(&Session->Descriptor.Send.Ring->Tail);
}

WINTUN_STATUS WINAPI
WintunWaitForPacket(_In_ TUN_SESSION *Session, _In_ DWORD Milliseconds)
{
    return WaitForSingleObject(Session->Descriptor.Send.TailMoved, Milliseconds);
}

WINTUN_STATUS WINAPI
WintunReceivePacket(_In_ TUN_SESSION *Session, _Out_bytecapcount_(*PacketSize) BYTE **Packet, _Out_ DWORD *PacketSize)
{
    DWORD Result;
    EnterCriticalSection(&Session->Send.Lock);
    if (Session->Send.Head >= Session->Capacity)
    {
        Result = ERROR_HANDLE_EOF;
        goto cleanup;
    }
    const ULONG BuffTail = InterlockedGetU(&Session->Descriptor.Send.Ring->Tail);
    if (BuffTail >= Session->Capacity)
    {
        Result = ERROR_HANDLE_EOF;
        goto cleanup;
    }
    if (Session->Send.Head == BuffTail)
    {
        Result = ERROR_NO_MORE_ITEMS;
        goto cleanup;
    }
    const ULONG BuffContent = TUN_RING_WRAP(BuffTail - Session->Send.Head, Session->Capacity);
    if (BuffContent < sizeof(TUN_PACKET))
    {
        Result = ERROR_INVALID_DATA;
        goto cleanup;
    }
    TUN_PACKET *BuffPacket = (TUN_PACKET *)&Session->Descriptor.Send.Ring->Data[Session->Send.Head];
    if (BuffPacket->Size > WINTUN_MAX_IP_PACKET_SIZE)
    {
        Result = ERROR_INVALID_DATA;
        goto cleanup;
    }
    const ULONG AlignedPacketSize = TUN_ALIGN(sizeof(TUN_PACKET) + BuffPacket->Size);
    if (AlignedPacketSize > BuffContent)
    {
        Result = ERROR_INVALID_DATA;
        goto cleanup;
    }
    *PacketSize = BuffPacket->Size;
    *Packet = BuffPacket->Data;
    Session->Send.Head = TUN_RING_WRAP(Session->Send.Head + AlignedPacketSize, Session->Capacity);
    Session->Send.PacketsToRelease++;
    Result = ERROR_SUCCESS;
cleanup:
    LeaveCriticalSection(&Session->Send.Lock);
    return Result;
}

void WINAPI
WintunReceiveRelease(_In_ TUN_SESSION *Session, _In_ const BYTE *Packet)
{
    EnterCriticalSection(&Session->Send.Lock);
    TUN_PACKET *ReleasedBuffPacket = (TUN_PACKET *)(Packet - offsetof(TUN_PACKET, Data));
    ReleasedBuffPacket->Size |= TUN_PACKET_RELEASE;
    while (Session->Send.PacketsToRelease)
    {
        const TUN_PACKET *BuffPacket = (TUN_PACKET *)&Session->Descriptor.Send.Ring->Data[Session->Send.HeadRelease];
        if ((BuffPacket->Size & TUN_PACKET_RELEASE) == 0)
            break;
        const ULONG AlignedPacketSize = TUN_ALIGN(sizeof(TUN_PACKET) + (BuffPacket->Size & ~TUN_PACKET_RELEASE));
        Session->Send.HeadRelease = TUN_RING_WRAP(Session->Send.HeadRelease + AlignedPacketSize, Session->Capacity);
        Session->Send.PacketsToRelease--;
    }
    InterlockedSetU(&Session->Descriptor.Send.Ring->Head, Session->Send.HeadRelease);
    LeaveCriticalSection(&Session->Send.Lock);
}

WINTUN_STATUS WINAPI
WintunAllocateSendPacket(_In_ TUN_SESSION *Session, _In_ DWORD PacketSize, _Out_bytecapcount_(PacketSize) BYTE **Packet)
{
    DWORD Result;
    EnterCriticalSection(&Session->Receive.Lock);
    if (Session->Receive.Tail >= Session->Capacity)
    {
        Result = ERROR_HANDLE_EOF;
        goto cleanup;
    }
    const ULONG AlignedPacketSize = TUN_ALIGN(sizeof(TUN_PACKET) + PacketSize);
    const ULONG BuffHead = InterlockedGetU(&Session->Descriptor.Receive.Ring->Head);
    if (BuffHead >= Session->Capacity)
    {
        Result = ERROR_HANDLE_EOF;
        goto cleanup;
    }
    const ULONG BuffSpace = TUN_RING_WRAP(BuffHead - Session->Receive.Tail - TUN_ALIGNMENT, Session->Capacity);
    if (AlignedPacketSize > BuffSpace)
    {
        Result = ERROR_BUFFER_OVERFLOW;
        goto cleanup;
    }
    TUN_PACKET *BuffPacket = (TUN_PACKET *)&Session->Descriptor.Receive.Ring->Data[Session->Receive.Tail];
    BuffPacket->Size = PacketSize | TUN_PACKET_RELEASE;
    *Packet = BuffPacket->Data;
    Session->Receive.Tail = TUN_RING_WRAP(Session->Receive.Tail + AlignedPacketSize, Session->Capacity);
    Session->Receive.PacketsToRelease++;
    Result = ERROR_SUCCESS;
cleanup:
    LeaveCriticalSection(&Session->Receive.Lock);
    return Result;
}

void WINAPI
WintunSendPacket(_In_ TUN_SESSION *Session, _In_ const BYTE *Packet)
{
    EnterCriticalSection(&Session->Receive.Lock);
    TUN_PACKET *ReleasedBuffPacket = (TUN_PACKET *)(Packet - offsetof(TUN_PACKET, Data));
    ReleasedBuffPacket->Size &= ~TUN_PACKET_RELEASE;
    while (Session->Receive.PacketsToRelease)
    {
        const TUN_PACKET *BuffPacket =
            (TUN_PACKET *)&Session->Descriptor.Receive.Ring->Data[Session->Receive.TailRelease];
        if (BuffPacket->Size & TUN_PACKET_RELEASE)
            break;
        const ULONG AlignedPacketSize = TUN_ALIGN(sizeof(TUN_PACKET) + BuffPacket->Size);
        Session->Receive.TailRelease =
            TUN_RING_WRAP(Session->Receive.TailRelease + AlignedPacketSize, Session->Capacity);
        Session->Receive.PacketsToRelease--;
    }
    InterlockedSetU(&Session->Descriptor.Receive.Ring->Tail, Session->Receive.TailRelease);
    if (InterlockedGet(&Session->Descriptor.Receive.Ring->Alertable))
        SetEvent(Session->Descriptor.Receive.TailMoved);
    LeaveCriticalSection(&Session->Receive.Lock);
}