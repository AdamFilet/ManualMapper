#pragma once

#include <Windows.h>

typedef struct _PEB
{
    UCHAR InheritedAddressSpace;                                            //0x0
    UCHAR ReadImageFileExecOptions;                                         //0x1
    UCHAR BeingDebugged;                                                    //0x2
    union
    {
        UCHAR BitField;                                                     //0x3
        struct
        {
            UCHAR ImageUsesLargePages : 1;                                    //0x3
            UCHAR IsProtectedProcess : 1;                                     //0x3
            UCHAR IsImageDynamicallyRelocated : 1;                            //0x3
            UCHAR SkipPatchingUser32Forwarders : 1;                           //0x3
            UCHAR IsPackagedProcess : 1;                                      //0x3
            UCHAR IsAppContainer : 1;                                         //0x3
            UCHAR IsProtectedProcessLight : 1;                                //0x3
            UCHAR IsLongPathAwareProcess : 1;                                 //0x3
        };
    };
    UCHAR Padding0[4];                                                      //0x4
    void* Mutant;                                                           //0x8
    void* ImageBaseAddress;                                                 //0x10
    void* Ldr;                                                              //0x18
    void* ProcessParameters;                                                //0x20
    void* SubSystemData;                                                    //0x28
    void* ProcessHeap;                                                      //0x30
    void* FastPebLock;                                                      //0x38
    void* volatile AtlThunkSListPtr;                                        //0x40
    void* IFEOKey;                                                          //0x48
    union
    {
        ULONG CrossProcessFlags;                                            //0x50
        struct
        {
            ULONG ProcessInJob : 1;                                           //0x50
            ULONG ProcessInitializing : 1;                                    //0x50
            ULONG ProcessUsingVEH : 1;                                        //0x50
            ULONG ProcessUsingVCH : 1;                                        //0x50
            ULONG ProcessUsingFTH : 1;                                        //0x50
            ULONG ProcessPreviouslyThrottled : 1;                             //0x50
            ULONG ProcessCurrentlyThrottled : 1;                              //0x50
            ULONG ProcessImagesHotPatched : 1;                                //0x50
            ULONG ReservedBits0 : 24;                                         //0x50
        };
    };
    UCHAR Padding1[4];                                                      //0x54
    union
    {
        void* KernelCallbackTable;                                          //0x58
        void* UserSharedInfoPtr;                                            //0x58
    };
    ULONG SystemReserved;                                                   //0x60
    ULONG AtlThunkSListPtr32;                                               //0x64
    void* ApiSetMap;                                                        //0x68
}PEB, * PPEB;

struct _CLIENT_ID
{
    VOID* UniqueProcess;                                                    //0x0
    VOID* UniqueThread;                                                     //0x8
};

typedef struct _TEB
{
    struct _NT_TIB NtTib;                                                   //0x0
    VOID* EnvironmentPointer;                                               //0x38
    struct _CLIENT_ID ClientId;                                             //0x40
    VOID* ActiveRpcHandle;                                                  //0x50
    VOID* ThreadLocalStoragePointer;                                        //0x58
    struct _PEB* ProcessEnvironmentBlock;                                   //0x60
    ULONG LastErrorValue;                                                   //0x68
}TEB, * PTEB;

typedef struct _API_SET_VALUE_ENTRY
{
    ULONG Flags;
    ULONG NameOffset;
    ULONG NameLength;
    ULONG ValueOffset;
    ULONG ValueLength;
} API_SET_VALUE_ENTRY, * PAPI_SET_VALUE_ENTRY;

typedef struct _API_SET_VALUE_ARRAY
{
    ULONG Flags;
    ULONG NameOffset;
    ULONG Unk;
    ULONG NameLength;
    ULONG DataOffset;
    ULONG Count;

    inline PAPI_SET_VALUE_ENTRY entry(void* pApiSet, DWORD i)
    {
        return (PAPI_SET_VALUE_ENTRY)((BYTE*)pApiSet + DataOffset + i * sizeof(API_SET_VALUE_ENTRY));
    }
} API_SET_VALUE_ARRAY, * PAPI_SET_VALUE_ARRAY;

typedef struct _API_SET_NAMESPACE_ENTRY
{
    ULONG Limit;
    ULONG Size;
} API_SET_NAMESPACE_ENTRY, * PAPI_SET_NAMESPACE_ENTRY;

typedef struct _API_SET_NAMESPACE_ARRAY
{
    ULONG Version;
    ULONG Size;
    ULONG Flags;
    ULONG Count;
    ULONG Start;
    ULONG End;
    ULONG Unk[2];

    inline PAPI_SET_NAMESPACE_ENTRY entry(DWORD i)
    {
        return (PAPI_SET_NAMESPACE_ENTRY)((BYTE*)this + End + i * sizeof(API_SET_NAMESPACE_ENTRY));
    }

    inline PAPI_SET_VALUE_ARRAY valArray(PAPI_SET_NAMESPACE_ENTRY pEntry)
    {
        return (PAPI_SET_VALUE_ARRAY)((BYTE*)this + Start + sizeof(API_SET_VALUE_ARRAY) * pEntry->Size);
    }

    inline ULONG apiName(PAPI_SET_NAMESPACE_ENTRY pEntry, wchar_t* output)
    {
        auto pArray = valArray(pEntry);
        memcpy(output, (char*)this + pArray->NameOffset, pArray->NameLength);
        return  pArray->NameLength;
    }
} API_SET_NAMESPACE_ARRAY, * PAPI_SET_NAMESPACE_ARRAY;


const uint64_t API_ = (uint64_t)0x2D004900500041; // L"api-"
const uint64_t EXT_ = (uint64_t)0x2D005400580045; // L"ext-";