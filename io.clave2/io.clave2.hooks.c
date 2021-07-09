#include <Windows.h>
#include <winternl.h>
#include "../kitchen_sink/kitchen_sink.h"
#include "io.clave2.emulator.h"

#include "io.clave2.hooks.h"

typedef NTSTATUS __stdcall tNtCreateFile(PHANDLE FileHandle, DWORD DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PIO_STATUS_BLOCK IoStatusBlock, PLARGE_INTEGER AllocationSize, ULONG FileAttributes, ULONG ShareAccess, ULONG CreateDisposition, ULONG CreateOptions, PVOID EaBuffer, ULONG EaLength);
typedef NTSTATUS __stdcall tNtDeviceIoControlFile(HANDLE FileHandle, HANDLE Event, PIO_APC_ROUTINE ApcRoutine, PVOID ApcContext, PIO_STATUS_BLOCK IoStatusBlock, ULONG IoControlCode, PVOID InputBuffer, ULONG InputBufferLength, PVOID OutputBuffer, ULONG OutputBufferLength);
typedef NTSTATUS __stdcall tNtQueryInformationFile(HANDLE FileHandle, PIO_STATUS_BLOCK IoStatusBlock, PVOID FileInformation, ULONG Length, FILE_INFORMATION_CLASS FileInformationClass);

static tNtCreateFile* ntdll_NtCreateFile = 0;
static tNtDeviceIoControlFile* ntdll_NtDeviceIoControlFile = 0;
static tNtQueryInformationFile* ntdll_NtQueryInformationFile = 0;


#define FAKE_CLAVE2_HANDLE (HANDLE)0x8499

const WCHAR* clave2_device_address = L"hid#vid_";
static char* hid_registry[6] = {
        "HID\\VID_1BC0&PID_8101&REV_0100",
        "HID\\VID_1BC0&PID_8101",
        "HID\\VID_1BC0&UP:FFA0_U:0001",
        "HID_DEVICE_UP:FFA0_U:0001",
        "HID_DEVICE_UPR:FF00-FFFF",
        "HID_DEVICE"
};
// Warning: This will likely fuck up usb additions later on in the process... someone else can write a filter or add a fake device.
#define SPDRP_HARDWAREID 0x00000001
typedef BOOL __stdcall tSetupDiGetDeviceRegistryPropertyA(void* DeviceInfoSet, void* DeviceInfoData, DWORD Property, PDWORD PropertyRegDataType, PBYTE PropertyBuffer, DWORD PropertyBufferSize, PDWORD RequiredSize);
tSetupDiGetDeviceRegistryPropertyA* real_SetupDiGetDeviceRegistryPropertyA = 0;
static void* last_DeviceInfoSet;
BOOL __stdcall x_SetupDiGetDeviceRegistryPropertyA(void* DeviceInfoSet, void* DeviceInfoData, DWORD Property, PDWORD PropertyRegDataType, PBYTE PropertyBuffer, DWORD PropertyBufferSize, PDWORD RequiredSize) {
    if(Property == SPDRP_HARDWAREID){
        last_DeviceInfoSet = DeviceInfoSet;
        unsigned int buffer_size = 0;
        for(int i=0; i < 6; i++){
            buffer_size += strlen(hid_registry[i]) + 1;
        }
        if (PropertyBufferSize < buffer_size) {
            if (RequiredSize) {
                *RequiredSize = buffer_size;
            }
            return 1;
        }
        unsigned int offset = 0;
        for(int i=0;i < 6; i++){
            strcpy((char*)PropertyBuffer+offset, hid_registry[i]);
            offset += strlen(hid_registry[i]) + 1;
        }
        return 1;
    }
    return real_SetupDiGetDeviceRegistryPropertyA(DeviceInfoSet, DeviceInfoData, Property, PropertyRegDataType, PropertyBuffer, PropertyBufferSize,RequiredSize);
}

typedef BOOL __stdcall tSetupDiGetDeviceInterfaceDetailA(void* DeviceInfoSet, void* DeviceInterfaceData, void* DeviceInterfaceDetailData, DWORD DeviceInterfaceDetailDataSize, PDWORD RequiredSize, void* DeviceInfoData);
tSetupDiGetDeviceInterfaceDetailA* real_SetupDiGetDeviceInterfaceDetailA = 0;
BOOL __stdcall x_SetupDiGetDeviceInterfaceDetailA(void* DeviceInfoSet, void* DeviceInterfaceData, void* DeviceInterfaceDetailData, DWORD DeviceInterfaceDetailDataSize, PDWORD RequiredSize, void* DeviceInfoData) {
    if(DeviceInfoSet == last_DeviceInfoSet){
        char* target_interface_detail = "\\\\?\\hid#vid_1bc0&pid_8101#6&73ec4cf&0&0000#{4d1e55b2-f16f-11cf-88cb-001111000030}"; // GUID_DEVINTERFACE_HID
        unsigned int detail_size = 4 + strlen(target_interface_detail) + 1;
        if (DeviceInterfaceDetailDataSize < detail_size) {
            *RequiredSize = detail_size;
            return 1;
        }
        *(unsigned int*)DeviceInterfaceDetailData = 5;
        strcpy(DeviceInterfaceDetailData+4, target_interface_detail);
        return 1;
    }
    return real_SetupDiGetDeviceInterfaceDetailA(DeviceInfoSet, DeviceInterfaceData, DeviceInterfaceDetailData, DeviceInterfaceDetailDataSize, RequiredSize, DeviceInfoData);
}


NTSTATUS NTAPI x_NtCreateFile(PHANDLE FileHandle, DWORD DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PIO_STATUS_BLOCK IoStatusBlock, PLARGE_INTEGER AllocationSize, ULONG FileAttributes, ULONG ShareAccess, ULONG CreateDisposition, ULONG CreateOptions, PVOID EaBuffer, ULONG EaLength) {

    if (ObjectAttributes && ObjectAttributes->ObjectName && ObjectAttributes->ObjectName->Buffer) {
        //	DBG_printfW(L"[NtCreateFile]: %s", ObjectAttributes->ObjectName->Buffer);
        if (wcsstr(ObjectAttributes->ObjectName->Buffer, clave2_device_address)) {
            *FileHandle = FAKE_CLAVE2_HANDLE;
            return 0;
        }

    }

    return ntdll_NtCreateFile(FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock, AllocationSize, FileAttributes, ShareAccess, CreateDisposition, CreateOptions, EaBuffer, EaLength);
}

NTSTATUS NTAPI x_NtQueryInformationFile(HANDLE FileHandle, PIO_STATUS_BLOCK IoStatusBlock, PVOID FileInformation, ULONG Length, FILE_INFORMATION_CLASS FileInformationClass) {
    if (FileHandle != FAKE_CLAVE2_HANDLE) {
        return ntdll_NtQueryInformationFile(FileHandle, IoStatusBlock, FileInformation, Length, FileInformationClass);
    }

    switch (FileInformationClass) {
        case 0x05:  // FileStandardInformation
            *(unsigned short*)FileInformation = 0x280;
            *(unsigned short*)(FileInformation+8) = 0x280;
            *(unsigned char*)(FileInformation+16) = 0x01;
            break;
        case 0x0E: // FilePositionInformation
            *(unsigned short*)FileInformation = 0x280;
            break;
        case 0x10: // FileModeInformation
        case 0x23: // FileAttributeTagInformation
            *(unsigned char*)FileInformation = 0x20;
            break;
        default:
            DBG_printfA("[io.clave2]: Unhandled NtQueryInformationFile Thing: %d", FileInformationClass);
            ntdll_NtQueryInformationFile(FileHandle, IoStatusBlock, FileInformation, Length, FileInformationClass);
            DBG_print_buffer(FileInformation, Length);
            break;
    }
    return 0;
}

NTSTATUS NTAPI x_NtDeviceIoControlFile(HANDLE FileHandle, HANDLE Event, PIO_APC_ROUTINE ApcRoutine, PVOID ApcContext, PIO_STATUS_BLOCK IoStatusBlock, ULONG IoControlCode, PVOID InputBuffer, ULONG InputBufferLength, PVOID OutputBuffer, ULONG OutputBufferLength) {

    if (FileHandle != FAKE_CLAVE2_HANDLE) {
        return ntdll_NtDeviceIoControlFile(FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock, IoControlCode, InputBuffer, InputBufferLength, OutputBuffer, OutputBufferLength);
    }

    ProcessClave2IoctlWindows(IoControlCode, InputBuffer, InputBufferLength, OutputBuffer, OutputBufferLength);
    return 0;
}


int InitHooks() {

    if(!HotPatch_patch("setupapi.dll", "SetupDiGetDeviceRegistryPropertyA", 0x0C, x_SetupDiGetDeviceRegistryPropertyA, (void**)&real_SetupDiGetDeviceRegistryPropertyA)){return FALSE;}
    if(!HotPatch_patch("setupapi.dll", "SetupDiGetDeviceInterfaceDetailA", 0x0A, x_SetupDiGetDeviceInterfaceDetailA, (void**)&real_SetupDiGetDeviceInterfaceDetailA)){return FALSE;}
    if(!HotPatch_patch("ntdll.dll", "NtCreateFile", 0x10, x_NtCreateFile, (void**)&ntdll_NtCreateFile)){return FALSE;}
    if(!HotPatch_patch("ntdll.dll", "NtQueryInformationFile", 0x10, x_NtQueryInformationFile, (void**)&ntdll_NtQueryInformationFile)){return FALSE;}
    if(!HotPatch_patch("ntdll.dll", "NtDeviceIoControlFile", 0x10, x_NtDeviceIoControlFile, (void**)&ntdll_NtDeviceIoControlFile)){return FALSE;}

    return TRUE;
}
