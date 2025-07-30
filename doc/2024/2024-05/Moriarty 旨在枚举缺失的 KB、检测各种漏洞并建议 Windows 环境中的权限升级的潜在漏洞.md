#  Moriarty 旨在枚举缺失的 KB、检测各种漏洞并建议 Windows 环境中的权限升级的潜在漏洞   
 Ots安全   2024-05-01 17:59  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/bL2iaicTYdZn7gtxSFZlfuCW6AdQib8Q1onbR0U2h9icP1eRO6wH0AcyJmqZ7USD0uOYncCYIH7ZEE8IicAOPxyb9IA/640?wx_fmt=gif "")  
  
**Moriarty**  
  
Moriarty 是一个综合性的 .NET 工具，它扩展了Watson和Sherlock的功能，最初由@_RastaMouse开发。它旨在枚举缺失的 KB、检测各种漏洞并建议 Windows 环境中的权限升级的潜在漏洞。Moriarty 结合了 Watson 和 Sherlock 的功能，增加了对新漏洞的增强扫描并集成了额外的检查。  
  
**支持的版本**  
  
Windows 10（版本：1507、1511、1607、1703、1709、1803、1809、1903、1909、2004、20H2、21H1、21H2、22H1、22H2）  
  
Windows 11（版本：21H2、22H1、22H2、23H1）  
  
服务器 2016、2019、2022  
  
**安装和构建说明**  
  
首先，使用 Git 将 Moriarty 存储库克隆到本地计算机：  
```
git clone https://github.com/BC-SECURITY/Moriarty.git
```  
  
**建设项目**  
  
克隆存储库后，您可以使用 Visual Studio 构建 Moriarty 可执行文件。  
  
**使用 Visual Studio**  
- Moriarty.sln在 Visual Studio 中打开。  
  
- 右键单击“解决方案资源管理器”中的解决方案，然后选择“恢复 NuGet 包”以确保所有依赖项都是最新的。  
  
- 将构建配置设置为“发布”。  
  
- 通过从菜单中选择“构建 > 构建解决方案”来构建解决方案。  
  
**用法**  
  
**帮助菜单**  
```
C:\> Moriarty.exe --help

███    ███  ██████  ██████  ██  █████  ██████  ████████ ██    ██
████  ████ ██    ██ ██   ██ ██ ██   ██ ██   ██    ██     ██  ██
██ ████ ██ ██    ██ ██████  ██ ███████ ██████     ██      ████
██  ██  ██ ██    ██ ██   ██ ██ ██   ██ ██   ██    ██       ██
██      ██  ██████  ██   ██ ██ ██   ██ ██   ██    ██       ██
                                                 v1.2
                                                 BC Security

Usage: Moriarty.exe [options]
Options:
  -h, --help       Display this help message.
  -d, --debug      Run in debug mode for additional output.
  -l, --list-vulns List all vulnerabilities that are scanned for.

Examples:
  Moriarty.exe -d
  Moriarty.exe --list-vulns

```  
  
**扫描**  
```
C:\> Moriarty.exe
███    ███  ██████  ██████  ██  █████  ██████  ████████ ██    ██
████  ████ ██    ██ ██   ██ ██ ██   ██ ██   ██    ██     ██  ██
██ ████ ██ ██    ██ ██████  ██ ███████ ██████     ██      ████
██  ██  ██ ██    ██ ██   ██ ██ ██   ██ ██   ██    ██       ██
██      ██  ██████  ██   ██ ██ ██   ██ ██   ██    ██       ██

                                                 v1.2
                                                 BC Security

 [*] OS Version: 22H2 (22621)
 [*] Enumerating installed KBs...
 [+] CVE-2023-36664 : VULNERABLE
  [>] https://github.com/jakabakos/CVE-2023-36664-Ghostscript-command-injection

 [+] PrintNightmare (CVE-2021-1675, CVE-2021-34527) : VULNERABLE
  [>] https://github.com/xbufu/PrintNightmareCheck/tree/main

 [*] Vulnerabilities found: 2/37
 [+] Scan Complete!
 
```  
  
**CVE 和漏洞**  
  
Moriarty 扫描各种 CVE 和漏洞。下面的表格详细介绍了每项内容，以及更详细的描述和 CVE 数据库的链接。  
```
MS10-015  Windows 内核中的漏洞与权限提升相关，允许攻击者执行任意代码。
MS10-092  Windows 任务计划程序中的漏洞允许通过升级的权限执行任意代码。
MS13-053  Windows 内核模式驱动程序中存在多个可能允许特权提升的漏洞。
MS13-081  Windows 内核模式驱动程序中存在多个可能允许远程执行代码的漏洞。
MS14-058  内核模式驱动程序中的漏洞可能允许通过特制 TrueType 字体文件远程执行代码。
MS15-051  Windows 内核模式驱动程序中的漏洞允许通过绕过 Windows 安全功能来提升权限。
MS15-078  Windows 字体驱动程序中的漏洞允许通过恶意制作的 OpenType 字体远程执行代码。
MS16-016  WebDAV 中的漏洞可能允许通过不正确的内存处理来提升权限。
MS16-032  辅助登录过程中存在漏洞，可能允许通过运行特制应用程序来提升权限。
MS16-034  Windows 内核模式驱动程序中的漏洞可能允许由于内核模式驱动程序处理内存中对象的方式而导致特权提升。
MS16-135  Windows 内核模式驱动程序中的漏洞可能允许由于内存中某些类型的对象处理不当而导致特权提升。
CVE-2017-7199  由于某些应用程序处理进程令牌的方式而导致 Windows 中的权限提升漏洞。
CVE-2019-0836  
CVE-2019-0836  Windows AppX 部署服务器中的提权漏洞，允许攻击者覆盖系统文件。
CVE-2019-1064  由于符号链接处理不当而导致 Windows 中的特权提升漏洞。
CVE-2019-1130  由于 Windows CSRSS 处理某些请求的方式而导致 Windows 中的特权提升漏洞。
CVE-2019-1253  由于权限设置不当而导致 Windows AppX 部署服务器中的权限提升漏洞。
CVE-2019-1315  由于硬链接处理不当，Windows 错误报告 (WER) 中存在权限提升漏洞。
CVE-2019-1385  由于 Windows 内存对象处理不当而导致的特权提升漏洞。
CVE-2019-1388  Windows UAC 中的一个漏洞，允许绕过 UAC 对话框，从而导致特权提升。
CVE-2019-1405  由于内存中对象处理不当而导致 Windows UPnP 服务中存在特权提升漏洞。
CVE-2020-0668  由于 Windows 中符号链接处理不当而导致的特权提升漏洞。
CVE-2020-0683  由于文件路径处理不当而导致 Windows 中的权限提升漏洞。
CVE-2020-0796  SMBv3 中的远程代码执行漏洞称为“SMBGhost”。
CVE-2020-1013  Windows Update Orchestrator 服务中存在本地权限提升漏洞。
CVE-2020-1013  PrintNightmare，Windows Print Spooler 中的远程代码执行漏洞。
CVE-2021-26855  ProxyLogon - Exchange Server 中的服务器端请求伪造 (SSRF) 漏洞，允许远程执行代码。
CVE-2021-26857  Exchange Server 中的漏洞可能允许攻击者执行远程代码。
CVE-2021-26858  Exchange Server 中存在身份验证后任意文件写入漏洞。
CVE-2021-27065  Exchange Server 中的身份验证后任意文件写入漏洞可能导致远程代码执行。
CVE-2021-44228  Log4Shell，Apache Log4j 中的远程代码执行漏洞。
CVE-2021-36934  HiveNightmare - 由于系统文件（包括安全帐户管理器 (SAM)）上的访问控制列表 (ACL) 过于宽松，导致本地权限升级的漏洞。
CVE-2022-34718  Windows TCP/IP 远程代码执行漏洞。
CVE-2022-40140  Microsoft Exchange Server 中存在导致远程代码执行的漏洞。
CVE-2022-22965  Spring4Shell，Spring框架中的远程代码执行漏洞。
CVE-2023-36664  Artifex Ghostscript 到 10.01.2 都会错误地处理管道设备的权限验证（带有 %pipe% 前缀或管道字符前缀）。
CVE-2023-23397  Microsoft Outlook 权限提升漏洞。
```  
  
  
项目地址：  
  
https://github.com/BC-SECURITY/Moriarty/tree/main  
  
  
  
  
感谢您抽出  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWgdSBqOibtgiaYWjL4pkRXwycNnFvFYVgXoExRy0gqCkqvrAghf8KPXnwQaYq77HMsjcVka7kPcBDQw/640?wx_fmt=gif "")  
  
.  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWgdSBqOibtgiaYWjL4pkRXwycd5KMTutPwNWA97H5MPISWXLTXp0ibK5LXCBAXX388gY0ibXhWOxoEKBA/640?wx_fmt=gif "")  
  
.  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWgdSBqOibtgiaYWjL4pkRXwycU99fZEhvngeeAhFOvhTibttSplYbBpeeLZGgZt41El4icmrBibojkvLNw/640?wx_fmt=gif "")  
  
来阅读本文  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWge7Mibiad1tV0iaF8zSD5gzicbxDmfZCEL7vuOevN97CwUoUM5MLeKWibWlibSMwbpJ28lVg1yj1rQflyQ/640?wx_fmt=gif "")  
  
**点它，分享点赞在看都在这里**  
  
