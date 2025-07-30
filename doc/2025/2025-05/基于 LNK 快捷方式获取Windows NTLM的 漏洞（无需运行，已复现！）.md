#  基于 LNK 快捷方式获取Windows NTLM的 漏洞（无需运行，已复现！）   
原创 Secu的矛与盾  Secu的矛与盾   2025-05-06 15:03  
  
### 1.1 “Right-Click LNK” 漏洞  
###   
  
国外的一名安全研究员Zeifan 的研究指出，Windows Explorer 在展示或右键预览 LNK 快捷方式时，会使用 SHGDN_FORPARSING  
 标志调用一系列 COM 接口（如 IInitializeNetworkFolder  
、IShellFolder2  
）获取目标路径，即使用户未双击快捷方式，也会触发对 UNC 路径的访问Security Research  
。利用 LNK 文件中 EnvironmentVariableDataBlock  
 的结构操控，可将恶意 UNC 路径嵌入至 TargetUnicode  
 缓冲区，一旦 Explorer 扫描到该文件即发起 SMB 连接，从而泄露 NTLM 哈希。  
### 1.2 LNK 文件结构操控  
###   
- **关键标志位**  
：通过设置 LinkFlags  
 中的 HAS_ARGUMENTS  
 与 IS_UNICODE  
，强制 Explorer 使用 Unicode 解析内部数据块；  
  
- **EnvironmentVariableDataBlock**  
：以 BlockSize=0x00000314  
（788 字节）和签名 0xA0000001  
 为前缀，接着分配 260 字节 ANSI 与 520 字节 Unicode 缓冲区，后者存放如 \\attacker.example.com\share  
 的 UNC 路径  
Security Research  
。  
  
- **触发流程**  
：当用户浏览快捷方式所在目录或右键文件时，Explorer 会提前解析该数据块并尝试访问上述 UNC 路径，自动发起 NTLM 身份验证。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/OQYwpDLv2j9Bica0tJmqBtwjrfoUz0f9UaHl4IWkutB9licUKFeNtzMX78iacm6Twadl4WxDiaSwsm3wicMDfZWPypA/640?wx_fmt=png&from=appmsg "")  
### 2.1与历史案例对比  
###   
  
**CVE-2017-8464**  
：通过展示恶意 LNK 图标触发远程代码执行（RCE），需要用户打开目录；相比之下，Zeifan 的漏洞侧重于凭据泄露，无需用户执行。  
  
**.library-ms 漏洞 (CVE-2025-24054)**  
：同样利用 Explorer 预览 Windows Library 文件导致 NTLM 哈希泄露，已在 2025 年 3 月补丁中修复  
。  
  
2.2 复现步骤：  
  
攻击机：  
  
kali 运行：  
```
sudo responder -I eth0 -w -d -v 
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/OQYwpDLv2j9Bica0tJmqBtwjrfoUz0f9UGxL1EYX3mAt36Eue8aMNdiblUuyiae2uxLqI27V4TCavcuRabDZcEY6w/640?wx_fmt=jpeg "")  
  
修改poc代码里的ip为攻击机ip，  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/OQYwpDLv2j9Bica0tJmqBtwjrfoUz0f9UqrXictXYx1CPfsFzAf6FCwjujZ7hkLMbLeU8YgPN3Iqzh7Hd2vEGWkQ/640?wx_fmt=png&from=appmsg "")  
  
使用vs编译或者gcc编译：  
```
x86_64-w64-mingw32-gcc poc.c -o lnk_poc.exe
```  
  
右键查看生成的lnk文件，然后看看kali终端  
  
  
2.3 讨论  
- **微软“不认”这个漏洞**  
  
- **依赖 Mark of the Web（MOTW）机制**  
  
微软认为，当用户从 Internet 下载文件时，Windows 会在文件元数据中打上 MOTW（“Web 标记”），并在首次打开或右击时弹出安全警告。这一机制应该足以提醒用户，防止恶意 .lnk 文件的滥用，因此“不达微软的补丁门槛”   
****  
  
- **作者（Nafiez）为何坚持这是个严重安全风险**  
  
**无需执行即可触发网络连接，轻易泄露凭据**  
  
通过精心构造的   
lnk 文件在仅“打开文件夹”或“右键查看属性”时就会解析并访问 UNC 路径（如 \\<IP>\c  
），进而在无用户主动运行程序的情况下发起 SMB 连接，被动泄露 NTLMv2 哈希 。  
  
**MOTW 并不能完全防御**  
  
许多组织会解除或忽略 MOTW 警告（例如通过组策略白名单内部站点、日志疲劳导致用户一律点击“继续”），而且一些攻击场景下 .lnk 文件并非通过浏览器下载，而是通过 U盘、内部文件共享等方式落地，MOTW 无法生效 。  
  
可以简化其利用  
  
原作者的poc还需要右键一下，但有人提出对其poc改良后可以对其进行升级，  
只需导航到恶意 LNK 文件所在的目录即可触发它。  
  
  
当然此类  
“中继攻击”存在已久，使用ntml认证也是windows的“预期功能”，也是“固有风险”，或许这算是一种“攻击方式/媒介的演化与创新吧”  
  
参考学习：  
```
https://www.mdsec.co.uk/2021/02/farming-for-red-teams-harvesting-netntlm/
```  
```
https://zeifan.my/Right-Click-LNK/
```  
  
免责声明：请勿利用文章内的相关技术或信息从事非法测试，由于传播、利用此文所提供的信息或者工具而造成的任何直接或者间接的后果及损失，均由使用者本人负责，所产生的一切不良后果与文章作者无关。该文章仅供学习用途使用。  
  
  
poc源码后台回复：  
```
lnk_poc
```  
  
  
