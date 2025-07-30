> **原文链接**: https://mp.weixin.qq.com/s?__biz=MjM5NjA0NjgyMA==&mid=2651323083&idx=1&sn=f8c83096621ff3fb1a6ffdc75cd02146

#  Windows磁盘清理工具权限提升漏洞PoC利用代码公开  
 FreeBuf   2025-06-14 10:26  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/qq5rfBadR38jUokdlWSNlAjmEsO1rzv3srXShFRuTKBGDwkj4gvYy34iajd6zQiaKl77Wsy9mjC0xBCRg0YgDIWg/640?wx_fmt=gif "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qq5rfBadR39ETicBhjbwY24ePk2YruTK7duGXoj4ANnqxB49gulz1mONiaaag1EnHQEGstHY6iagj6jM73IvGYIHw/640?wx_fmt=png&from=appmsg "")  
  
  
  
研究人员已发布针对CVE-2025-21420的概念验证（PoC）利用代码，该漏洞是新发现的Windows磁盘清理工具（cleanmgr.exe）权限提升漏洞。  
  
### Part01  
### 漏洞技术分析  
  
  
该漏洞源于Windows磁盘清理工具存在的CWE-59类缺陷（文件访问前链接解析不当）。攻击者可利用SilentCleanup计划任务（在Windows系统中以提升权限运行）内部的链接解析机制缺陷，将权限提升至SYSTEM级别。  
  
  
![漏洞分析示意图](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR39ETicBhjbwY24ePk2YruTK7wbm7qagfmLN44ibuegnS2obAAOciagsOAb87JVPuVuLA6XQUPiaYXSBRw/640?wx_fmt=jpeg&from=appmsg "")  
  
  
最新cleanmgr.exe二进制文件分析显示，微软已通过SetProcessMitigationPolicy函数调用实施了ProcessRedirectionTrustPolicy（值为16）的缓解策略，表明该组件已包含重定向防护机制，这暗示微软已知该组件可能遭受链接追踪攻击。  
  
  
![防护机制示意图](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR39ETicBhjbwY24ePk2YruTK7XnEAcQ6kbtucqKf2fGSFElWjfF79IXSadxfsSXzDmy9sETClKScDjA/640?wx_fmt=jpeg&from=appmsg "")  
  
  
尽管存在这些防护措施，研究人员发现启用了"以最高权限运行"的SilentCleanup计划任务仍可能遭受复杂的重定向攻击。该漏洞特别针对清理进程对临时文件夹的处理逻辑，尤其是位于C:$Windows.~WS、C:\ESD\Windows和C:\ESD\Download目录下的文件夹。  
  
  
![临时文件夹处理示意图](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR39ETicBhjbwY24ePk2YruTK71KXIianqLKk9ajzc0aNy4KYLWyIWicht4AK4BkJM9lRuOHhBQPdQYSpQ/640?wx_fmt=jpeg&from=appmsg "")  
  
  
进程监控工具显示，清理工具会检查这些文件夹是否存在，并在未正确验证符号链接或连接点的情况下直接删除其内容。  
  
  
**Part02**  
### 攻击技术细节  
###   
  
安全研究员Moiz-2x发布的PoC利用代码展示了一个多阶段攻击链，通过利用任意文件夹删除/移动/重命名操作实现SYSTEM权限提升。攻击方法涉及创建SilentCleanup任务在常规执行期间会处理的特定目录结构。  
  
  
攻击脚本会创建三个目标文件夹：C:$Windows.~WS、C:\ESD\Windows和C:\ESD\Download，并在其中填充虚拟文本文件。攻击的关键组件采用两种高级技术：FolderOrFileDeleteToSystem和FolderContentsDeleteToFolderDelete。这些方法将清理操作从预期的C:\ESD\Windows目录重定向到敏感的C:/Config.msi文件夹（包含关键的Windows Installer缓存文件）。  
  
  
攻击过程需要精确的时序协调。攻击者必须先建立恶意目录结构，配置重定向机制，然后触发SilentCleanup任务。成功利用该漏洞后，攻击者可删除受保护的系统文件，最终通过替换osk.exe（屏幕键盘）等系统工具实现SYSTEM级访问。  
  
  
**Part03**  
### 缓解措施建议  
###   
  
该漏洞影响Windows核心组件，且该组件设计上就以提升权限运行，因此具有重大安全风险。SilentCleanup任务是Windows维护操作的重要组成部分，简单禁用会影响系统性能和存储管理。  
  
  
建议组织立即评估受影响情况并采取适当防御措施。研究人员指出，包括Windows Defender在内的现代反病毒解决方案可能检测到该利用技术，要求攻击者将某些进程排除在实时保护之外，这为安全监控工具提供了额外的检测层。  
  
  
微软预计将在后续安全更新中修复该漏洞。系统管理员应在补丁发布后优先应用，并考虑对异常的SilentCleanup任务行为实施额外监控。  
  
  
参考来源：  
  
PoC Exploit Released for Windows Disk Cleanup Tool Elevation of Privilege Vulnerability  
  
https://cybersecuritynews.com/poc-exploit-released-for-windows-disk-cleanup-tool/  
  
  
###   
###   
###   
### 推荐阅读  
  
[](https://mp.weixin.qq.com/s?__biz=MjM5NjA0NjgyMA==&mid=2651322946&idx=1&sn=c9cbbd848459bfe0a36fa121ff364ad0&scene=21#wechat_redirect)  
  
### 电台讨论  
  
****  
  
![图片](https://mmbiz.qpic.cn/mmbiz_gif/qq5rfBadR3icF8RMnJbsqatMibR6OicVrUDaz0fyxNtBDpPlLfibJZILzHQcwaKkb4ia57xAShIJfQ54HjOG1oPXBew/640?wx_fmt=gif&wxfrom=5&wx_lazy=1&tp=webp "")  
  
