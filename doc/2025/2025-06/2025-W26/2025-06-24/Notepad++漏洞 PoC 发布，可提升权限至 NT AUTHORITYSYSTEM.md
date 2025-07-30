> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzAxMjYyMzkwOA==&mid=2247531265&idx=1&sn=19e218b029466f8e4f24059b96021fae

#  Notepad++漏洞 PoC 发布，可提升权限至 NT AUTHORITY\SYSTEM  
 Ots安全   2025-06-24 05:59  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/bL2iaicTYdZn7gtxSFZlfuCW6AdQib8Q1onbR0U2h9icP1eRO6wH0AcyJmqZ7USD0uOYncCYIH7ZEE8IicAOPxyb9IA/640?wx_fmt=gif "")  
  
描述  
  
Notepad++ v8.8.1 安装程序中存在一个权限提升漏洞，该漏洞允许非特权用户通过不安全的可执行文件搜索路径获取 SYSTEM 级权限。只需极少的用户交互即可利用此漏洞。  
  
漏洞详情  
- 类型：不受控制的 EXE/DLL 搜索路径（二进制植入）  
  
- 影响：本地权限提升至 NT AUTHORITY\SYSTEM  
  
- 受影响的软件： Notepad++ v8.8.1 安装程序 - 发布日期：2025-05-05  
  
- 严重程度：高  
  
技术概述  
  
安装程序在当前工作目录中搜索可执行文件依赖项而不进行验证，从而允许攻击者放置恶意可执行文件，这些可执行文件将在安装期间以 SYSTEM 权限加载。  
  
欲了解更多信息，请参阅此博客：Microsoft 安全加载库  
  
攻击方法  
- 准备：攻击者将恶意可执行文件（例如 regsvr32.exe）放置在目录中  
  
- 攻击：用户下载并运行 Notepad++ v8.8.1 安装程序  
  
- 执行：安装程序以 SYSTEM 权限从当前目录加载恶意可执行文件  
  
- 结果：攻击者获得完全系统控制权  
  
感知  
  
进程监视器日志显示安装程序正在当前目录中搜索可执行文件  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rWGOWg48taeBPuV8xNIutx8uv43QwicajT0Paz2CvZEQhaoYeXiahgtsRxkNzpxKW9ibjsBQcaicvKfkZib7xS2LVHA/640?wx_fmt=png&from=appmsg "")  
- 概念验证表明，通过反向 shell 成功提升权限  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rWGOWg48taeBPuV8xNIutx8uv43QwicajCWYuD5cAcz5XKgtmfqGLJQUlWR7vj0S5sOYyS8pBz33nbPXNfafiasw/640?wx_fmt=png&from=appmsg "")  
  
视频演示证实了漏洞利用成功。  
> 概念验证材料： 带有 PoC 和视频的 Google Drive 文件夹  
  
> https://drive.google.com/drive/folders/11yeUSWgqHvt4Bz5jO3ilRRfcpQZ6Gvpn  
  
  
  
安全隐患  
  
权限提升：非特权用户获得系统级权限  
  
代码执行：任意代码以提升的权限运行  
  
数据泄露：敏感数据被盗的可能性  
  
横向移动：受感染的系统可能被用来攻击网络  
  
真实世界的攻击场景  
  
攻击者可能利用社会工程学或点击劫持技术，诱骗用户将合法安装程序和恶意可执行文件下载到同一目录（通常是“下载”文件夹，也称为“易受攻击”目录）。安装程序运行后，攻击将以 SYSTEM 权限自动执行。  
  
类似漏洞  
- CVE-2023-6401和CVE-2023-47452 - 在记事本的早期版本中  
  
- CVE-2024-44346：类似二进制植入漏洞  
  
- Dell SupportAssist 漏洞（DSA-2024-312）  
  
建议  
1. 修改安装程序以使用绝对路径进行依赖项加载  
  
1. 对已加载的可执行文件实施数字签名验证  
  
1. 创建并使用具有随机名称的安全临时目录  
  
1. 遵循 Microsoft 的安全库加载指南  
  
结论  
  
这是一个需要立即关注的严重安全漏洞。虽然微软将某些二进制植入问题归类为“纵深防御”，但考虑到该漏洞会在极少的用户交互下获取 SYSTEM 权限，其严重性需要优先修复。  
  
参考  
- https://www.dell.com/support/kbdoc/en-us/000227899/dsa-2024-312-security-update-for-dell-supportassist-for-home-pcs-installer-file-local-privilege-escalation-vulnerability  
  
- https://unit42.paloaltonetworks.com/vulnerabilities-in-iconics-software-suite/  
  
- https://nvd.nist.gov/vuln/detail/CVE-2025-26624  
  
- https://unit42.paloaltonetworks.com/dll-hijacking-techniques/  
  
- https://support.microsoft.com/en-us/topic/secure-loading-of-libraries-to-prevent-dll-preloading-attacks-d41303ec-0748-9211-f317-2edc819682e1  
  
POC：  
  
https://github.com/notepad-plus-plus/notepad-plus-plus/security/advisories/GHSA-9vx8-v79m-6m24  
  
  
  
  
感谢您抽出  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWgdSBqOibtgiaYWjL4pkRXwycNnFvFYVgXoExRy0gqCkqvrAghf8KPXnwQaYq77HMsjcVka7kPcBDQw/640?wx_fmt=gif "")  
  
.  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWgdSBqOibtgiaYWjL4pkRXwycd5KMTutPwNWA97H5MPISWXLTXp0ibK5LXCBAXX388gY0ibXhWOxoEKBA/640?wx_fmt=gif "")  
  
.  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWgdSBqOibtgiaYWjL4pkRXwycU99fZEhvngeeAhFOvhTibttSplYbBpeeLZGgZt41El4icmrBibojkvLNw/640?wx_fmt=gif "")  
  
来阅读本文  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWge7Mibiad1tV0iaF8zSD5gzicbxDmfZCEL7vuOevN97CwUoUM5MLeKWibWlibSMwbpJ28lVg1yj1rQflyQ/640?wx_fmt=gif "")  
  
**点它，分享点赞在看都在这里**  
  
