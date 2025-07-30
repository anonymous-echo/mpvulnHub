> **原文链接**: https://mp.weixin.qq.com/s?__biz=MjM5NjA0NjgyMA==&mid=2651324157&idx=1&sn=d1cefdecef852c70267c3183969ad839

#  新型macOS恶意软件利用进程注入与远程通信窃取钥匙串凭证  
 FreeBuf   2025-07-03 11:03  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/qq5rfBadR38jUokdlWSNlAjmEsO1rzv3srXShFRuTKBGDwkj4gvYy34iajd6zQiaKl77Wsy9mjC0xBCRg0YgDIWg/640?wx_fmt=gif "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qq5rfBadR3ibAQoue6wgHf164hWwTEak1zCtVygBEVKlmB0ibMd6Dyn26jhg10OKXJ4HebHWHhaMq3drcgC5DqWA/640?wx_fmt=png&from=appmsg "")  
  
  
网络安全研究人员发现针对Web3和加密货币平台的新型macOS恶意软件活动，其采用的技术手段在苹果生态系统中极为罕见。这款被命名为NimDoor的恶意软件通过进程注入能力和加密WebSocket通信窃取敏感用户凭证与金融数据，标志着macOS威胁的显著升级。  
  
  
**Part01**  
## 社交工程攻击入口  
  
  
攻击始于典型的社交工程手段：朝鲜黑客组织通过Telegram冒充可信联系人安排虚假商务会议。受害者会收到伪造的Zoom会议邀请，附带要求从攻击者控制的域名（如support.us05web-zoom[.]forum）下载并执行名为"Zoom SDK更新脚本"的恶意文件，这些域名刻意模仿Zoom官方基础设施。  
  
  
**Part02**  
## 多语言架构与进程注入技术  
  
  
该恶意软件区别于普通macOS威胁的核心在于其技术复杂性和多层架构。SentinelOne分析团队发现，攻击者利用通常为调试工具保留的系统权限（entitlements），在macOS上实施罕见的进程注入技术。这种手法使恶意代码能够植入合法进程，既增强隐蔽性又规避传统检测机制。  
  
  
攻击链采用多种编程语言编写的组件：AppleScript负责初始访问，C++实现进程注入，而核心功能则由Nim语言编译的二进制文件完成。这种技术组合表明攻击者致力于开发能有效入侵现代macOS系统、同时难以分析检测的复杂工具。  
  
  
**Part03**  
## 基于信号拦截的持久化机制  
  
  
恶意软件最具创新性的特性是其持久化机制——前所未有地利用了macOS信号处理功能。NimDoor没有采用LaunchAgents或Login Items等传统方法，而是通过监控系统信号维持驻留。其CoreKitAgent组件为SIGINT（中断信号）和SIGTERM（终止信号）建立处理程序，有效拦截终止恶意进程的尝试。  
  
  
当用户或系统试图通过标准方法终止恶意软件时，这些信号处理程序会被触发，使进程无法正常退出。此时恶意软件会借机重新安装自身：将LaunchAgent写入~/Library/LaunchAgents/com.google.update.plist，并复制组件文件确保系统重启后仍能保持持久化。该机制通过以下代码实现：  

```
posix_spawnattr_init(&attrp) && !posix_spawnattr_setflags(&attrp, POSIX_SPAWN_START_SUSPENDED);
posix_spawn(&pid, filename, 0, &attrp, argv_1, environ);
kill(pid, SIGCONT);
```

  
  
![image](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR3ibAQoue6wgHf164hWwTEak1LBCEme6B6kNDcWKaIEoyuv0KgCoCMjuHCoLxf58Pz4L7XXH7tXwGjg/640?wx_fmt=jpeg&from=appmsg "")  
  
登录或重启激活持久化机制后的执行链（来源：SentinelOne）  
  
****  
**Part04**  
## 加密通信与数据窃取  
  
  
恶意软件通过WebSocket Secure(wss)协议与命令控制服务器wss://firstfromsep[.]online/client通信，采用RC4加密与base64编码的多层保护。该加密通道用于外泄窃取的钥匙串（Keychain）凭证、Chrome/Firefox等主流浏览器的数据以及Telegram聊天记录，同时有效规避网络监控工具的检测。  
  
  
**参考来源：**  
  
New macOS Malware Employs Process Injection and Remote Communications to Exfiltrate Keychain Credentials  
  
https://cybersecuritynews.com/new-macos-malware-employs-process-injection-and-remote-communications/  
  
  
###   
###   
###   
  
**推荐阅读**  
  
[](https://mp.weixin.qq.com/s?__biz=MjM5NjA0NjgyMA==&mid=2651324079&idx=1&sn=c11acae8f7897f7fa528977c559d8c05&scene=21#wechat_redirect)  
  
### 电台讨论  
  
****  
  
  
  
![图片](https://mmbiz.qpic.cn/mmbiz_gif/qq5rfBadR3icF8RMnJbsqatMibR6OicVrUDaz0fyxNtBDpPlLfibJZILzHQcwaKkb4ia57xAShIJfQ54HjOG1oPXBew/640?wx_fmt=gif&wxfrom=5&wx_lazy=1&tp=webp "")  
  
   
  
