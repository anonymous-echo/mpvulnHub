#  CNCERT：关于Google Chrome存在沙箱逃逸漏洞的安全公告   
 安全内参   2025-03-31 18:16  
  
安全公告编号:  
CNTA-2025-0005  
  
  
  
  
2025年3月28日，国家信息安全漏洞共享平台（CNVD）收录了Google  Chrome沙箱逃逸漏洞（CNVD-2025-06046，对应CVE-2025-2783）。攻击者利用该漏洞可远程绕过Chrome的沙箱保护机制，造成信息泄露、代码执行等危害。目前，漏洞细节尚未公开，谷歌公司已发布新版本修复该漏洞。CNVD建议受影响的用户尽快升级至最新版本  
。  
  
**一、漏洞情况分析**  
  
Chrome是一款由谷歌公司开发的网页浏览器，具有较好的性能、出色的兼容性和丰富的扩展程序。Chrome支持多标签页浏览，每个标签页都在独立的沙箱（SandBox）内运行，沙箱是Chrome的安全边界，用来隔离恶意代码对浏览器其他页面或用户系统的破坏，各标签页间的独立性提升了Chrome整体的稳定性和安全性。  
  
2025年3月28日，国家信息安全漏洞共享平台收录了Google  Chrome沙箱逃逸漏洞。由于Chrome沙箱机制与Windows操作系统内核交互时存在逻辑错误缺陷，未经授权的攻击者可在远程条件下，利用该漏洞绕过Chrome的沙箱保护机制，造成信息泄露、代码执行等危害。攻击者综合利用该漏洞，可实现对目标主机的管理权限控制。  
  
CNVD对上述漏洞的综合评级为“高危”。  
  
**二、漏洞影响范围**  
  
漏洞影响的产品版本包括：  
  
Google Chrome（Windows）< 134.0.6998.177  
  
**三、漏洞处置建议**  
  
目前，谷歌公司已发布新版本修复该漏洞，CNVD建议受影响的用户尽快通过官方链接下载并更新至最新版本：  
  
https://www.google.cn/chrome/  
  
同时，CNVD建议用户不要随意点击访问通过电子邮件、即时通讯软件等途径传播的不明网站链接或文件。  
  
    
  
附参考链接：  
  
https://www.kaspersky.com/about/press-releases/kaspersky-discovers-sophisticated-chrome-zero-day-exploit-used-in-active-attacks  
  
https://chromereleases.googleblog.com/2025/03/stable-channel-update-for-desktop_25.html  
  
  
  
  
  
  
   
  
  
**推荐阅读**  
- [网安智库平台长期招聘兼职研究员](http://mp.weixin.qq.com/s?__biz=MzI4NDY2MDMwMw==&mid=2247499450&idx=2&sn=2da3ca2e0b4d4f9f56ea7f7579afc378&chksm=ebfab99adc8d308c3ba6e7a74bd41beadf39f1b0e38a39f7235db4c305c06caa49ff63a0cc1d&scene=21#wechat_redirect)  
  
  
- [欢迎加入“安全内参热点讨论群”](https://mp.weixin.qq.com/s?__biz=MzI4NDY2MDMwMw==&mid=2247501251&idx=1&sn=8b6ebecbe80c1c72317948494f87b489&chksm=ebfa82e3dc8d0bf595d039e75b446e14ab96bf63cf8ffc5d553b58248dde3424fb18e6947440&token=525430415&lang=zh_CN&scene=21#wechat_redirect)  
  
  
  
  
  
  
文章来源：CNVD漏洞平台  
  
  
点击下方卡片关注我们，  
  
带你一起读懂网络安全 ↓  
  
  
  
  
  
