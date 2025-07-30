#  可蠕虫化AirPlay漏洞：公共WiFi环境下可零点击远程控制苹果设备   
 FreeBuf   2025-05-06 10:29  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/qq5rfBadR38jUokdlWSNlAjmEsO1rzv3srXShFRuTKBGDwkj4gvYy34iajd6zQiaKl77Wsy9mjC0xBCRg0YgDIWg/640?wx_fmt=gif "")  
  
  
网络安全研究人员近日披露了苹果AirPlay协议中一系列现已修复的安全漏洞，攻击者成功利用这些漏洞可控制支持该专有无线技术的设备。以色列网络安全公司Oligo将这些漏洞统称为AirBorne。  
  
  
![image](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR3icNdKTCNmT3XtcOLcUnUhX898qZ39a1wcVXe0ia3iaNy9v7dILXg5gVFf31J9VlSrHgbCt8yE5hdJZA/640?wx_fmt=jpeg&from=appmsg "")  
  
  
**01**  
  
  
## 漏洞组合可形成蠕虫式攻击  
  
##   
  
  
  
  
研究人员Uri Katz、Avi Lumelsky和Gal Elbaz指出："攻击者可串联利用这些漏洞，控制支持AirPlay的设备——包括苹果设备和采用AirPlay SDK（软件开发工具包）的第三方设备。"其中CVE-2025-24252与CVE-2025-24132等漏洞组合后，可形成无需用户交互的蠕虫化远程代码执行（RCE，Remote Code Execution）攻击链，使恶意软件能在受感染设备连接的任何本地网络中传播。  
  
  
这种攻击方式可能为部署后门和勒索软件等复杂攻击创造条件，构成严重安全威胁。整体而言，这些漏洞可实现：  
  
- 零点击或单点击远程代码执行  
  
- 绕过访问控制列表（ACL）和用户交互验证  
  
- 本地任意文件读取  
  
- 信息泄露  
  
- 中间人（AitM）攻击  
  
- 拒绝服务（DoS）攻击  
  
**02**  
  
  
  
## 具体攻击场景分析  
  
  
  
通过串联CVE-2025-24252和CVE-2025-24206漏洞，攻击者可对与其处于同一网络的macOS设备实施零点击RCE攻击。但此攻击需要目标设备的AirPlay接收器处于开启状态，且设置为"同一网络上的任何人"或"所有人"模式。  
  
  
典型攻击场景中，受害设备连接公共Wi-Fi时即被入侵。若该设备后续接入企业网络，攻击者将获得入侵同一网络其他设备的通道。  
  
  
**03**  
  
  
  
## 关键漏洞清单  
  
  
- CVE-2025-24271：访问控制漏洞，允许同一网络中的攻击者绕过配对验证向已登录Mac发送AirPlay指令  
  
- CVE-2025-24137：可导致任意代码执行或应用终止的漏洞  
  
- CVE-2025-24132：基于栈的缓冲区溢出漏洞，可在采用AirPlay SDK的扬声器和接收器上实现零点击RCE  
  
- CVE-2025-24206：认证漏洞，允许本地网络攻击者绕过认证策略  
  
- CVE-2025-24270：可导致敏感用户信息泄露的漏洞  
  
- CVE-2025-24251：可导致应用异常终止的漏洞  
  
- CVE-2025-31197：可导致应用异常终止的漏洞  
  
- CVE-2025-30445：类型混淆漏洞，可导致应用异常终止  
  
- CVE-2025-31203：整数溢出漏洞，可造成拒绝服务状态  
  
**04**  
  
  
  
## 补丁发布情况  
  
  
  
苹果已在以下版本中修复这些漏洞：  
- iOS 18.4与iPadOS 18.4  
  
- iPadOS 17.7.6  
  
- macOS Sequoia 15.4  
  
- macOS Sonoma 14.7.5  
  
- macOS Ventura 13.7.5  
  
- tvOS 18.4  
  
- visionOS 2.4  
  
部分漏洞（CVE-2025-24132和CVE-2025-30422）还在以下组件中修复：  
- AirPlay音频SDK 2.7.1  
  
- AirPlay视频SDK 3.6.0.126  
  
- CarPlay通信插件R18.1  
  
Oligo强调："企业必须立即将所有支持AirPlay的苹果设备及其他终端升级至最新版本。安全负责人还需明确告知员工，其所有支持AirPlay的个人设备也需立即更新。"  
  
  
![图片](https://mmbiz.qpic.cn/mmbiz_gif/qq5rfBadR39ibFdyjP3Qp8CEJxFWljbW1y91mvSZuxibf3Q3g2rJ32FNzoYfx4yaBmWbfwcRaNicuMo3AxIck2bCw/640?wx_fmt=gif&from=appmsg&wxfrom=5&wx_lazy=1&tp=webp "")  
  
  
  
  
  
[](https://mp.weixin.qq.com/s?__biz=MjM5NjA0NjgyMA==&mid=2651319938&idx=1&sn=8b4f45b0d0c45643793a84ad8bca2a13&scene=21#wechat_redirect)  
  
[](https://mp.weixin.qq.com/s?__biz=MjM5NjA0NjgyMA==&mid=2651319699&idx=1&sn=127e9ca1a8d55931beae293a68e3b706&scene=21#wechat_redirect)  
  
[](https://mp.weixin.qq.com/s?__biz=MjM5NjA0NjgyMA==&mid=2651319086&idx=1&sn=e2ff862babd7662c4fa06b0e069c03f2&scene=21#wechat_redirect)  
  
  
  
  
  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/qq5rfBadR39ibFdyjP3Qp8CEJxFWljbW1uEIoRxNoqa17tBBrodHPbOERbZXdjFvNZC5uz0HtCfKbKx3o3XarGQ/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
![图片](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR3icFibibPIGEfXsibI0C3or4BS5KDnCKUfVLVQGsc9BiaQTUsrwzfcianumzeLVcmibOmm2FzUqef2V6WPQQ/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
  
  
  
![图片](https://mmbiz.qpic.cn/mmbiz_gif/qq5rfBadR38mFMbqsUOVbBDicib7jSu7FfibBxO3LTiafGpMPic7a01jnxbnwOtajXvq5j2piaII2Knau7Av5Kxvp2wA/640?wx_fmt=gif&from=appmsg&wxfrom=5&wx_lazy=1&tp=webp "")  
  
![图片](https://mmbiz.qpic.cn/mmbiz_gif/qq5rfBadR3icF8RMnJbsqatMibR6OicVrUDaz0fyxNtBDpPlLfibJZILzHQcwaKkb4ia57xAShIJfQ54HjOG1oPXBew/640?wx_fmt=gif&wxfrom=5&wx_lazy=1&tp=webp "")  
  
