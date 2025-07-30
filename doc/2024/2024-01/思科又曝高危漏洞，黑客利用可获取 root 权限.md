#  思科又曝高危漏洞，黑客利用可获取 root 权限   
 网络安全应急技术国家工程中心   2024-01-15 14:55  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/GoUrACT176mZM6iag1XORHrsw5SDRn0c6AcGqu101qOn9SXGyjaDgWxOFIZbN48rnticJ0PUBMdiaibXje5cXTUE4w/640?wx_fmt=jpeg&from=appmsg "")  
  
近日，思科修补了一个关键的 Unity Connection 安全漏洞，该漏洞可让未经认证的攻击者在未打补丁的设备上远程获得 root 权限。  
  
Unity Connection 是一个完全虚拟化的消息和语音邮件解决方案，适用于电子邮件收件箱、Web 浏览器、Cisco Jabber、Cisco Unified IP Phone、智能手机或平板电脑，支持高可用性和冗余。  
  
该漏洞（CVE-2024-20272）出现在该软件基于网络的管理界面上，是由于特定 API 缺乏身份验证以及对用户提供的数据验证不当造成的。攻击者可通过向目标和易受攻击系统上传任意文件，在底层操作系统上执行命令。成功利用后，攻击者可以在系统上存储恶意文件，在操作系统上执行任意命令，并将权限提升至 root。  
  
幸运的是，思科的产品安全事故响应小组（PSIRT）表示，目前还没有证据表明该漏洞已被利用的情况出现。  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/GoUrACT176mZM6iag1XORHrsw5SDRn0c6b2ZXRySqhnyianic9dhbmyuARzEhQcDkXhkr7piaHmGW27flSFQT6bJjQ/640?wx_fmt=jpeg "")  
  
# 利用 PoC 漏洞进行命令注入  
  
##   
## 1月10日，思科宣布修补了多款产品中的十个中等严重性安全漏洞，这些漏洞允许攻击者升级权限、发起跨站脚本（XSS）攻击、注入命令等。  
  
其中一个漏洞的概念验证利用代码已在网上公布，该漏洞是思科 WAP371 无线接入点基于 Web 的管理界面中的一个命令注入漏洞，被追踪为 CVE-2024-20287。  
  
尽管攻击者可以利用这个漏洞在未打补丁的设备上以 root 权限执行任意命令，但要成功利用这个漏洞还需要管理凭据。  
  
  
表示，由于思科WAP371设备已于2019年6月达到报废年限，因此不会发布固件更新来修补CVE-2024-20287安全漏洞。  
  
同时，该公司建议网络上有 WAP371 设备的客户尽快迁移到思科 Business 240AC 接入点。  
  
去年10 月，思科还修补了两个零日漏洞（CVE-2023-20198 和 CVE-2023-20273），这些漏洞在一周内被利用入侵了 50,000 多台 IOS XE 设备。**参考资料：**  
https://www.bleepingcomputer.com/news/security/cisco-says-critical-unity-connection-bug-lets-attackers-get-root/  
  
原文来源：FreeBuf  
  
“投稿联系方式：010-82992251   sunzhonghao@cert.org.cn”  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/GoUrACT176n1NvL0JsVSB8lNDX2FCGZjW0HGfDVnFao65ic4fx6Rv4qylYEAbia4AU3V2Zz801UlicBcLeZ6gS6tg/640?wx_fmt=jpeg&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
