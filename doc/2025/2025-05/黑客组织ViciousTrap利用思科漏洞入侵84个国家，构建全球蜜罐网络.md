#  黑客组织ViciousTrap利用思科漏洞入侵84个国家，构建全球蜜罐网络   
 FreeBuf   2025-05-26 10:15  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/qq5rfBadR38jUokdlWSNlAjmEsO1rzv3srXShFRuTKBGDwkj4gvYy34iajd6zQiaKl77Wsy9mjC0xBCRg0YgDIWg/640?wx_fmt=gif "")  
  
  
![image](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR39w01nibicEbKc4GuaQJBqG96FwzOtyFsafy89VibYyZ13y9rrW1TLyefVptjbLSK7SREIq8qQXDIhkQ/640?wx_fmt=jpeg&from=appmsg "")  
  
  
网络安全研究人员近日披露，一个代号为ViciousTrap的威胁组织已入侵全球84个国家近5300台网络边缘设备，将其改造成类蜜罐网络。该组织利用思科小型企业路由器（型号包括RV016、RV042、RV042G、RV082、RV320和RV325）的关键漏洞CVE-2023-20118实施大规模入侵，其中中国澳门地区受影响最严重，有850台设备遭劫持。  
  
### Part01  
### 攻击链分析  
  
  
法国安全公司Sekoia在分析报告中指出："感染链会执行一个名为NetGhost的shell脚本，将被入侵路由器特定端口的入站流量重定向至攻击者控制的蜜罐基础设施，从而实现网络流量拦截。"值得注意的是，此前该漏洞的利用活动曾被归因于另一个名为PolarEdge的僵尸网络。  
  
  
虽然尚无证据表明这两起事件存在关联，但研究人员认为ViciousTrap幕后黑手正通过入侵各类互联网设备（包括SOHO路由器、SSL VPN、DVR和BMC控制器）构建蜜罐网络，受影响品牌超过50个，涉及Araknis Networks、华硕（ASUS）、友讯（D-Link）、领势（Linksys）和威联通（QNAP）等厂商。  
  
  
![image](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR39w01nibicEbKc4GuaQJBqG96QUML9tAPJJVIyT6VqAVBtlWDB5jj6q1KeXBIKbumaAf1YtiaOa7HdhQ/640?wx_fmt=jpeg&from=appmsg "")  
  
### Part02  
### 攻击技术细节  
  
  
攻击链首先利用CVE-2023-20118漏洞通过ftpget下载执行bash脚本，该脚本随后联系外部服务器获取wget二进制文件。接着二次利用思科漏洞执行通过wget获取的第二阶段脚本。这个内部代号为NetGhost的脚本会将受害系统的网络流量重定向至攻击者控制的第三方基础设施，实施中间人（AitM）攻击，并具备自删除功能以消除取证痕迹。  
  
  
Sekoia表示所有攻击尝试均源自单一IP地址（101.99.91[.]151），最早活动可追溯至2025年3月。研究人员还发现，ViciousTrap在一个月后的攻击中复用了PolarEdge僵尸网络曾使用的未公开WebShell。  
  
  
![image](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR39w01nibicEbKc4GuaQJBqG96GV4dvkO9ajhUWrgxYHtAK0cnyAicEn4Vmjxz5LQ3wICIGeZzvMcHmvg/640?wx_fmt=jpeg&from=appmsg "")  
  
### Part03  
### 最新攻击动态  
  
  
本月初，攻击者还从另一个IP地址（101.99.91[.]239）针对华硕路由器发起攻击，但未在受感染设备上部署蜜罐。所有活跃IP均位于马来西亚，属于主机商Shinjiru运营的自治系统AS45839。基于与GobRAT基础设施的微弱关联性，以及流量被重定向至中国台湾和美国多地资产的事实，研究人员判断攻击者可能来自中文地区。  
  
  
Sekoia总结称："虽然我们高度确信ViciousTrap构建的是蜜罐式网络，但其最终目标仍不明确。"安全研究员指出："这种重定向机制使攻击者成为静默观察者，能够收集漏洞利用尝试，甚至可能截获传输中的WebShell访问凭证。"  
  
  
**参考来源：**  
  
**ViciousTrap Uses Cisco Flaw to Build Global Honeypot from 5,300 Compromised Devices**  
  
https://thehackernews.com/2025/05/vicioustrap-uses-cisco-flaw-to-build.html  
  
  
###   
###   
###   
### 推荐阅读  
  
[](https://mp.weixin.qq.com/s?__biz=MjM5NjA0NjgyMA==&mid=2651321451&idx=1&sn=5471e9d1f4dd5999849c99d712ba7bd8&scene=21#wechat_redirect)  
###   
### 电台讨论  
  
****  
  
![图片](https://mmbiz.qpic.cn/mmbiz_gif/qq5rfBadR3icF8RMnJbsqatMibR6OicVrUDaz0fyxNtBDpPlLfibJZILzHQcwaKkb4ia57xAShIJfQ54HjOG1oPXBew/640?wx_fmt=gif&wxfrom=5&wx_lazy=1&tp=webp "")  
  
  
  
