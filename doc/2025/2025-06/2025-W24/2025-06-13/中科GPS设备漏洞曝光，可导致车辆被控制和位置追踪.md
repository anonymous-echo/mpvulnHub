> **原文链接**: https://mp.weixin.qq.com/s?__biz=MjM5NjA0NjgyMA==&mid=2651323069&idx=4&sn=77515d1b0ea03422f212c22ce648451c

#  中科GPS设备漏洞曝光，可导致车辆被控制和位置追踪  
 FreeBuf   2025-06-13 10:00  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/qq5rfBadR38jUokdlWSNlAjmEsO1rzv3srXShFRuTKBGDwkj4gvYy34iajd6zQiaKl77Wsy9mjC0xBCRg0YgDIWg/640?wx_fmt=gif "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR38Tl4wYSAtXiaoFKOv5riaQkxbLBsF8eiaHKlkUniaqAuxwk8Y4fqibRSM3JmbZy0PJd2fjLRnbiacJGbGw/640?wx_fmt=jpeg&from=appmsg "")  
  
### Part01  
### 中科GPS设备存在两处漏洞  
###   
  
美国网络安全和基础设施安全局（CISA）发布警告称，中科（SinoTrack）GPS设备存在两处漏洞，远程攻击者可利用这些漏洞未经授权访问车辆设备配置文件。研究人员指出，根据设备型号不同，攻击者可能借此追踪车辆位置，甚至切断燃油泵电源。  
  
  
CISA在公告中表示："成功利用这些漏洞可使攻击者通过通用web管理界面未经授权访问设备配置文件。获取设备配置文件后，攻击者可能对联网车辆执行某些远程功能，例如追踪车辆位置，以及在支持的情况下切断燃油泵电源。"  
  
### Part02  
### 漏洞详情说明  
###   
  
**CVE-2025-5484**  
（CVSS评分：8.3）- 中科设备使用所有设备通用的默认密码，且在安装过程中不强制要求修改。由于用户名仅为设备标签上印刷的ID，攻击者通过物理接触设备或在eBay等平台的在线照片中发现该信息即可轻易获取访问权限。这使得攻击者入侵变得异常简单。  
  
  
**CVE-2025-5485**  
（CVSS评分：8.6）- 中科设备使用所有设备通用的默认密码，且在安装过程中不强制要求修改。由于用户名仅为设备标签上印刷的ID，攻击者通过物理接触设备或在eBay等平台的在线照片中发现该信息即可轻易获取访问权限。这使得攻击者入侵变得异常简单。  
###   
### Part03  
### 安全建议  
###   
### CISA敦促用户立即修改默认密码、隐藏设备ID，并在采取行动前评估风险。由于中科公司未对CISA的通报作出回应，用户应直接联系供应商确认。CISA同时建议遵循网络安全最佳实践，避免点击钓鱼链接，发现可疑活动及时上报。截至目前，尚未有公开报道显示这些漏洞已被利用。  
  
  
**参考来源：**  
  
****  
**SinoTrack GPS device flaws allow remote vehicle control and location tracking**  
  
https://securityaffairs.com/178922/security/sinotrack-gps-device-flaws-allow-remote-vehicle-control-and-location-tracking.html  
  
  
###   
###   
###   
  
**推荐阅读**  
  
[](https://mp.weixin.qq.com/s?__biz=MjM5NjA0NjgyMA==&mid=2651322946&idx=1&sn=c9cbbd848459bfe0a36fa121ff364ad0&scene=21#wechat_redirect)  
  
### 电台讨论  
  
****  
  
  
  
![图片](https://mmbiz.qpic.cn/mmbiz_gif/qq5rfBadR3icF8RMnJbsqatMibR6OicVrUDaz0fyxNtBDpPlLfibJZILzHQcwaKkb4ia57xAShIJfQ54HjOG1oPXBew/640?wx_fmt=gif&wxfrom=5&wx_lazy=1&tp=webp "")  
  
