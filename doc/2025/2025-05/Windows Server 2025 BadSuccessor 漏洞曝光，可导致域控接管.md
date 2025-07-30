#  Windows Server 2025 "BadSuccessor" 漏洞曝光，可导致域控接管   
FreeBuf  FreeBuf   2025-05-27 11:57  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/qq5rfBadR38jUokdlWSNlAjmEsO1rzv3srXShFRuTKBGDwkj4gvYy34iajd6zQiaKl77Wsy9mjC0xBCRg0YgDIWg/640?wx_fmt=gif "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR3iccVtiaSzLOdiaOWSeZ0SmRIqwoE6p612wnDSuUnEoLkkApteF4pKiaf3Trp4uzQ0C7xsCRC1REkz19w/640?wx_fmt=jpeg&from=appmsg "")  
  
### Part01  
### 漏洞概述  
  
  
Windows Server 2025操作系统中新发现的"BadSuccessor"安全漏洞（CVE编号待分配）允许攻击者完全接管Active Directory（活动目录）域控制器。目前漏洞验证代码（PoC）已在安全社区流传，但微软尚未发布官方补丁。  
  
  
![漏洞验证截图](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR3iccVtiaSzLOdiaOWSeZ0SmRIqJfkTrN6q5sEZEO5Ek6t7vr6YdPSLq0ic7Br3Lh2SkU4bM5B0nTPtvXg/640?wx_fmt=jpeg&from=appmsg "")  
  
图片来源：Logan Goins  
  
### Part02  
### 技术影响  
  
  
该漏洞属于权限提升类缺陷，通过篡改域控的dMSA（动态管理系统账户）验证机制实现域环境接管。攻击者利用此漏洞可：  
  
- 绕过身份认证获取域管理员权限  
  
- 在目标网络内横向移动  
  
- 部署持久化后门  
  
- 窃取或篡改域内所有凭据数据  
  
### Part03  
### 当前状态  
  
  
网络安全研究人员证实：  
  
- 漏洞影响Windows Server 2025所有已发布版本  
  
- 攻击复杂度评级为"低"（无需特殊权限即可利用）  
  
- 微软安全响应中心已确认收到报告，但未提供补丁时间表  
  
**参考来源：**  
  
**Windows Server 2025 “BadSuccessor” Flaw Allows Domain Takeover (PoC Available, No Patch)**  
  
https://securityonline.info/windows-server-2025-badsuccessor-flaw-allows-domain-takeover-poc-available-no-patch/  
  
  
###   
###   
###   
### 推荐阅读  
  
[](https://mp.weixin.qq.com/s?__biz=MjM5NjA0NjgyMA==&mid=2651321451&idx=1&sn=5471e9d1f4dd5999849c99d712ba7bd8&scene=21#wechat_redirect)  
###   
### 电台讨论  
  
****  
  
![图片](https://mmbiz.qpic.cn/mmbiz_gif/qq5rfBadR3icF8RMnJbsqatMibR6OicVrUDaz0fyxNtBDpPlLfibJZILzHQcwaKkb4ia57xAShIJfQ54HjOG1oPXBew/640?wx_fmt=gif&wxfrom=5&wx_lazy=1&tp=webp "")  
  
