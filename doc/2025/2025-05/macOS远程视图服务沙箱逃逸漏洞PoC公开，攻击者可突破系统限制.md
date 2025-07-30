#  macOS远程视图服务沙箱逃逸漏洞PoC公开，攻击者可突破系统限制   
 FreeBuf   2025-05-13 10:16  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/qq5rfBadR38jUokdlWSNlAjmEsO1rzv3srXShFRuTKBGDwkj4gvYy34iajd6zQiaKl77Wsy9mjC0xBCRg0YgDIWg/640?wx_fmt=gif "")  
  
  
![macOS远程视图服务沙箱逃逸漏洞示意图](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR3ibOLMac5XMiaCZbZsyz6bOtic7Y7icgZe7LBTJdO89icOo5coZL6Tb1q74H3O5FibjcaKGEL1DslMQvchA/640?wx_fmt=jpeg&from=appmsg "")  
  
  
苹果公司近日针对macOS系统中新披露的CVE-2025-31258漏洞发布补丁，该漏洞可能允许恶意应用程序突破沙箱限制，获取未授权的系统资源访问权限。在安全研究员Seo Hyun-gyu公开概念验证（PoC）利用代码后，该漏洞已在macOS Sequoia 15.5版本中得到修复。  
  
### Part01  
### 漏洞技术分析  
  
  
该漏洞存在于RemoteViewServices（远程视图服务）框架中，这是macOS系统中一个底层但至关重要的组件。虽然知名度不高，但该框架负责处理内容渲染和预览功能，特别是Quick Look快速查看和远程文档浏览等特性。  
  
  
根据匿名研究人员的发现报告，该漏洞可实现沙箱逃逸，可能使攻击者获取受限系统资源或用户数据的未授权访问权限。苹果在安全公告中确认："应用程序可能突破其沙箱限制"，并表示已通过移除存在漏洞的代码解决问题。  
  
### Part02  
### 修复与风险提示  
  
  
苹果公司确认该漏洞已在macOS Sequoia 15.5版本中修复，并敦促用户立即安装更新。值得注意的是，在苹果发布补丁后不久，研究员Seo Hyun-gyu便在GitHub上公开了PoC利用代码，并在YouTube发布了演示视频。尽管苹果表示尚未发现该漏洞在野被利用的证据，但PoC的公开显著提高了未打补丁系统的风险等级。  
  
  
此次修复是苹果周一发布的综合性安全更新的一部分，更新范围涵盖macOS、iOS和iPadOS等多个操作系统。建议所有macOS用户，特别是Sequoia 15.5之前版本的用户，立即安装最新更新以确保系统安全。  
  
  
**参考来源：**  
  
**PoC Released: CVE-2025-31258 Sandbox Escape in macOS via RemoteViewServices**https://securityonline.info/poc-released-cve-2025-31258-sandbox-escape-in-macos-via-remoteviewservices/  
  
  
###   
###   
###   
### 推荐阅读  
  
[](https://mp.weixin.qq.com/s?__biz=MjM5NjA0NjgyMA==&mid=2651320016&idx=1&sn=8488591c0f5d5cf6414cef9bfa60bf62&scene=21#wechat_redirect)  
  
### 电台讨论  
  
****  
****  
  
  
  
![图片](https://mmbiz.qpic.cn/mmbiz_gif/qq5rfBadR3icF8RMnJbsqatMibR6OicVrUDaz0fyxNtBDpPlLfibJZILzHQcwaKkb4ia57xAShIJfQ54HjOG1oPXBew/640?wx_fmt=gif&tp=webp&wxfrom=5&wx_lazy=1 "")  
  
