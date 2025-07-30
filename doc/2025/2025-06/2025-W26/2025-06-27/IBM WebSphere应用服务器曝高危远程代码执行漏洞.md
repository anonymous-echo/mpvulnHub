> **原文链接**: https://mp.weixin.qq.com/s?__biz=MjM5NjA0NjgyMA==&mid=2651323993&idx=4&sn=a39d5181504a9caeda8bbcff989ef625

#  IBM WebSphere应用服务器曝高危远程代码执行漏洞  
 FreeBuf   2025-06-27 11:01  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/qq5rfBadR38jUokdlWSNlAjmEsO1rzv3srXShFRuTKBGDwkj4gvYy34iajd6zQiaKl77Wsy9mjC0xBCRg0YgDIWg/640?wx_fmt=gif "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR38uzFbE5KvC4Ju5WsibnbMoPNXOEECKPbywU1PnS0N6fLs5YWXvlcGYQqB0ia32XeArtMXlpzA7U44Q/640?wx_fmt=jpeg&from=appmsg "")  
  
  
IBM近日发布安全警报，披露WebSphere Application Server（WebSphere应用服务器）8.5和9.0版本存在高危漏洞CVE-2025-36038。  
  
  
该漏洞CVSS基准评分高达9.0，攻击者可通过构造恶意的序列化载荷实现未经认证的远程代码执行（RCE），对企业级Java应用构成严重威胁。截至目前，暂没有报告显示攻击者利用该漏洞进行攻击。  
  
  
对于大型企业而言，WebSphere Application Server是一个极其重要的平台，因为它是主流 Java EE 应用服务器之一。据悉，目前全球有两千家企业在使用  
WebSphere Application Server。  
  
  
**Part01**  
### 漏洞技术细节  
  
  
IBM 的安全公告显示：  
  
IBM WebSphere Application Server 可能允许远程攻击者使用特制的序列化对象序列在系统上执行任意代码。  
  
  
该漏洞一旦被成功利用，攻击者无需事先认证即可远程注入并执行恶意代码，导致系统完全沦陷。  
  
  
**Part02**  
### 受影响版本范围  
  
  
漏洞影响以下WebSphere应用服务器版本：  
- 9.0.0.0至9.0.5.24版本  
  
- 8.5.0.0至8.5.5.27版本  
  
这些版本在企业环境中部署广泛，依赖IBM中间件运行Java EE应用的各行业均面临重大风险。  
  
  
**Part03**  
### 修复方案  
  
  
IBM已提供详细修复指南，强烈建议用户立即采取行动：  
  
- **9.0版本用户**  
- 安装9.0.5.25或更高版本修复包（预计2025年第三季度发布）  
  
- 根据临时修复的要求升级到最低修复包级别  
，应用针对PH66674的临时补丁  
  
  
- **8.5版本用户**  
- 安装  
8.5.5.28  
或更高版本修复包（预计2025年第三季度发布）  
  
- 根据临时修复的要求升级到最低修复包级别  
，应用针对PH66674的临时补丁  
  
**参考来源：**  
  
CVE-2025-36038: Critical RCE Vulnerability Discovered in IBM WebSphere Application Server  
  
https://securityonline.info/cve-2025-36038-critical-rce-vulnerability-discovered-in-ibm-websphere-application-server/  
  
  
###   
###   
###   
  
**推荐阅读**  
  
[](https://mp.weixin.qq.com/s?__biz=MjM5NjA0NjgyMA==&mid=2651323665&idx=1&sn=15875d40f858538184006215073544fb&scene=21#wechat_redirect)  
  
### 电台讨论  
  
****  
  
  
  
![图片](https://mmbiz.qpic.cn/mmbiz_gif/qq5rfBadR3icF8RMnJbsqatMibR6OicVrUDaz0fyxNtBDpPlLfibJZILzHQcwaKkb4ia57xAShIJfQ54HjOG1oPXBew/640?wx_fmt=gif&wxfrom=5&wx_lazy=1&tp=webp "")  
  
