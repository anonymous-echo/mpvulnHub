> **原文链接**: https://mp.weixin.qq.com/s?__biz=MjM5NjA0NjgyMA==&mid=2651324992&idx=4&sn=202ab52532231d393da9f3e3e9320e01

#  Node.js路径穿越与哈希拒绝服务攻击漏洞威胁Windows应用  
 FreeBuf   2025-07-16 10:31  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/qq5rfBadR38jUokdlWSNlAjmEsO1rzv3srXShFRuTKBGDwkj4gvYy34iajd6zQiaKl77Wsy9mjC0xBCRg0YgDIWg/640?wx_fmt=gif "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR3ibCbuTG6icJiajjUCSoQJ1QzF67ILvzNjnCouF0QRM7KlkKmj1lQjmNT8TOpVVnM5HANnr1icSkM6jhA/640?wx_fmt=jpeg&from=appmsg "")  
  
  
OpenJS基金会已针对Node.js 24.x、22.x和20.x版本发布重要更新，修复了两个高危漏洞——CVE-2025-27210和CVE-2025-27209。这些漏洞会影响依赖JavaScript V8引擎的Windows应用程序及Web服务。  
  
  
**Part01**  
## 漏洞影响范围  
##   
## 这两个分别涉及路径穿越绕过和哈希碰撞拒绝服务（HashDoS）的漏洞，已威胁全球数百万后端和全栈应用程序，具体漏洞情况见下文。  
  
  
**Part02**  
## CVE-2025-27210  
## 利用Windows设备名实现路径穿越  
  
  
Windows平台上的Node.js应用存在路径规范化缺陷，攻击者可通过CON、PRN或AUX等特殊设备名称绕过目录遍历保护机制。  
  
  
OpenJS基金会指出："Node.js中对CVE-2025-23084的修复方案存在缺陷，特别是处理CON、PRN和AUX等Windows设备名时。"该漏洞源于path.normalize()和path.join() API处理设备名的方式，攻击者可借此操纵文件系统路径，访问未授权文件或目录。  
  
  
**Part03**  
## CVE-2025-27209  
## V8引擎rapidhash引发哈希拒绝服务复现  
  
  
第二个漏洞影响Node.js 24.x用户，源于V8 JavaScript引擎近期对字符串哈希算法的改动。虽然新版rapidhash提升了性能，却重新打开了哈希拒绝服务攻击的大门。  
  
  
Node.js团队解释称："攻击者即使不知道哈希种子，只要控制待哈希字符串，就能制造大量哈希碰撞。"尽管V8团队未将此视为安全缺陷，但Node.js维护团队基于实际影响将其认定为漏洞。  
  
  
哈希拒绝服务攻击可通过淹没哈希表使后端服务瘫痪，严重降低服务器性能。  
  
  
**Part04**  
## 已发布修复版本  
  
  
OpenJS基金会已发布以下修复版本：  
- Node.js v20.19.4  
  
- Node.js v22.17.1  
  
- Node.js v24.4.1  
  
**参考来源：**  
  
High-Severity Node.js Flaws Expose Windows Apps to Path Traversal (CVE-2025-27210) & HashDoS (CVE-2025-27209) Attacks  
  
https://securityonline.info/high-severity-node-js-flaws-expose-windows-apps-to-path-traversal-cve-2025-27210-hashdos-cve-2025-27209-attacks/  
  
  
###   
###   
###   
  
**推荐阅读**  
  
[](https://mp.weixin.qq.com/s?__biz=MjM5NjA0NjgyMA==&mid=2651324846&idx=2&sn=0751255f1f80386d498c5f17dc100c06&scene=21#wechat_redirect)  
  
### 电台讨论  
  
****  
  
  
  
![图片](https://mmbiz.qpic.cn/mmbiz_gif/qq5rfBadR3icF8RMnJbsqatMibR6OicVrUDaz0fyxNtBDpPlLfibJZILzHQcwaKkb4ia57xAShIJfQ54HjOG1oPXBew/640?wx_fmt=gif&wxfrom=5&wx_lazy=1&tp=webp "")  
  
   
  
