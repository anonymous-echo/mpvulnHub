> **原文链接**: https://mp.weixin.qq.com/s?__biz=MjM5NjA0NjgyMA==&mid=2651323140&idx=3&sn=45827901940f918a640dfd1f6b37d59a

#  Windows SMB高危漏洞分析：Kerberos缺陷导致攻击者可获取SYSTEM权限  
 FreeBuf   2025-06-15 10:03  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/qq5rfBadR38jUokdlWSNlAjmEsO1rzv3srXShFRuTKBGDwkj4gvYy34iajd6zQiaKl77Wsy9mjC0xBCRg0YgDIWg/640?wx_fmt=gif "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR381bjehnibWmYSicwgoWLKLWbLLnuuTX7OaJFXPjnGP52OCExaFcJQ3w1utCJJUs6neNFEootIpTt0w/640?wx_fmt=jpeg&from=appmsg "")  
  
  
**Part01**  
### 漏洞概述  
  
  
Windows SMB 客户端新披露的安全漏洞（编号 CVE-2025-33073）引发广泛关注，该漏洞可能允许攻击者将权限提升至 SYSTEM 级别。该漏洞 CVSS 评分为 8.8 分，源于 SMB 协议栈中的访问控制缺陷，特别是 Kerberos 认证子密钥管理机制存在问题。  
  
  
根据安全公告，"成功利用此漏洞的攻击者可获取 SYSTEM 权限"——这是 Windows 环境中的最高访问级别。  
  
  
![Windows SMB 权限提升漏洞示意图](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR381bjehnibWmYSicwgoWLKLWbp7rSib9tWiankEIagDxxyQJMNxlOMVaZRIUKSL3qpaqZZoVu7ibaoFibvw/640?wx_fmt=jpeg&from=appmsg "")  
  
  
**Part02**  
### 攻击原理  
###   
  
要利用此漏洞，攻击者需诱骗受害者连接至恶意 SMB 服务器，可通过钓鱼攻击、路过式下载或水坑攻击等技术实现。成功连接后，恶意服务器会滥用 Kerberos 认证流程伪造特权令牌，最终获取本地提权访问。  
  
  
漏洞根源在于 SMB 客户端协商 Kerberos 认证时的处理机制： 研究人员解释："当 SMB 客户端选择 Kerberos 而非 NTLM 时，会调用 SpInitLsaModeContext 函数……最终将会话密钥插入全局列表 KerbSKeyList。"  
  
  
漏洞关键技术要素包括：  
- 使用 KerbCreateSKeyEntry 存储与特权登录 ID（SYSTEM 或 NETWORK SERVICE）关联的子密钥和令牌  
  
- KerbDoesSKeyExist 函数检查机制缺陷，允许攻击者在特定条件下重用该子密钥  
  
- 若客户端名称与机器名匹配，且子密钥存在于 KerbSKeyList 中，生成的令牌将被提升为 SYSTEM 权限  
  
  
研究人员指出："如果 IsSystem 为真，令牌信息的用户字段将被设为 SYSTEM，同时本地管理员 SID 会被添加至组字段。"  
  
  
**Part03**  
### 攻击链分析  
###   
1. 攻击者搭建精心设计的恶意 SMB 服务器  
  
1. 受害机器被诱导向恶意服务器发起 SMB 连接  
  
1. 服务器响应强制客户端使用 Kerberos 认证  
  
1. 生成子密钥并将特权令牌数据记录至 KerbSKeyList  
  
1. 服务器使用子密钥伪造有效的 AP-REQ 票据  
  
1. SMB 客户端接受并验证伪造票据  
  
1. 通过 KerbMakeTokenInformationV3 生成 SYSTEM 令牌，获取管理员权限  
  
目前，GitHub 上已公开该漏洞的概念验证（PoC）利用代码，这使得系统管理员和安全团队需要更紧急地应对此问题。  
  
  
**参考来源：**  
  
Windows SMB Flaw (CVE-2025-33073): SYSTEM Privilege Escalation via Kerberos, PoC Available  
  
https://securityonline.info/windows-smb-flaw-cve-2025-33073-system-privilege-escalation-via-kerberos-poc-available/  
  
  
###   
###   
###   
  
**推荐阅读**  
  
[](https://mp.weixin.qq.com/s?__biz=MjM5NjA0NjgyMA==&mid=2651322946&idx=1&sn=c9cbbd848459bfe0a36fa121ff364ad0&scene=21#wechat_redirect)  
  
### 电台讨论  
  
****  
  
  
  
![图片](https://mmbiz.qpic.cn/mmbiz_gif/qq5rfBadR3icF8RMnJbsqatMibR6OicVrUDaz0fyxNtBDpPlLfibJZILzHQcwaKkb4ia57xAShIJfQ54HjOG1oPXBew/640?wx_fmt=gif&wxfrom=5&wx_lazy=1&tp=webp "")  
  
