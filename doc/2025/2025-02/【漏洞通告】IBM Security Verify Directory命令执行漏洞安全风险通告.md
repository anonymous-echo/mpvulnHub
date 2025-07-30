#  【漏洞通告】IBM Security Verify Directory命令执行漏洞安全风险通告   
 嘉诚安全   2025-02-13 00:29  
  
**漏洞背景**  
  
  
  
  
  
  
  
  
近日，嘉诚安全监测到IBM Security Verify Directory命令执行漏洞，漏洞编号为：  
CVE-2024-51450。  
  
  
IBM Security Verify Directory是一款企业级身份和访问管理解决方案，提供安全的用户身份管理和目录服务，支持复杂的认证和授权需求，帮助组织保护敏感数据。IBM Security Verify Access Appliance是一款用于管理企业应用程序访问的解决方案，提供身份验证、单点登录、权限控制和多因素认证功能。两者通过集中管理用户访问权限和安全策略，确保企业应用的安全性与合规性，广泛应用于提升组织的网络安全性和用户管理效率。  
  
  
鉴于漏洞危害较大，嘉诚安全提醒相关用户尽快更新至安全版本，避免引发漏洞相关的网络安全事件。  
  
**漏洞详情**  
  
  
  
  
  
  
  
  
经研判，该漏洞为  
**高危**  
漏洞  
。  
IBM安全验证目录（IBM Security Verify Directory）和安全验证访问设备（IBM Security Verify Access Appliance）存在两个严重漏洞，可能被攻击者利用，导致未授权访问和命令执行。CVE-2024-51450是一个远程命令注入漏洞，允许远程经过身份验证的攻击者通过发送精心构造的请求，在系统上执行任意命令，CVSS评分为9.1，漏洞级别严重。CVE-2024-49814是一个本地权限提升漏洞，允许经过身份验证的用户通过不必要的权限执行操作，从而获得更高权限，可能完全控制系统，CVSS评分为7.8，漏洞级别高危。  
  
**危害影响**  
  
  
  
  
  
  
  
  
影响版本：  
  
10.0.0<=IBM Security Verify Directory<=10.0.3  
  
**处置建议**  
  
  
  
  
  
  
  
  
1.升级版本  
  
下载并安装IBM Security Verify Directory版本10.0.3.1以解决相关安全问题。  
  
下载链接：  
  
https://www.ibm.com/support/pages/ibm-security-verify-directory-fix-level-10031-download-document/  
  
2.通用建议  
  
定期更新系统补丁，减少系统漏洞，提升服务器的安全性。  
  
加强系统和网络的访问控制，修改防火墙策略，关闭非必要的应用端口或服务，减少将危险服务（如SSH、RDP等）暴露到公网，减少攻击面。  
  
使用企业级安全产品，提升企业的网络安全性能。加强系统用户和权限管理，启用多因素认证机制和最小权限原则，用户和软件权限应保持在最低限度。  
  
启用强密码策略并设置为定期修改。  
  
3.参考链接  
  
https://www.ibm.com/support/pages/node/7182558  
  
https://nvd.nist.gov/vuln/detail/CVE-2024-51450  
  
https://nvd.nist.gov/vuln/detail/CVE-2024-49814  
  
https://securityonline.info/ibm-security-verify-directory-vulnerable-to-critical-security-flaw-cve-2024-51450-cvss-9-1/  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/1t8LLTibEW5NtxqlBL1HLib8jMO0PWtibWTWTFPOa3ND1lyaEQyBgp2fodg9A1XxvPjY7L6ILtK26MBGhofWE0ORw/640?wx_fmt=png&wx_ "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/sDiaO8GNKJrJnzIYoQAv2nF3pgKm4SgdFkzuniaicBHQxgSdu0U0xyYbNDOcNkDMWCjwJNwKnic9ASAhhxEpkFL6lg/640?wx_fmt=gif&wx_ "")  
  
  
