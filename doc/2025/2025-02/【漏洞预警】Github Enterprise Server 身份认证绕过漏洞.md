#  【漏洞预警】Github Enterprise Server 身份认证绕过漏洞   
原创 MasterC  企业安全实践   2025-02-13 09:09  
  
一、漏洞描述  
  
GitHub 企业版是 GitHub.com 的 自托管 (Self-Hosted) 版本，旨在为企业和组织提供一个安全、可控、私有的代码协作和 DevOps 平台。  
  
该平台存在一个身份认证绕过漏洞，攻击者可以利用该漏洞，通过构造恶意的 SAML 响应，绕过身份验证，从而冒充其他用户登录 GitHub Enterprise。  
  
二、漏洞等级  
  
高危  
  
三、受影响版本  
- 3.12.14 之前的版本  
  
- 3.13.10 之前的版本  
  
- 3.14.7 之前的版本  
  
- 3.15.2 之前的版本  
  
- 3.16.0 之前的版本  
  
  
四、安全版本  
- GitHub Enterprise Server 3.12.14  
  
- GitHub Enterprise Server 3.13.10  
  
- GitHub Enterprise Server 3.14.7  
  
- GitHub Enterprise Server 3.15.2  
  
- GitHub Enterprise Server 3.16.0  
  
  
五、修复建议  
  
目前官方已修复该漏洞，建议受影响用户尽快前往官网升级至安全版本。  
  
六、缓解方案  
  
目前暂无缓解方案  
  
七、参考链接  
  
https://docs.github.com/en/enterprise-server@3.12/admin/release-notes#3.12.14  
  
https://docs.github.com/en/enterprise-server@3.13/admin/release-notes#3.13.10  
  
https://docs.github.com/en/enterprise-server@3.14/admin/release-notes#3.14.7  
  
https://docs.github.com/en/enterprise-server@3.15/admin/release-notes#3.15.2  
  
  
