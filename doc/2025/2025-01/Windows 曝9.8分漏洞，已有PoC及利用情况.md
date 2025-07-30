#  Windows 曝9.8分漏洞，已有PoC及利用情况   
老布-Freebuf  乌雲安全   2025-01-07 03:00  
  
SafeBreach Labs的研究人员发布了关于Windows轻量级目录访问协议（LDAP）的一个关键漏洞的概念验证（PoC）和漏洞利用方法，该漏洞编号为CVE - 2024 - 49112。微软在2024年12月10日的补丁星期二更新中披露了此漏洞，其CVSS严重性评分高达9.8。  
  
  
CVE - 2024 - 49112属于远程代码执行（RCE）漏洞，会对包括域控制器（DC）在内的Windows服务器产生影响。域控制器在组织网络里是关键组成部分，负责管理身份验证和用户权限等工作。  
  
### 漏洞影响  
  
> 1. 让未打补丁的服务器崩溃；  
> 2. 在LDAP服务环境下执行任意代码；  
> 3. 有可能破坏整个域环境。  
  
###   
### 漏洞利用技术细节  
  
****  
此漏洞是由于LDAP相关代码中的整数溢出问题引发。未经身份验证的攻击者可通过发送特制的RPC调用来触发恶意的LDAP查询，成功利用时可能导致服务器崩溃或者进一步实现远程代码执行。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR38iaJkN6SWjhqluJCpjZW7hnuTWHibJxjMK8l230CfqeJ6kHGmDFRdJSsWuicAqnkr515nbCUJCbdBSg/640?wx_fmt=jpeg&from=appmsg "")  
  
  
SafeBreach Labs开发了一个名为“LDAPNightmare”的PoC漏洞利用工具，以此展示该漏洞的严重性。该漏洞利用按以下攻击流程可使未打补丁的Windows服务器崩溃：  
> 1. 攻击者向目标服务器发送DCE/RPC请求；  
> 2. 目标服务器向攻击者的DNS服务器查询以获取信息；  
> 3. 攻击者回应主机名和LDAP端口；  
> 4. 目标服务器发送NBNS广播以定位攻击者的主机名；  
> 5. 攻击者回复其IP地址；  
> 6. 目标服务器成为LDAP客户端，并向攻击者的机器发送CLDAP请求；  
> 7. 攻击者发送恶意引用响应，致使LSASS（本地安全机构子系统服务）崩溃并重启服务器。  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR38iaJkN6SWjhqluJCpjZW7hndRDrgjp6MDxibriaWicmSNj7RRL3RyzX4AOvibWbHeVEcTj9XOv3rA9PEg/640?wx_fmt=jpeg&from=appmsg "")  
  
  
SafeBreach已经验证，微软的补丁通过解决整数溢出问题有效地缓解了该漏洞。所有未打补丁的Windows Server版本都会受到此漏洞影响，其中包括Windows Server 2019和2022。利用该漏洞可能让攻击者控制域环境，所以这会成为勒索软件团伙和其他威胁行为者的主要目标。  
  
  
建议组织马上采取以下行动：  
> 1. 立即应用微软2024年12月的补丁；  
> 2. 在补丁安装完成之前，监控可疑的DNS SRV查询、CLDAP引用响应和DsrGetDcNameEx2调用；  
> 3. 使用SafeBreach的PoC工具（可从GitHub获取）来测试自身环境。  
  
  
  
