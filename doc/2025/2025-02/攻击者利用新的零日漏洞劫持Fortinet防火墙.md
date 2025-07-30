#  攻击者利用新的零日漏洞劫持Fortinet防火墙   
鹏鹏同学  黑猫安全   2025-02-12 01:29  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/8dBEfDPEceicvPuXb9EFFX3xqtQkPpsCGpGAm1yJaXZicqRX0tUVE2ibicayicLkicJ8iaCCib3G3YTML8sZDAxiavha9ZA/640?wx_fmt=png&from=appmsg "")  
  
Fortinet警告称，威胁行为者正在利用FortiOS和FortiProxy中的一个新的零日漏洞（编号为CVE-2025-24472，CVSS评分为8.1）来劫持Fortinet防火墙。  
  
该漏洞是一个身份验证绕过问题，可能允许远程攻击者通过制作恶意构造的CSF代理请求来获取超级管理员权限。  
  
公告中写道：“一个影响FortiOS 7.0.0至7.0.16和FortiProxy 7.2.0至7.2.12、7.0.0至7.0.19的身份验证绕过漏洞[CWE-288]可能允许远程攻击者通过制作恶意构造的CSF代理请求获取超级管理员权限。”  
  
该漏洞影响FortiOS 7.0.0至7.0.16、FortiProxy 7.0.0至7.0.19以及FortiProxy 7.2.0至7.2.12版本。Fortinet已在FortiOS 7.0.17及以上版本和FortiProxy 7.0.20/7.2.13及以上版本中修复了该漏洞。  
  
Fortinet将此漏洞添加到与2024年1月披露的漏洞CVE-2024-55591相关的公告中。CVE-2024-55591漏洞是一个影响FortiOS 7.0.0至7.0.16和FortiProxy 7.0.0至7.0.19以及7.2.0至7.2.12版本的身份验证绕过漏洞[CWE-288]。该漏洞可能允许远程攻击者通过向Node.js websocket模块发送恶意构造的请求来获取超级管理员权限。  
  
“一个影响FortiOS和FortiProxy的身份验证绕过漏洞[CWE-288]可能允许远程攻击者通过向Node.js websocket模块或制作恶意构造的CSF代理请求获取超级管理员权限。”公告中写道，“请注意，报告显示该漏洞正在被广泛利用。”  
  
威胁行为者利用这些漏洞创建恶意管理员或本地用户，修改防火墙策略，并通过访问SSL VPN进入内部网络。  
  
Fortinet还提供了针对此问题的临时缓解措施，建议禁用HTTP/HTTPS管理界面或通过本地策略限制可以访问该界面的IP地址。  
  
Arctic Wolf的研究人员最近观察到针对Fortinet FortiGate防火墙的攻击，涉及未经授权的登录、账户创建和配置更改。  
  
Arctic Wolf表示，当前的活动可以分为四个不同的阶段：  
  
1. 漏洞扫描（2024年11月16日至2024年11月23日）  
  
2. 侦察（2024年11月22日至2024年11月27日）  
  
3. SSL VPN配置（2024年12月4日至2024年12月7日）  
  
4. 横向移动（2024年12月16日至2024年12月27日）  
  
该公司推测，威胁行为者可能利用了目标系统中的零日漏洞。  
  
“12月初，Arctic Wolf Labs开始观察到涉及Fortinet FortiGate防火墙设备可疑活动的攻击活动。通过访问受影响防火墙的管理界面，威胁行为者能够更改防火墙配置。在受感染的环境中，观察到威胁行为者使用DCSync提取凭据。”Arctic Wolf表示，“虽然尚未确认此次攻击的初始访问向量，但Arctic Wolf Labs高度确信，考虑到受影响组织的时间线压缩以及受影响的固件版本，很可能是大规模利用了零日漏洞。”  
  
Arctic Wolf Labs于2024年12月12日向Fortinet报告了此次攻击活动，FortiGuard Labs于2024年12月17日确认已知并正在调查。  
  
  
