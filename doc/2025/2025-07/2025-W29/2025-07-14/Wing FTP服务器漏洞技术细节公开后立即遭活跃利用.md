> **原文链接**: https://mp.weixin.qq.com/s?__biz=Mzg3OTc0NDcyNQ==&mid=2247494237&idx=2&sn=4f4911a4425e6d7a7ed5b3a283a1dc40

#  Wing FTP服务器漏洞技术细节公开后立即遭活跃利用  
鹏鹏同学  黑猫安全   2025-07-14 01:03  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/8dBEfDPEce9iaUUKxz9qml8B1KdZHobXZicsFxXKJIHajdLictmJsM2EXZGr6icGbjoyYic6FLibj2YUl5DvlRZptmlA/640?wx_fmt=png&from=appmsg "")  
  
Wing FTP Server是一款支持FTP/FTPS/SFTP/HTTP/S等多协议的文件传输解决方案，提供跨平台（Windows/Linux/macOS）服务及可视化网页管理界面。该软件日前曝出可导致系统完全沦陷的致命漏洞（CVE-2025-47812），攻击者利用空字节处理缺陷注入恶意Lua代码，最终能以root/SYSTEM权限执行任意命令。  
  
根据MITRE发布的公告："Wing FTP Server 7.4.4之前版本存在空字节（'\0'）处理缺陷，攻击者可向用户会话文件注入任意Lua代码，进而以FTP服务默认权限（Linux为root，Windows为SYSTEM）执行系统命令。该漏洞允许通过匿名FTP账户触发，将导致服务器完全失陷。"  
  
漏洞根源在于SessionModule.lua脚本加载会话文件时缺乏有效验证。攻击者通过操纵与Cookie（UID）关联的会话文件，在执行目录列表等任何需认证操作时即可触发代码执行。由于该服务默认以高权限运行且未启用沙箱隔离等防护机制，最终获得的将是系统级控制权。  
  
尽管漏洞利用需要认证凭证，但启用的匿名FTP账户同样可被利用。这意味着攻击者能从基础用户权限（包括匿名登录）直接提权至系统管理员身份，实现跨平台的完全控制。  
  
**时间线显示漏洞遭快速武器化：**  
- 2025年6月30日：漏洞技术细节首次公开  
  
- 2025年7月1日：Huntress确认攻击活动已开始  
  
- 2025年7月10日：研究机构发布完整分析报告  
  
Arctic Wolf警告称："攻击者通过用户名字段插入特殊字符绕过字符串处理，在访问特定页面时触发预植入的Lua恶意代码。已观测到攻击者尝试下载执行恶意程序、进行系统侦察及部署远控软件的行为模式。此类边缘设备漏洞常被用于数据窃取和后续勒索软件攻击。"  
  
安全团队强烈建议用户立即升级至7.4.4及以上版本。所有早期版本均受此漏洞影响，且随着漏洞利用代码（PoC）的扩散，预计将出现更大规模的攻击浪潮。  
  
  
