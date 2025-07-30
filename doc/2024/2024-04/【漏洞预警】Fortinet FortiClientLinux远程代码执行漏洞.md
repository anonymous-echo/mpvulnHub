#  【漏洞预警】Fortinet FortiClientLinux远程代码执行漏洞   
cexlife  飓风网络安全   2024-04-11 22:49  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ibhQpAia4xu01kbcu9smwOmtiaialC3F09Do6fIiafLnERXm0Zdyh6x8kSSMNacIE6tV66qeGy1dicFeM5leGdWwoFxg/640?wx_fmt=png&from=appmsg "")  
  
**漏洞描述:**  
FortiClient是一种全面的安全解决方案,可保护终端用户设备、网络和应用程序,FortiClient for Linux支持Ubuntu、Debian、CentOS、Red Hat等多个Linux发行版,提供了FortiTelemetry、防病毒、SSL VPN和漏洞扫描等多种功能,近日监测到Fortinet FortiClientLinux中修复了一个远程代码执行漏洞（CVE-2023-45590）,其CVSS评分为9.4,Fortinet FortiClientLinux 版本7.2.0、7.0.6 - 7.0.10、7.0.3 - 7.0.4中存在漏洞,该漏洞源于危险的Nodejs配置,未经身份验证的威胁者可通过诱导FortiClientLinux用户访问恶意网站来触发该漏洞从而导致任意代码执行。**影响范围:**Fortinet FortiClientLinux 7.2.0Fortinet FortiClientLinux 7.0.6 - 7.0.10Fortinet FortiClientLinux 7.0.3 - 7.0.4**安全措施:**升级版本目前该漏洞已经修复,受影响用户可升级到以下版本:Fortinet FortiClientLinux7.2.0:升级到7.2.1或更高版本Fortinet FortiClientLinux7.0.6-7.0.10、7.0.3-7.0.4:升级到7.0.11或更高版本。**下载链接:**https://docs.fortinet.com/document/forticlient/7.2.1/linux-release-notes/912707**临时措施:**暂无**参考链接:**https://www.fortiguard.com/psirt/FG-IR-23-087  
