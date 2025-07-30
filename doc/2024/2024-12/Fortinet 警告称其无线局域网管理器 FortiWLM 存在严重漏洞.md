#  Fortinet 警告称其无线局域网管理器 FortiWLM 存在严重漏洞   
鹏鹏同学  黑猫安全   2024-12-19 16:20  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/8dBEfDPEce9yXgrRhdklFicicTFlM6j4icfRZ1iaYnnv39ibwLSFtZbrlWTewEZrZA6hBdeuu5MkUTfvmojURqibGxHg/640?wx_fmt=png&from=appmsg "")  
  
Fortinet 警告称，现已修补的无线局域网管理器（FortiWLM）漏洞（追踪为 CVE-2023-34990，CVSS 评分为 9.6）可能导致管理员访问和敏感信息泄露。供应商发布的通告中写道：“FortiWLM 中的相对路径遍历 [CWE-23] 可能允许远程未经身份验证的攻击者读取敏感文件。”Horizon3.ai 安全研究员 Zach Hanley (@hacks_zach) 向 Fortinet 报告了此漏洞。  
  
该漏洞影响以下产品：  
- FortiWLM 版本 8.6.0 至 8.6.5（已在 8.6.6 或更高版本中修复）  
  
- FortiWLM 版本 8.5.0 至 8.5.4（已在 8.5.5 或更高版本中修复）  
  
Hanley 解释说，漏洞 CVE-2023-34990 使远程攻击者能够通过针对特定端点的精心制作的请求来利用日志读取功能。Horizon3.ai 发布的报告中写道：“此漏洞允许远程未经身份验证的攻击者通过针对 /ems/cgi-bin/ezrf_lighttpd.cgi 端点的精心制作的请求，访问并滥用系统上的内置功能，该功能旨在读取特定的日志文件。此问题是由于请求参数缺乏输入验证，允许攻击者遍历目录并读取系统上的任何日志文件。”  
  
报告还指出，FortiWLM 的详细日志暴露了会话 ID，使攻击者能够利用日志文件读取漏洞劫持会话并访问经过身份验证的端点。FortiWLM 中经过身份验证的用户的会话 ID 令牌在每次设备启动时保持静态。攻击者可以通过日志文件读取漏洞利用这一点，劫持会话并获得管理员访问权限。  
  
研究人员还注意到，漏洞 CVE-2023-34990 可以与 CVE-2023-48782（CVSS 评分为 8.8）链接，导致在 root 上下文中远程执行任意代码。威胁演员经常针对 Fortinet 设备，因此客户迅速更新其安装至关重要。  
  
报告总结道：“尽管我们发现它在州、地方和教育（SLED）以及医疗保健客户中很受欢迎，但幸运的是，互联网曝光仅限于大约 15 个实例。”  
  
  
