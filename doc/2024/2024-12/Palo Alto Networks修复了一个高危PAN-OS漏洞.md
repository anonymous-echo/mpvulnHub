#  Palo Alto Networks修复了一个高危PAN-OS漏洞   
鹏鹏同学  黑猫安全   2024-12-27 23:00  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/8dBEfDPEce8uY9FKjuAcPAadGPjEO3oM6CSIABR9HDibHQsRNIia1xPeFNDXaQZndh0B2dcZWYY68iaVf2aLZsAag/640?wx_fmt=png&from=appmsg "")  
  
Palo Alto Networks修复了PAN-OS软件中的一个高危漏洞CVE-2024-3393（CVSS评分：8.7），该漏洞可能导致拒绝服务（DoS）攻击。未经身份验证的攻击者可以通过数据平面发送恶意数据包来利用此漏洞重启防火墙。反复利用此漏洞会导致防火墙进入维护模式。  
  
安全公告指出：“Palo Alto Networks PAN-OS软件的DNS安全功能中存在拒绝服务漏洞，允许未经身份验证的攻击者通过防火墙的数据平面发送恶意数据包，从而重启防火墙。反复尝试触发此情况会导致防火墙进入维护模式。”   
  
如果通过Prisma Access限制访问权限仅限于已认证的最终用户，则此漏洞的严重性降低至CVSS评分7.1。此漏洞影响PAN-OS 10.X和11.X版本，包括运行这些版本的Prisma Access。PAN-OS 10.1.14-h8、10.2.10-h12、11.1.5、11.2.3及更高版本已修复此漏洞。只有在启用DNS安全日志记录时才能利用此漏洞。  
  
Palo Alto Networks了解到，当客户的防火墙阻止触发此问题的恶意DNS数据包时，他们会面临拒绝服务（DoS）的情况。该网络安全厂商已通过发布PAN-OS 10.1.14-h8、PAN-OS 10.2.10-h12、PAN-OS 11.1.5、PAN-OS 11.2.3及所有更高版本的PAN-OS解决了此问题。该公司指出，PAN-OS 11.0已于2024年11月17日结束生命周期（EOL），因此不会为此版本提供修复程序。为了缓解此问题，客户可以通过Panorama或非托管防火墙中的DNS策略设置，将所有DNS安全类别的日志严重性设置为“无”。对于由Strata Cloud Manager (SCM)管理的防火墙，用户可以通过打开支持案例来禁用每个设备或所有设备上的DNS安全日志记录。Prisma Access租户也应打开支持案例以禁用日志记录，直到完成升级。  
  
