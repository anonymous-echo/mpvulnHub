#  黑客利用 DoS 漏洞禁用 Palo Alto Networks 防火墙   
Rhinoer  犀牛安全   2025-01-05 16:00  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qvpgicaewUBmSOG8vhibNNX653xKltTWMFd9CDLvINJuKkr0MmcBH2jibTSOFg1tePU2ZFWcUbBiaPdwe5bc2VZqJA/640?wx_fmt=png&from=appmsg "")  
  
Palo Alto Networks 警告称，黑客正在利用 CVE-2024-3393 拒绝服务漏洞，通过强制重启来禁用防火墙保护。  
  
然而，反复利用该安全问题会导致设备进入维护模式，需要人工干预才能恢复正常运行。  
  
公告中指出：“Palo Alto Networks PAN-OS 软件的 DNS 安全功能中存在拒绝服务漏洞，允许未经身份验证的攻击者通过防火墙的数据平面发送恶意数据包，从而重新启动防火墙。”  
  
DoS 漏洞被积极利用  
  
Palo Alto Networks 表示，未经身份验证的攻击者可以通过向受影响的设备发送特制的恶意数据包来利用此漏洞。  
  
该问题仅影响启用“DNS 安全”日志记录的设备，而受 CVE-2024-3393 影响的产品版本如下所示。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qvpgicaewUBmSOG8vhibNNX653xKltTWMFyiaqFEbk4RqNRficebOx3jkAK1j8tQaqVcT6LJ8QUmLgDKkXBP6JHLmg/640?wx_fmt=png&from=appmsg "")  
  
该供应商确认该漏洞已被积极利用，并指出当防火墙阻止利用该漏洞的攻击者发送的恶意 DNS 数据包时，客户会遇到中断。  
  
该公司已解决 PAN-OS 10.1.14-h8、PAN-OS 10.2.10-h12、PAN-OS 11.1.5、PAN-OS 11.2.3 及后续版本中的漏洞。  
  
然而，需要注意的是，受 CVE-2024-3393 影响的 PAN-OS 11.0 将不会收到补丁，因为该版本已于 11 月 17 日达到其生命周期终止 (EOL) 日期。  
  
对于无法立即更新的用户，Palo Alto Networks 还发布了解决方法和缓解问题的步骤：  
  
对于非托管 NGFW、由 Panorama 管理的 NGFW 或由 Panorama 管理的 Prisma Access：  
1. 导航至：对象 → 安全配置文件 → 反间谍软件 → DNS 策略 → 每个反间谍软件配置文件的 DNS 安全。  
  
1. 将所有配置的 DNS 安全类别的日志严重性更改为“无”。  
  
1. 提交更改并在应用修复后恢复日志严重性设置。  
  
对于由 Strata Cloud Manager (SCM) 管理的 NGFW：  
  
选项 1：使用上述步骤直接在每个 NGFW 上禁用 DNS 安全日志记录。  
  
选项 2：通过打开支持案例禁用租户中所有 NGFW 的 DNS 安全日志记录。  
  
对于由 Strata Cloud Manager (SCM) 管理的 Prisma Access：  
1. 打开支持案例以禁用租户中所有 NGFW 的 DNS 安全日志记录。  
  
1. 如果需要，请在支持案例中请求加快 Prisma Access 租户升级。  
  
信息来源：ThehackerNews  
  
