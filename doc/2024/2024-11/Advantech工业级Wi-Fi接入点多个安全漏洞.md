#  Advantech工业级Wi-Fi接入点多个安全漏洞   
 锋刃科技   2024-11-30 18:13  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/fWmp3zFswgHuG0kQXHbMmQ5ib1HgckCXrCn1uZvh27QTKBzARYGgTdch9tksIsBvRytQnNo20qj8v2pyvVia3EUA/640?wx_fmt=gif&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
  
Advantech EKI 系列工业级 Wi-Fi 接入点是用于工业自动化和物联网（IoT）环境中的无线网络解决方案。它们设计用于提供高性能的无线连接，并支持远程监控与管理，适用于智能工厂、自动化生产线等应用。  
  
  
  
  
  
  
  
  
  
**01 漏洞描述**  
  
  
  
Advantech EKI 系列工业级 Wi-Fi 接入点中，发现了多达 20 个安全漏洞，其中 6 个漏洞被标记为关键漏洞。这些漏洞可能允许攻击者绕过身份验证、执行恶意代码，并可能完全控制受影响的设备。  
  
**关键漏洞包括**：  
1. **CVE-2024-50370 - CVE-2024-50374**（CVSS 9.8）：这些漏洞涉及操作系统命令的特殊元素未被正确处理（命令注入漏洞），允许攻击者执行任意命令，获取 root 权限。  
  
1. **CVE-2024-50375**（CVSS 9.8）：缺少身份验证的关键功能，允许未经授权的用户执行高权限操作。  
  
1. **CVE-2024-50376**（CVSS 7.3）：一个跨站脚本（XSS）漏洞，攻击者可以通过恶意 Wi-Fi 网络名称（SSID）传播 JavaScript 代码，从而远程执行命令。  
  
1. **CVE-2024-50359**（CVSS 7.2）：操作系统命令注入漏洞，可以与 XSS 漏洞（CVE-2024-50376）联合使用，提升攻击效果。  
  
  
  
****  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/fWmp3zFswgHEXiaN1n0cqgQF7gibBicgJK8TlG2ZGbSQk3949YnhiaQdZvcmoderqAAh6L5OYicAHicDFXqvPKGGTBhw/640?wx_fmt=png&from=appmsg "")  
  
  
  
  
**02****漏洞影响泛微**  
  
  
- **受影响产品**：Advantech EKI 系列工业 Wi-Fi 接入点  
  
- **固件版本**：所有受影响的设备版本（低于修复版本）  
  
- EKI-6333AC-2G 和 EKI-6333AC-2GD（固件版本低于 1.6.5）  
  
- EKI-6333AC-1GPO（固件版本低于 1.2.2）  
  
- **攻击方式**：  
  
- 攻击者需要物理接近受害设备，使用恶意的接入点广播特制数据包。  
  
- 攻击者可以通过恶意配置的 SSID（Wi-Fi 网络名）诱使管理员访问受感染的页面，触发 XSS 漏洞并结合命令注入漏洞，获取 root 权限，进一步执行恶意操作。  
  
  
  
  
  
**03****漏洞修复方案**  
  
  
  
- **固件更新**：  
  
- 对于 **EKI-6333AC-2G** 和 **EKI-6333AC-2GD** 型号，升级固件至 **1.6.5** 版本。  
  
- 对于 **EKI-6333AC-1GPO** 型号，升级固件至 **1.2.2** 版本。  
  
- **安全措施**：  
  
- 建议用户及时更新设备固件，并确认网络安全配置，以防止恶意接入点的攻击。  
  
- 定期检查和维护网络设备，确保所有设备和管理系统都使用最新的安全补丁。  
  
  
  
  
  
  
  
  
**04 参考链接**  
  
  
  
https://thehackernews.com/2024/11/over-two-dozen-flaws-identified-in.html  
  
  
**END**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Ljib4So7yuWjgINrN72W7AwgiaqWlJJfJg7RQPtVjGIF1m7QZ47gNtFk06Ql0nibicTvEpbtI4SXhThwcpmbfW7XvA/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
