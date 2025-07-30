#  已复现！Palo Alto Networks PAN-OS 身份验证绕过漏洞   
应急响应中心  亚信安全   2025-02-14 10:15  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/iczzp36h0nbFjsRMzFAmuiaicxbfwHFlyHlt2XzBsxMrH7CA7HBicsRtMSeSY3V6obAPfO3hRw9Hs7Fpp4cBvgY4uw/640?wx_fmt=jpeg "")  
  
  
今日，亚信安全CERT监控到安全社区研究人员发布安全通告，披露了Palo Alto Networks PAN-OS 身份验证绕过漏洞(CVE-2025-0108) 。在PAN-OS中由于Nɡinх/Aрасhе对路径的处理不同从而导致身份验证绕过、未经身份验证的攻击者能够通过网络访问管理Ｗеb界面。  
  
  
目前官方已发布安全更新，亚信安全CERT建议受影响的客户尽快升级至最新版本。  
  
  
PanOS 是 Palo Alto Networks 防火墙的核心操作系统，也称为下一代防火墙（Next-Generation Firewall, NGFW）操作系统。它不仅仅是一个简单的防火墙软件，而是旨在提供深度安全保护和网络可见性的全面平台。它的设计目标是应对现代网络威胁，例如高级恶意软件、应用层攻击和数据泄露。  
  
  
  
**漏洞编号、类型、等级**  
  
  
  
- CVE-2025-0108  
  
- 身份验证绕过漏洞  
  
- 高危  
  
  
  
  
**漏洞状态**  
  
  
  
<table><tbody style="box-sizing: border-box;"><tr style="box-sizing: border-box;"><td colspan="1" rowspan="1" style="border-width: 1px;border-color: rgb(62, 62, 62);border-style: solid;background-color: rgb(145, 145, 145);box-sizing: border-box;padding: 0px;" width="20.0000%"><section style="margin: 5px 0%;box-sizing: border-box;"><section style="text-align: justify;padding: 0px 5px;font-size: 14px;color: rgb(255, 255, 255);box-sizing: border-box;"><p style="text-align: center;white-space: normal;margin: 0px;padding: 0px;box-sizing: border-box;"><strong style="box-sizing: border-box;">细节</strong></p></section></section></td><td colspan="1" rowspan="1" style="border-width: 1px;border-color: rgb(62, 62, 62);border-style: solid;background-color: rgb(145, 145, 145);box-sizing: border-box;padding: 0px;" width="20.0000%"><section style="margin: 5px 0%;box-sizing: border-box;"><section style="padding: 0px 5px;font-size: 14px;color: rgb(255, 255, 255);box-sizing: border-box;"><p style="margin: 0px;padding: 0px;box-sizing: border-box;"><strong style="box-sizing: border-box;">PoC</strong></p></section></section></td><td colspan="1" rowspan="1" style="border-width: 1px;border-color: rgb(62, 62, 62);border-style: solid;background-color: rgb(145, 145, 145);box-sizing: border-box;padding: 0px;" width="20.0000%"><section style="margin: 5px 0%;box-sizing: border-box;"><section style="padding: 0px 5px;font-size: 14px;color: rgb(255, 255, 255);box-sizing: border-box;"><p style="margin: 0px;padding: 0px;box-sizing: border-box;"><strong style="box-sizing: border-box;">EXP</strong></p></section></section></td><td colspan="1" rowspan="1" style="border-width: 1px;border-color: rgb(62, 62, 62);border-style: solid;background-color: rgb(145, 145, 145);box-sizing: border-box;padding: 0px;" width="20.0000%"><section style="margin: 5px 0%;box-sizing: border-box;"><section style="padding: 0px 5px;font-size: 14px;color: rgb(255, 255, 255);box-sizing: border-box;"><p style="margin: 0px;padding: 0px;box-sizing: border-box;"><strong style="box-sizing: border-box;">在野利用</strong></p></section></section></td><td colspan="1" rowspan="1" style="border-width: 1px;border-color: rgb(62, 62, 62);border-style: solid;background-color: rgb(145, 145, 145);box-sizing: border-box;padding: 0px;" width="20.0000%"><section style="margin: 5px 0%;box-sizing: border-box;"><section style="padding: 0px 5px;font-size: 14px;color: rgb(255, 255, 255);box-sizing: border-box;"><p style="margin: 0px;padding: 0px;box-sizing: border-box;"><strong style="box-sizing: border-box;">复现情况</strong></p></section></section></td></tr><tr style="box-sizing: border-box;"><td colspan="1" rowspan="1" style="border-width: 1px;border-color: rgb(62, 62, 62);border-style: solid;box-sizing: border-box;padding: 0px;" width="20.0000%"><section style="margin: 5px 0%;box-sizing: border-box;"><section style="padding: 0px 5px;font-size: 14px;color: rgb(62, 62, 62);box-sizing: border-box;"><p style="margin: 0px;padding: 0px;box-sizing: border-box;">已公开</p></section></section></td><td colspan="1" rowspan="1" style="border-width: 1px;border-color: rgb(62, 62, 62);border-style: solid;box-sizing: border-box;padding: 0px;" width="20.0000%"><section style="margin: 5px 0%;box-sizing: border-box;"><section style="padding: 0px 5px;font-size: 14px;color: rgb(62, 62, 62);box-sizing: border-box;"><p style="margin: 0px;padding: 0px;box-sizing: border-box;">已公开</p></section></section></td><td colspan="1" rowspan="1" style="border-width: 1px;border-color: rgb(62, 62, 62);border-style: solid;box-sizing: border-box;padding: 0px;" width="20.0000%"><section style="margin: 5px 0%;box-sizing: border-box;"><section style="padding: 0px 5px;font-size: 14px;color: rgb(62, 62, 62);box-sizing: border-box;"><p style="margin: 0px;padding: 0px;box-sizing: border-box;">已公开</p></section></section></td><td colspan="1" rowspan="1" style="border-width: 1px;border-color: rgb(62, 62, 62);border-style: solid;box-sizing: border-box;padding: 0px;" width="20.0000%"><section style="margin: 5px 0%;box-sizing: border-box;"><section style="padding: 0px 5px;font-size: 14px;color: rgb(62, 62, 62);box-sizing: border-box;"><p style="margin: 0px;padding: 0px;box-sizing: border-box;">未发现</p></section></section></td><td colspan="1" rowspan="1" style="border-width: 1px;border-color: rgb(62, 62, 62);border-style: solid;box-sizing: border-box;padding: 0px;" width="20.0000%"><section style="margin: 5px 0%;box-sizing: border-box;"><section style="padding: 0px 5px;font-size: 14px;color: rgb(62, 62, 62);box-sizing: border-box;"><p style="margin: 0px;padding: 0px;box-sizing: border-box;">已复现</p></section></section></td></tr></tbody></table>  
  
  
**受影响版本**  
  
  
  
- PAN OS 11.2 < 11.2.4-h4  
  
- PAN OS 11.1 < 11.1.6-h1  
  
- PAN OS 10.2 < 10.2.13-h3  
  
- PAN OS 10.1 < 10.1.14-h9  
  
  
  
  
**产品解决方案**  
  
  
  
目前亚信安全怒狮引擎已第一时间新增了检测规则，支持CVE-2025-0108漏洞的检测，请及时更新TDA、AE产品的特征库到最新版本。规则编号：106065018，规则名称：PAN-OS身份验证绕过漏洞(CVE-2025-0108)。  
  
  
更新方式如下：  
  
TDA产品在线更新方法：登录系统-》系统管理-》系统升级-》特征码更新；  
  
AE产品在线更新方法：登录系统-》管理-》更新-》特征码更新。  
  
TDA、AE产品离线升级PTN包下载链接如下：  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/iczzp36h0nbFjsRMzFAmuiaicxbfwHFlyHlia2FeSCWOuFRPXHDUcqXyficYwEr3qibPLq0PWKLMHwiaWmyxiaN3NkLKHw/640?wx_fmt=png "")  
  
详细下载地址请后台咨询  
  
  
**修复建议**  
  
  
  
官方已发布安全补丁通告，建议受影响的用户到官网下载补丁升级到最新版本。  
  
  
https://security.paloaltonetworks.com/CVE-2025-0108  
  
  
**参考链接**  
  
  
  
- https://security.paloaltonetworks.com/CVE-2025-0108  
  
- https://github.com/iSee857/CVE-2025-0108-PoC  
  
- https://slcyber.io/blog/nginx-apache-path-confusion-to-auth-bypass-in-pan-os/  
  
  
  
  
本文发布的补丁下载链接均源自各原厂官方网站。尽管我们努力确保官方资源的安全性，但在互联网环境中，文件下载仍存在潜在风险。为保障您的设备安全与数据隐私，敬请您在点击下载前谨慎核实其安全性和可信度。  
  
  
  
  
了解亚信安全，请点击  
**“阅读原文”**  
  
