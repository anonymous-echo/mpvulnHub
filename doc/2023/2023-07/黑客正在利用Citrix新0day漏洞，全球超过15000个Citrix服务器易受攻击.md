#  黑客正在利用Citrix新0day漏洞，全球超过15000个Citrix服务器易受攻击   
看雪学苑  看雪学苑   2023-07-25 17:59  
  
近日，美国网络安全与基础设施安全局（CISA）警告称，黑客正在利用一个新发现的零日漏洞，针对Citrix NetScaler应用程序交付控制器（ADC）和Citrix Gateway设备实施网络攻击。  
  
  
Citrix公司曾于上周提醒其客户，该漏洞（CVE-2023-3519，CVSS评分9.8）是一种代码注入漏洞，存在于NetScaler应用交付控制器（ADC）和Gateway中，可导致未经身份验证的远程代码执行，并正在野外被积极利用。该公司补充说，成功利用该漏洞的前提是设备配置为网关（VPN虚拟服务器、ICA代理、CVPN、RDP代理）或AAA虚拟服务器。  
  
  
Citrix发布的公告中写道：“已观察到对未采取措施的设备的漏洞利用。强烈建议受影响的NetScaler ADC和NetScaler Gateway客户尽快安装相关的更新版本。”  
  
  
美国CISA透露，有黑客正在利用该漏洞在易受攻击的系统上部署Web shell。CISA前不久发布了一份名为“威胁行为者利用Citrix CVE-2023-3519植入Web shell”的网络安全咨询，警告组织机构注意此事件。据了解，2023年6月，威胁行为者利用该零日漏洞在一家关键基础设施组织的NetScaler ADC设备上植入了Web shell。该Web shell使威胁行动者能够发现受害者的活动目录（AD）并收集外泄AD数据。威胁行为者试图横向移动到域控制器，但被网络分割所阻止。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8FSBIvicCYiaiczYjmcE4MLHDNjnMAFA5gRjmiayUnrGLeYicA5ticb48CsEgNBNIwjo7oyDVEpKltX69icw/640?wx_fmt=png "")  
  
  
根据Shadowserver Foundation研究人员的报告，目前至少有15000台Citrix服务器暴露在CVE-2023-3519攻击的风险之下。其中大部分服务器位于美国和德国。CISA建议，被感染的组织应采取以下措施：隔离或下线可能受到影响的主机；重建受损主机；设置新帐户凭据；收集及审查正在运行的进程/服务、异常身份验证和最近的网络连接。  
  
  
  
编辑：左右里  
  
资讯来源：Bleepingcomputer  
  
转载请注明出处和本文链接  
  
  
**每日涨知识**  
  
包（packet）  
  
通过通信线路作为一个单位传输的一组信息。包含 IP header（IP 头）以及 payload（有  
效负荷）。  
  
  
﹀  
  
﹀  
  
﹀  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/Uia4617poZXP96fGaMPXib13V1bJ52yHq9ycD9Zv3WhiaRb2rKV6wghrNa4VyFR2wibBVNfZt3M5IuUiauQGHvxhQrA/640?wx_fmt=jpeg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/1UG7KPNHN8E9S6vNnUMRCOictT4PicNGMgHmsIkOvEno4oPVWrhwQCWNRTquZGs2ZLYic8IJTJBjxhWVoCa47V9Rw/640?wx_fmt=other "")  
  
**球分享**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/1UG7KPNHN8E9S6vNnUMRCOictT4PicNGMgHmsIkOvEno4oPVWrhwQCWNRTquZGs2ZLYic8IJTJBjxhWVoCa47V9Rw/640?wx_fmt=gif "")  
  
**球点赞**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/1UG7KPNHN8E9S6vNnUMRCOictT4PicNGMgHmsIkOvEno4oPVWrhwQCWNRTquZGs2ZLYic8IJTJBjxhWVoCa47V9Rw/640?wx_fmt=gif "")  
  
**球在看**  
  
****  
****  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/1UG7KPNHN8FxuBNT7e2ZEfQZgBuH2GkFjvK4tzErD5Q56kwaEL0N099icLfx1ZvVvqzcRG3oMtIXqUz5T9HYKicA/640?wx_fmt=gif "")  
  
戳  
“阅读原文  
”  
一起来充电吧！  
  
