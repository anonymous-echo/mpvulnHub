#  存在近30年的零点击RCE漏洞，所有Windows服务器都可能受害   
看雪学苑  看雪学苑   2024-08-09 18:03  
  
近日，安全研究员Ver、Lewis Lee和zhiniang Peng发布了一个高危漏洞的概念验证 (https://sites.google.com/site/zhiniangpeng/blogs/MadLicense) ，该漏洞名为“MadLicense”（CVE-2024-38077，CVSS 9.8），影响Windows Server 2000到Windows Server 2025的所有版本。  
此预身份验证远程代码执行 (RCE) 漏洞使攻击者能够完全控制目标服务器，并且无需任何形式的用户交互。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8FkMOZxo9hJgSwj1AM3p2ZxyU5xOmVb5we0AGDuspJryq2Fec6TcZjicwRg7DEvia9NaiaJK9owEfBvQ/640?wx_fmt=png&from=appmsg "")  
  
  
该漏洞存在于Windows的远程桌面授权服务 (RDL，负责管理远程桌面服务的许可证)中，而RDL广泛部署于众多组织之中——研究人员确认至少有 170000 个 RDL 服务直接暴露在互联网上，使其很容易受到利用。此外，RDL 服务通常集成在关键业务系统之中，从而进一步放大了该漏洞的潜在影响。  
  
  
据了解，MadLicense 漏洞源于CDataCoding:：DecodeData函数中的堆溢出——此函数在处理用户输入的许可秘钥包时，未正确地检验解码后数据长度与缓冲区大小之间的关系，导致缓冲区溢出。未经身份验证的攻击者可连接到远程桌面许可服务并发送恶意消息，从而允许远程执行代码。  
  
  
研究人员成功演示了在Windows Server 2025上的概念验证（提供的 PoC 是伪代码，并且故意进行混淆以防止滥用），成功率接近 100%。该漏洞有效规避了所有当前的缓解措施，包括最近在 Windows Server 2025 中引入的 LFH 缓解措施。  
  
  
虽然PoC只演示了该漏洞在 Windows Server 2025 上的利用情况，但研究人员强调，由于旧版本的缓解措施较少，该漏洞可以在旧版本的 Windows Server 上更快、更有效地被利用。 研究人员还指出，  
该PoC旨在加载远程DLL，但只需稍加修改，就可以在RDL进程中执行任意shellcode，从而使攻击更加隐蔽。  
  
  
另外，有研究人员报告在 Github 上发现了CVE-2024-38077的PoC代码。虽然该代码的真实性尚未得到证实，但此发现进一步突显了修补的迫切性。该漏洞在公开披露前一个月已向微软报告，并且已在微软7 月安全补丁中得到修复。强烈建议各机构立即更新其 Windows Server 系统，以防范潜在的攻击。  
  
  
  
编辑：左右里  
  
资讯来源：microsoft、cybersecuritynews  
  
转载请注明出处和本文链接  
  
  
﹀  
  
﹀  
  
﹀  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/Uia4617poZXP96fGaMPXib13V1bJ52yHq9ycD9Zv3WhiaRb2rKV6wghrNa4VyFR2wibBVNfZt3M5IuUiauQGHvxhQrA/640?wx_fmt=jpeg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/1UG7KPNHN8E9S6vNnUMRCOictT4PicNGMgHmsIkOvEno4oPVWrhwQCWNRTquZGs2ZLYic8IJTJBjxhWVoCa47V9Rw/640?wx_fmt=gif "")  
  
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
  
