#  俄罗斯称利用WinRAR 漏洞的攻击活动与乌克兰有关   
 关键基础设施安全应急响应中心   2024-04-07 15:45  
  
据总部位于莫斯科的网络安全公司F.A.C.C.T.称，他们发现了一个与乌克兰有关联的新黑客组织，该组织至少从今年1月以来就开始运作。  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR3icUdw0lzgKU0oiatITB0iaxxPbjou7FJiabXLlyhhX74WoJxAXzSVVJPcg0ia3NPW7UWNgOSaKHiaben2w/640?wx_fmt=jpeg&from=appmsg&wxfrom=13&tp=wxpic "")  
  
F.A.C.C.T.将该组织命名为 PhantomCore，并将一种以前未具名的远程访问恶意软件标记为 PhantomRAT。他们声称黑客利用了Windows文件存档工具WinRAR中的一个已知漏洞，该漏洞被鉴定为 CVE-2023-38831。  
  
F.A.C.C.T 表示，PhantomCore 使用的策略与之前利用该漏洞的攻击不同，黑客是通过利用特制的 RAR 存档执行恶意代码，而非之前观察到的 ZIP 文件。  
  
为了将 PhantomRAT 传送到受害者的系统中，黑客使用了网络钓鱼电子邮件，其中包含伪装成合同的 PDF 文件，其中的可执行文件只有在受害者使用低于 6.23 版本的 WinRAR 打开 PDF 文件时才会启动。在攻击的最后阶段，感染了PhantomRAT的系统能够从命令和控制（C2）服务器下载文件，并将文件从受感染的主机上传到黑客控制的服务器。  
  
此外，在攻击活动期间，黑客可以获得包括主机名、用户名、本地 IP 地址和操作系统版本在内的信息，以帮助黑客进行进一步的攻击。  
  
在分析过程中还发现了三个PhantomRAT的测试样本，根据F.A.C.C.T.的说法，这些样本是从乌克兰上传的。“我们可以有一定程度的信心说，进行这些袭击的攻击者可能位于乌克兰境内，“研究人员说。  
  
Check Point在调查了该报告和有问题的漏洞后，指出存档中的特定样本仅针对 64 位系统，在其他攻击中，有效载荷可能会有所不同，如果攻击者需要，也可能会同时影响 32 位和 64 位系统。  
  
微软威胁情报战略主管 Sherrod DeGrippo 表示，该公司以前没有观察到 F.A.C.C.T. 认为属于该组织的具体活动，但该漏洞已被网络犯罪分子和国家支持的APT组织广泛利用。  
  
  
  
原文来源：FreeBuf  
  
“投稿联系方式：010-82992251   sunzhonghao@cert.org.cn”  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/iaz5iaQYxGogvC8qicuLNlkT5ibJnwu1leQiabRVqFk4Sb3q1fqrDhicLBNAqVY4REuTetY1zBYuUdic0nVhZR4FHpAfg/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
