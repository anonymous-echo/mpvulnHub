#  SAP NetWeaver中存在严重漏洞，面临主动利用威胁   
原创 David Jones  信息安全D1net   2025-04-27 09:44  
  
点击上方“**蓝色字体**  
”，选择 “**设为星标**  
”  
  
关键讯息，D1时间送达！  
  
已观察到攻击者正在投放webshell后门程序，研究人员警告称，该应用程序在政府机构中颇受欢迎。  
  
安全研究人员警告称，黑客正在积极利用SAP NetWeaver Visual Composer中一个关键的无限制文件上传漏洞。  
  
该漏洞(编号为CVE-2025-31324)可能会使未经身份验证的用户上传恶意可执行二进制文件，该漏洞的严重等级为10。  
  
Reliaquest的研究人员在调查中发现攻击者将JSP webshell上传到可公开访问的目录中后，向SAP披露了这一漏洞。  
  
研究人员最初怀疑黑客是在利用一个编号为CVE-2017-9844的旧漏洞，或者是一个未报告的远程文件包含漏洞，然而，Reliaquest观察到的是最新系统的受损情况。  
  
“漏洞CVE-2017-9844是针对拒绝服务(DoS)和可能的远程代码执行(RCE)(未提及RFI)与对同一URI的请求相关的，因此，我们认为这是全新的漏洞或是范围扩大。”Reliaquest的一位发言人在周二向Cybersecurity Dive表示。  
  
Reliaquest的研究人员警告称，SAP技术在政府机构中广泛使用，一旦成功入侵，可能会使黑客进入政府网络。  
  
据Reliaquest称，攻击者正在使用Brute Ratel和Heaven’s Gate进行执行和逃避检测。  
  
SAP的一位发言人证实，该公司已被告知SAP NetWeaver Visual Composer中存在一个漏洞，该漏洞可能允许在特定的Java Servlets中未经身份验证和授权的代码执行。  
  
该公司表示，尚未了解到任何客户数据或系统受损的情况，它于4月8日发布了一个临时解决方案，并正在开发一个补丁，将于4月30日提供。  
  
SAP的一位发言人在Reliaquest的研究发布后证实，周四发布了一个紧急补丁。Reliaquest和Onapsis的研究人员在他们的博客文章中指出，已经发布了一个紧急补丁。  
  
尽管SAP保证没有立即产生影响，但安全公司正在报告针对该漏洞的持续攻击尝试。  
  
watchTowr的研究人员发现，威胁行为者正在投放webshell后门程序并获得进一步访问权限。  
  
“这种在野外积极利用漏洞和广泛影响的情况，使得我们很快就会看到多方大规模利用漏洞的可能性极大，”watchTowr的首席执行官Benjamin Harris通过电子邮件向Cybersecurity Dive表示。“如果你以为还有时间，那就没有了。”  
  
Onapsis Research Labs的CEO Mariano Nunez表示，Onapsis已确定有10000多个面向互联网的SAP应用程序可能因该漏洞而面临泄露风险。  
  
Nunez补充道，“其中50%-70%的应用程序已启用易受攻击的组件，并可能已经遭到入侵。”  
  
不过，该易受攻击的组件默认并未启用，因此Onapsis正在确认易受影响的系统数量。  
  
网络安全和基础设施安全局(CISA)正在按照标准程序跟踪该漏洞，并与供应商和其他合作伙伴合作，以确定是否需要进一步的沟通，一位发言人向Cybersecurity Dive表示。  
  
版权声明：本文为企业网D1Net编译，转载需在文章开头注明出处为：企业网D1net，如果不注明出处  
，企业网D1net将保留追究其法律责任的权利。  
  
  
（来源：企业网D1net）  
  
**关于企业网D1net(www.d1net.com)**  
  
  
  
  
国内  
头部  
ToB IT门户  
，同时在运营国内最大的甲方CIO专家库和智力输出及社交平台-信众智(www.cioall.com)。旗下运营19个IT行业公众号(  
微信搜索D1net即可关注  
)  
  
  
  
如果您在企业IT、网络、通信行业的某一领域工作，并希望分享观点，欢迎给企业网D1Net投稿。  
封面图片来源于摄图网  
  
**投稿邮箱：**  
  
editor@d1net.com  
  
**合作电话：**  
  
010-58221588（北京公司）  
  
021-51701588（上海公司）   
  
**合作邮箱：**  
  
Sales@d1net.com  
  
企业网D1net旗下信众智是CIO（首席信息官）的专家库和智力输出及资源分享平台，有六万多CIO专家，也是目前最大的CIO社交平台。  
  
  
信众智对接CIO为CIO服务，提供数字化升级转型方面的咨询、培训、需求对接等落地实战的服务。也是国内最早的toB共享经济平台。同时提供猎头，选型点评，IT部门业绩宣传等服务。  
  
**扫描 “**  
**二维码**  
**” 可以查看更多详情**  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/OuQdh6iaViaXaIOY0mjrTgicElErUqymD4icjEneq6YYVpiadU3pDLRHwqFrW9Y2Ht0uKeuIEjO3hDxfiatbI5KcibHIA/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
