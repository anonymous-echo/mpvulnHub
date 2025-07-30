#  VMware：立即、马上修复这个严重的认证绕过漏洞！   
Sergiu Gatlan  代码卫士   2022-08-03 17:40  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Az5ZsrEic9ot90z9etZLlU7OTaPOdibteeibJMMmbwc29aJlDOmUicibIRoLdcuEQjtHQ2qjVtZBt0M5eVbYoQzlHiaw/640?wx_fmt=gif "")  
  
   
聚焦源代码安全，网罗国内外最新资讯！  
  
**编译：代码卫士**  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/oBANLWYScMQZlfZPYlNMLcY0Au5oOjicKq4xyY0Go7dZ4qYibQezy2l674IcBypDSYKrYt7HM0UvSWBZwWoA6BXQ/640?wx_fmt=gif "")  
  
**VMware 公司提醒管理员称，应立即修复影响多款产品中影响本地域用户的认证绕过漏洞，它可导致未认证攻击者获得管理员权限。该漏洞的编号为CVE-2022-31656。**  
  
该漏洞是由 VNG Security 公司的研究员 Petrus Viet 发现的，影响 VMware Workspace ONE Access、Identity Manager 和 vRealize Automation。VMware 将该漏洞评级为“严重”级别，CVSSv3的基本分为9.8分。  
  
VMware 还修复了其它多个漏洞，它们可导致攻击者在未修复服务器上造成远程代码执行（CVE-2022-31658和CVE-2022-31665）和权限提升（CVE-2022-31660、CVE-2022-31661和CVE-2022-31664）后果。  
  
VMware 公司的云基础设施安全和合规架构师 Bob Plankers 表示，“快速采取措施修复或缓解本地部署上的这些漏洞极其重要。如果你所在的组织机构使用ITIL 方法更改管理，则可视作‘紧急’变更。”  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/oBANLWYScMQZlfZPYlNMLcY0Au5oOjicKbdlgV9Wxv76lyjKPy9qeQ45w33HQrHu7OIuo2wFBiarCvuEZ615ibC9A/640?wx_fmt=png "")  
  
**督促管理员立即修复**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/oBANLWYScMQZlfZPYlNMLcY0Au5oOjicKVWXGtOmQ9CyAYOiciaLADnYTzmN7lqt47qNL79ja5aicfrKYUuP1KiazEg/640?wx_fmt=png "")  
  
  
  
VMware公司提醒称，“应按照VMSA 中的指令立即修复或缓解该严重漏洞。所有环境都是不同的，对风险的容忍度也不尽相同，且具有不同的安全控制和纵深防御措施以缓解风险，因此客户必须就如何处理做出自己的决策。然而，鉴于该漏洞的严重性，我们强烈建议立即采取措施。”  
  
受这些漏洞影响的所有VMware 产品包括：  
  
- VMware Workspace ONE Access (Access)  
  
- VMware Workspace ONE Access Connector (Access Connector)  
  
- VMware Identity Manager (vIDM)  
  
- VMware Identity Manager Connector (vIDM Connector)  
  
- VMware vRealize Automation (vRA)  
  
- VMware Cloud Foundation  
  
- vRealize Suite Lifecycle Manager  
  
  
  
VMware 指出，未有证据表明CVE-2022-31656认证绕过漏洞已遭利用。VMware 公司已公布补丁下载链接并在知识库网站上发布了详细的安装指令。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/oBANLWYScMQZlfZPYlNMLcY0Au5oOjicKbdlgV9Wxv76lyjKPy9qeQ45w33HQrHu7OIuo2wFBiarCvuEZ615ibC9A/640?wx_fmt=png "")  
  
**应变措施**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/oBANLWYScMQZlfZPYlNMLcY0Au5oOjicKVWXGtOmQ9CyAYOiciaLADnYTzmN7lqt47qNL79ja5aicfrKYUuP1KiazEg/640?wx_fmt=png "")  
  
  
  
VMware 公司还为无法立即修复该漏洞的客户共享了临时应变措施。  
  
VMware 公司要求管理员禁用除一个配置管理员以外的所有用户，并通过SSH登录，重启服务。不过，该公司不建议使用这种应变措施并指出，完全解决该漏洞的唯一方法就是修复易受攻击产品，“清除您环境中这些漏洞的唯一方法就是应用VMSA-2022-0021中提供的补丁。虽然应变措施是方便的，但并不会清除这些漏洞，而且几乎总是会引入打补丁不会引入的其它复杂问题。虽然修复或应用应变措施的决定在您，但VMware 一直强烈建议打补丁是最简单也是最可靠的解决之道。”  
  
VMware公司还提供了一份支持文档，列出了关于该漏洞的相关问题和答复。  
  
今年5月份，VMware 公司修复了一个几乎一样的严重漏洞，CVE-2022-22972。该漏洞由 Innotec Security 公司的研究员 Bruno López 发现，位于 Workspace ONE Access、VMware Identity Manager (vIDM) 和vRealize Automation 中。  
  
  
  
  
代码卫士试用地址：  
https://codesafe.qianxin.com  
  
开源卫士试用地址：  
https://oss.qianxin.com****  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
**推荐阅读**  
  
[](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247513172&idx=1&sn=5c228a525bd6eb94d24f697d88af3c6d&chksm=ea94853edde30c2897319ed8aac13685ecca7d05bf4ecdee1d9b30c9d7f4faf24df0c1a993d2&scene=21#wechat_redirect)  
[在线阅读版：《2022中国软件供应链安全分析报告》全文](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247513174&idx=1&sn=e474d1ea23ed7cce10e2ae2f872fc003&chksm=ea94853cdde30c2a963cfa00a536764ea55cdee7ba6ef4a7716a28f82a97ca630dc271ee5224&scene=21#wechat_redirect)  
  
  
[奇安信发布《2022中国软件供应链安全分析报告》 谁会成为下一个Log4j2？](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247513172&idx=1&sn=5c228a525bd6eb94d24f697d88af3c6d&chksm=ea94853edde30c2897319ed8aac13685ecca7d05bf4ecdee1d9b30c9d7f4faf24df0c1a993d2&scene=21#wechat_redirect)  
  
  
[【缺陷周话】第 8 期 ：路径遍历](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247488437&idx=1&sn=1a69efdeb4538b0a40bff7111083418a&chksm=ea9722dfdde0abc9d91f77892e3c2217f132292effd96d404b2302fbd1ce468c32b42adcee1c&scene=21#wechat_redirect)  
  
  
[Fortinet 修复多个路径遍历漏洞](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247512788&idx=3&sn=894340534673ba25a49c72eec950b0d7&chksm=ea9483bedde30aa8e9c0b3355eeee1ce56ec6cb1f2d55b60888cea9487bd8397fff4294a955d&scene=21#wechat_redirect)  
  
  
[UnRAR二进制中出现路径遍历缺陷，可导致在Zimbra上执行远程代码](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247512652&idx=1&sn=1f0239704b1c73ee0e257706adbbdb7b&chksm=ea948326dde30a30d018078b393ff08ad41338fe3d025707bd85876ba4871ec610ccf27fe747&scene=21#wechat_redirect)  
  
  
[OWASP 企业安全控制库中存在路径遍历漏洞](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247511663&idx=1&sn=3ba1b13cb21175d489dbe23c4ce4159e&chksm=ea949f05dde31613107734cbe6ad4a8840e20c1df7f47d2672fbc539e78a28a383783788d00d&scene=21#wechat_redirect)  
  
  
[开源容器化应用 Kubernetes 被曝严重的路径遍历漏洞](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247489610&idx=4&sn=f52329501c559b864939e52a62a2c2ea&chksm=ea972920dde0a0364d387a5f8efd519c871b7053d750326095984819e64128d1f24c0219d452&scene=21#wechat_redirect)  
  
  
  
  
**原文链接**  
  
https://www.bleepingcomputer.com/news/security/vmware-urges-admins-to-patch-critical-auth-bypass-bug-immediately/  
  
  
题图：  
Pexels License  
‍  
  
  
  
**本文由奇安信编译，不代表奇安信观点。转载请注明“转自奇安信代码卫士 https://codesafe.qianxin.com”。**  
  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/oBANLWYScMSf7nNLWrJL6dkJp7RB8Kl4zxU9ibnQjuvo4VoZ5ic9Q91K3WshWzqEybcroVEOQpgYfx1uYgwJhlFQ/640?wx_fmt=jpeg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/oBANLWYScMSN5sfviaCuvYQccJZlrr64sRlvcbdWjDic9mPQ8mBBFDCKP6VibiaNE1kDVuoIOiaIVRoTjSsSftGC8gw/640?wx_fmt=jpeg "")  
  
**奇安信代码卫士 (codesafe)**  
  
国内首个专注于软件开发安全的产品线。  
  
   ![](https://mmbiz.qpic.cn/mmbiz_gif/oBANLWYScMQ5iciaeKS21icDIWSVd0M9zEhicFK0rbCJOrgpc09iaH6nvqvsIdckDfxH2K4tu9CvPJgSf7XhGHJwVyQ/640?wx_fmt=gif "")  
  
   
觉得不错，就点个 “  
在看  
” 或 "  
赞  
” 吧~  
