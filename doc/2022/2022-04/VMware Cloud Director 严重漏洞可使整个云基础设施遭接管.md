#  VMware Cloud Director 严重漏洞可使整个云基础设施遭接管   
Bill Toulas  代码卫士   2022-04-18 18:28  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Az5ZsrEic9ot90z9etZLlU7OTaPOdibteeibJMMmbwc29aJlDOmUicibIRoLdcuEQjtHQ2qjVtZBt0M5eVbYoQzlHiaw/640?wx_fmt=gif "")  
  
   
聚焦源代码安全，网罗国内外最新资讯！  
  
**编译：代码卫士**  
  
****  
![](https://mmbiz.qpic.cn/mmbiz_png/JaFvPvvA2J1TfC1KiaJk7cf6QAwOOQaqjLu1g8iatCpoGrC63KrUg28O1ia5ecf7VSTR9LjBicqbGyTavmo2Mzd4Eg/640?wx_fmt=png "")  
  
上周四，VMWare 公司发布更新，修复了位于 Cloud Director 产品中的一个严重漏洞 (CVE-2022-22966)，它可被用于发动远程代码执行攻击。该漏洞评分为9.1，由研究员 Jari Jääskelä 发现。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/JaFvPvvA2J1TfC1KiaJk7cf6QAwOOQaqjJr0R3PWpichEeruLhlJ1ibosp4nC0PFo5t2tLy8phVfyibica0j298bH8g/640?wx_fmt=png "")  
  
  
  
VMWare 在安全公告中指出，“认证的高权限恶意人员如具有对 VMware Cloud Director的网络访问权限，则租户或提供商可利用远程代码执行漏洞获得对服务器的访问权限。”  
  
VMware Cloud Director 此前被称为 “vCloud Director” 由很多著名的云提供商用于运营并管理云基础设施并获得对多个站点和地理位置数据中心的可见性。换句话说，该漏洞可导致攻击者获得对敏感数据的访问权限并接管整个基础设施中的私有云。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/vnT4hbaLoX7CVwP3ChLicpEFMN4RzYLOyAUpxON3YANQDBL3bxBaPOKBz3p58HcCZR6BsV5zQpvdgLictCLNkLHw/640?wx_fmt=png "")  
  
**受影响版本**  
  
  
受影响版本包括 10.1.x、10.2.x 和 10.3.x 版本，修复方案已在 10.1.4.1、10.2.2.3和10.3.3 中发布。该公司还发布缓解措施，以免用户无法升级至所推荐版本。  
  
几天前，VMware 还修复了位于 Workspace One Access 中遭在野利用的严重漏洞 (CVE-2022-22954)，它和VMware Workspace ONE Access 和 Identity Manager 中的服务器端模板注入导致的远程代码执行漏洞有关。  
  
鉴于 VMware 产品经常成为威胁行动者的攻击目标，因此相关组织机构应尽快应用必要的缓解措施，以阻止潜在威胁。  
  
  
  
  
代码卫士试用地址：  
https://codesafe.qianxin.com  
  
开源卫士试用地址：  
https://oss.qianxin.com****  
  
  
  
  
  
  
  
  
  
  
**推荐阅读**  
  
[VMware 多款产品中存在严重漏洞](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247511275&idx=2&sn=48fb390bdc078c47711bb43b50e10497&chksm=ea949d81dde31497aeab17336c350e0458ba0632a10470c76964a41c8580514c2ffe73ac1a48&scene=21#wechat_redirect)  
  
  
[VMware 修复多款产品中的高危漏洞](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247510568&idx=2&sn=490a1bafa5b61a77f098599397dab01b&chksm=ea949b42dde31254332fa19be2613b491c36773fe16a8f8723fde1dd3b07195daddf7d11d400&scene=21#wechat_redirect)  
  
  
[VMWare 认证软件存在SSRF漏洞，可用于访问用户数据](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247510219&idx=2&sn=b52589c2c6fd1cd3211e7c73094e3b31&chksm=ea9499a1dde310b7493e2e78484fe3e09608e712c4f69b5d15478563e36356020771d195ed5b&scene=21#wechat_redirect)  
  
  
[VMware 修复 Workstation、Fusion 和 ESXi中的多个漏洞](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247509972&idx=2&sn=b4c9f57787b08360fcac6ecc1acfb024&chksm=ea9496bedde31fa81f9f41f6d5301bd1d0279c9bcbd9a2e131e1e1941d3656d2f81a461c1961&scene=21#wechat_redirect)  
  
  
[CISA 督促VMware 管理员修复Workspace ONE UEM 中的严重漏洞](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247509759&idx=1&sn=d05266c70a447284902794f0d154da42&chksm=ea949795dde31e831c95b6614723cb43935a3fc5b79dbf2f0eb9edda4a8916ff3bdcdb5cf269&scene=21#wechat_redirect)  
  
  
  
  
  
**原文链接**  
  
https://thehackernews.com/2022/04/critical-vmware-cloud-director-bug.html  
  
  
题图：Pixabay License  
  
  
  
**本文由奇安信编译，不代表奇安信观点。转载请注明“转自奇安信代码卫士 https://codesafe.qianxin.com”。**  
  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/oBANLWYScMSf7nNLWrJL6dkJp7RB8Kl4zxU9ibnQjuvo4VoZ5ic9Q91K3WshWzqEybcroVEOQpgYfx1uYgwJhlFQ/640?wx_fmt=jpeg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/oBANLWYScMQjfQ8ZhaOGYOwiaOkCe6UVnwG4PcibqI6sJ3rojqp5qaJa0wA2lxYb0VKwria7pHqS9rJwSPSykjMsA/640?wx_fmt=jpeg "")  
  
**奇安信代码卫士 (codesafe)**  
  
国内首个专注于软件开发安全的产品线。  
  
   ![](https://mmbiz.qpic.cn/mmbiz_gif/oBANLWYScMQ5iciaeKS21icDIWSVd0M9zEhicFK0rbCJOrgpc09iaH6nvqvsIdckDfxH2K4tu9CvPJgSf7XhGHJwVyQ/640?wx_fmt=gif "")  
  
   
觉得不错，就点个 “  
在看  
” 或 "  
赞  
” 吧~  
