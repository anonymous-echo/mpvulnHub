#  微软 Azure FabricScape 漏洞可被用于劫持 Linux 集群   
Sergiu Gatlan  代码卫士   2022-06-30 18:21  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Az5ZsrEic9ot90z9etZLlU7OTaPOdibteeibJMMmbwc29aJlDOmUicibIRoLdcuEQjtHQ2qjVtZBt0M5eVbYoQzlHiaw/640?wx_fmt=gif "")  
  
   
聚焦源代码安全，网罗国内外最新资讯！  
  
**编译：代码卫士**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/oBANLWYScMQ14gANfpzIJKovICjicY8CHGhRrZEXXuZoezDV6QX121O5SdXbHK3vKI45ZVv7xvequbrcmp1oia2w/640?wx_fmt=png "")  
  
  
微软修复了 Service Fabric (SF) 应用托管平台上的一个容器逃逸漏洞 FabricScape，它可导致威胁行动者将权限提升至root，控制主机节点并攻陷整个 SF Linux 集群。  
  
SF 是业务关键应用平台，托管了100多万款应用，同时还为很多微软产品提供动力，包括但不限于 Azure SQL Database、Azure Cosmos DB、Microsoft Intune、Azure Event Hubs、Azure IoT Hub、Dynamics 365、Skype for Business、Cortana、Microsoft Power BI以及很多核心 Azure 服务。  
  
该缺陷的编号为CVE-2022-30137，是由Palo Alto Networks 公司 Unit 42 团队的研究员发现的，他们还在1月30日将漏洞告知微软。该漏洞是因为Data Collection Agent (DCA) Service Fabric 组件中的条件竞争任意写造成的，可导致攻击者创建符号链接获得代码执行权限，以恶意内容覆写节点文件系统中的文件。  
  
微软建议称，“微软推荐用户继续检查所有的可访问主机集群的容器化工作负载（Linux 和 Windows）。在默认情况下，SF集群是一个单租户环境，因此应用程序之间并无隔离。可通过 Azure Service Fabric 安全最佳实践页面创建隔离以及关于托管不受信任代码的其它指南。”  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/oBANLWYScMQ14gANfpzIJKovICjicY8CHmRd1vic7b57w1B1XiaudfumIoJbbGTXOo6ZicxhJ8dvTFt6pNP5FvVQBw/640?wx_fmt=png "")  
  
**漏洞在五个月后修复**  
  
  
微软在6月14日发布微软 Azure Service Fabric 9.0 累积更新，修复了该漏洞。从6月14日开始，修复方案已自动推送至 Linux 集群。在 Linux 集群上启用了自动更新的客户无需采取其它措施。  
  
不过，建议未安装自动更新的 Azure Service Fabric 的用户，尽快将 Linux 集群更新至 Service Fabric 发布的最新版本。  
  
研究人员表示，“虽然我们并未发现在野攻击迹象，但仍然督促组织机构立即行动起来，判断环境是否易受攻击并且如果遭攻击则快速打补丁。”  
  
微软表示，已通过 Zure Service Health 发送门户通知，将自动更新推送给尚未启用自动更新的客户。  
  
****  
  
代码卫士试用地址：  
https://codesafe.qianxin.com  
  
开源卫士试用地址：  
https://oss.qianxin.com  
  
  
  
  
  
  
  
  
  
  
  
  
**推荐阅读**  
  
[价值4万美元的微软Azure漏洞 ExtraReplica，没有CVE编号](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247511627&idx=1&sn=8437c9d6450d98c727d653f1661b090c&chksm=ea949f21dde316375d993c85f24a29825426042f405f05a45d606e25b9d9520b8a6f34fec4d8&scene=21#wechat_redirect)  
  
  
[200多个恶意NPM程序包针对Azure 开发人员，发动供应链攻击](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247511070&idx=3&sn=a1f87fa84198504a6fd9c1d6d258152f&chksm=ea949d74dde314621963b38e7e1cb232355f633eff9cdb3e6d6989e764ee387af86886c7a87f&scene=21#wechat_redirect)  
  
  
[微软修复严重的Azure漏洞，可用于泄露客户数据](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247510812&idx=2&sn=fa2c2ed3bfc4be6140668dae37e6368f&chksm=ea949a76dde3136033500106ba611bf1696eb7578d687de4acff1e32a973fafe7c167c6e0e09&scene=21#wechat_redirect)  
  
  
[微软 Azure App Service 漏洞 NotLegit已存在4年，客户源代码被暴露](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247509831&idx=1&sn=a4427c171ef002981ea290ab81e24572&chksm=ea94962ddde31f3b3adeb35d9a53c4bb5c7f6bad04ce0e2b863b0b7202b86a8a7043c450e7b8&scene=21#wechat_redirect)  
  
  
[微软在 Linux 虚拟机偷偷安装Azure App，后修复严重漏洞但Linux虚拟机难以修复](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247507893&idx=1&sn=cefb593c11692ee3f342d9b62b7b0a57&chksm=ea94eedfdde367c91881b8cb4f1a6df580cad5473f0229907a438b507360a55692c73d304470&scene=21#wechat_redirect)  
  
  
  
  
  
**原文链接**  
  
https://www.bleepingcomputer.com/news/security/microsoft-azure-fabricscape-bug-let-hackers-hijack-linux-clusters/  
  
  
  
题图：  
Pixab  
ay License  
  
  
  
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
