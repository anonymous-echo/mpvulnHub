#  微软云服务爆容器逃逸漏洞，攻击者可接管Linux集群   
 关键基础设施安全应急响应中心   2022-07-01 15:26  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/iaz5iaQYxGogvw3MvrmjjKKBuSndYbAT0kuRq4ZREurR4qwticYwD5mtPzFsl49UCfoSZmWYGy0AF0FvGhxWrZGDg/640?wx_fmt=jpeg "")  
- 微软旗下应用程序托管平台Service Fabric爆出容器逃逸漏洞“FabricScape”，攻击者可以提权控制主机节点，乃至接管平台Linux集群；  
  
- 微软花了  
近5个月时间修复漏洞，目前已将修复程序推送至自动更新通道，未开启该平台自动更  
新功能的用户需尽快更新。  
  
6月30日消息，微软修复了旗下**应用程序托管平台Service Fabric（SF）的容器逃逸漏洞“FabricScape”。利用此漏洞，恶意黑客可以提升至root权限，夺取主机节点控制权，进而危及整个SF Linux集群。**  
  
微软公布的数据显示，Service Fabric是一套关键业务应用程序托管平台，目前**托管的应用总数已超百万。**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/FzZb53e8g7udX2QLYR9UcbPvRTg2DQRLQ7E4ibrWib3JPQ90UAmg9Ixt72J8iby0XrYDc0icw70ujRka9DEnRDwSeQ/640?wx_fmt=png "")  
  
该平台还支持多种微软产品，包括但不限于Azure SQL Database、Azure Cosmos DB、Microsoft Intune、Azure Event Hubs、Azure IoT Hub、Dynamics 365、Skype for Business Cortana、Microsoft Power BI及其他多项核心Azure服务。  
  
这个漏洞编号为**CVE-2022-30137**，由Palo Alto Networks公司的Unit 42团伙发现，并于今年1月30日报告给微软的。  
  
该漏洞之所以出现，是因为**Fabric的数据收集代理（DCA）服务组件（以root权限运行）包含竞争条件下的随意写入机制，导致恶意黑客可通过创建符号链接的方式，利用恶意内容覆盖节点文件系统中的文件，获取代码执行权限。**  
  
Unit 42的报告详细介绍了CVE-2022-30137执行代码漏洞的利用方法，以及接管SF Linux集群的更多细节。  
  
微软公司表示，“微软建议客户持续审查一切有权访问其主机集群的容器化工作负载（包括Linux与Windows）。”  
  
“默认情况下，SF集群是单租户环境，各应用程序之间不存在隔离。但您可以在其中创建隔离，关于如何托管不受信代码的更多指南，请参阅Azure Service Fabric安全最佳实践页面。”  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/iaz5iaQYxGogvw3MvrmjjKKBuSndYbAT0k4B1G6IluVOPZEvOKMjq1f1UpUib4uzSmcwSkdbJgVica1HQzzZFJ4B6g/640?wx_fmt=jpeg "")  
  
图：FabricScape恶意利用流程（Unit 42）  
  
**漏洞修复花了五个月**  
  
根据Unit 42的报告，微软公司于6月14日发布了Microsoft Azure Service Fabric 9.0 Cumulative Update，最终解决了这个漏洞（微软则表示，相关修复程序已在5月26日发布）。  
  
微软为该漏洞发布安全公告后，从6月14日开始，已将修复程序推送至Linux集群的自动更新通道。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/FzZb53e8g7udX2QLYR9UcbPvRTg2DQRLnf5VFnPyGiaHR2wBCa5O8P67rLYx4UOeaYVpbqVJfzEx2SdiaYjjVP5w/640?wx_fmt=png "")  
  
**在Linux集群上启用自动更新的客户，无需采取任何额外处理措施。**  
  
对于没有为Azure Service Fabric开启自动更新的用户，建议大家尽快将Linux集群升级至最新Service Fabric版本。  
  
Palo Alto Networks公司表示，“虽然我们并未发现任何成功利用该漏洞的在野攻击，但仍然希望能敦促各组织立即采取行动，确认自身环境是否易受攻击，并迅速安装补丁。”  
  
微软公司表示，对于**尚未启用自动更新的客户，他们已经通过Azure Service Health门户发出关于此问题的安全通知。**  
  
**参考资料：**  
  
bleepingcomputer.com  
  
  
  
原文来源  
：  
安全内参  
  
“投稿联系方式：孙中豪 010-82992251   sunzhonghao@cert.org.cn”  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/iaz5iaQYxGogucKMiatGyfBHlfj74r3CyPxEBrV0oOOuHICibgHwtoIGayOIcmJCIsAn02z2yibtfQylib07asMqYAEw/640?wx_fmt=jpeg "")  
