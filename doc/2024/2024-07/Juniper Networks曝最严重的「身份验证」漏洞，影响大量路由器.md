#  Juniper Networks曝最严重的「身份验证」漏洞，影响大量路由器   
 网络安全应急技术国家工程中心   2024-07-02 15:24  
  
近日，Juniper Networks被曝存在一个极其严重的「身份验证」漏洞，对Session Smart 路由器（SSR）、Session Smart Conductor和WAN Assurance 路由器等产品造成比较明显的影响。目前，Juniper已紧急发布了相应的漏洞补丁，用户可及时进行系统更新。  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR39LcdUTibWwO2fKdibMKDKm2AYmU0dgRSoWffXqHXzyN1MBLM5CcwP1w2N46PF4YTC6HneFOShTa0UA/640?wx_fmt=jpeg&from=appmsg&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
该漏洞编号为CVE-2024-2973，攻击者可利用该漏洞完全控制设备。简单来说，JuniperSession Smart 路由器、Session Smart Conductor在运行冗余对等设备时，存在使用替代路径或通道绕过身份验证的漏洞，从而使得攻击者可以有效绕过身份验证，并对设备具有高控制度。  
  
Juniper Networks进一步指出，只有在高可用性冗余配置中运行的Router或Conductor才会受到该漏洞的影响。  
  
事实上，大多数企业为了保证服务或业务的连续性，网络管理员往往都会应用 「高可用性冗余配置」，以此提升不间断服务或者对恶意事件的抵抗能力。这也意味着，易受攻击的配置在关键任务网络基础设施中相当常见，包括大型企业环境、数据中心、电信、电子商务以及政府或公共服务。  
  
受 该漏洞（CVE-2024-2973 ）影响的产品版本包括：  
### 1、Session Smart 路由器  
- 5.6.15 之前的所有版本  
  
- 从 6.0 到 6.1.9-lts 之前的所有版本  
  
- 从 6.2 起，6.2.5-sts 之前的所有版本  
  
### 2、WAN Assurance 路由器  
- 6.1.9-lts 之前的 6.0 版本  
  
- 6.2.5-sts 之前的 6.2 版本  
  
Session Smart 路由器在 5.6.15、6.1.9-lts 和 6.2.5-sts 版本中提供了安全更新。  
  
WAN Assurance路由器在连接到Mist Cloud时会自动打上补丁，但High-Availability集群的管理员需要升级到SSR-6.1.9或SSR-6.2.5。  
  
Juniper Networks指出，升级 Conductor 节点足以将修复程序自动应用到连接的路由器上，但路由器仍应升级到最新可用版本。应用漏洞修复程序不会中断生产流量，对基于 Web 的管理和 API 的停机时间影响极小，约为30秒。  
  
注意，该漏洞没有其他变通方法，建议采取的行动仅限于应用可用的修复程序。  
  
由于瞻博网络产品部署在关键和有价值的环境中，因此成为黑客攻击的目标。2023年，Juniper Networks  EX 交换机和 SRX 防火墙涉及四个漏洞组成的攻击链，且在供应商发布相关公告后不到一周就观察到了恶意活动。  
  
几个月后，CISA 对上述漏洞的主动利用发出警告，并敦促联邦机构和关键组织在四天内应用安全更新，足以体现CISA的急迫性和漏洞的危害性。  
  
**参考资料：**  
  
https://www.bleepingcomputer.com/news/security/juniper-releases-out-of-cycle-fix-for-max-severity-auth-bypass-flaw/  
  
  
  
原文来源  
：FreeBuf  
  
“投稿联系方式：010-82992251   sunzhonghao@cert.org.cn”  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/GoUrACT176n1NvL0JsVSB8lNDX2FCGZjW0HGfDVnFao65ic4fx6Rv4qylYEAbia4AU3V2Zz801UlicBcLeZ6gS6tg/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
