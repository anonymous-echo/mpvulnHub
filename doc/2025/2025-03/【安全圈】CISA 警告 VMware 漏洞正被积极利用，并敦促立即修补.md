#  【安全圈】CISA 警告 VMware 漏洞正被积极利用，并敦促立即修补   
 安全圈   2025-03-06 19:00  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGylgOvEXHviaXu1fO2nLov9bZ055v7s8F6w1DD1I0bx2h3zaOx0Mibd5CngBwwj2nTeEbupw7xpBsx27Q/640?wx_fmt=other&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
**关键词**  
  
  
  
安全漏洞  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGyliaAnbWZNIdnNMnibrp5ERSAjory5ruicxwOqSvve3bZNcxM08v1aHp3sVQEpU3WkIfYUR0Nsoo4F07w/640?wx_fmt=jpeg&from=appmsg "")  
  
美国网络安全和基础设施安全局 (CISA) 于 2025 年 3 月 4 日发布紧急警报，在确认存在野外利用后，将三个严重的 VMware 漏洞添加到其已知利用漏洞 (KEV) 目录中。  
  
漏洞CVE-2025-22224、CVE-2025-22225 和 CVE-2025-22226允许具有虚拟机 (VM) 特权访问的攻击者提升权限、在虚拟机管理程序上执行代码并窃取敏感内存数据。  
  
这些漏洞由微软威胁情报中心 (MSTIC) 发现，影响VMware ESXi、Workstation、Fusion、Cloud Foundation 和 Telco Cloud Platform 产品。  
  
CISA 的咨询与博通发布补丁的时间一致，强调联邦机构和私人组织需要根据具有约束力的操作指令 (BOD) 优先采取补救措施。  
## VMware 漏洞 被利用  
### 严重 TOCTOU 缺陷可导致虚拟机管理程序接管 (CVE-2025-22224)  
  
CVE-2025-22224 是这三个漏洞中最严重的一个，CVSS 评分为 9.3，它是 VMware ESXi 和 Workstation 中的检查时间使用时间 (TOCTOU) 竞争条件。  
  
具有虚拟机管理权限的攻击者可以利用此堆溢出漏洞在 VMX 进程（管理虚拟机操作的虚拟机管理程序组件）内执行任意代码。  
  
成功利用该漏洞可以控制主机系统，从而实现跨虚拟化基础设施的横向移动。  
### 通过任意写入实现沙盒逃逸（CVE-2025-22225）  
  
CVE-2025-22225 (CVSS 8.2) 允许经过身份验证的攻击者通过 VMX 进程将任意数据写入 ESXi 主机，从而实现沙盒逃逸。通过操纵内核内存，攻击者可以获得提升的权限来部署恶意软件或破坏服务。  
  
此缺陷在多租户云环境中尤其危险，因为单个受损的虚拟机就可能危及整个集群。  
### 虚拟机管理程序内存泄漏（CVE-2025-22226）  
  
第三个漏洞 CVE-2025-22226（CVSS 7.1）源于 VMware 主机客户文件系统 (HGFS) 中的越界读取。  
  
利用此漏洞的攻击者可以从 VMX 进程中提取敏感数据，包括存储在虚拟机管理程序内存中的加密密钥或凭据。虽然它比其他漏洞的严重性要低，但它为策划进一步的攻击提供了关键的侦察数据。  
  
Broadcom 发布了针对所有受影响产品的修复程序，其中包括：  
- ESXi 8.0/7.0：修补程序 ESXi80U3d-24585383 和 ESXi70U3s-24585291  
  
- Workstation 17.x：版本 17.6.3 解决了 CVE-2025-22224/22226  
  
- Fusion 13.x：更新 13.6.3 解决了 CVE-2025-22226  
  
使用 VMware Cloud Foundation 或 Telco Cloud Platform 的组织必须应用异步修补程序或升级到修复的 ESXi 版本。  
1. 立即修补：优先更新 ESXi、Workstation 和 Fusion。  
  
1. 监控虚拟机活动：检测不寻常的权限提升或内存访问模式。  
  
1. 利用 BOD 22-01 框架：将补救工作流程与 CISA 的 KEV 时间表保持一致。  
  
由于已经发现漏洞，延迟修补可能会引发类似 2024 年 vCenter Server 事件的大规模漏洞。由于虚拟化是关键基础设施的基础，因此主动防御对于阻止寻求持续访问的国家对手至关重要。  
  
来源：https://cybersecuritynews.com/cisa-warns-vmware-vulnerabilities/  
  
  END    
  
  
阅读推荐  
  
  
[【安全圈】最新黑产技术曝光，只需19分钟即可劫持AI大模型](https://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652068282&idx=1&sn=d8c361d857947b4f7ddd18672093ed23&scene=21#wechat_redirect)  
  
  
  
[【安全圈】全球 49,000 多个门禁管理系统存在巨大安全漏洞](https://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652068282&idx=2&sn=cfbab77073fc932a8b466a9586809efc&scene=21#wechat_redirect)  
  
  
  
[【安全圈】GitHub 大规模恶意软件行动：Redox Stealer盯上游戏玩家与盗版用户](https://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652068282&idx=3&sn=b6b1eda81cdc868cb996830336a5f909&scene=21#wechat_redirect)  
  
  
  
[【安全圈】320万用户因恶意浏览器扩展程序遭信息泄露](https://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652068282&idx=4&sn=101d9a5f9ab1488a2654bb7bdb7ebdf5&scene=21#wechat_redirect)  
  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/aBHpjnrGylgeVsVlL5y1RPJfUdozNyCEft6M27yliapIdNjlcdMaZ4UR4XxnQprGlCg8NH2Hz5Oib5aPIOiaqUicDQ/640?wx_fmt=gif "")  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/aBHpjnrGylgeVsVlL5y1RPJfUdozNyCEDQIyPYpjfp0XDaaKjeaU6YdFae1iagIvFmFb4djeiahnUy2jBnxkMbaw/640?wx_fmt=png "")  
  
**安全圈**  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/aBHpjnrGylgeVsVlL5y1RPJfUdozNyCEft6M27yliapIdNjlcdMaZ4UR4XxnQprGlCg8NH2Hz5Oib5aPIOiaqUicDQ/640?wx_fmt=gif "")  
  
  
←扫码关注我们  
  
**网罗圈内热点 专注网络安全**  
  
**实时资讯一手掌握！**  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/aBHpjnrGylgeVsVlL5y1RPJfUdozNyCE3vpzhuku5s1qibibQjHnY68iciaIGB4zYw1Zbl05GQ3H4hadeLdBpQ9wEA/640?wx_fmt=gif "")  
  
**好看你就分享 有用就点个赞**  
  
**支持「****安全圈」就点个三连吧！**  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/aBHpjnrGylgeVsVlL5y1RPJfUdozNyCE3vpzhuku5s1qibibQjHnY68iciaIGB4zYw1Zbl05GQ3H4hadeLdBpQ9wEA/640?wx_fmt=gif "")  
  
  
