#  【安全圈】VMware 修复了 ESX 产品中三个被积极利用的零日漏洞   
 安全圈   2025-03-06 19:00  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGylgOvEXHviaXu1fO2nLov9bZ055v7s8F6w1DD1I0bx2h3zaOx0Mibd5CngBwwj2nTeEbupw7xpBsx27Q/640?wx_fmt=other&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
**关键词**  
  
  
  
零日漏洞  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGyliaAnbWZNIdnNMnibrp5ERSAjib6vZed0IksdztEz96TErGfQyRKwJxVdibDv6ZzYqADibNIFbia2bvgFBQ/640?wx_fmt=png&from=appmsg "")  
  
  
博通发布了安全更新，以解决 ESX 产品中三个被广泛利用的 VMware 零日漏洞。  
  
这些漏洞分别被编号为 CVE-2025-22224、CVE-2025-22225 和 CVE-2025-22226，影响多个 VMware ESX 产品，包括 VMware ESXi、vSphere、Workstation、Fusion、Cloud Foundation 和 Telco Cloud Platform。  
  
微软威胁情报中心的研究人员发现了这三个漏洞。  
  
具有特权管理员或根访问权限的攻击者可以链接漏洞来逃离虚拟机内的沙盒。  
  
以下是这些漏洞的描述：  
- CVE-2025-22224（CVSS 评分为 9.3）VMCI 堆溢出漏洞：该漏洞是 VMware ESXi 和 Workstation 中的 TOCTOU（检查时间使用时间）问题，可导致越界写入。“具有虚拟机本地管理权限的恶意行为者可能会利用此问题以虚拟机在主机上运行的 VMX 进程的身份执行代码。”咨询中写道。   
  
- CVE-2025-22225（CVSS 评分 8.2）VMware ESXi 任意写入漏洞：该漏洞是 VMware ESXi 中的任意写入问题。具有 VMX 进程内权限的攻击者可能触发任意内核写入，从而导致沙盒逃逸。  
  
- CVE-2025-22226（CVSS 评分为 7.1）HGFS 信息泄露漏洞：该漏洞是一种影响 VMware ESXi、Workstation 和 Fusion 的信息泄露漏洞。该漏洞是由于 HGFS 中的越界读取造成的。具有虚拟机管理权限的攻击者可能能够利用此问题从 vmx 进程中泄漏内存。   
  
-   
该虚拟化巨头证实，其掌握的信息表明这三个漏洞已被广泛利用。  
  
该公司表示：“2025 年 3 月 4 日，博通发布了重要的 VMware 安全公告 (VMSA) VMSA-2025-0004，解决了在 VMware ESX 中发现并解决的安全漏洞，该漏洞涉及威胁行为者可以通过正在运行的虚拟机访问虚拟机管理程序的机制。”“这些漏洞是否正在被‘在野’利用？”Broadcom 有信息表明，这些问题已被“广泛”利用。“这是‘虚拟机逃逸’吗？”“是的。在这种情况下，已经入侵虚拟机客户操作系统并获得特权访问权限（管理员或 root）的攻击者可以进入虚拟机管理程序本身。”  
  
该公司尚未透露有关攻击或背后威胁行为者的具体细节。  
  
  
来源：https://securityaffairs.com/174911/security/vmware-fixed-three-actively-exploited-zero-days-in-esx-products.html  
  
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
  
  
