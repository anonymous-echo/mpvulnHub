#  管好IT资产，高效防治漏洞（1）   
原创 Richard  方桥安全漏洞防治中心   2025-03-25 19:19  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/2JVOUiaJORTv7gEGKpGgkb35GpPIA5kWegGTQ9rniaDTlpjySXgIctPJwjIkUcg1ibP43VZdzFgHUic4fOHEg0YULQ/640?wx_fmt=png&from=appmsg "")  
  
很难想象IT资产管理做得不好，而安全漏洞防治工作做得很好。  
  
**那么，安全漏洞防治需要什么样的IT资产管理？**  
  
我们先看看 NIST SPECIAL PUBLICATION 1800-5 IT Asset Management（IT资产管理）里面的这张图。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/2JVOUiaJORTv7gEGKpGgkb35GpPIA5kWe7mBUD3UIiabgTBF6BxrqjmRpf7fnGrrq4qFT4aL0vpgR5K5zLbCTejw/640?wx_fmt=png&from=appmsg "")  
  
图1. Asset Lifecycle，右边是笔者翻译的中文版本  
  
从安全漏洞防治对IT资产管理的需求出发，我们将这个生命周期适当简化、变形，得到下面这张图。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/2JVOUiaJORTv7gEGKpGgkb35GpPIA5kWeYI6JtLcMUOofhPibh1Fl1KX0tPZcD9lIqDeZOAwcakBJhQmc683W5Ag/640?wx_fmt=png&from=appmsg "")  
  
图2. 简化的IT资产生命周期。图中的资产包括主机（物理机、虚拟机等），容器（docker、POD等），软件，组件，文件等。安全漏洞防治主要关注包括BIOS、操作系统在内的软件和组件。  
  
从上图可以看出，  
- 上线前安全审查（图中①）是防范漏洞进入运行环境的关键控制措施。  
  
- 在运行环境中，只有受控的资产得到有效管理（图中②）。包括有效降低资产失控比例的控制措施。  
  
- 正式下线离开运行环境需要妥当处置（图中③），包括检查是否有效地清除了资产可能包含的敏感信息。  
  
我们重点讨论②。即  
“有效管理受控资产，有效降低资产失控的比例。”  
### 首先，有效管理受控资产，  
  
漏洞“发现-评估-修补-验证”各环节对资产管理的需求如下图所示。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/2JVOUiaJORTv7gEGKpGgkb35GpPIA5kWeQHAt5trPC9TZpUGgDF9DT9ialSLro8CnDOdYL7iafMfXlzibZYSxib6KoQ/640?wx_fmt=png&from=appmsg "")  
  
图3. 安全漏洞防治各环节对IT资产管理的需求  
  
**如何有效管理？**  
  
安全团队面临的挑战是缺少数据来源。有时会陷入两难境地：自己做，费时费力用得不多；寄希望于其他系统，拿到的信息很难满足安全漏洞防治的需求。  
  
下图是一种可行的**整合思路**  
。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/2JVOUiaJORTv7gEGKpGgkb35GpPIA5kWekgFtwY93wNb5ZDVvSI7O8icoxFQ8cHE9JySelQpWcyXsozkE37iaLueA/640?wx_fmt=png&from=appmsg "")  
  
图4. 安全漏洞防治需要的IT资产管理，一种整合方法  
> 运维团队可能有CMDB；开发团队可能有SBOM；安全团队有主机安全系统、网络漏洞扫描、终端防病毒/EDR等数据……这些数据整合在一起，形成“IT资产数据仓库（IT Asset Management Inventory）”，可为安全漏洞防治提供良好的数据支撑。  
  
  
建成后的IT资产数据仓库，可以服务于以下几种安全漏洞防治工作场景：  
  
——排查监管通告漏洞（如：两高一弱）  
  
——剔除误报的漏洞  
  
——整合漏洞情报精准预警  
  
——基于资产相对价值的漏洞风险评估  
  
——定位漏洞责任人（责任链），提供丰富的资产信息支持漏洞处置。  
  
（站到更为全局的安全运营来看，IT资产数据仓库还有更多应用场景。在此暂不展开。）  
### 然后，有效降低资产失控的比例  
  
要做到这点，需结合自动化工具、标准化流程和系统化管理策略。下面给出一种参考方法。  
1. **监测互联网资产**  
：  
部署互联网资产测绘工具，或者使用第三方服务监测暴露在互联网上的资产（公网IP、域名、网站、邮箱、小程序、APP、各公共平台上的官方账号等）。  
  
1. **自动发现技术**  
：  
部署支持**无代理/有代理扫描**  
的IT资产管理系统，定期检测网络中的所有资产（硬件、软件、网络设备），找出未登记的资产；从网络流量中发现没管住的资产。  
  
1. **建立集中的IT资产数据仓库**  
：  
所有资产信息集中存储在仓库中，消除散布在各处的“数据孤岛”。  
  
1. **全生命周期追踪**  
：  
参考本文前面的图2，抓住关键的“上线”和“下线”环节。  
  
1. **权限控制**  
：  
结合组织结构设置与工作角色匹配的访问权限，防止未授权人员操作关键资产信息。  
  
1. **审计与合规**  
：  
系统自动生成审计日志，并追溯违规变更资产信息的责任。  
  
1. **标准化操作流程**  
：  
制定IT资产上线、下线SOP，并通过系统强制执行。  
  
1. **培训与意识提升**  
：  
持续宣贯，定期培训，强调IT资产登记和合规操作的重要性，减少人为疏漏。  
  
综合使用以上措施实现“主动管控”，显著降低IT资产失控的比例，确保每项软硬件资产可视、可控。  
  
IT资产管理是一个很大的话题。本文从“高效防治漏洞”对IT资产管理的需求出发，提出“有效管理受控资产”和“有效降低资产失控的比例”这两个目标。后续文章将讨论“服务于安全漏洞防治工作的IT资产管理”具体实现方案。  
  
  
  
- End -  
  
  
  
推荐阅读  
- [健全管理体系，为安全漏洞防治注入原力](https://mp.weixin.qq.com/s?__biz=Mzk0OTQzMDI4Mg==&mid=2247484693&idx=1&sn=ca0090285d46708dafaa723acfa45208&scene=21#wechat_redirect)  
  
  
- [安全漏洞防治中心建设、运行、迭代](https://mp.weixin.qq.com/s?__biz=Mzk0OTQzMDI4Mg==&mid=2247484663&idx=1&sn=c65c7831bfad68d2b76ea9860f35f0a3&scene=21#wechat_redirect)  
  
  
- [09 漏洞从哪里来?——技术进步](https://mp.weixin.qq.com/s?__biz=Mzk0OTQzMDI4Mg==&mid=2247484629&idx=1&sn=6de6ab160491093bb6242e749b9f8555&scene=21#wechat_redirect)  
  
  
- [05 漏洞从哪里来？——体系痼疾（制度化）](https://mp.weixin.qq.com/s?__biz=Mzk0OTQzMDI4Mg==&mid=2247484541&idx=1&sn=57e4d0c60cf1cb54008e73f1b4751545&scene=21#wechat_redirect)  
  
  
