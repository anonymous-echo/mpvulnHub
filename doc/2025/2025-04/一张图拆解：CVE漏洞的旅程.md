#  一张图拆解：CVE漏洞的旅程   
 哆啦安全   2025-04-17 00:55  
  
   
  
   
  
   
  
近日，CVE要被终止资助而引起了热议。甚至有人这样描述“全球所有行业都依赖CVE计划在管理威胁时保持生存，因此像这样的突然停顿就像剥夺了网络安全行业的氧气，还指望它能自发长出腮部一样。”  
> All industries worldwide depend on the CVE program to keep their heads above water when it comes to managing threats, so an abrupt halt like this would be like depriving the cybersecurity industry of oxygen and expecting it to spontaneously sprout gills,  
  
> https://www.theregister.com/2025/04/16/homeland_security_funding_for_cve/  
  
  
还有人直接制作了一张图来阐述CVE披露系统的运作机制以及MITRE的重要性。而本文将用文字拆解这张图，和大家一起看看CVE的生命周期。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/jM058YXsURwplNpjicfjrTjW3fSgCTgrLeN0VysjiavBCyw4C7blOkNKNtRdH8pr1hf2lD3e3T0ThgnVmyOQ2Rpw/640?wx_fmt=png&from=appmsg "")  
### 什么是CVE？  
> CVE（Common Vulnerabilities and Exposures）的全称是公共漏洞和暴露，是公开披露的网络安全漏洞列表。IT人员、安全研究人员查阅CVE获取漏洞的详细信息，进而根据漏洞评分确定漏洞解决的优先级。在CVE中，每个漏洞按CVE-1999-0067、CVE-2014-10001、CVE-2014-100001这样的形式编号。CVE编号是识别漏洞的唯一标识符。CVE编号由CVE编号机构（CVE Numbering Authority，CNA）分配，CVE编号机构主要由IT供应商、安全厂商和安全研究组织承担。  
  
> https://info.support.huawei.com/info-finder/encyclopedia/zh/CVE.html  
  
### CVE有什么作用？  
> 如果没有CVE，每个IT供应商或安全组织都维护自己的漏洞数据库，数据无法共享，大家对漏洞的认识也不统一。CVE为漏洞赋予唯一编号并标准化漏洞描述，主要作用如下：  
  
• IT人员、安全研究人员基于相同的语言理解漏洞信息、确定修复漏洞的优先级并努力解决漏洞。  
  
• 不同的系统之间可以基于CVE编号交换信息。  
  
• 安全产品或安全工具开发者可以将CVE作为基线，评估产品的漏洞检测覆盖范围。  
  
有的人可能会认为公开披露漏洞会给黑客带来可乘之机，黑客会利用这些漏洞发起攻击。其实利大于弊...  
  
> https://info.support.huawei.com/info-finder/encyclopedia/zh/CVE.html  
  
## CVE系统：漏洞管理的全景图  
  
当我们谈论软件安全时，漏洞的发现与披露是整个安全管理流程的起点。根据流程图所示，一个漏洞从被发现到正式成为安全社区认可的"发现"，需要经历一系列严格且系统化的步骤。这个过程不仅涉及多个机构，还需要专业的评估和分类。  
### 第一步：漏洞的发现与初步披露  
  
漏洞的生命周期始于发现。这可能是安全研究人员、白帽黑客、或是企业内部安全团队在软件或系统中识别出的安全弱点。一旦发现，研究者通常会选择向受影响的厂商或相关安全机构披露这一信息。  
### 第二步：CVE编号授权机构的验证  
  
在图示中，我们可以看到Adobe、Microsoft、Google、Debian、GitHub和Cisco等知名科技公司都参与了CVE编号授权工作。这些机构主要负责：  
1. 1. 验证所报告漏洞的真实性和严重程度  
  
1. 2. 为符合条件的漏洞分配唯一的CVE编号  
  
值得注意的是，这些授权机构通常只提供漏洞的标题和受影响产品的基本信息。此外，正如图中所示，不是所有的安全公告（例如某些GitHub安全公告）都会成为正式的CVE。这些机构的运作主要由某些企业自身资金支持，体现了这些企业在网络安全生态中的一些投入。  
### 第三步：MITRE的核心角色  
  
MITRE作为CVE系统的管理者，在整个生态中占据着中枢位置。根据图示信息，MITRE由美国国土安全部和CISA资助，年度资金约为3000万美元。其核心职责是：  
1. 1. 接收并审核来自各CVE编号授权机构的漏洞信息  
  
1. 2. 管理和维护CVE.org网站，确保所有经验证的漏洞信息得到妥善发布  
  
1. 3. 协调全球范围内的CVE编号授权机构，保证CVE系统的一致性和权威性  
  
从目前网络安全行业的实践来说，MITRE的重要性不言而喻——它是连接漏洞发现者、技术厂商和安全社区的关键纽带，确保关键安全信息能够及时、准确地传递给需要的各方。  
### 第四步：NVD的一些工作  
  
这张图显示了，一旦漏洞信息发布到CVE.org，美国国家漏洞数据库(NVD)便会接手后续工作。NVD由美国商务部和NIST资助，年度预算约850万美元。其主要工作包括：  
1. 1. 从CVE.org获取基础漏洞信息  
  
1. 2. 显著丰富漏洞数据，添加CVSS评分（漏洞严重程度评分系统）  
  
1. 3. 补充CPE（通用平台枚举）、CWE（通用弱点枚举）信息  
  
1. 4. 提供配置建议和缓解措施  
  
1.   
### 第五步：生态系统的延伸  
  
在CVE和NVD之外，这张图还展示了安全生态的其他重要组成部分：  
1. 1. **第三方漏洞丰富服务提供商**  
（如VulnCheck）：这些机构通过收集和整合多源信息，进一步丰富漏洞数据。  
  
1. 2. **安全扫描工具**  
（如Palo Alto Networks、Snyk和Wiz）：这些工具将CVE数据库与自身扫描能力相结合，帮助组织识别系统中存在的已知漏洞。值得注意的是，许多安全工具也有自己的内部编号系统，有些漏洞可能不会获得正式CVE编号。  
  
1. 3. **CISA的关键角色**  
：作为美国网络安全和基础设施安全局，CISA由国土安全部资助（约30亿美元），负责在识别到特别危险的漏洞时发布KEV（已知可利用漏洞）警报，为组织提供优先修复指导。  
  
1.   
## MITRE在CVE生态系统的地位  
  
从图示和上述拆解可以清晰看出，MITRE在整个CVE生态系统中的地位至关重要，原因主要有：  
1. 1. **中立权威性**  
：作为非营利组织，MITRE提供了一个偏中立的平台，不受单一商业利益驱动，保证了CVE系统的公正性。  
  
1. 2. **统一协调功能**  
：MITRE协调全球范围内的CVE编号授权机构，确保CVE编号的唯一性和一致性，避免了漏洞信息的碎片化。  
  
1. 3. **信息传播枢纽**  
：通过维护CVE.org，MITRE确保关键漏洞信息能够被广泛传播，为全球安全社区提供标准化的参考。  
  
1. 4. **体系建设基础**  
：MITRE的工作为其它环节提供了坚实基础，是整个漏洞管理生态的基石。  
  
值得注意的是，图中标注"This could go away"（这可能会消失）指向MITRE，这一标注值得关注。如果MITRE的角色发生变化，整个CVE生态系统可能需要重新调整，这反映了MITRE在系统中的重要性。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/LtmuVIq6tF1ZJzW9ibM2tSp4PC2iaUUQibAdLMku072pfdkBbR1vL06NwawFicVTylnWK9j699W1hZCqkMVibP9fKVA/640?wx_fmt=png&from=appmsg "")  
## 结语  
  
通用漏洞与披露数据库  
（CVE）是网络安全行业的一个重要组成部分，而MITRE则是确保这一系统有效运作的核心机构。在日益复杂的网络安全环境中，标准化的漏洞识别和共享机制显得尤为重要，而CVE 系统的价值不仅是记录漏洞，更是让全球安全团队“看见”风险。MITRE 作为中立的枢纽，在十余年间证明了标准化与协作的力量。  
这也许是近日CVE服务要被中断资助而引起热议的原因。  
  
对此，你怎么看呢？欢迎留言讨论~  
  
   
  
参考：   
- https://www.theregister.com/2025/04/16/homeland_security_funding_for_cve/  
  
- https:/  
/i  
nfo.support.huawei.com/info-  
finder/encyclopedia/  
zh/CVE.html  
  
- https://app.excalidraw.com/l/6qFzFKIJXdd/8mfIhW6Styp  
  
- http  
s://  
w  
w  
w.bleepingcomputer.com/news/security/cisa-extends-funding-to-ensure-no-lapse-in-critical-cve-services/  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/jM058YXsURwxM5VRwYWuYjOzHcZyJiap78zGKutXDayBCkRLf1sDnxWskice3Ata2VZDwU1ZJL6cVNJhkLVpeE5A/640?wx_fmt=png&from=appmsg "")  
  
**社区交流订阅：**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/jM058YXsURyy8pmTFKrArN88GyeDOBdG3KfZHkjATfNCGbicN0MicAeVJ9yBPY1ApeHp6xNMiaMFK1Kn07AIsCwnA/640?wx_fmt=jpeg&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/jM058YXsURwplNpjicfjrTjW3fSgCTgrLnltVbJbia5Eek20oibWVR8NNWFBuhGyuBGnicA0fxEiaQCk2j5D1YlX6mA/640?wx_fmt=png&from=appmsg "")  
  
   
  
