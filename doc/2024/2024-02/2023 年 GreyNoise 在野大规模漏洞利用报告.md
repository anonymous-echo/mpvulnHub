#  2023 年 GreyNoise 在野大规模漏洞利用报告   
原创 Avenger  威胁棱镜   2024-02-06 14:00  
  
美国第十八任总统、南北战争中出色的将领   
Ulysses S. Grant 曾说“战争的艺术很简单：找到敌人在哪里，尽可能快地对他们进行猛烈打击”。  
GreyNoise 的创始人   
Andrew Morris 认为：尽管攻击技术复杂多变、市场风起云涌，防御的艺术也很简单：找到攻击者使用的技术，确定攻击来自哪里，尽快让攻击无效化。  
  
**概述**  
  
2023   
年   
GreyNoise 新增了   
290 个标签，覆盖   
242 个常见漏洞利用。其中，  
67 个标签在   
CISA 的已知利用漏洞（  
KEV）目录中，  
23 个标签与勒索软件有关。  
  
2023   
年，社区查询了   
1730 万次   
GreyNoise GNQL 查询请求。排名前五的标签为：  
- Citrix Adc
NetScaler Information Disclosure Attempt  
（  
CVE-2023-4966）  
  
- Huawei HG532
UPnP Worm  
（  
CVE-2017-17215）  
  
- RealTek
Miniigd UPnP Worm  
（  
CVE-2014-8361）  
  
- GPON Router
Worm  
（  
CVE-2018-10561）  
  
- Netgear
Command Injection  
（  
CVE-2016-6277）  
  
从频度来看，  
5.188.210.227 这个   
IP 地址引起了很多人的关注：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/dlhiccJOdNYY7V6bibkicCmA5xsKFpwez8l1GFPcNAolkWmOutg6qgk4hb3ABgP4MafnGAOKH4x9OQcqmpvnaDSZA/640?wx_fmt=png&from=appmsg "")  
  
  
  
**年度漏洞：CVE-2023-34362**  
  
在   
Progress 于   
2023 年   
5 月   
31 日披露   
CVE-2023-34362 前几周，攻击者就开始利用该漏洞进行攻击了，  
Cl0p 勒索软件团伙是最早利用该漏洞的攻击者之一。研究显示，该漏洞的受害者可能超过   
2600 个组织，波及近   
9000 万人。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/dlhiccJOdNYY7V6bibkicCmA5xsKFpwez8lDBVnWJ245bN4K01qibiaYzo1Wia0jqHjKbibKysUshsgqbicxODkQX0cia0w/640?wx_fmt=png&from=appmsg "")  
  
  
  
**年度漏洞：CVE-2023-4966**  
  
CVE-2023-4966  
（又称   
CitrixBleed）针对  
Citrix NetScaler ADC 和  
 NetScaler
Gateway 允许攻击者绕过多因子认证劫持会话。包括  
 LockBit 勒索软件团伙在内的多个黑客组织已积极利用该漏洞，平均每天三十多个   
IP 对外进行攻击。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/dlhiccJOdNYY7V6bibkicCmA5xsKFpwez8l6clqxD5bbpEfYMZrT5z8YUp3ytgJveRs1gwYrrYDjico1lGDzQGKdOw/640?wx_fmt=png&from=appmsg "")  
  
  
  
**年度漏洞：CVE-2023-27350**  
  
2023   
年   
4 月中旬   
CVE-2023-27350 被发现，  
FBI 名为   
Bl00dy 的勒索软件团伙也开始针对该漏洞进行攻击。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/dlhiccJOdNYY7V6bibkicCmA5xsKFpwez8l3CXsRu2v5xaDNQ9ByBjXJqxF7XSI9JXlQ9WpoicMowTBeqVToIN8bZA/640?wx_fmt=png&from=appmsg "")  
  
  
  
**已知利用漏洞（KEV）**  
  
CISA   
的已知利用漏洞（  
KEV）列表旨在为美国政府内外部提供有针对性的主动威胁列表，值得防守者花时间进行优先修复的。  
67 个 GreyNoise 跟踪的标签，活动情况如下所示：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/dlhiccJOdNYY7V6bibkicCmA5xsKFpwez8lVibCricA6u5MgU6M4UQkqewzh3TzfYchZF9ZuqAxMGZmLibPJLyJCmsXw/640?wx_fmt=png&from=appmsg "")  
  
  
63%   
的情况下   
GreyNoise 发布标签都比   
CISA 披露   
KEV 清单要早。  
2023 年，  
CISA 增加了有哪些勒索软件攻击者利用该漏洞进行攻击的标签。目前，已有   
20% 的   
KEV 被勒索软件团伙用于攻击。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/dlhiccJOdNYY7V6bibkicCmA5xsKFpwez8lSx0HtLkxRsAhIRzN5CbkMgmMcph6W5IlWdyNgxqbGGCSTewPwuwnrg/640?wx_fmt=png&from=appmsg "")  
  
  
  
**国家冲突中的漏洞利用**  
  
俄乌冲突、巴以冲突等重大冲突，双方不仅局限在物理空间中进行对抗。相比物理空间中的范围可控，网络空间中的对抗往往会产生溢出效应。例如乌克兰安全局称**俄罗斯黑客入侵摄像头，对基辅的防空系统和关键基础设施进行监控**。乌克兰安全局已经拆除了近万台摄像头，“攻击者本打算利用这些摄像头调整对乌克兰的导弹袭击”。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/dlhiccJOdNYY7V6bibkicCmA5xsKFpwez8lvRSsn8gFzmpkYiaxG5NibufC8sMmicOkrTpX1sywKCVDjW4FXQXAd15eA/640?wx_fmt=png&from=appmsg "")  
  
  
另外，  
2023 年   
12 月也有利用以色列生产的工控设备存在的漏洞攻击美国水务相关单位的事情发生。  
  
**国家视角数据**  
  
GreyNoise   
重点介绍了沙特阿拉伯这个国家在   
2023 年   
10 月的数据情况。整个月，  
GreyNoise 发现了   
52602 次针对沙特阿拉伯的攻击，以及沙特阿拉伯对其他国家  
/地区的   
2204 次攻击。  
  
攻击来源国家  
TOP 20 如下所示：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/dlhiccJOdNYY7V6bibkicCmA5xsKFpwez8lP4icTZibjM7HF55th7s4TMQ3701s59bmicibbq2pxsYC1GqILiciayMghTeA/640?wx_fmt=png&from=appmsg "")  
  
  
攻击源   
IP 绝大多数都是来自   
ISP 的：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/dlhiccJOdNYY7V6bibkicCmA5xsKFpwez8lJf44pFKDUfk2bA2eP1Q0pC8jevBgibvE6qe7zoRt4D1dyo7FrOUVMxA/640?wx_fmt=png&from=appmsg "")  
  
  
  
从标签聚合来看，僵尸网络要承担较大责任。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/dlhiccJOdNYY7V6bibkicCmA5xsKFpwez8ll6PF3sPzC2yDoPVnWpXPpeLQHeILFCK5iaARkptc4srPhuuZBibbOwrA/640?wx_fmt=png&from=appmsg "")  
  
  
  
对外发起的攻击，则主要流向了美国和英国。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/dlhiccJOdNYY7V6bibkicCmA5xsKFpwez8lGrZDLXD02iaqaiapblS3FY5JkiauVAadGTnum16BpibZqfZjkloWCu2BRQ/640?wx_fmt=png&from=appmsg "")  
  
  
  
沙特阿拉伯在   
2007 年就通过了《反网络犯罪法》，制定了国家网络安全战略，并且成立了国家网络安全局（  
NCA）。**如果政府发现沙特境内对外发起攻击，根据具体罪行严重情况，最高可能会处以一年监禁或 50 万沙特里亚尔（近 100 万人民币）的罚款**。  
  
**标签**  
  
GreyNoise   
共支持   
45 个   
CWE 标签，如下七个标签就占据了   
70% 的当量。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/dlhiccJOdNYY7V6bibkicCmA5xsKFpwez8l7fR1VQGZZ2VHqBwpNuxJAxn4HUp1tNGia1eAyL6IPk5pIRdCotltRSA/640?wx_fmt=png&from=appmsg "")  
  
  
  
MITRE
ATT&CK   
标签也是一样，如下七个技术项占到了六成的比例。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/dlhiccJOdNYY7V6bibkicCmA5xsKFpwez8lnCQyLku7GTeFhGw8YsmsgLgDNgWNsXgic7hSGfPPkvBLpn9zcIeuN0g/640?wx_fmt=png&from=appmsg "")  
  
  
2022 年 GreyNoise 在野大规模漏洞利用报告  
，可以参看以前的文章：  
> 2022 年 GreyNoise 在野大规模漏洞利用报告  
  
> Avenger，公众号：威胁棱镜[2022 年 GreyNoise 在野大规模漏洞利用报告](http://mp.weixin.qq.com/s?__biz=MzkyMzE5ODExNQ==&mid=2247485978&idx=1&sn=07bf7f46e252b422b01fa798879f6b85&chksm=c1e9fdd6f69e74c00386beb25b03252a79cd4d14e985be2d2f18645a7483b88dc9e8ef46beb7#rd)  
  
  
  
