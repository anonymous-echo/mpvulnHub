#  攻防演练实战秘诀：让0day内存马从送命题秒变送分题   
原创 ThreatBook  微步在线   2022-06-22 18:20  
  
2022年的国家级攻防演练即将拉开帷幕，对于诸多参演企业而言，可谓是一年一度的终极大考。  
  
大考面前，众生平等。  
  
不管是参演过多次的企业，还是首次参演的企业，考前必然都心怀忐忑。  
  
  
综合历届攻防演练情况来看，攻防演练实战化趋势越见明显，同时也更强调“克敌制胜”：**检测并快速响应红队的入侵**  
只是“及格线”；要获得“好成绩”还必须“克敌”，即要**确定红队入侵手法，对攻击过程进行溯源，真实还原红队入侵路线；**  
如果还能对**红队进行画像，更进一步锁定入侵红队信息，并确定身份**  
的话，那么“三甲”也就不远了。  
  
相反地，红队要想获得好表现，就要千方百计躲开蓝队的检测/追踪。对于网络安全行业而言，公认难以被蓝队察觉的入侵方式有两种：**0day和内存马**  
。  
  
0day与内存马之所以有如此大的威慑力，主要原因在于**前者难防范，后者难检测**。防范检测难，但并不意味着没有办法，先来分析0day防范的关键点。  
  
**01**  
  
**如何破除0day防范之难**  
  
0day在入侵前期确实有优势，**但从后续攻击手法来看，与其他入侵行为并无本质上的不同。******  
  
结合Cyber Kill Chain网络杀伤链模型，再以**入侵作用的位置进行划分，在前五个阶段，红队本身就占据主动**，0day漏洞利用能够进一步隐藏红队的入侵行为。但是，当红队发起的入侵进行到“**命令控制**”环节时，攻守之势异也。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Yv6ic9zgr5hSd1XyPpojNdDSbIwq7jlaiaxZwqdLs3VeREvIOTkjcCobI147lqDXKsEhF68Duddv0qfnNq2bnDibw/640?wx_fmt=png "")  
  
“命令控  
制”阶段意味着攻击的真正开  
始，为了获取靶标，红队必然要进行一系列操作：  
提  
权、创建新账号、登录……，在正常系统里，这些都是异常行为，会被告警。  
  
但如果只针对单个事件/行为进行告警，安全人员很容易被大量告警信息淹没。这也是大多数安全从业人员的真实写照，**繁多的告警导致真正的威胁告警未能及时发现，从而错过了最佳响应时间。**  
  
这时，您需要一个工具——能对告警信息进行分析，筛选出最具威胁告警的工具，从而破除红队伪装，抓住真正的威胁。  
  
微步在线的OneEDR正是那个满足您需求的理想选择。  
  
**02**  
  
**OneEDR：让0day秒变1day**  
  
OneEDR是如何检测到0day漏洞利用的入侵行为的呢？  
  
首先，OneEDR会监控各种Web远程命令执行操作，全面覆盖0day漏洞利用，并标记为异常行为进行风险打分和告警。其次，OneEDR会对所有异常行为和操作进行聚合分析，利用图算法将红队的整个攻击链条关联起来整体判定打分进行告警，最后以图形的方式呈现。具体效果如下图：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Yv6ic9zgr5hSd1XyPpojNdDSbIwq7jlaiavOrK6Ldo86AY9ANyh6Qh1Aaw3L7wqsFO3zeGWhBj6EwQ7B02w1R5vw/640?wx_fmt=png "")  
  
OneEDR通过进程链路图，还原内网攻击路径。如果是Webshell，可通过TDP联动找到源IP；如果是爆破，OneEDR能直接找到源IP  
  
**事件聚合**  
是微步在线OneEDR中特有的能力，这个能力是基于微步在线5项专利技术实现的，包括：  
- 威胁情报样本数据获取专利（专利号：CN113919514A）；  
  
- 针对入侵事件检测专利（专利号：CN114006775A）；  
  
- 入侵事件检测模型构建专利（专利号：CN113836527B）；  
  
- 告警关联专利（专利号：CN113949621A）；  
  
- 聚合信息确定威胁事件专利（专利号：CN112087465B）等。  
  
利用这一系列专利技术，OneEDR不仅能够准确地抓住红队的入侵行为，还能展现红队的整个攻击链条及最新进展。  
对于蓝队/企业而言，可以说是“攻防战场”单向透明了——原本的“送命题”秒变“送分题”！  
  
既然检测到了真正的入侵行为，后续的事情就简单了。  
  
利用OneEDR的资产分组功能，锁定红队入侵的涉事单位及关联单位，同时还可锁定主要负责人及相关责任人，及时地对涉事资产进行处理。  
  
然后OneEDR通过利用各种记录信息（比如全量日志），进行溯源分析，以确定红队身份信息。  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/Yv6ic9zgr5hSd1XyPpojNdDSbIwq7jlaiaFdnOrSCLnDpk7zHYUR97kEEvicicPaUc7BaTM7dTJ7VVp0t5b6Vh86icw/640?wx_fmt=jpeg "")  
  
O  
neED  
R通过记录全量日志，进行溯源分析。  
还可以通过SQL语句进行自定义  
  
OneEDR还可以展示攻击的频次以及手段、使用方法，与其他信息相结合，对红队的网络攻击源和威胁样本进行画像，从而确定红队信息。  
比如下图中显示的是一次SSH爆破告警分析信息：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Yv6ic9zgr5hSd1XyPpojNdDSbIwq7jlaiaLaUiarsUiboicmsd6loicuVXceQU9wwHicS95UtiaicMffkRrtCfxTprmrpNA/640?wx_fmt=png "")  
  
在  
实际应用中，正是**由于OneEDR强大的事件聚合能力**  
，很多蓝队将**OneEDR的告警作为参考标准，以此避免被海量告警淹没**  
，将有限的精力投入到真正的告警上。  
并且，OneEDR的事件聚合功能的另一大好处是，在一长串的攻击链条中，哪怕漏报了其中几个异常行为，也不会对整个事件告警带来大的影响，**因为OneEDR告警的是攻击链，而非单独的点**  
。  
  
哪怕是谈之色变的0day，只要入侵就会有异常行为，进而被OneEDR检测到，并最终追踪到0day，0day的发布之日就是0day的灭亡之时。这在去年的国家级攻防演练中已经被事实证明：  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/Yv6ic9zgr5hSd1XyPpojNdDSbIwq7jlaiaDZRpfe5aEhhFDTjtsFDckeN3XGlqMjOqH5GbNwicbGsUraE3yWb5Y2Q/640?wx_fmt=jpeg "")  
  
在去年的国家级攻防演练中，OneEDR通过事件聚合  
功能，成功抓住红队利用某厂商的VPN-0day漏洞进行的渗透入侵行为  
  
解决了0day问题，再来说说内存马。  
  
**03**  
  
**让内存马无所遁形**  
  
内存马是  
无文件攻击中的一种，一般认为是由Webshell发展而来：  
从大马到小马拉大马、一句话木马、加密一句话木马，然后是最终极的加密内存马。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Yv6ic9zgr5hSd1XyPpojNdDSbIwq7jlaia8SKBnKYlibrU43PZFIFsQIuPgfPqia2s632ppwIjsiaURfKackhJ2Mm9w/640?wx_fmt=png "")  
  
内存Webshell的分类，其中Java类无文件攻击是最主流使用的方式  
  
OneEDR团队针对过去几年中大量的无文件攻击案例进行分析表明，在所有的无文件攻击中，Java web内存马（简称Java内存马）是使用最频繁的，同时，也是利用最成熟的攻击方式。Java内存马通常有servlet、spring/tomcat等框架，以及字节码增强型等三种不同的利用方式，但归根到底，**Java内存马要影响的都是加载到jvm中的类**。  
  
针对Java内存马这一威胁类型，OneEDR采用具有微步在线自主知识产权的**内存马检测专利技术**（专利号：CN113946825B），通过利用Java instrumentation将检测逻辑attach到jvm上，只需三步：  
- 通过java agent获取jvm中所有加载的类；  
  
- 遍历每个类，把可能被攻击方增加/篡改的类，都标记为风险类；  
  
- 遍历风险类，检查是否为Webshell，关键特征：高风险类的class文件是否存在内存马。  
  
除了Java web内存马的检测之外，OneEDR即将推出针对Windows平台下的内存马检测功能，让内存马无处可藏、无所遁形！  
  
0day和内存马只是OneEDR展现的一部分能力，实际上，作为一款主机入侵检测与响应平台，OneEDR远不止如此，比如：  
- OneEDR具备ATT&CK中**90%**的攻击手段检出能力，覆盖超过**300+**的常见攻击技术和子技术；  
  
- 内置的12款自研引擎，检出准确率**高达99%**；  
  
- 通过事件聚合、图算法，还原攻击链路，便于用户处置和溯源；  
  
- 对应ATT&CK黑客攻击行为进行单点检测，再对攻击链路进行检测，以此达到实战化对抗的目的。  
  
除此之外，OneEDR还能够与微步在线的网络流量检测与响应平台TDP配合使用，TDP同样具备0day漏洞的检出能力，两者强强联合，让0day和内存马等高级威胁无所遁形。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Yv6ic9zgr5hSd1XyPpojNdDSbIwq7jlaiaO4a7nlBV8GMcJ5iaDIH0GHy8WkOL0ACIq4eZ5UlXMcZxsUvw9eTd5IQ/640?wx_fmt=png "")  
  
OneEDR与TDP组合使用，通过行为+文件+网络全方位检测与响应，让检测能力再上层楼  
  
**您希望在短期内提高企业网络安全等级吗？**  
  
**您希望在短期内提升企业安全团队技能水平吗？**  
  
**您希望在短期内加强企业攻防演练核心竞争力吗？**  
  
**OneEDR，您值得一试！**  
  
  
**安全传送门**  
  
  
Free Trial  
  
如果您有防范内存马的需求  
  
或正面临0day的威胁  
  
欢迎联系我们  
  
↓  
↓↓  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Yv6ic9zgr5hSd1XyPpojNdDSbIwq7jlaiaibnwdx2iaeQFucnZUl06HZyBZX1r0Zjt2iaVSB5NRfxGR7fQ8icbfgZMUQ/640?wx_fmt=png "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Yv6ic9zgr5hTIdM9koHZFkrtYe5WU5rHxSDicbiaNFjEBAs1rojKGviaJGjOGd9KwKzN4aSpnNZDA5UWpY2E0JAnNg/640?wx_fmt=png "")  
  
400-030-1051  
  
  
  
  
· END ·  
  
  
点击下方名片，关注我们  
  
觉得内容不错，就点下  
“**赞**”和  
“**在看**”  
  
如果不想错过新的内容推送，可以设为**星标**  
![](https://mmbiz.qpic.cn/mmbiz_png/Yv6ic9zgr5hTYyCkc91euAiaGULJSbiaHricFHs2dd2sib20WTJKwHYD90Jia9HCKxnmJUwnkicGU7rVP3EYCVh3dMnng/640?wx_fmt=png "")  
哦  
  
  
