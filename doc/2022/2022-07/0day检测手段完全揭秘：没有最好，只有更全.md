#  0day检测手段完全揭秘：没有最好，只有更全   
原创 ThreatBook  微步在线   2022-07-22 12:34  
  
| 本文共 1261 字，阅读预计 3 分钟 |  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/Yv6ic9zgr5hSNsiaB3CrdGXic75CwlY6ib7dgNjicH9kmibR7iarEsJHicU3qLcTg09S4yjSMXVUoPqXA8ZL0C8WnCTKug/640?wx_fmt=jpeg "")  
  
  
**这个世界上，能让网安人士魂（ti）牵（xin）梦（diao）绕（dan）的，不仅有一年一度的攻防演练，还有在攻防演练中“大火”的0day漏洞。**  
由于是未知漏洞，且官方并未公开发布漏洞补丁，在任何场合0day的杀伤力都无法被忽视。  
  
  
  
而真正让0day漏洞站在攻击工具制高点的，则在于实战环境中想要全面准确进行0day检测实在太难了。**从流量到终端，从IDS到IPS，从下一代防火墙到端点，从shellcode检测到机器学习进行异常流量检测，大家尝试了各种办法，都宣称自己能够检测未知0day漏洞，但其实都没能很好解决0day检测的问题。**  
不过，在与黑客斗智斗勇的过程中，倒是出现了几个对抗0day的“关键阶段”：  
  
  
  
**阶段1：想收高价值漏洞，却收了一堆POC******  
  
2005年7月25日，美国数字电子产品制造商3Com所属部门TippingPoint率先发起了一项国际软件漏洞倡议行动（Zero Day Initiative，ZDI)，花费不菲的奖励，从独立安全研究人员手上购买当时一众知名软件的0day漏洞。**虽然投入巨大，但ZDI收录的0day，并非一定可被“利用”的漏洞，而是 “存在可能性的概念验证的漏洞”（POC，Proof of Concept），根本无法应用在产品中进行0day检测。**  
  
**阶段2：文件沙箱，覆盖文件型0day检测******  
  
以沙箱起家的FireEye，把0day检测技术提到了另一个台阶。从2004年开始，对客户端的攻击增加，基于终端的Word、Excel、PPT、Adobe等软件的攻击数量暴增。2010年，FireEye推出用文件沙箱解决针对客户端的0day漏洞检测，可对Word、Excel、PPT等文件型漏洞进行检测，成为了文件型0day检测的利器。**不过，这种检测方式也有其局限性，对于0click的远程漏洞利用无解。**  
  
**阶段3：获取高价值漏洞，转身成为黑客经纪人******  
  
有需求，就有市场，而率先抓住这个需求，从事0day漏洞买与卖的企业，则是一家叫做Zerodium的美国信息安全公司。这家企业的核心业务就是大量收购高价值漏洞，并明确表态不要“概念验证”（POC）的漏洞，而是“可被利用”的漏洞。获取漏洞后，这家公司又对漏洞进行明码标价，将研究报告、保护措施以及安全建议，售卖给政府、黑客等群体，转身成为漏洞中间商，黑客的经纪人。根据媒体报道，该公司已有1500多名”在野”研究员，在2015到2021年购买漏洞花费超过5千万美元。  
  
**阶段4：检测技术+高价值漏洞，实现关键0day漏洞检测******  
  
**0day漏洞属于未发现漏洞，想要全面进行检测，光靠技术不够，还需获取高价值0day漏洞数据。**  
微步在线威胁感知平台TDP基于机器学习与通用检测，在挑战赛高强度对抗的环境下对Web类0day自动检出率高达50%以上。  
  
同时，微步TDP又收录了影响范围广、危害大、红队利用率极高的高价值0day漏洞放入TDP流量检测中，可对大部分关键0day实现有效检测，并及时阻断。与Zerodium不同的是，微步会将相关漏洞告知给对应厂商，并协助厂商进行漏洞修复。  
  
**从0day检测能力上线以来，微步TDP目前已监测到存在多个在野利用0day漏洞，**  
涉及知名OA、开发应用、财务软件等平台。出于安全性要求考虑，此处不做更多细节透露。  
  
攻防对抗没有尽头，网络安全我们一起守护。  
  
  
  
  
  
**安全传送门**  
  
  
Free Trial  
  
已购买TDP产品用户  
  
如需使用0day检测能力  
  
请直接与对应服务人员联系  
  
如需试用微步TDP 0day检测能力  
  
欢迎扫码联系我们  
  
↓  
↓↓  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Yv6ic9zgr5hSNsiaB3CrdGXic75CwlY6ib7dfarhpOsQO8WTLAv04umAibaXapic0BgKzpl9AFDTx4EPIcvOe8wwPS0w/640?wx_fmt=png "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Yv6ic9zgr5hTIdM9koHZFkrtYe5WU5rHxSDicbiaNFjEBAs1rojKGviaJGjOGd9KwKzN4aSpnNZDA5UWpY2E0JAnNg/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
400-030-1051  
  
  
  
· END ·  
  
  
点击下方名片，关注我们  
  
觉得内容不错，就点下  
“**赞**”和  
“**在看**”  
  
如果不想错过新的内容推送，可以设为**星标**  
![](https://mmbiz.qpic.cn/mmbiz_png/Yv6ic9zgr5hTYyCkc91euAiaGULJSbiaHricFHs2dd2sib20WTJKwHYD90Jia9HCKxnmJUwnkicGU7rVP3EYCVh3dMnng/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
哦  
  
