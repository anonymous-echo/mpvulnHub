#  TETRA:BURST：热门无线通信系统中存在5个新漏洞   
THN  代码卫士   2023-07-27 17:33  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Az5ZsrEic9ot90z9etZLlU7OTaPOdibteeibJMMmbwc29aJlDOmUicibIRoLdcuEQjtHQ2qjVtZBt0M5eVbYoQzlHiaw/640?wx_fmt=gif "")  
  
   
聚焦源代码安全，网罗国内外最新资讯！****  
  
**编译：代码卫士**  
  
**政府实体和关基行业广为使用的无线电通信陆地集群无线电 (TETRA) 标准中存在5个漏洞，其中包含被认为是故意预留的后门，可泄露敏感信息。**  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/oBANLWYScMTC64dm9d8xrebfJjKAGtg3N68cGWIN5Lbg6QUIwEmnVliatEqZ67vnsXKsVeNicNMxBQbu9Wib6REgw/640?wx_fmt=png "")  
  
  
这些漏洞由荷兰公司 Midnight Blue在2021年发现但一直到现在才发布，它们被统称为 “TETRA:BURST”。关于这些漏洞是否已遭在野利用，尚无定论。  
  
Midnight Blue 公司指出，“具体根据基础设施和设备配置的不同情况，这些漏洞可导致实时解密、先收割后解密 (harvest-now-decrypt-later) 攻击、信息注入、用户去匿名化或会话密钥 pinning。”  
  
TETRA 是由欧洲电信标准研究院 (ETSI) 在1995年确立的标准，用于100多个国家中，美国之外的一些国家将其用作军警无线电通信系统。它还用于控制重要系统如电力网、天然气管道和铁路。话虽如此，但WIRED报道称，TETRA的无线电预测用于至少二十多种位于美国的关键基础设施中，如多款电力设施、某州边控机构、一家炼油厂、多家化工厂、一家主要的大众运输系统、三个国际机场和一个美军训练基地。  
  
该系统由一系列机密的专有加密算法支撑，即用于认证和密钥分发的 TETRA 认证算法 (TAA1) 套件和用于空中接口加密 (AIE) 的 TETRA 加密算法 (TEA)，它们都是受到保密协议保护的商业机密。  
  
Midnight Blue 逆向工程 TAA1 和 TEA 后发现了五个严重性从低危到严重不等的漏洞，可导致“被动和主动对手发动实际的拦截和操纵攻击”：  
  
- CVE-2022-24400：位于认证算法中的漏洞，可导致攻击者将DCK设为0。  
  
- CVE-2022-24401：AIE 密钥流生成器依赖于网络时间，以未认证的方式被公开播报，可导致解密预言攻击。  
  
- CVE-2022-24402：TEA1 算法中存在一个后门，将原始的80比特密钥减少为可在数分钟内在消费者硬件上被暴力破解的密钥大小。  
  
- CVE-2022-24403：用于混淆无线电身份的加密方案中存在一个弱设计，可导致攻击者去匿名化并追踪用户。  
  
- CVE-2022-24404：AIE 尚缺乏加密文本认证，可导致延展性攻击。  
  
  
  
网络安全公司 Forescout 表示，“以上问题造成的影响高度依赖于 TETRA 的使用方式，如它是否传输语音或数据以及使用了哪种加密算法。”  
  
其中最严重的漏洞是CVE-2022-24401，在无需加密密钥的情况下可被用于暴露文本、语音或数据通信。CVE-2022-24402 是第二个严重程度最高的漏洞，可导致攻击者注入数据流量，监控和控制工业设备。该公司解释称，“解密该流量并注入恶意流量可导致攻击者实现拒绝控制/视图或操纵控制/视图，从而执行威胁行为如打开电动变电站中的断路器，导致类似于Industroyer 恶意软件那样的断电事故。”  
  
Midnight Blue 公司提到，“CVE-2022-24402 显然是故意造成的，其计算步骤的作用只是为了减少该密钥的有效熵”。  
  
但是ETSI 驳斥了“后门”的说法，表示“TETRA 安全标准是与国家安全局一起制定的，旨在并受限于削弱加密的出口管控。”  
  
  
代码卫士试用地址：  
https://codesafe.qianxin.com  
  
开源卫士试用地址：https://oss.qianxin.com  
  
  
  
  
  
  
  
  
  
  
  
  
**推荐阅读**  
  
[奇安信入选全球《静态应用安全测试全景图》代表厂商](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247516678&idx=1&sn=5b9e480c386161b1e105f9818b2a5a3d&chksm=ea94b36cdde33a7a05cafa9918733669252a02611c222b02bc6e66cbb508ee3fbf748453ee7a&scene=21#wechat_redirect)  
  
  
[奇安信入选全球《软件成分分析全景图》代表厂商](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247515374&idx=1&sn=8b491039bc40f1e5d4e1b29d8c95f9e7&chksm=ea948d84dde30492f8a6c9953f69dbed1f483b6bc9b4480cab641fbc69459d46bab41cdc4859&scene=21#wechat_redirect)  
  
  
[为躲避网络攻击船只欲“穿越”回二战无线电时代](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247485489&idx=2&sn=4f71e964b1c6006a9390b264837d3471&chksm=ea97395bdde0b04dc823bf8895f9b9a684554c3e7ff48724858ed872517e9a0bb88d5cbb18ff&scene=21#wechat_redirect)  
  
  
[黑客可利用无线电波通过Siri和Google Now劫持安卓和iPhone设备](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247485867&idx=3&sn=788d619de8f291fe142cf2c2af982f18&chksm=ea9738c1dde0b1d73f91c8c7351c0b20b3fb8b4a34053168d8e7d7764a5ed91e3f8c351eaa10&scene=21#wechat_redirect)  
  
  
  
  
**原文链接**  
  
https://thehackernews.com/2023/07/tetraburst-5-new-vulnerabilities.html  
  
  
题图：Pexels License  
  
  
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
  
