#  研究员发现 Akamai配置不当漏洞，获得4.6万美元奖励   
Emma Woollacott  代码卫士   2022-10-08 18:01  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Az5ZsrEic9ot90z9etZLlU7OTaPOdibteeibJMMmbwc29aJlDOmUicibIRoLdcuEQjtHQ2qjVtZBt0M5eVbYoQzlHiaw/640?wx_fmt=gif "")  
  
   
聚焦源代码安全，网罗国内外最新资讯！  
  
**编译：代码卫士**  
  
两名意大利研究员发现了一个Akamai 配置不当问题，获得超过4.6万美元的奖励。  
  
  
Akamai是当前世界上使用最广泛的内容交付网络 (CDNs) 之一，超过1000家企业都在使用它，如苹果、微软、Airbnb以及美国国防部等。  
  
研究员Jacopo Tediosi 和 Francesco Mariani 在通过漏洞奖励平台 Whitejar 使用Akamai 查找网站上的漏洞时发现了一个配置不当漏洞，可导致攻击者以任意内容投毒缓存。  
  
研究人员指出，该漏洞是常见HTTP走私和hop-by-hop标头滥用技术的结合。特殊标头 “hop-by-hop” 在将请求推送给下一个代理或目标之前，被从代理中删除。然而，将Content-Length标头指定为 “hop-by-hop” 导致Akamai Edge Nodes 将其删除。这就导致后续节点出现去同步化问题，这些后续节点将部分HTTP请求解读为单独的第二个新请求。第二个响应已排队，之后被发送给其它客户端或用户的请求响应中，从而导致HTTP走私漏洞。  
  
Tediosi表示，“攻击者可将恶意的任意内容插入Akamai网络的任意域名中，从而影响其主要客户如美国国防部、PayPal、Airbnb、Mastercard、PlayStation、微软、苹果等。这意味着它们可随意修改网站的外观和行为，也可导致用户浏览器在原始网站上执行非预设行为，就像用户在这样做一样。”  
  
**修复方案已发布**  
  
  
Akamai 通过阻止在 Connection 标头值中指定 Content-Length 关键词的方式修复了该漏洞，不过相关安全公告尚未发布。  
  
Tediosi 和 Mariani 在3月24日联系 Akamai 并安排协同披露，并在4月2日静默修复该漏洞。遗憾的是，在该流程开始时，研究员即被告知Akamai公司不提供任何漏洞奖励或其它奖励。  
  
不过，就在Akamai着手修复该漏洞时，这两名研究员决定尝试并从该公司的某些客户处获得了漏洞奖励。Tediosi表示，“这是唯一一种让我们的工作获得奖励的方式，因为Akamai未设立漏洞奖励计划。坦白而言我不愿意使用这种方式，但它确实起作用了而且让我们保持道德黑客的身份。我稍有担心的事，这种困难可能导致攻击者不报告所发现的漏洞，从而导致这些漏洞仍然存在web中，或者更糟糕的是漏洞可能在黑市售卖。”  
  
研究员因最初的研究成果，从Whitejar平台获得5000美元，虽然很多漏洞平台和组织机构如 Bugcrowd、微软和苹果公司等无法复现该漏洞，但是其他人乐意为此支付报酬：PayPal支付2.52万美元、Airbnb支付1.4875万美元、喜屋酒店支付4000美元、Valve支付750美元、Zomato支付450美元，以及高盛支付100美元。  
  
Tediosi表示，他认为使用hop-by-hop 标头进行走私可能也影响Akamai公司以外的实现，并值得进一步研究。另外，他建议称很可能也可绕过 Akamai发布的修复方案。  
  
  
****  
****  
  
代码卫士试用地址：  
https://codesafe.qianxin.com  
  
开源卫士试用地址：  
https://oss.qianxin.com  
  
  
  
  
  
  
  
  
  
  
  
  
**推荐阅读**  
  
[Akamai DNS 全球断网 谷歌等大批网站在线服务宕机](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247506536&idx=4&sn=7cf07663b1745b55c2a6c68a5be1612c&chksm=ea94eb02dde36214d4b2906eb0cd5016471959a9fb9f07d5846e80a64e072032d1640c209378&scene=21#wechat_redirect)  
  
  
[数据库配置不当，8.8亿条医疗记录遭泄露](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247508847&idx=2&sn=69fda91db14f44156bbda8c709543fd8&chksm=ea949205dde31b1380876edee60c97cca229f5f3ce33734d4a9ce744adcc15e3f2b001e582ea&scene=21#wechat_redirect)  
  
  
[微软低代码工具 Power Apps 配置不当，暴露3800万条数据记录](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247507370&idx=2&sn=8e34bbb16c6371589e7ada0ee17bc9c7&chksm=ea94ecc0dde365d6c0ca8adbfc44bbcb4be4d0912990df75daee2ef4803e305c5ad16828f6eb&scene=21#wechat_redirect)  
  
  
[Git 仓库配置不当 日产北美公司的源代码遭泄露](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247500006&idx=2&sn=a2c53f313742933a397fea09c2e61660&chksm=ea94f18cdde3789aea2cbe4004672d4f603cc97045039c5707dfd57882f2780871f02a3681cf&scene=21#wechat_redirect)  
  
  
  
  
**原文链接**  
  
https://portswigger.net/daily-swig/researchers-net-46k-for-akamai-misconfiguration-vulnerability  
  
  
题图：  
Pixabay License  
‍  
  
  
  
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
