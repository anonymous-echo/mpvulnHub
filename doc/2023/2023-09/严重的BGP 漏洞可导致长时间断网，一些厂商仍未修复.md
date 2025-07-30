#  严重的BGP 漏洞可导致长时间断网，一些厂商仍未修复   
Eduard Kovacs  代码卫士   2023-08-31 17:33  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Az5ZsrEic9ot90z9etZLlU7OTaPOdibteeibJMMmbwc29aJlDOmUicibIRoLdcuEQjtHQ2qjVtZBt0M5eVbYoQzlHiaw/640?wx_fmt=gif "")  
  
   
聚焦源代码安全，网罗国内外最新资讯！****  
  
**编译：代码卫士**  
  
**本周二，一名研究员提醒称，多种重要的边界网关协议 (BGP) 实现受一个严重漏洞影响，可使互联网处于长时间断网状态。然而，一些厂商仍未修复该漏洞。**  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/oBANLWYScMTzkQRvRWAYrT8nlXhtgKef45RagEsjL0ZAIbJqP6qTSNC7pKu36nhOjR4ia9R7WsBlhy34tkBae2g/640?wx_fmt=png "")  
  
  
该漏洞由BGP 解决方案公司 BGP.Tools 公司的所有人 Ben Cox 发现。BGP 是用于在互联网上自主系统之间交换路由信息的网关协议。BGP 劫持和泄露可用于将用户重定向至任意站点或引发严重的破坏。  
  
BGP 交换 UPDATE 信息来广告路由信息，包括IP段以及提供额外上下文的属性。Cox 发现的这个问题与这些属性以及处理这些属性的 BGP 实现能力有关。具体而言，如果路由器不理解属性，则可能在没有影响的情况下将其传递，但如果理解属性且属性被损坏，则会触发错误，BGP 会话关闭，阻止受影响网络与余下互联网进行通信。  
  
Cox 在博客文章中解释称，“通过某些合理教育构造的 payload，有人可设计以无害方式在互联网‘旅行’的 BGP UPDATE，直到它触及目标厂商并导致厂商重置会话。如果该数据源自为网络提供更广阔互联网访问权限的 BGP 连接，则可导致网络从互联昂断开。”  
  
Cox 还提到，“这种攻击甚至并非一次性的‘撞击’，因为‘恶意’路由仍然存储在端路由器中；当会话重启，与所构造payload 的路由再次传输时，受害者路由器将再次重置，从而可能导致断网时间延长。”  
  
该问题并非只是理论问题。Cox 是在巴西一家小网络厂商于6月初披露互联网路由含有损坏属性，从而导致其它网络遭严重破坏后开始对该问题进行研究。  
  
Cox 创建了一个基本的模糊测试工具，测试多种 BGP 实现是否受影响，结果发现，MikroTik、Ubiquiti、Arista、华为、思科和 Bird 并不受影响。Juniper Networks 公司的 Junos OS、诺基亚的 SR-OS、Extreme Networks 公司的 EXOS、OpenBSD 公司的 OpenBGPd 以及 FRRouting 受影响。  
  
Cox 将这项研究成果告知受影响厂商，但表示只有 OpenBSD (CVE-2023-38283) 迅速退出补丁。Juniper 和 FRR 公司的开发人员分别分配了编号CVE-2023-4481和CVE-2023-3882，但并未修复该漏洞。诺基亚和 Extreme 显然并未打算修复该漏洞。  
  
不过，组织机构仍可采取多项措施应对。Cox 发现厂商拒绝提醒客户后，建议他们执行一些缓解措施。Cox 表示厂商披露流程大费周章且令人沮丧。他提到，“如果报告安全漏洞的目标是降低对客户的伤害，我认为向供应商报告问题并不具备足够影响且不值得做，结果只是让个人失去了时间和理智。”  
  
****  
代码卫士试用地址：  
https://codesafe.qianxin.com  
  
开源卫士试用地址：https://oss.qianxin.com  
  
  
  
  
  
  
  
  
  
  
  
  
**推荐阅读**  
  
[谷歌不慎劫持BGP路由导致日本断网约1小时](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247485478&idx=2&sn=3b5388e0f5981b1a7838003e73650a8d&chksm=ea97394cdde0b05a5e4fb2086bae12683b027cadf09e22603da6d6d8d88a9345a8d1e54fb2f3&scene=21#wechat_redirect)  
  
  
[因电信设备短缺，俄罗斯面临互联网服务中断风险](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247511152&idx=2&sn=12f27be84395e4d1214dd67c00ea57b3&chksm=ea949d1adde3140c21802c4823d493bdae9d77d48e91e4af32662aa9f6761313e7d00e1443a6&scene=21#wechat_redirect)  
  
  
[Akamai DNS 全球断网 谷歌等大批网站在线服务宕机](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247506536&idx=4&sn=7cf07663b1745b55c2a6c68a5be1612c&chksm=ea94eb02dde36214d4b2906eb0cd5016471959a9fb9f07d5846e80a64e072032d1640c209378&scene=21#wechat_redirect)  
  
  
[CISA：企业断网3到5天，赶走网络中的 SolarWinds 黑客](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247504260&idx=2&sn=32c7f97b8827411a5c108d939278913f&chksm=ea94e0eedde369f8dd16525e8e241688760f741dfadeb746526bdc245a5af85a934c352d1e25&scene=21#wechat_redirect)  
  
  
[谷歌不慎劫持BGP路由导致日本断网约1小时](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247485478&idx=2&sn=3b5388e0f5981b1a7838003e73650a8d&chksm=ea97394cdde0b05a5e4fb2086bae12683b027cadf09e22603da6d6d8d88a9345a8d1e54fb2f3&scene=21#wechat_redirect)  
  
  
  
  
**原文链接**  
  
https://www.securityweek.com/bgp-flaw-can-be-exploited-for-prolonged-internet-outages/  
  
  
题图：  
Pixabay  
 License  
  
****  
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
  
