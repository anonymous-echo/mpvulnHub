#  Apache MINA 存在严重的满分漏洞，可导致RCE   
DO SON  代码卫士   2024-12-27 06:36  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Az5ZsrEic9ot90z9etZLlU7OTaPOdibteeibJMMmbwc29aJlDOmUicibIRoLdcuEQjtHQ2qjVtZBt0M5eVbYoQzlHiaw/640?wx_fmt=gif "")  
  
   
聚焦源代码安全，网罗国内外最新资讯！  
  
**编译：代码卫士**  
  
**用于构建高性能和可口站网络应用的热门网络应用框架 Apache MINA 中存在一个严重漏洞，CVE-2024-52046，CVSS评分为满分10分，可导致攻击者在易受攻击系统上执行任意代码。用户应立即修复该漏洞。**  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/oBANLWYScMShMvJUCBxV63DZqqPgME879htCYRHcn9onALVibcAOn5ibee2RHD8iaeHb70CTwX7g5Kp8XmREfBQNQ/640?wx_fmt=png&from=appmsg "")  
  
  
  
Apache MINA 因供端口如TCP/IP和UDP/IP等简化网络编程的抽象的事件驱动异步API而为人所知，它广泛用于多种应用中。然而，ObjectSerializationDecoder 组件中的漏洞可遭恶意利用。该解码器通过Java的原生反序列化来处理序列化数据，缺乏重要的安全检查。  
  
该问题的根因在于易受攻击的MINA版本处理对象反序列化的方式。如果没有正确的防御措施，攻击者可发送特殊构造的恶意序列化数据，而当该数据由 ObjectSerializationDecoder 处理时，可导致远程代码执行 (RCE) 后果。这意味着攻击者可能完全控制受影响系统。  
  
该漏洞影响大量 Apache MINA 版本，尤其是：  
  
- Apache MINA 2.0.0至2.0.26  
  
- Apache MINA 2.1.0至2.1.9  
  
- Apache MINA 2.2.0至2.2.3  
  
  
  
值得注意的是，并非所有使用MINA的应用都自动易受攻击。当应用使用 IoBuffer#getObject() 方法时就会引发风险。当使用 ObjectSerializationCodecFactory 类的 ProtocolCodecFilter 实例被加入过滤器链时，该方法可能会被调用。如果应用程序依赖于这些特定的类和方法，则用户可能遭暴露且必须立即采取措施。  
  
Apache MINA 团队已迅速修复了该严重漏洞。如下为已修复版本：  
  
- Apache MINA 2.0.27  
  
- Apache MINA 2.1.10  
  
- Apache MINA 2.2.4  
  
  
  
不过，只升级版本是不够的。已更新版本引入了一个重要的安全增强措施：开发人员必须明确定义 ObjectSerializationDecoder 允许序列化的类。可通过如下三个新方法实现：  
  
- accept(ClassNameMatcher classNameMatcher)  
  
- accept(Pattern pattern)  
  
- accept(String… patterns)  
  
  
  
在默认情况下，该解码器将拒绝所有类，主要是以“拒绝所有”原则为准，除非已获得明确允许。这就增加了一个重要的控制层，组织不可信和潜在恶意对象的反序列化。  
  
Apache MINA 团队已澄清指出，FtpServer、SSHd和Vysper 子项目并不受该漏洞影响。  
  
****  
代码卫士试用地址：  
https://codesafe.qianxin.com  
  
开源卫士试用地址：https://oss.qianxin.com  
  
  
  
  
  
  
  
  
  
  
  
  
  
**推荐阅读**  
  
[Apache Tomcat 漏洞导致服务器易受RCE攻击](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247521893&idx=1&sn=867f98595849107577a98fcaf043a177&scene=21#wechat_redirect)  
  
  
[Apache修复 Struts 2 中的严重 RCE 漏洞](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247521787&idx=1&sn=aa7443d590ca0182f0cbd4386c81152a&scene=21#wechat_redirect)  
  
  
[Apache Avro SDK 中存在严重漏洞，可导致在 Java 应用中实现RCE](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247520994&idx=1&sn=0feb249fd14e6b8b07d5d6531f3287c2&scene=21#wechat_redirect)  
  
  
[CISA 提醒注意已遭利用的 Apache HugeGraph-Server 漏洞](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247520886&idx=1&sn=d50fe47ebc8b4ad640aab8d8ead453e4&scene=21#wechat_redirect)  
  
  
[Apache 修复严重的 OFBiz 远程代码执行漏洞](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247520714&idx=2&sn=a3784b5b2245f1449edaefa3064d676f&scene=21#wechat_redirect)  
  
  
  
  
  
**原文链接**  
  
  
https://securityonline.info/cve-2024-52046-cvss-10-critical-apache-mina-flaw-could-allow-remote-code-execution/  
  
  
题图：  
Pexels   
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
  
