#  Apache Ivy 注入漏洞可导致攻击者提取敏感数据   
 代码卫士   2023-08-23 18:56  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Az5ZsrEic9ot90z9etZLlU7OTaPOdibteeibJMMmbwc29aJlDOmUicibIRoLdcuEQjtHQ2qjVtZBt0M5eVbYoQzlHiaw/640?wx_fmt=gif "")  
  
   
聚焦源代码安全，网罗国内外最新资讯！****  
  
**编译：代码卫士**  
  
  
**Apache Ivy 中存在一个 XPath 盲注漏洞，可导致攻击者提取数据并访问仅限运行 Apache Ivy 的机器访问的敏感信息。**  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/oBANLWYScMTBuxyicQbZX3tSS9tjia3WY9QLfrhwqYKwkL4x3s9APkaXKXibvg4jcI4fKEianV3zwCEgt4pSPGM4BQ/640?wx_fmt=png "")  
  
  
该漏洞位于 Apache Ivy 2.5.2以下版本中，当解析自身配置 Maven POMs时同时解析 XML 文件时就会触发，可导致外部文档下载和扩展任何实体引用。威胁行动者可利用该 XPath 盲注漏洞以不同方式操纵和执行 Ivy 或访问机器中的敏感信息。该漏洞是因为对XML外部实体引用的限制不当造成的。  
  
Apache Ivy 是一款依赖管理器，负责解析项目依赖且是 Apache Ant 项目的一部分，通过使用 XML 文件定义项目依赖，列出构建项目的必要资源。该漏洞的CVE编号是CVE-2022-46751，CVSS 评分尚未给出。  
  
  
**Apache Ivy 2.5.2 版本发布**  
  
  
  
在 Aapche Ivy 版本2.5.2 之前，Apache Ivy 在解析 Maven POMs 和其它文件时都会进行DTD 处理。不过，新发布的Apache Ivy 2.5.2 版本已为除了 Maven POMs 以外的所有文件禁用了DTD 处理，仅允许包含用于处理现有 Maven POMs 的DTD 片段。  
  
它们并非合法的 XML 文件但获得 Maven POMs 接受。Apache Ivy 是 Apache Ant 项目的一部分，负责自动化源自 Apache Tomcat 项目2000软件构建流程。  
  
建议用户升级至最新版本Apache Ivy 2.5.2 来阻止漏洞遭利用。或者用户可使用 Java 系统属性来限制对外部DTD的处理。  
  
  
  
代码卫士试用地址：  
https://codesafe.qianxin.com  
  
开源卫士试用地址：https://oss.qianxin.com  
  
  
  
  
  
  
  
  
  
  
  
  
**推荐阅读**  
  
[未修复的 Apache Tomcat 服务器传播 Mirai 僵尸网络恶意软件](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247517295&idx=1&sn=7f61402b12fbd46cb399a19ff93ca28e&chksm=ea94b505dde33c13b5e70aa9fdbdf02fc8dc58ac05568e19c5af6385458348da2464e9fa4c8b&scene=21#wechat_redirect)  
  
  
[Apache Jackrabbit 中存在严重的RCE漏洞](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247517243&idx=3&sn=aec30860da6f2a9d9af2ea532a32b258&chksm=ea94b551dde33c4713eeba8084b8b9a9eff3f5fb6ef34ea6ac25267f911bc21fd317e9ca8c8d&scene=21#wechat_redirect)  
  
  
[Apache Superset 会话验证漏洞可导致攻击者访问未授权资源](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247516346&idx=2&sn=c84ae42d9a4eab4b30b8eba4a27130a5&chksm=ea94b1d0dde338c6da3cc189e548d10cc3511c1ef2d59f067bd428a6efae2df174b66c93b0f6&scene=21#wechat_redirect)  
  
  
[【已复现】Apache Kafka Connect JNDI注入漏洞(CVE-2023-25194)安全风险通告](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247515512&idx=2&sn=e98e47bd34da117cc9f366253220df47&chksm=ea948c12dde30504b800504eae806ba06d26ac8b0598b1bc3e9808c2574a3161a52d5a6e6edf&scene=21#wechat_redirect)  
  
  
[在线阅读版：《2023中国软件供应链安全分析报告》全文](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247517225&idx=1&sn=8154b433ae2be87ccbae15bc0fb09a00&chksm=ea94b543dde33c55c168c44e830d62b03e9b34ca072871d10156273a3f282cab7ccc42b9b430&scene=21#wechat_redirect)  
  
  
[奇安信入选全球《静态应用安全测试全景图》代表厂商](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247516678&idx=1&sn=5b9e480c386161b1e105f9818b2a5a3d&chksm=ea94b36cdde33a7a05cafa9918733669252a02611c222b02bc6e66cbb508ee3fbf748453ee7a&scene=21#wechat_redirect)  
  
  
[奇安信入选全球《软件成分分析全景图》代表厂商](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247515374&idx=1&sn=8b491039bc40f1e5d4e1b29d8c95f9e7&chksm=ea948d84dde30492f8a6c9953f69dbed1f483b6bc9b4480cab641fbc69459d46bab41cdc4859&scene=21#wechat_redirect)  
  
  
  
  
**原文链接**  
  
https://gbhackers.com/apache-ivy-injection-flaw/  
  
  
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
  
