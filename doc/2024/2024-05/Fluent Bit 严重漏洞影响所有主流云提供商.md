#  Fluent Bit 严重漏洞影响所有主流云提供商   
SERGIU GATLAN  代码卫士   2024-05-21 17:32  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Az5ZsrEic9ot90z9etZLlU7OTaPOdibteeibJMMmbwc29aJlDOmUicibIRoLdcuEQjtHQ2qjVtZBt0M5eVbYoQzlHiaw/640?wx_fmt=gif "")  
  
   
聚焦源代码安全，网罗国内外最新资讯！  
  
**编译：代码卫士**  
  
****  
**Fluent Bit 中存在一个严重漏洞，可被用于拒绝服务和远程代码执行攻击中，影响所有主流云提供商和很多技术巨头。**  
  
  
Fluent Bit 是一款极其热门的日志和度量解决方案，适用于主流Kubernetes 发行版本内嵌的 Windows、Linux 和 macOS 系统，包括Amazon AWS、Google GCP 和Microsoft Azure 等。  
  
在2024年3月前，Fluent Bit的下载和部署次数超过130亿次，比2022年10月的30亿次下载量迅猛增加。许多网络安全企业如 CrowdStrike 和趋势科技以及很多技术公司如思科、VMware、Intel、Adobe 和戴尔等都在使用它。  
  
该严重漏洞的编号是CVE-2024-4323，被发现它的Tenable 研究员称为  “Linguistic Lumberjack”，是严重的内存损坏漏洞，在2.0.7版本中引入，是由 Fluent Bit 的嵌入式HTTP 服务器对追踪请求的解析中存在堆缓冲区溢出弱点引发的。  
  
尽管未认证攻击者可轻松利用该漏洞触发拒绝服务或远程捕获敏感信息，但他们也可在条件正确和时间足够的情况下利用该漏洞创建可靠利用，获得远程代码执行权限。Tenable 公司表示，“虽然此类堆缓冲区溢出漏洞已知可遭利用，但创建可靠利用不仅困难而且尤其耗时。研究人员认为最显而易见且最主要的风险是可实现拒绝服务和信息泄露后果。”  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/oBANLWYScMQXuPia5bPgkLvBRTicQPI1RIsXeBFudVvBEJ2C5FrgoK4RzibGY8HDtmjKIVa6cGroaF8k36lv53gcg/640?wx_fmt=gif&from=appmsg "")  
  
**补丁在 Fluent Bit 3.0.4中发布**  
  
  
  
  
  
研究员在4月30日报送漏洞，修复方案已在5月15日提交到 Fluent Bit的主分支中。包含该补丁的官方发布已在 Fluent Bit 3.0.4中交付。  
  
研究人员还在5月15日通过漏洞披露平台告知微软、亚马逊和谷歌。在所有受影响平台获得修复方案之前，建议用户通过限制对 Fluent Bit 监控API 访问以访问授权用户和服务的方式缓解该问题。如果该易受攻击的API端点不在使用状态，也可将其禁用，确保拦截任何潜在攻击并删除攻击面。  
  
  
****  
****  
代码卫士试用地址：  
https://codesafe.qianxin.com  
  
开源卫士试用地址：https://oss.qianxin.com  
  
  
  
  
  
  
  
  
  
  
  
**推荐阅读**  
  
[Linux 恶意软件攻击配置不当的云服务器](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247519011&idx=1&sn=17a70a9a2f2ffda628277cf2e0884282&chksm=ea94ba49dde3335f1ba768295ca8970e7a2a3d6080ee433e0eaa41f8b52859e0ae9f0acd6635&scene=21#wechat_redirect)  
  
  
[谷歌云修复影响 Kubernetes 服务的提权漏洞](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247518533&idx=1&sn=2cd4cf6cb64d8674ff01d4eb89b22c43&chksm=ea94b82fdde33139a30d7d743eee2c64a91f8291a4eba9f5bf73b936e2e833a01aebbabd7c9d&scene=21#wechat_redirect)  
  
  
[开源云软件 CasaOS 中存在两个严重漏洞](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247517920&idx=1&sn=681d0c6677cad099a71c676242ba72f4&chksm=ea94b78adde33e9cfd5d18cd2b56dca916c908ab7b190ab9985975c9146af878a0fe5d5b63bb&scene=21#wechat_redirect)  
  
  
[谷歌云 SQL Service 中存在严重漏洞，导致敏感数据遭暴露](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247516609&idx=1&sn=e6bef0b6cbbd3d38ef6d69c14130bdcc&chksm=ea94b0abdde339bd0efab5037b36b84212e32e77cb0a866ec8ea90ff15509d9afb7433ee96d5&scene=21#wechat_redirect)  
  
  
  
  
**原文链接**  
  
  
https://www.bleepingcomputer.com/news/security/critical-fluent-bit-flaw-impacts-all-major-cloud-providers/  
  
  
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
  
