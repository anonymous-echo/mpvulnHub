#  19个月之后，博通终于修复了这些 SANnav漏洞   
Steve Zurier  代码卫士   2024-04-26 17:25  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Az5ZsrEic9ot90z9etZLlU7OTaPOdibteeibJMMmbwc29aJlDOmUicibIRoLdcuEQjtHQ2qjVtZBt0M5eVbYoQzlHiaw/640?wx_fmt=gif "")  
  
   
聚焦源代码安全，网罗国内外最新资讯！  
  
**编译：代码卫士**  
  
**安全研究员 Pierre Barre 指出，经过19个月与博通就 SANnav 管理应用中的多个漏洞进行沟通后，博通终于在今年4月份修复了这些漏洞，距离首次证实漏洞已过去了11个月。**  
  
  
  
Barre 在一篇博客文章中指出，在所发现的18个漏洞中，3个可导致攻击者发送恶意数据并拦截以明文形式拦截的凭据，从而攻陷整个 SANnav Fibre Channel 基础设施。  
  
SecurityWeek媒体报道称，第一个漏洞存在的原因是 SANnav 虚拟即缺乏正确的安全措施，包括默认防火墙等，从而可能导致攻击者触及 Apache Kafka 事件流平台的API。其它两个问题是因将HTTP用作HTTPS被拦截情况下的管理协议以及系统日志流量以明文形式发送引发。  
  
DoControl 公司的产品副总裁 Guy Rosenthal 指出，“Brocade（博通在2017年将其收购）的工程团队存在自身安全问题，他们并未给产品打补丁以及在首次登录时强制更改密码、技术不安全如HTTP以明文形式发送信息、不具备配置好的防火墙、在用户账户中留后门等。因此攻击易于执行且易于避免。”  
  
Barre 解释称，他最初在2022年9月通过戴尔将安全评估结果发给 Brocade 支持团队，但遭 Brocade 拒绝，因为当时并未修复最新版本的 SANnav。Barre 写道，“很幸运，我在2023年5月获得对SANnav 最新版本的访问权限，并证实所有此前被拒绝的漏洞仍然存在。另外，我还在更新报告时找到了其它三个0day漏洞。”证实所有漏洞皆存在的更新报告在2023年5月发送给 Brocade 产品安全事件响应团队 (PSIRT)，后者最终承认并修复了这些漏洞。  
  
Critical Start 公司的高级威胁研究经历 Callie Guenther 提到，“延迟发布 SANnav 设备漏洞补丁的原因有多个。首先，从多样性和严重性方面来讲，这些漏洞较为复杂，要求投入大量时间开发有效补丁。这些补丁必须足够健壮，不能中断现有部署或引入新漏洞。”他提到资源分配可能影响了修复时间。从厂商的优先级和可用资源来看，修复这些漏洞可能不会一蹴而就，尤其是当这些漏洞最初被低估的时候。最后，他认为广泛验证和测试至关重要：它能够保证有效补丁且不会引发更多问题，尤其是在如SAN管理这样复杂的环境中更是如此。他提到，“全面的测试流程可能也是导致补丁发布延迟的原因之一。”  
  
  
代码卫士试用地址：  
https://codesafe.qianxin.com  
  
开源卫士试用地址：https://oss.qianxin.com  
  
  
  
  
  
  
  
  
  
  
  
  
**推荐阅读**  
  
[博通Brocade漏洞影响多家大厂的存储解决方案](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247512679&idx=2&sn=59d6ec9653aaf6de0cfe4f624fe39695&chksm=ea94830ddde30a1b240c47dd7ca7dba361eef098dba1a723363510aee0f8b42df1d2234a6ae5&scene=21#wechat_redirect)  
  
  
[博通芯片中间件被曝严重漏洞，数亿台电缆调制解调器易受攻击](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247492127&idx=2&sn=6f7791b8fdc89cb105374f0bd46f485a&chksm=ea94d375dde35a63b29a40c47bc0f74fe56f47edc647ad36d2a6911c8d9705c9cdb1d1f54523&scene=21#wechat_redirect)  
  
  
[安全抢先知|YouTube 禁发黑客教学视频；博通或收购赛门铁克; D-Link 和 FTC 和解](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247490360&idx=2&sn=5a04d63d53632df9168c4a4d4da98576&chksm=ea972a52dde0a3440a013892cd382bd724940a9086817af3a1f5c81d8bebe4910ff8b174ad91&scene=21#wechat_redirect)  
  
  
[华为苹果三星等均受影响：博通 WiFi 驱动被曝漏洞，可导致 RCE 和 DoS](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247489762&idx=2&sn=74a7aa82de7def2e844ab6dff1b8d8ff&chksm=ea972988dde0a09ea4b42144f922c135a00541345ddaec391449eab29d100efd6db339677bfc&scene=21#wechat_redirect)  
  
  
[博通高通收购尚未达成 美国政府国安调查先行但意在中国？](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247486615&idx=2&sn=9b621111b19ab7d137cb964307dd8b34&chksm=ea973dfddde0b4ebd4f0e695d49573d4dfcc3183770fb4241dc4e61520bcf0f0a788e9b630d9&scene=21#wechat_redirect)  
  
  
  
  
  
**原文链接**  
  
  
https://www.scmagazine.com/news/after-a-19-month-saga-broadcom-finally-patches-brocade-sannav-bugs  
  
  
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
  
