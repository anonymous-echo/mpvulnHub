#  开源BI分析工具 Metabase 中存在远程代码执行漏洞，未完全修复   
综合编译  代码卫士   2023-07-28 18:20  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Az5ZsrEic9ot90z9etZLlU7OTaPOdibteeibJMMmbwc29aJlDOmUicibIRoLdcuEQjtHQ2qjVtZBt0M5eVbYoQzlHiaw/640?wx_fmt=gif "")  
  
   
聚焦源代码安全，网罗国内外最新资讯！****  
  
**编译：代码卫士**  
  
**在商业情报 (BI) 领域，开源工具 Metabase 以无缝的数据解释能力占据一席之地。该自助服务BI工具已用于全球各地的组织机构中，赋能用户提出数据问题并获得可视化的、易于理解的答案。Metabase 的设计对用户友好，无需了解SQL或其它编程语言的知识，扩宽了组织机构中的可用性。**  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/oBANLWYScMSia4VIgUfejar5Z08pmwjcXcYcgWeYMsCrneZUqatpD1H5NOfH8ILiaBYqRRykn5I0n0P0uEiaPEL9g/640?wx_fmt=gif "")  
  
  
Metabase 与多种数据来源相连，如关系数据库、云存储和平面文件等，展现出其灵活性。一旦数据来源被限，用户可使用未编译的拖拽界面创建查询，使 Metabase 能够创建数据可视化如图表、图形和表格。  
  
功能强大的Metabase 中被指存在一个非常严重的漏洞CVE-2023-38646，可导致未认证攻击者以与 Metabase 服务器相同的权限执行任意命令。该漏洞意味着 Metabase 可成为恶意攻击的潜在入口点，从而攻陷所运营系统的完整性。  
  
该漏洞对Metabase 社区版和企业版的几个版本也带来影响。受影响的社区版为 0.43 到0.46，而企业版的受影响版本是1.43到1.46。不过它们也有不受影响的版本：社区版0.43.7.2及后续版本以及企业版1.43.7.2及后续版本。  
  
强烈建议用户立即升级至不受影响的 Metabase 版本。该漏洞可导致攻击者利用并攻陷系统，从而导致重大的数据泄露事故以及业务运营被中断。  
  
另外，有安全研究员表示，Metabase 并未将已修复代码发布在开源仓库中，因此使用 Metabase 开源版本的用户仍然易受攻击。  
  
  
  
代码卫士试用地址：  
https://codesafe.qianxin.com  
  
开源卫士试用地址：https://oss.qianxin.com  
  
  
  
  
  
  
  
  
  
  
  
  
**推荐阅读**  
  
[奇安信入选全球《静态应用安全测试全景图》代表厂商](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247516678&idx=1&sn=5b9e480c386161b1e105f9818b2a5a3d&chksm=ea94b36cdde33a7a05cafa9918733669252a02611c222b02bc6e66cbb508ee3fbf748453ee7a&scene=21#wechat_redirect)  
  
  
[奇安信入选全球《软件成分分析全景图》代表厂商](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247515374&idx=1&sn=8b491039bc40f1e5d4e1b29d8c95f9e7&chksm=ea948d84dde30492f8a6c9953f69dbed1f483b6bc9b4480cab641fbc69459d46bab41cdc4859&scene=21#wechat_redirect)  
  
  
[谷歌警示自家员工：别使用Bard 生成的代码](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247516769&idx=2&sn=4714ae37829a0d86ecc67fac45cde3fa&chksm=ea94b30bdde33a1dfa036205c64ef8ce7aa81a5958ce4c9fce8ec8a15cba40097e098fd45644&scene=21#wechat_redirect)  
  
  
[谷歌为 Chrome 沙箱逃逸利用链提供三倍赏金](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247516649&idx=1&sn=4e785a24db31c0a5ba6444f993a7c15e&chksm=ea94b083dde339956da54b6ff9b4036c037a976bad07e12c44d2db445eef51db0ed4c00ef820&scene=21#wechat_redirect)  
  
  
[谷歌云 SQL Service 中存在严重漏洞，导致敏感数据遭暴露](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247516609&idx=1&sn=e6bef0b6cbbd3d38ef6d69c14130bdcc&chksm=ea94b0abdde339bd0efab5037b36b84212e32e77cb0a866ec8ea90ff15509d9afb7433ee96d5&scene=21#wechat_redirect)  
  
  
[谷歌推出安卓应用奖励计划，最高赏金3万美元](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247516557&idx=1&sn=c5b0b33ec535dbef4720e3ee78d2af0a&chksm=ea94b0e7dde339f157a4a05676f75b42a307ecc12eaeddf553d77f0763783564b7f1d2ff9376&scene=21#wechat_redirect)  
  
  
[别慌！谷歌推出顶级域名 .zip 和 .mov](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247516545&idx=2&sn=027866140a8270ccf02c68bba02524df&chksm=ea94b0ebdde339fd94a432a91b6d0ce08b043432ef020df771a1aac76904e15151c230c7808f&scene=21#wechat_redirect)  
  
  
  
  
**原文链接**  
  
https://securityonline.info/cve-2023-38646-remote-command-execution-vulnerability-in-metabase/  
  
  
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
  
