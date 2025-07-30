#  速修复MOVEit Transfer 中的这个新0day！   
Ravie Lakshmanan  代码卫士   2023-06-12 18:22  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Az5ZsrEic9ot90z9etZLlU7OTaPOdibteeibJMMmbwc29aJlDOmUicibIRoLdcuEQjtHQ2qjVtZBt0M5eVbYoQzlHiaw/640?wx_fmt=gif "")  
  
   
聚焦源代码安全，网罗国内外最新资讯！****  
  
**编译：代码卫士**  
  
****  
**MOVEit Transfer 应用所属公司 Progress Software 发布补丁，修复影响该文件传输解决方案的全新 SQL 漏洞，该漏洞可导致敏感信息被盗。**  
  
  
  
  
Progress Software 公司在2023年6月9日发布的一份安全公告中提到，“MOVEit Transfer web 应用中存在多个SQL 注入漏洞，可导致未认证攻击者获得对 MOVEit Transfer 数据库的越权访问权限。攻击者可向 MOVEit Transfer 应用高端点提交构造的 payload，导致 MOVEit 数据库内容遭修改和披露。”  
  
这些缺陷影响 MOVEit Transfer 应用的所有版本，已在版本 2021.0.7 (13.0.7)、2021.1.5 (13.1.5)、2022.0.5 (14.0.5)、2022.1.6（14.1.6）和2023.0.2 (15.0.2) 中修复。所有 MOVEit Cloud 实例均已得到完全修复。  
  
该漏洞是由网络安全公司 Huntress 在代码审计过程中发现并报告的。Progress Software 表示尚未发现该漏洞遭在野利用的迹象。  
  
此前，MOVEit Transfer 漏洞 (CVE-2023-34362) 已被大量用于在目标系统上释放 web shell。该攻击活动被归咎于臭名昭著的 CI0p 勒索团伙，该团伙此前就发动数据盗取活动并在2020年12月起在多个管理文件传输平台中利用多个 0day。  
  
企业调查和风险咨询公司 Kroll 也发现证据表明，该犯罪团伙从2021年7月起就一直利用CVE-2023-34362漏洞，并至少从2022年4月开始利用多种方法从受陷的 MOVEit 服务器中提取数据。2021年7月的多种恶意侦查和测试活动从本质上来讲被指使手动执行，之后才在2022年4月转为自动机制，探测多种组织机构并收集信息。  
  
该公司表示，“CI0p 威胁组织机构在 GoAnywhere 事件发生时就完成了 MOVEit Transfer 利用，并选择先后而非并行执行这些攻击活动。这些研究成果说明重大规划和准备很可能推动大量利用事件。”  
  
CI0p 勒索团伙向受影响企业发布勒索通告，督促它们在2023年6月14日之前与其取得联系，否则将在数据泄露网站上发布所盗信息。  
  
  
代码卫士试用地址：  
https://codesafe.qianxin.com  
  
开源卫士试用地址：https://oss.qianxin.com  
  
  
  
  
  
  
  
  
  
  
  
  
**推荐阅读**  
  
[](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247511052&idx=3&sn=fb116392e405ae62e6c339117fffdb59&chksm=ea949d66dde31470758b6ee8f9dbecdb67ef6c0c8af277f26b83b60dbac95748d28db787a4b4&scene=21#wechat_redirect)  
[奇安信入选全球《软件成分分析全景图》代表厂商](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247515374&idx=1&sn=8b491039bc40f1e5d4e1b29d8c95f9e7&chksm=ea948d84dde30492f8a6c9953f69dbed1f483b6bc9b4480cab641fbc69459d46bab41cdc4859&scene=21#wechat_redirect)  
  
  
[MOVEit 文件传输软件0day被用于窃取数据](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247516660&idx=1&sn=bb8f16701a800011a7e9bc8857cd59d2&chksm=ea94b09edde33988e2fee2cb9c23d0031149201a1722cfabc8899b76b31016a44a835836d8a9&scene=21#wechat_redirect)  
  
  
[黑客早在2022年10月就利用0day 攻击 Barracuda ESG 设备](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247516628&idx=2&sn=eb96b9d65915efbbd1f1b4c2d593f8ee&chksm=ea94b0bedde339a888633e30fcb2b3c54d03a36f0627a8c4fbc37aa593420cfd86fd86d9dbf4&scene=21#wechat_redirect)  
  
  
[Barracuda 邮件网关遭 0day 漏洞利用攻击](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247516580&idx=2&sn=fee108ee4d61523b8dc544a5c1bfd2b8&chksm=ea94b0cedde339d822e3ed4ea277e795e733ad86df5ff4de2e3d1c97f16ea72d051b98a2395c&scene=21#wechat_redirect)  
  
  
[苹果修复3个已遭利用的新 0day](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247516531&idx=1&sn=71b3e940c482c53d52c592cdfe3992db&chksm=ea94b019dde3390fb1ecf3bd947eb8852a1f27e29e28f9c88b97d9bb2087840f62be6d882d4b&scene=21#wechat_redirect)  
  
  
  
  
**原文链接**  
  
  
https://thehackernews.com/2023/06/new-critical-moveit-transfer-sql.html  
  
  
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
  
