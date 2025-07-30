#  Zimbra 紧急提醒手动修复已遭利用的0day   
Sergiu Gatlan  代码卫士   2023-07-14 17:21  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Az5ZsrEic9ot90z9etZLlU7OTaPOdibteeibJMMmbwc29aJlDOmUicibIRoLdcuEQjtHQ2qjVtZBt0M5eVbYoQzlHiaw/640?wx_fmt=gif "")  
  
   
聚焦源代码安全，网罗国内外最新资讯！****  
  
**编译：代码卫士**  
  
**今天，Zimbra 督促管理员手动修复已遭活跃利用于攻击 Zimbra Collaboration Suite (ZCS) 邮件服务器的 0day 漏洞。目前该漏洞尚未获得CVE编号。**  
  
ZCS 邮件服务器是使用广泛的邮件和协作平台，目前应用于全球140个国家的20多万个企业中，包括全球1000多个政府和金融组织机构。本周四，Zimbra 公司在安全公告中提醒称，“Zimbra Collaboration Suite 8.8.15版本中存在一个漏洞，可影响数据的机密性和完整性。修复方案计划在7月补丁发布中公布。”但该公司并未提到该漏洞已遭在野利用。  
  
该漏洞是一个反射型 XSS 漏洞，由谷歌威胁分析团队 (TAG) 的研究员 Clément Lecigne 发现并报告。作为 XSS 攻击的一部分，攻击者人员可窃取敏感的用户信息或者在易受攻击系统上执行恶意代码。  
  
虽然 Zimbra 公司并未透露该漏洞已遭利用，但谷歌TAG团队的研究员 Maddie Stone 批量称该漏洞是在一次针对性攻击中发现的。虽然 Zimbra 公司尚未发布安全补丁，但提供了管理员可手动应用以删除该攻击向量的修复方案。该公司指出，“要维护最高安全水平，我们建议您在所有邮箱节点上手动应用修复方案。”具体的缓解措施如下：  
  
1、备份文件 /opt/zimbra/jetty/webapps/zimbra/m/momoveto  
  
2、编辑该文件并到达第40行  
  
3、将参数值更新为 <input name="st" type="hidden" value="${fn:escapeXml(param.st)}"/>  
  
4、在更新前，该代码行为  <input name="st" type="hidden" value="${param.st}"/>。  
  
escapeXml() 函数将通过逃逸 XML 标记中使用的特殊字符阻止 XSS 缺陷来清理用户输入的数据。  
  
无需重启 Zimbra 服务即可部署该缓解措施。  
  
  
**Zimbra 服务器遭攻击**  
  
  
  
近年来，多个 Zimbra 漏洞遭在野利用以攻陷全球数百个易受攻击的邮件服务器，因此管理员应优先缓解该 0day 漏洞。  
  
例如，2022年6月，Zimbra 认证绕过和远程代码执行漏洞被用于攻陷1000多台服务器。从2022年9月开始，黑客开始滥用位于 Zimbra Collaboration Suite 中的未修复 RCE 漏洞，在两个月的时间里攻陷近900台易受攻击的服务器。Winter Vivern俄罗斯黑客组织自2023年2月利用另外一个反射型XSS漏洞攻击与北约政府有关的网络邮件门户并窃取属于官员、政府、军队人员和外交人员的邮箱。  
  
Zimbra 母公司 Synacor 的发言人暂未就此事置评。  
  
  
  
代码卫士试用地址：  
https://codesafe.qianxin.com  
  
开源卫士试用地址：https://oss.qianxin.com  
  
  
  
  
  
  
  
  
  
  
  
  
**推荐阅读**  
  
[奇安信入选全球《静态应用安全测试全景图》代表厂商](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247516678&idx=1&sn=5b9e480c386161b1e105f9818b2a5a3d&chksm=ea94b36cdde33a7a05cafa9918733669252a02611c222b02bc6e66cbb508ee3fbf748453ee7a&scene=21#wechat_redirect)  
  
  
[奇安信入选全球《软件成分分析全景图》代表厂商](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247515374&idx=1&sn=8b491039bc40f1e5d4e1b29d8c95f9e7&chksm=ea948d84dde30492f8a6c9953f69dbed1f483b6bc9b4480cab641fbc69459d46bab41cdc4859&scene=21#wechat_redirect)  
  
  
[黑客正在利用Zimbra ZCS中的未修复RCE漏洞](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247514145&idx=2&sn=de026e7969cb14c915002400434f0be1&chksm=ea94894bdde3005d4a094cd8e5125835831ac95a26d5e5666cca5c1b0300b99ce4e581210d69&scene=21#wechat_redirect)  
  
  
[UnRAR二进制中出现路径遍历缺陷，可导致在Zimbra上执行远程代码](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247512652&idx=1&sn=1f0239704b1c73ee0e257706adbbdb7b&chksm=ea948326dde30a30d018078b393ff08ad41338fe3d025707bd85876ba4871ec610ccf27fe747&scene=21#wechat_redirect)  
  
  
[开源邮件平台Zimbra 出现新漏洞，用户登录凭据可被盗](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247512333&idx=3&sn=8b2d3c40a59f28ad4ef19cca4e7de98c&chksm=ea948067dde3097194f650240489cdb2bfb2ee4a852e63ff960607da69af4ddc744d0a0e03d5&scene=21#wechat_redirect)  
  
  
[Zimbra 软件曝新漏洞，发送恶意邮件即可劫持Zimbra 服务器](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247506589&idx=3&sn=25f25b69bdec8f2533fce73ac56f0a5e&chksm=ea94ebf7dde362e1241e85a223c49542619a6898cbe740db046c3f938b8c59498d85f6f11fbf&scene=21#wechat_redirect)  
  
  
  
  
**原文链接**  
  
https://www.bleepingcomputer.com/news/security/zimbra-urges-admins-to-manually-fix-zero-day-exploited-in-attacks/  
  
  
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
  
