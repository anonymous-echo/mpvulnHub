#  补丁星期二：微软、Adobe和Firefox纷纷修复已遭利用的 0day 漏洞   
综合编译  代码卫士   2023-09-13 16:42  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Az5ZsrEic9ot90z9etZLlU7OTaPOdibteeibJMMmbwc29aJlDOmUicibIRoLdcuEQjtHQ2qjVtZBt0M5eVbYoQzlHiaw/640?wx_fmt=gif "")  
  
   
聚焦源代码安全，网罗国内外最新资讯！****  
  
**编译：代码卫士**  
  
**今天是微软9月补丁星期二，共修复59个漏洞，其中2个是已遭利用的 0day。Adobe 和Mozilla公司也发布安全更新，分别修复了已遭利用的一个 0day。**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/oBANLWYScMQbylDuVfFniawnNiaIbkhRp8iaBriadia9aNJicNP6dG4Lup91EEmlxRfbdCTemveIPnSKGia7wweeGTCww/640?wx_fmt=png "")  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/oBANLWYScMQbylDuVfFniawnNiaIbkhRp8iaBriadia9aNJicNP6dG4Lup91EEmlxRfbdCTemveIPnSKGia7wweeGTCww/640?wx_fmt=png "")  
  
**微软**  
  
  
  
本次微软共修复59个漏洞，其中：  
  
- 3个安全特性绕过漏洞  
  
- 24个远程代码执行漏洞  
  
- 9个信息泄露漏洞  
  
- 3个拒绝服务漏洞  
  
- 5个欺骗漏洞  
  
- 5个Edge-Chromium 漏洞  
  
  
  
已遭利用的两个0day 漏洞是：  
  
- CVE-2023-36802：微软 Streaming Service Proxy 提权漏洞。  
  
- CVE-2023-36371：微软Word 信息泄露漏洞，当打开文档时，攻击者可利用该漏洞窃取NTLM 哈希，而这些哈希可被破解或用于 NTLM 中继攻击中获取账户权限。预览面板也是攻击向量，意味着漏洞利用无需用户交互。  
  
  
  
值得关注的其它漏洞还包括：  
  
- CVE-2023-29332：微软Azure Kubernetes Service 提权漏洞。它可导致远程未认证攻击者获得 Cluster Administration 权限。虽然此类漏洞此前出现过，但该漏洞由于可从互联网访问，无需用户交互且利用复杂度低，因此该漏洞值得关注。虽然微软给定的评级是“利用可能性较低“，但基于远程未认证攻击者即可利用，因此对于攻击者而言诱惑力也很大。  
  
- CVE-2023-38148：Internet Connection Sharing (ICS) 远程代码执行漏洞。虽然该漏洞的CVSS评分为8.8，但好在它仅限于网络临近攻击者，而且成功利用也需要启动ICS，可导致攻击者在受影响系统上运行代码。  
  
- CVE-2023-38146：Windows Themes 远程代码执行漏洞。该漏洞可能并非本月修复的最严重漏洞之一，但却引发一波回忆杀。如果攻击者可说服用户打开特别构造的主题文件，则可实现代码执行后果。如果听起来就像20多年前的屏保程序漏洞，确实如此。而这要多亏Pwn2Own 大赛获胜者 Thijs Alkemade 和 Daan Keuper 的努力，才让它出现在我们面前。  
  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/oBANLWYScMQbylDuVfFniawnNiaIbkhRp8iaBriadia9aNJicNP6dG4Lup91EEmlxRfbdCTemveIPnSKGia7wweeGTCww/640?wx_fmt=png "")  
  
**Adobe 修复已遭利用0day**  
  
  
  
Adobe 公司发布安全更新，修复了位于 Acrobat 和 Reader 中的一个 0day 漏洞CVE-2023-26369，虽然目前尚未发布详情，但已知情况是该漏洞同时影响 Windows 和 macOS 系统。  
  
攻击者在成功利用一个界外写漏洞后，可利用该漏洞获得代码执行权限。Adobe 将该漏洞的评级为满分，并强烈建议管理员尽快在72小时时间窗口内修复该漏洞。该漏洞影响的产品如下：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/oBANLWYScMQbylDuVfFniawnNiaIbkhRp8Tf16RaSCxnPVgy4beqhXZ7pLTud76ntNeIQaUFFCEr7J08DBVbhyLg/640?wx_fmt=png "")  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/oBANLWYScMQbylDuVfFniawnNiaIbkhRp8iaBriadia9aNJicNP6dG4Lup91EEmlxRfbdCTemveIPnSKGia7wweeGTCww/640?wx_fmt=png "")  
  
**Mozilla 紧急修复Firefox 中的已遭利用0day**  
  
  
  
Mozilla 公司紧急修复了一个已遭在野利用的严重漏洞CVE-2023-4863。该漏洞影响 Firefox 浏览器和 Thunderbird 邮件客户端。该漏洞是由位于 WebP 代码库 (libwebp) 中的堆缓冲溢出漏洞引发的，可导致设备崩溃、任意代码执行等后果。  
  
Mozilla 公司已在 Firefox 117.0.1、Firefox ESR 115.2.1、Firefox ESR 102.15.1、Thunderbird 102.15.1和 Thunderbird 115.2.2中修复该漏洞。虽然关于该漏洞的具体详情尚未披露，但该漏洞已在真实场景中遭利用。因此强烈建议用户更新至Firefox 和 Thunderbird 最新版本，使系统免遭攻击。  
  
Mozilla 还表示该漏洞还影响使用易受攻击 WebP 代码库版本的其它软件，其中之一就是谷歌 Chrome 浏览器。Chrome 浏览器将在数天或数周内向所有用户推送补丁。  
  
  
代码卫士试用地址：  
https://codesafe.qianxin.com  
  
开源卫士试用地址：https://oss.qianxin.com  
  
  
  
  
  
  
  
  
  
  
  
  
**推荐阅读**  
  
[谷歌紧急修复已遭利用的 Chrome 0day](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247517626&idx=1&sn=516906d0d9c95466942c198e8b3644eb&chksm=ea94b4d0dde33dc68afa3a330f73b5e599c28832120edd5bd8f61ef250cf8d2ea50d208b5591&scene=21#wechat_redirect)  
  
  
[苹果紧急修复两个已遭利用的 0day](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247517599&idx=1&sn=f4c64820b9383523f48091354491d150&chksm=ea94b4f5dde33de3f2f7c7d26b6bc5178d7deb13b62b5e3b5220b9ad188751bce855b427f00b&scene=21#wechat_redirect)  
  
  
[Rapid7 2023年中威胁局势回顾：勒索攻击ROI仍高居不下；0day 漏洞利用规模扩大](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247517476&idx=1&sn=0c931ea491e1ceec5bc4d0c6633d9fea&chksm=ea94b44edde33d587886a4ead4f7e7be77d88f83456be4274728de062d3cbe95501c219bff65&scene=21#wechat_redirect)  
  
  
[Ivanti 紧急修复 API 认证绕过0day漏洞](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247517421&idx=1&sn=31756dd565b1bbd216e954def83c61dc&chksm=ea94b587dde33c91e83a737ae3eb0a14c48a427523b94dba12823b03eac1cecf97a890e21afa&scene=21#wechat_redirect)  
  
  
[谷歌紧急修复已遭利用的 Chrome 0day](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247517626&idx=1&sn=516906d0d9c95466942c198e8b3644eb&chksm=ea94b4d0dde33dc68afa3a330f73b5e599c28832120edd5bd8f61ef250cf8d2ea50d208b5591&scene=21#wechat_redirect)  
  
  
[微软7月补丁星期二修复132个漏洞：5个已遭利用0day且1个无补丁](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247517016&idx=1&sn=5074282ae6c24bac3355b40d1cabb8fa&chksm=ea94b232dde33b24e9adff41dd364497012cd4fe06f43ac2e6579c5f297ce1443c3c745b757b&scene=21#wechat_redirect)  
  
  
[洞少事大：微软5月补丁星期二需关注的漏洞](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247516449&idx=1&sn=17fb3428de6050c5e0ce8daaa751c406&chksm=ea94b04bdde3395de1c91c780a8796919fd059dce25c7d3ae460bbf340057ec40a3581920c4d&scene=21#wechat_redirect)  
  
  
  
  
**原文链接**  
  
https://www.bleepingcomputer.com/news/microsoft/microsoft-september-2023-patch-tuesday-fixes-2-zero-days-59-flaws/  
  
https://www.bleepingcomputer.com/news/security/adobe-warns-of-critical-acrobat-and-reader-zero-day-exploited-in-attacks/  
  
https://www.zerodayinitiative.com/blog/2023/9/12/the-september-2023-security-update-review  
  
https://www.bleepingcomputer.com/new  
s/security/mozilla-patches-firefox-thunderbird-against-zero-day-exploited-in-attacks/  
  
  
  
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
  
