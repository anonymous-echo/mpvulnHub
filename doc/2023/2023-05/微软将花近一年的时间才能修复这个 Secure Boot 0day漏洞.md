#  微软将花近一年的时间才能修复这个 Secure Boot 0day漏洞   
 代码卫士   2023-05-12 17:37  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Az5ZsrEic9ot90z9etZLlU7OTaPOdibteeibJMMmbwc29aJlDOmUicibIRoLdcuEQjtHQ2qjVtZBt0M5eVbYoQzlHiaw/640?wx_fmt=gif "")  
  
   
聚焦源代码安全，网罗国内外最新资讯！  
  
**作者：ANDREW CUNNINGHAM**  
  
**编译：代码卫士**  
  
****  
![](https://mmbiz.qpic.cn/mmbiz_png/vnT4hbaLoX6Inlu2SGYBwg77ZPry2yAAgEMG81vlTyibUKjGaL84ZXJicHMLoQhia6qGkiaNGZjNnwokM7Ql83icObA/640?wx_fmt=png "")  
  
**微软在本月补丁星期二发布补丁，修复了ESET公司研究员所发现的遭 BlackLotus bootkit 利用的 Secure Boot 绕过漏洞 CVE-2023-24932。最初的漏洞编号是CVE-2022-21894，已在今年1月份修复，而本次发布的补丁修复的是运行 Windows 10 和 11 版本以及 Windows Server 2008及之后版本的系统上被活跃利用的另外一个缓解措施。**  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/oBANLWYScMQNicpDd0I8J163S6jaejZFcvH8k6M0Y3pI7c8Fh2DS2wn92xhnGMsQUUktUwh4FqtJ8IZ3HLz8Hzw/640?wx_fmt=png "")  
  
  
BlackLotus bootkit 是首个已知的可绕过 Secure Boot 防御措施的真实恶意软件，它可在用户电脑开始加载 Windows 及其很多安全防御措施前，执行恶意代码。十多年来，很多企业如戴尔、惠普等销售的多数 Windows 个人电脑都默认启用 Secure Boot。运行 Windows 11 的个人电脑必须启用 Secure Boot 才能满足该软件的系统要求。  
  
微软表示，攻击者如具有对系统的物理访问权限或管理员权限，则可利用该漏洞。该漏洞影响启用 Secure Boot 的物理个人电脑和虚拟机。  
  
强调这一修复方案的部分原因在于，与很多优先级高的 Windows 修复方案不同，本更新在安装之后的至少几个月后，将默认禁用；另外部分原因在于，它将最终导致当前的 Windows 引导媒体无法启动。该修复方案要求对 Windows 引导管理器进行更改，而这些变更一旦启用则不可改变。  
  
微软在关于该更新的一篇支持文章中提到，“Secure Boot 特性精确地控制初始化操作系统时允许加载的引导媒体，如果该修复方案未能正确启用，则可能引起中断并阻止系统启动。” 安全分析研究员 Will Dormann 表示，“需要注意，CVE-2023-24932 的更新实际上并未修复任何问题。它只是给你提供了应用该修复方案的选择。”  
  
另外，一旦这些修复方案被启用，则用户的个人电脑将无法从老旧的不包含这些修复方案的可引导媒体进行启动。大量媒体受影响：Windows 安装媒体如从微软 ISO 文件中创建的 DVD 和 USB 驱动；由 IT 部门维护的自定义 Windows 安装镜像；完整的系统备份；网络引导驱动如 IT 部门用于调试机器和部署新的 Windows 镜像的驱动；使用 Windows PE 的精简引导驱动；以及和原始设备制造商个人电脑一起出售的恢复媒体。  
  
由于不希望突然将任意用户的系统转换为不可启动状态，微软将在未来几个月推出更新。该补丁的初始版本需要大量用户干预才能使系统启用：首先用户需要安装五月份的安全更新，之后使用包含五个步骤的流程手动更新并验证“调用文件”，更新系统隐藏的 EFI 引导分区及 registry。这些步骤导致更老旧的、更易受攻击的引导程序将无法获得个人电脑的信任。  
  
第二次更新将在7月发布，该更新虽然将不会启用该补丁但将使得启用更简单。第三次更新将在“2024年的第一季度”发布，使修复方案默认可启用并在所有已修复 Windows 个人电脑上使更老旧的引导媒体为不可启用状态。微软表示，“正在寻求加快这一安排的机会”，尽管并未说明具体情况。  
  
ESET 公司的威胁研究总监 Jean-Ian Boutin 对 BlackLotus 和其它 bootkit 的严重程度的评论是，“最重要的要点是，UEFI bootkit BlackLotus 能够在使用已启用 Secure Boot 的最新 Windows 版本的新近系统上自安装。尽管该漏洞比较老旧，但仍然很可能被用于绕过所有的安全措施并攻陷系统的引导流程，从而使攻击者控制系统启动的早期阶段。同时它呈现出一种趋势：攻击者关注 EFI 系统分区 (ESP) 而非固件或其植入，虽然牺牲了更轻易部署的隐秘性但获得了类似能力。”  
  
这一修复方案并非首个说明底层 Secure Boot 和 UEFI 漏洞难以修复的安全事件。计算机和主板厂商 MSI 最近遭勒索攻击且导致签名密钥被泄露，而对于该公司来说，告知产品不去信任通过受陷密钥签名的固件更新并非易事。  
  
  
****  
![](https://mmbiz.qpic.cn/mmbiz_png/oBANLWYScMQZeSribxs2yU1w56EMvgX9cDBCiabniazxdxtQ25cBCAd5vBJIM2sOv1khjzwwViaT0pS74U6piaiauiaGA/640?wx_fmt=png "")  
  
  
  
代码卫士试用地址：  
https://codesafe.qianxin.com  
  
开源卫士试用地址：https://oss.qianxin.com  
  
  
  
  
  
  
  
  
  
  
  
  
**推荐阅读**  
  
[](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247511052&idx=3&sn=fb116392e405ae62e6c339117fffdb59&chksm=ea949d66dde31470758b6ee8f9dbecdb67ef6c0c8af277f26b83b60dbac95748d28db787a4b4&scene=21#wechat_redirect)  
[奇安信入选全球《软件成分分析全景图》代表厂商](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247515374&idx=1&sn=8b491039bc40f1e5d4e1b29d8c95f9e7&chksm=ea948d84dde30492f8a6c9953f69dbed1f483b6bc9b4480cab641fbc69459d46bab41cdc4859&scene=21#wechat_redirect)  
  
  
[洞少事大：微软5月补丁星期二需关注的漏洞](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247516449&idx=1&sn=17fb3428de6050c5e0ce8daaa751c406&chksm=ea94b04bdde3395de1c91c780a8796919fd059dce25c7d3ae460bbf340057ec40a3581920c4d&scene=21#wechat_redirect)  
  
  
[研究员在微软 Azure API 管理服务中发现3个漏洞](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247516392&idx=3&sn=f563d9d06d17140943a9006f9816fecd&chksm=ea94b182dde33894747c1e2aa9ddbd52a923d8f1cc8ec0edd712caa946b58d97a9ac1bda8ecf&scene=21#wechat_redirect)  
  
  
[微软 Edge 被指将用户访问的站点发送给Bing](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247516356&idx=2&sn=a80a338de7f5bf0f3031105e790dd2d2&chksm=ea94b1aedde338b8f6759c7868cd9e80e84ec8924e26c0512b897c1c6c6b13bf7bee8db22774&scene=21#wechat_redirect)  
  
  
[微软四月补丁星期二值得关注的漏洞](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247516226&idx=2&sn=e7f2dafb8a5996808eb986ee331cc878&chksm=ea94b128dde3383e7747fbb60df716ad987539ab7a5b46d2212e3c63ee1e6e0e8deee53cef41&scene=21#wechat_redirect)  
  
  
  
  
**原文链接**  
  
  
https://arstechnica.com/information-technology/2023/05/microsoft-patches-secure-boot-flaw-but-wont-enable-fix-by-default-until-early-2024/  
  
  
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
  
