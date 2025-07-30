#  Ruby 服务器中存在 Rack::Static 漏洞，可导致数据遭泄露   
Ravie Lakshmanan  代码卫士   2025-04-28 08:39  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Az5ZsrEic9ot90z9etZLlU7OTaPOdibteeibJMMmbwc29aJlDOmUicibIRoLdcuEQjtHQ2qjVtZBt0M5eVbYoQzlHiaw/640?wx_fmt=gif "")  
   
聚焦源代码安全，网罗国内外最新资讯！  
  
**编译：代码卫士**  
  
**网络安全研究员披露了位于 Rack Ruby web 服务器界面中的多个安全漏洞。如遭成功利用，它们可导致攻击者越权访问文件、注入恶意数据并在某些情况下篡改日志。**  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/oBANLWYScMQvOLaX63rYCEv4gVic2iaGtGynnpC8Nl6a1wWItddn72p40C9MtUHXw9axF6sAzjzBPZAOg561v07w/640?wx_fmt=png&from=appmsg "")  
  
  
这些漏洞如下：  
  
- CVE-2025-27610（CVSS评分7.5）：路径遍历漏洞，在特定root：directory下可用于获得对所有文件的访问权限，前提是攻击者可以判断这些文件的路径。  
  
- CVE-2025-27111（CVSS评分6.9）：对CRLF序列的不当妥协和对日志输出的不当中和漏洞，可用于操纵日志内容并修改日志文件。  
  
- CVE-2025-25184（CVSS评分5.7）：对CRLF序列的中和不当和对日志输出的不当中和漏洞，可用于操纵日志内容并注入恶意数据。  
  
  
  
成功利用这些漏洞可导致攻击者隐藏攻击踪迹、读取恶意文件并注入恶意数据。  
  
发现这些漏洞的公司 OPSWAT 提到，“在这些漏洞中，CVE-2025-27610最为严重，因为它可导致未认证攻击者检索敏感信息包括配置文件、凭据和机密数据，最终导致数据泄露。”  
  
这些漏洞的根因在于，用于提供静态内容如 JavaScript、样式表和图片的中间件 Rack:Static 在提供文件前并未清理用户提供的路径，从而导致攻击者可提供特殊构造的路径访问该静态文件目录以外的文件。OPSWAT公司表示，“具体而言，当 :root 参数并未明确定义时，Rack 默认该值是当前的工作目录，将其赋值为 Dir.pwd的值，从而将其制定为Rack 应用的 web root目录。”  
  
因此，如果 :root 选项未明确或者配置不当为 :urls 选项，未认证的攻击者就能够通过路径遍历技术武器化CVE-2025-27610，来访问web 目录以外的敏感文件。  
  
为缓解该漏洞，建议更新至最新版本。如无法立即打补丁，则建议不使用 Rack::Static，或者确保 root: 指向仅包含应被公开访问的文件的目录路径。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/oBANLWYScMQvOLaX63rYCEv4gVic2iaGtGjnnT7B6mkWXVicqn9k2QC6H7chAAfgxOKqT8dkf25ibpBVEvxEjXicPtA/640?wx_fmt=gif&from=appmsg "")  
  
**Infodraw 媒体中继服务中的严重漏洞**  
  
  
此前不久，Infodraw 媒体中继服务 (MRS) 中存在一个严重漏洞，攻击者可通过位于系统登录页面的用户名参数中的路径遍历漏洞CVE-2025-43928（CVSS 9.8），读取或删除任意文件。  
  
Infodraw 是以色列的一家移动视频监控解决方案厂商，该解决方案可通过电信网络传输音频、视频和GPS数据。该公司在网站上提到，其设备用于很多国家的执法机构、非公开调查、车队管理和公共交通行业。  
  
安全研究员 Tim Philipp Schäfers 在一份声明中提到，“一个简单的路径遍历漏洞可导致未认证攻击者从系统中读取文件。另外，一个‘任意文件删除漏洞’的存在导致攻击者可从系统删除任何文件。”该漏洞可通过用户名如 “../../../../” 进行登录，影响MRS的Windows 和 Linux 版本。尽管如此，该漏洞仍未被修复。位于比利时和卢森堡的易受攻击系统已在负责任披露后被下线。  
  
Philipp Schäfers表示，‘“建议受影响组织机构立即下线应用（尽管之前已提前预警，但制造商并未发布补丁，该漏洞可能在不久后遭恶意人员利用）。如无法立即打补丁，则应通过其它措施保护系统安全（例如使用VPN或特定的IP拦截）。”  
  
  
代码卫士试用地址：  
https://codesafe.qianxin.com  
  
开源卫士试用地址：https://oss.qianxin.com  
  
  
  
  
  
  
  
  
  
  
  
  
  
**推荐阅读**  
  
[GitHub 发现ruby-saml中的新漏洞，可用于接管账户](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247522499&idx=2&sn=26c6be6088417f7563b0041ef251fe1f&scene=21#wechat_redirect)  
  
  
[恶意 PyPI、NPM、Ruby 包正在瞄准 Mac 设备](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247517570&idx=3&sn=e1e8c3f4da181c45574f67a713fa11bb&scene=21#wechat_redirect)  
  
  
[RubyGems 包管理器中存在严重的 Gems 接管漏洞](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247511738&idx=1&sn=3e4c8ab0a54ec620b25047d6fd043b3e&scene=21#wechat_redirect)  
  
  
[热门Ruby 库中存在严重的命令注入漏洞](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247511304&idx=1&sn=25c992c5e2ab4d11a0999e24aad7e99f&scene=21#wechat_redirect)  
  
  
[RubyGems出现重定向木马漏洞 可影响数百万用户](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247485939&idx=5&sn=e3251e0e65310e939b207d6260fed292&scene=21#wechat_redirect)  
  
  
  
  
  
**原文链接**  
  
https://thehackernews.com/2025/04/researchers-identify-rackstatic.html  
  
  
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
  
   
觉得不错，就点个 “  
在看  
” 或 "  
赞  
” 吧~  
  
