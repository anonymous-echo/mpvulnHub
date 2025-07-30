#  速修复Progress Flowmon中的这个CVSS满分漏洞   
Bill Toulas  代码卫士   2024-04-25 17:28  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Az5ZsrEic9ot90z9etZLlU7OTaPOdibteeibJMMmbwc29aJlDOmUicibIRoLdcuEQjtHQ2qjVtZBt0M5eVbYoQzlHiaw/640?wx_fmt=gif "")  
  
   
聚焦源代码安全，网罗国内外最新资讯！  
  
**编译：代码卫士**  
  
**用于监控网络性能和可见性的工具Progess Flowmon中，存在一个严重漏洞，其PoC 利用代码已发布。**  
  
  
  
Progress Flowmon 具有性能追踪、诊断及网络检测和响应特性，客户遍布全球1500多家企业，包括 SEGA、起亚、TDK、大众、Orange和Tietoevry等。  
  
该漏洞的编号是CVE-2024-2389，CVSS评分为10分，由Rhino 安全实验室的研究人员发现。攻击者可通过特殊构造的API请求获得对 Flowmon web 接口的未认证访问权限，利用该漏洞执行任意系统命令。Flowon 的开发者 Progress Software 公司最初在4月4日提醒注意该漏洞，指出它影响 v12.x和v11.x版本。该公司督促系统管理员升级至最新版本 v12.3.4和11.1.14。  
  
安全更新已通过“自动包下载”系统或厂商下载中心的自动和手动方式发布。Progress软件公司也建议升级所有 Flowmon 模块。  
  
  
**利用代码已发布**  
  
  
Rhino 安全实验室在今天发布了该漏洞的技术详情以及演示，展示了攻击者如何利用该漏洞植入 webshell 并提权至 root。  
  
研究人员解释称，他们能够操纵 “pluginPath” 或“文件参数”注入命令以嵌入恶意命令。通过命令替换语句如 $(…)，研究人员可实现任意命令执行。他们解释称，“命令盲目执行，因此无法看到所执行命令的输出，但可以将webshell写入 /var/www/shtml/。”  
  
值得注意的是，意大利CSIRT 在约两周前提醒称，利用代码已出现。一名研究员曾在4月10日发布有效的 PoC。  
  
  
**Flowmon 服务器被暴露**  
  
  
遭暴露的 Flowmon 实例似乎取决于搜索引擎。  
  
在本文发布之时，Fofa 搜索引擎显示约有500台 Flowmon 服务器被暴露在网络；Shodan和Hunter搜索显示少于100台。4月19日，Progress软件公司发布安全公告向客户保证称并未发现利用该漏洞的证据。然而，应当尽快更新至安全版本至关重要。  
  
****  
  
代码卫士试用地址：  
https://codesafe.qianxin.com  
  
开源卫士试用地址：https://oss.qianxin.com  
  
  
  
  
  
  
  
  
  
  
  
  
**推荐阅读**  
  
[GitLab强烈建议尽快修复 CVSS 满分漏洞](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247516580&idx=1&sn=3e272b8a4ba9c8f7b596e5bc1c9f6576&chksm=ea94b0cedde339d8dee6f14566aaa4da84cb44e202cc0582353695ecd4620c832ba4c9ddab91&scene=21#wechat_redirect)  
  
  
[Synology 修复严重的VPN路由器漏洞，CVSS评分10分](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247515192&idx=1&sn=e87e601569d5822582e1538bb28323b7&chksm=ea948d52dde30444d574600b79a6c202142ec2bf9b6ce53a72934ada80a5c93a9670132bbf3f&scene=21#wechat_redirect)  
  
  
[热门开源后端软件Parse Server中存在严重的 RCE ，CVSS评分10分](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247510991&idx=2&sn=1396eb76de81d7c7c1a252c7028381fe&chksm=ea949aa5dde313b398c64c3399132d91861cd3ec85bc341afbcfc8899e6d3818f2c52bb846db&scene=21#wechat_redirect)  
  
  
[戴尔 Wyse Thin 客户端设备受两个 CVSS 10分严重漏洞影响](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247499356&idx=3&sn=cdf75bc010884c697a2f5d110e30372a&chksm=ea94cf36dde346204b9beec70baeae529898556ac57e05f383d9d20b244aef8aba3339f239f6&scene=21#wechat_redirect)  
  
  
  
  
  
**原文链接**  
  
  
https://www.bleepingcomputer.com/news/security/maximum-severity-flowmon-bug-has-a-public-exploit-patch-now/  
  
  
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
  
