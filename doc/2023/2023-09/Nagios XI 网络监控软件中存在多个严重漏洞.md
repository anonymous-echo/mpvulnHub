#  Nagios XI 网络监控软件中存在多个严重漏洞   
THN  代码卫士   2023-09-21 18:11  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Az5ZsrEic9ot90z9etZLlU7OTaPOdibteeibJMMmbwc29aJlDOmUicibIRoLdcuEQjtHQ2qjVtZBt0M5eVbYoQzlHiaw/640?wx_fmt=gif "")  
  
   
聚焦源代码安全，网罗国内外最新资讯！****  
  
**编译：代码卫士**  
  
**Nagios XI 网络监控软件中存在多个漏洞，可导致提权和信息泄露。**  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/oBANLWYScMSxg65qmpvVjN13NNac2hWgtmY0QicKic0zbIicQ8xD2yO9bUGaSLM3esWvtD1Clcm41sQtD3F7DjWqg/640?wx_fmt=png "")  
  
  
这四个漏洞的编号从CVE-2023-40931到CVE-2023-40934，影响 Nagios XI 5.11.1及以下版本。研究员在2023年8月4日报送这些漏洞，厂商在9月11日已在版本5.11.2中修复。  
  
Outpost24 公司的研究员 Astrid Tedenbrant 表示，“其中三个漏洞（CVE-2023-40931、CVE-2023-40933和CVE-2023-40934）可导致用户以各种权限级别，通过SQL注入访问数据库字段。通过这些漏洞获得的数据可能用于在产品中进一步提权并获得敏感的用户数据如密码哈希和API令牌。”  
  
CVE-2023-40932与Custom Logo 组件中的XSS 缺陷有关，可用于读取敏感数据如从登录页面获取明文密码。  
  
这些漏洞简述如下：  
  
- CVE-2023-40931：Banner 确认端点中的SQL注入  
  
- CVE-2023-40932：Custom Logo组件中的XSS  
  
- CVE-2023-40933：Announcement Banner 设置中的SQL 注入  
  
- CVE-2023-40934：Core配置管理器 (CCM) 中Host/Service 提权中的SQL注入  
  
  
  
这三个SQL注入漏洞如遭成功利用，可导致认证攻击者执行任意SQL命令，而XSS漏洞可用于注入任意JavaScript 以及读取和修改页面数据。这并非Nagios XI 中首次出现安全问题。2021年，Skylight Cyber 和 Claroty 公司发现12个漏洞，可用于劫持基础设施并实现远程代码执行后果。  
  
  
代码卫士试用地址：  
https://codesafe.qianxin.com  
  
开源卫士试用地址：https://oss.qianxin.com  
  
  
  
  
  
  
  
  
  
  
  
  
**推荐阅读**  
  
[开源软件 Nagios 曝11个漏洞，可使IT 基础设施遭接管引发供应链攻击](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247508034&idx=1&sn=df9320bdbbd95b0efc6bc9e40e988d10&chksm=ea949128dde3183e6b34bee221df0209108c871d56033febb800b00afa39a8bdf79d9d10346c&scene=21#wechat_redirect)  
  
  
[GitLab 督促用户安装安全更新，修复严重的管道漏洞](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247517701&idx=2&sn=9efeb89e9c34a3dcb192e347897ea5d3&chksm=ea94b76fdde33e79439751b5f121c7f1c6903963de1ec1e650ed19876271b10ebc9271391861&scene=21#wechat_redirect)  
  
  
[CISA 发布开源软件安全路线图](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247517654&idx=1&sn=7d8162734766c1f2b28308d2eb7a3ff4&chksm=ea94b4bcdde33daadaef6eb96bca05af2bc5cd7e02a3dd802bb942bb6631bcf8a9249c342094&scene=21#wechat_redirect)  
  
  
[PHPFusion 开源 CMS 中存在严重漏洞](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247517570&idx=2&sn=7f19eccf19674dfcdf5f6515082f6989&chksm=ea94b4e8dde33dfedce31e414840f4579284cf9589c84909a1efa2bda3cb52dea3b0de2e1433&scene=21#wechat_redirect)  
  
  
[关于美国政府发布的开源软件安全RFI，你需要知道的都在这里](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247517551&idx=1&sn=93963f8732fec9933bef958c4700e81a&chksm=ea94b405dde33d13f46130eef5bedb6639dcd942e8a39a702915016722232f021dc712f73b32&scene=21#wechat_redirect)  
  
  
  
  
**原文链接**  
  
  
https://thehackernews.com/2023/09/critical-security-flaws-exposed-in.html  
  
  
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
  
