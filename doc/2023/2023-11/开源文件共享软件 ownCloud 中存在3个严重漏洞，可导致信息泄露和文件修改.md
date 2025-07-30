#  开源文件共享软件 ownCloud 中存在3个严重漏洞，可导致信息泄露和文件修改   
THN  代码卫士   2023-11-27 17:41  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Az5ZsrEic9ot90z9etZLlU7OTaPOdibteeibJMMmbwc29aJlDOmUicibIRoLdcuEQjtHQ2qjVtZBt0M5eVbYoQzlHiaw/640?wx_fmt=gif "")  
  
   
聚焦源代码安全，网罗国内外最新资讯！****  
  
**编译：代码卫士**  
  
**开源的文件共享软件 ownCloud 的维护人员提醒称，软件中存在三个严重漏洞，可用于泄露敏感信息和修改文件。**  
  
  
  
这些漏洞的简述如下：  
  
- 容器化部署中的敏感凭据和配置泄露，影响 graphapi 0.2.0至0.3.0版本（CVSS评分10）  
  
- 使用 Pre-Signed URL 绕过WebDAV Api 认证，影响核心版本10.6.0至10.13.0（CVSS评分9.8）  
  
- 子域验证绕过，影响 0.6.1之前的 oauth2 版本（CVSS评分9.0）  
  
  
  
该公司在说明第一个安全漏洞时表示，“'graphapi”应用依赖于提供URL的第三方库。当访问该URL时，它会披露 PHP 环境的配置详情 (phpinfo)。该信息包括 web 服务器的所有环境变量。在容器化部署中，这些环境变量可能包括敏感数据如 ownCloud 管理员密码、邮件服务器凭据和许可证密钥。”  
  
ownCloud 建议删除 "owncloud/apps/graphapi/vendor/microsoft/microsoft-graph/tests/GetPhpInfo.php" 文件，并禁用 phpinfo 函数。同时建议用户修改机密信息如 ownCloud 管理员密码、邮件服务器和数据库凭据以及 Object-Store/S3 访问密钥。  
  
第二个漏洞可使攻击者访问、修改或删除任何文件 sans 认证，前提是受害者的用户名是已知的以及受害者未配置签名密钥，而这是默认行为。  
  
第三个漏洞和访问控制不当有关，它可导致攻击者“传递一个特殊构造的 redirect-url，绕过验证码，从而使攻击者将回调重定向至由攻击者控制的TLD。”  
  
除了在 oauth2 app 的验证码中增加加固措施外，ownCloud 建议用户禁用“允许子域名”选项进行缓解。  
  
前不久，CrushFTP 解决方案中存在一个严重的RCE漏洞CVE-2023-43177且PoC 已发布。该漏洞可遭未认证攻击者用于访问文件、在主机上运行任意程序并获取明文密码。该漏洞已在 CrushFTP 10.5.2 中修复且于2023年8月10日发布。CrushFTP 在当时发布的安全公告中提到，“该漏洞的严重性在于，它不仅无需任何认证，而且还能匿名执行，窃取其它用户的会话并提权至管理员用户权限。”  
  
  
代码卫士试用地址：  
https://codesafe.qianxin.com  
  
开源卫士试用地址：https://oss.qianxin.com  
  
  
  
  
  
  
  
  
  
  
  
  
**推荐阅读**  
  
[开源内容管理系统Drupal 修复信息泄露和 XSS 漏洞](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247495080&idx=2&sn=62a0ad9712974813d2dd852f3c2f83f7&chksm=ea94dcc2dde355d4c612ac1a4bb1435e3744d89b3de131ddeaa82e6312ab1f8305618b88c74e&scene=21#wechat_redirect)  
  
  
[开源自动化服务器软件 Jenkins 被曝严重漏洞，可泄露敏感信息](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247494725&idx=1&sn=6bf29dab175c73db77b72934be87d9a0&chksm=ea94dd2fdde35439bd8c3b7485f574d8020d07f6614e4b0ab18aeb58270939e2f498b50612c0&scene=21#wechat_redirect)  
  
  
[开源云软件 CasaOS 中存在两个严重漏洞](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247517920&idx=1&sn=681d0c6677cad099a71c676242ba72f4&chksm=ea94b78adde33e9cfd5d18cd2b56dca916c908ab7b190ab9985975c9146af878a0fe5d5b63bb&scene=21#wechat_redirect)  
  
  
[注意！开源命令行工具Curl 中存在严重漏洞](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247517813&idx=1&sn=d93b115c2f34ccedd19200ec3263c342&chksm=ea94b71fdde33e0974bce7d6de4b942fca9a77a250a6426c544c4657b24a753a32bb9a185c31&scene=21#wechat_redirect)  
  
  
[PHPFusion 开源 CMS 中存在严重漏洞](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247517570&idx=2&sn=7f19eccf19674dfcdf5f6515082f6989&chksm=ea94b4e8dde33dfedce31e414840f4579284cf9589c84909a1efa2bda3cb52dea3b0de2e1433&scene=21#wechat_redirect)  
  
  
[使用广泛的开源框架 Expo中存在多个 OAuth 漏洞，导致账户遭接管](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247516580&idx=3&sn=167c3b3338d23cf14213471948cfc1fa&chksm=ea94b0cedde339d839a79eabe54cb687eb0f8bd5b2f135cadbc58cffcbc6b04f783f530dead1&scene=21#wechat_redirect)  
  
  
  
  
**原文链接**  
  
https://thehackernews.com/2023/11/warning-3-critical-vulnerabilities.html  
  
  
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
  
