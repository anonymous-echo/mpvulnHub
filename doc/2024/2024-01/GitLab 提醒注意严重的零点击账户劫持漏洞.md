#  GitLab 提醒注意严重的零点击账户劫持漏洞   
Bill Toulas  代码卫士   2024-01-15 17:33  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Az5ZsrEic9ot90z9etZLlU7OTaPOdibteeibJMMmbwc29aJlDOmUicibIRoLdcuEQjtHQ2qjVtZBt0M5eVbYoQzlHiaw/640?wx_fmt=gif "")  
  
   
聚焦源代码安全，网罗国内外最新资讯！****  
  
**编译：代码卫士**  
  
**GitLab 发布社区版和企业版的安全更新，修复了两个漏洞，其中一个在无需用户交互的情况下可劫持账户。**  
  
  
GitLab 强烈建议用户尽快更新所有的 DevSecOps 平台易受版本（自托管安装需要手动更新），并提醒称，如果没有“提到产品的具体部署类型，那就说明所有类型均受影响。”  
  
  
**漏洞详情**  
  
  
  
  
  
GitLab 所修复的漏洞中最严重的是CVSS评分为10分的漏洞CVE-2023-7028。成功利用该漏洞无需任何用户交互。  
  
该漏洞是认证漏洞，可导致密码重置请求被发送给任意的未经认证的邮件地址，从而导致账户接管。如启用了双因素认证，则可能重置密码但第二个验证因素仍然要求成功登录。  
  
劫持 GitLab 账户可对组织机构造成重大影响，因为该平台通常用于托管专有代码、API 密钥和其它敏感数据。另外一个风险是供应链攻击。当 GitLab 用作CI/CD时，攻击者可通过在实时环境中插入恶意代码的方式攻陷仓库。  
  
该漏洞由安全研究员 Asterion 通过 HackerOne 漏洞奖励平台报送，在2023年5月1日推出的16.1.0版本中引入。受影响版本如下：  
  
- 16.1.5之前的16.1版本  
  
- 16.2.8之前的16.2版本  
  
- 16.3.6之前的16.3版本  
  
- 16.4.4之前的16.4版本  
  
- 16.5.6之前的16.5版本  
  
- 16.6.4之前的16.6版本  
  
- 16.7.2之前的16.7版本  
  
  
  
该漏洞已在 GitLab 16.7.2、16.5.6和16.6.4中修复，且修复方案已向后兼容到16.1.6、16.2.9和16.3.7版本。GitLab 提到并未发现该漏洞遭利用的证据，不过与防御人员分享了如下攻陷标志：  
- Check gitlab-rails/production_json.log for HTTP requests to the /users/password path with params.value.email consisting of a JSON array with multiple email addresses.  
  
- Check gitlab-rails/audit_json.log for entries with meta.caller.id of PasswordsController#create and target_details consisting of a JSON array with multiple email addresses.  
  
GitLab 修复的第二个严重漏洞是CVE-2023-5356，CVSS评分为9.6，可用于滥用 Slack/Mattermost 集成，以其它用户身份执行slash 命令。在Mattermost环境中，slash 命令可将外部应用集成到workspace；在Slack 环境中，它们可用作在消息编辑框中启动应用的快捷键。  
  
GitLab 还修复了如下几个漏洞：  
  
- CVE-2023-4812：位于GitLab 15.3及后续版本中的高危漏洞，可通过修改此前已获同意的合并请求，绕过CODEOWNERS 的同意。  
  
- CVE-2023-6955：GitLab 16.7.2之前版本中Workspace 的访问控制不当漏洞，可导致攻击者在与另外一个组代理相关的组中创建workspace。  
  
- CVE-2023-2030：提交签名验证漏洞，影响 GitLab CE/EE 版本12.2及后续版本，因签名验证不当可导致已签名的提交元数据遭修改。  
  
  
  
GitLab 在更新页面中还给出了相关指南和官方更新资源。  
  
****  
****  
代码卫士试用地址：  
https://codesafe.qianxin.com  
  
开源卫士试用地址：https://oss.qianxin.com  
  
  
  
  
  
  
  
  
  
  
  
  
**推荐阅读**  
  
[GitLab 督促用户安装安全更新，修复严重的管道漏洞](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247517701&idx=2&sn=9efeb89e9c34a3dcb192e347897ea5d3&chksm=ea94b76fdde33e79439751b5f121c7f1c6903963de1ec1e650ed19876271b10ebc9271391861&scene=21#wechat_redirect)  
  
  
[GitLab强烈建议尽快修复 CVSS 满分漏洞](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247516580&idx=1&sn=3e272b8a4ba9c8f7b596e5bc1c9f6576&chksm=ea94b0cedde339d8dee6f14566aaa4da84cb44e202cc0582353695ecd4620c832ba4c9ddab91&scene=21#wechat_redirect)  
  
  
[GitLab 远程代码执行漏洞安全风险通告](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247513707&idx=1&sn=6c80379607fc2214bebf651c01750491&chksm=ea948701dde30e17d699dd8ce24dd9852b091e66462aee72c89a53dae49d8d3027bb1ddb3c99&scene=21#wechat_redirect)  
  
  
[GitLab修复GitHub import函数中的RCE漏洞](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247514207&idx=1&sn=eda12473aec122dcbe50bf0b2545da32&chksm=ea948935dde300234feefd9ebdb2e36056f43a607bd274323e86088fbc98d2737efa2f63658f&scene=21#wechat_redirect)  
  
  
[GitLab 修复两个严重的远程代码执行漏洞](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247513659&idx=2&sn=2f2dfa5beb36144d258cfc9aae9a6961&chksm=ea948751dde30e47c001f82da2a744dd9248717d7d94b35de8b94974f3fa361b8b3dfe6effc5&scene=21#wechat_redirect)  
  
  
  
  
**原文链接**  
  
https://www.bleepingcomputer.com/news/security/gitlab-warns-of-critical-zero-click-account-hijacking-vulnerability/  
  
  
题图：Pixabay License  
  
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
  
