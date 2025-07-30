#  GitHub 严重漏洞导致4000多个仓库易遭repojacking攻击   
THN  代码卫士   2023-09-13 16:42  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Az5ZsrEic9ot90z9etZLlU7OTaPOdibteeibJMMmbwc29aJlDOmUicibIRoLdcuEQjtHQ2qjVtZBt0M5eVbYoQzlHiaw/640?wx_fmt=gif "")  
  
   
聚焦源代码安全，网罗国内外最新资讯！****  
  
**编译：代码卫士**  
  
**GitHub 存在一个漏洞，可导致数千个仓库易遭repojacking（仓库劫持）攻击。**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/oBANLWYScMQbylDuVfFniawnNiaIbkhRp8iaBriadia9aNJicNP6dG4Lup91EEmlxRfbdCTemveIPnSKGia7wweeGTCww/640?wx_fmt=png "")  
  
  
Checkmarx 公司的安全研究员 Elad Rapoport 在一份技术报告中提到，该漏洞“可导致攻击者利用GitHub 仓库创建和用户名重命名操作中的条件竞争”，“成功利用该漏洞可导致多种语言如 Go、PHP和Swift 以及 GitHub 操作中的4000多个代码包遭劫持”。  
  
GitHub在2023年3月1日收到负责任的披露后，在9月1日修复了该问题。  
  
Repojacking 即仓库劫持，指威胁者能够绕过名为“流行仓库名称空间退出”机制，最终控制仓库。该防御措施的目的是阻止其它用户创建与用户账户更名时克隆超过100个的仓库名称一样的仓库，也就是说用户名和仓库名称的组合被视作“退出”。如果该机制被轻松绕过，则可导致威胁者创建具有相同用户名的账户并上传恶意仓库，从而导致软件供应链攻击。  
  
研究人员利用参控股创建和用户名更名之间的潜在条件竞争实现了仓库劫持。具体步骤如下：  
  
1、受害者拥有名称空间 “victim_user/repo”  
  
2、受害者将 “victim_user”更名为 “renamed_user”  
  
3、“victim_user/repo” 仓库退出。  
  
4、拥有 “attacker_user” 的威胁者同时创建名为 “repo” 的仓库并将用户名 “attacker_user” 更名为 “victim_user”.  
  
最后一步使通过仓库创建的API请求以及用户名变更的 renamed 请求拦截实现的。近9个月前，GitHub 修复了一个类似的可导致仓库劫持攻击的类似绕过漏洞。  
  
研究人员指出，“GitHub 仓库创建和用户名更名操作中这类新漏洞的发现说明了与‘流行仓库名称空间退出’机制相关联的持久风险”。  
  
  
  
代码卫士试用地址：  
https://codesafe.qianxin.com  
  
开源卫士试用地址：https://oss.qianxin.com  
  
  
  
  
  
  
  
  
  
  
  
  
**推荐阅读**  
  
[GitHub 提醒 Lazarus 黑客组织利用恶意项目攻击开发人员](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247517127&idx=2&sn=18d95fca91d5d3e707a2b97d82c043f3&chksm=ea94b2addde33bbb3417005732d1595e151e3bf9cdd4f1a6e4ffc8cea828afc2e4b65a7f88d8&scene=21#wechat_redirect)  
  
  
[Linux 内核漏洞虚假 PoC 发 GitHub，专门攻击研究员](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247517057&idx=3&sn=ac0e0bde77420df4712fba006d14f767&chksm=ea94b2ebdde33bfd540cb9d9cd4757ae8042142e812d7913a4f1c2bfa3c36967e61192a4c9d0&scene=21#wechat_redirect)  
  
  
[GitHub 上的虚假0day PoC 推送 Windows 和 Linux 恶意软件](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247516737&idx=2&sn=368349f3292248a0829924a329eab306&chksm=ea94b32bdde33a3d73ce830890ee3113abe962086d9059767525a81c0884679a6ca038ff9aa7&scene=21#wechat_redirect)  
  
  
[数百万个 GitHub 仓库易受 RepoJacking 攻击](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247516818&idx=2&sn=215a7396e245627552e38f2ca838cf66&chksm=ea94b3f8dde33aeeba7088e9749ab03df49490eef201a642c17b168aeea2e123e1f5390ea3b4&scene=21#wechat_redirect)  
  
  
  
  
**原文链接**  
  
https://thehackernews.com/2023/09/critical-github-vulnerability-exposes.html  
  
  
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
  
