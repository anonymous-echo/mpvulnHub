#  Atlassian 紧急修复已遭利用的 Confluence 0day   
Sergiu Gatlan  代码卫士   2023-10-09 18:04  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Az5ZsrEic9ot90z9etZLlU7OTaPOdibteeibJMMmbwc29aJlDOmUicibIRoLdcuEQjtHQ2qjVtZBt0M5eVbYoQzlHiaw/640?wx_fmt=gif "")  
  
   
聚焦源代码安全，网罗国内外最新资讯！****  
  
**编译：代码卫士**  
  
**澳大利亚软件公司 Atlassian 紧急修复了位于 Cofluence Data Center and Server 软件中的一个严重的已遭利用的 0day 漏洞CVE-2023-22515，其CVSS评分为满分10分。**  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/oBANLWYScMQlib8xW4DWtdQNeLNx139icWx4JWRSGlic9PvFibVtdII0pvHdl8JypIuITnQ80XAAdMZrjnwJrtBxUQ/640?wx_fmt=gif "")  
  
  
该公司提到，“从一些客户处获知，外部攻击者可能已经利用了位于可公开访问呢的 Confluence Data Center and Server 实力中的未知漏洞，创建越权的 Confluence 管理员账户并访问 Confluence 实力。Atlassian Cloud 站点不受该漏洞影响。如用户的 Confluence 站点可经由 atlassian.net 域访问，则说明该站点由 Atlassian 托管且不受漏洞影响。”  
  
该漏洞的编号是CVE-2023-22515，是一个严重的提权漏洞，影响 Confluence Data Center and Server 8.0.0及后续版本，可在无需用户交互的复杂度低下的攻击中遭远程利用。  
  
使用受影响版本的用户应尽快修复至已修复版本即 8.3.3或后续版本、8.4.3或后续版本以及8.5.2及后续版本。除升级和应用缓解措施外，Atlassian 公司还指出如无法立即应用补丁，则关闭受影响实例或将其与互联网访问隔离。管理员可删除与该漏洞相关联的已知攻击向量，方法是阻止访问 Confluence 实力上的 /setup/*端点。该公司提到，“公开互联网上的实例易处于风险之中，因为该漏洞可遭匿名利用。”  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/oBANLWYScMQlib8xW4DWtdQNeLNx139icWQibEYlpowrLXOAn4fHtC9rhxY1tofgI1qQdxwuJQb24ib7cazN7TQ7jA/640?wx_fmt=png "")  
  
  
**建议管理员检查攻陷迹象**  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/oBANLWYScMQlib8xW4DWtdQNeLNx139icW8sAHjKornNsoibcicfDPrHdvPia4WmlocMR9YagV9G1zqibhhicklAQ2RdA/640?wx_fmt=png "")  
  
  
  
Atlassian 公司还建议查看所有 Confluence 实例中是否存在受陷指标，包括：  
  
- Confluence-administrator 组的异常成员  
  
- 新建的异常用户账户  
  
- 网络访问日志中对 /setup/*.action 的请求  
  
- Confluence 主页目录中atlassian-confluence-security.log 中异常消息中出现/setup/setupadministrator.action  
  
  
  
补丁发布后，威胁行动者很可能将tongguo 逆向发布所修复的弱点，从而加速创建可用exploit。Atlassian 公司提醒称，“如果确定 Confluence Server/DC实例已遭攻陷，则我们建议立即关闭并从网络/互联网断开服务器。另外，可能需要立即关闭其它可能共享用户库或与受陷系统共同用户秘密组合的其它系统。”  
  
立即修复Confluence 服务器至关重要，因为恶意人员对它们的兴趣高涨，此前AvosLocker 和 Cerber2021勒索软件、Linux 僵尸网络恶意软件以及加密矿机都说明了这一点。去年，CISA 下令要求联邦机构修复另外一个严重的 Confluence 漏洞CVE-2022-26138。  
  
****  
  
代码卫士试用地址：  
https://codesafe.qianxin.com  
  
开源卫士试用地址：https://oss.qianxin.com  
  
  
  
  
  
  
  
  
  
  
  
  
**推荐阅读**  
  
[Atlassian 安全更新修复多个高危漏洞](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247517726&idx=2&sn=fb70a13cea95f2a283f72cea5e804abc&chksm=ea94b774dde33e62ceae3c08c4f637d76f5c3e2592a17823a66b9442cfc21a4a65b04d7edfce&scene=21#wechat_redirect)  
  
  
[第三方app受陷，Atlassian 数据被盗](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247515624&idx=3&sn=67fc0501190042defabcc173a6eb618f&chksm=ea948c82dde30594c6d827c3f9a2ec0f74bc3ac9f01de20c08188c4f469b2a74cbf9381d0a01&scene=21#wechat_redirect)  
  
  
[Atlassian 修复Crowd 和 Bitbucket 产品中的严重漏洞](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247514682&idx=2&sn=dc35e642f56cb043c698c74c4a7cc1db&chksm=ea948b50dde3024635cc241de37f67ec45fccba1bb52808e5a89a1908c6cd04233a2502e782c&scene=21#wechat_redirect)  
  
  
[立即修复！Atlassian Bitbucket 服务器易受严重的 RCE漏洞影响](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247513716&idx=1&sn=17534c8b961a4ef3a27b7ecdf4588568&chksm=ea94871edde30e08de08a258e2ba454e862dc7b989c93439978434f6141872e937b7f16615b0&scene=21#wechat_redirect)  
  
  
[Atlassian 修复严重的Confluence 硬编码凭据漏洞](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247513005&idx=2&sn=65a9ae762a7954f9a33b371fd2aed816&chksm=ea9482c7dde30bd1bd79614e758e742a403975ff8cae09386f6fdd5615bc8176574e05c1b6e9&scene=21#wechat_redirect)  
  
  
  
  
**原文链接**  
  
https://www.bleepingcomputer.com/news/security/atlassian-patches-critical-confluence-zero-day-exploited-in-attacks/  
  
  
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
  
