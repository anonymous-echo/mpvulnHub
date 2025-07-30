#  速修复！ConnectWise ScreenConnect 中存在多个严重漏洞   
THN  代码卫士   2024-02-21 18:23  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Az5ZsrEic9ot90z9etZLlU7OTaPOdibteeibJMMmbwc29aJlDOmUicibIRoLdcuEQjtHQ2qjVtZBt0M5eVbYoQzlHiaw/640?wx_fmt=gif "")  
  
   
聚焦源代码安全，网罗国内外最新资讯！  
  
**编译：代码卫士**  
  
**ConnectWise 发布软件更新，修复了位于 ScreenConnect 远程桌面和访问软件中的两个漏洞，其中一个严重漏洞可导致在受影响系统上远程执行代码的后果。**  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/oBANLWYScMSYHMPmAwVEnoTRGp7EaW8tw9ZkmiatiaPicMBYeguib7pGwxgJDQxkaJYQ7GvBgyWnJ5gawh6NxdCzjA/640?wx_fmt=png&from=appmsg "")  
  
  
这些漏洞目前尚无 CVE 编号，具体如下：  
  
- 通过所选路径或信道绕过认证（CVSS评分10分）  
  
- 对受限目录的路径名称限制不当，即“路径遍历”（CVSS评分8.4）  
  
  
  
该公司将这些漏洞的严重性评为“严重”，指出“可导致执行远程代码或直接影响机密数据或重要系统”。这两个漏洞均影响 ScreenConnect 版本23.9.7及之前版本，修复方案已在23.9.8中推出。这些缺陷由该公司在2024年2月13日报送。  
  
虽然目前尚未有证据表明这些漏洞已遭在野利用，但运行自托管或本地版本的用户应尽快升级至最新版本。  
  
ConnectWise 公司提到，“ConnectWise 将提供 22.4至 23.9.7的更新版本，修复严重问题，但强烈建议合作伙伴更新至 ScreenConnect 23.9.8版本。”  
  
  
****  
  
代码卫士试用地址：  
https://codesafe.qianxin.com  
  
开源卫士试用地址：https://oss.qianxin.com  
  
  
  
  
  
  
  
  
  
  
  
  
**推荐阅读**  
  
[ConnectWise ScreenConnect 存在多个严重漏洞](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247518661&idx=1&sn=48be12903202ba82036940d836623b98&chksm=ea94b8afdde331b9243bf468dce82e9634d0e670b49e816400b6ca910a520aea0ba8c6ae631b&scene=21#wechat_redirect)  
  
  
[立即修复！ConnectWise 服务器备份管理器存在RCE，可引发供应链攻击](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247514374&idx=1&sn=3f99157ad088fa0a807c23423d8a79cd&chksm=ea94886cdde3017a9d648b9dfef4798a356e899f902a64bed87b23e3369f706944cb5e0ab77a&scene=21#wechat_redirect)  
  
  
[速修复！Fortra GoAnywhere MFT 中存在严重的认证绕过漏洞](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247518740&idx=1&sn=f97575a3c85c3e1d61c6ede1e31c0f1d&chksm=ea94bb7edde33268c42b5b9a74eb3ee30ceb5c34a906ff95500378175e985f1b8e0554fbcf3d&scene=21#wechat_redirect)  
  
  
[速修复！Buffalo VR-S1000 VPN 路由器中存在多个漏洞](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247518521&idx=2&sn=d1483115a5167b8609e5a7831a484672&chksm=ea94b853dde33145411a1b3ea61de5a9a53c48827d14d5ada05726694e593b5b6974c761e302&scene=21#wechat_redirect)  
  
  
[速修复！开源通信框架 FreeSWITCH 受严重漏洞影响](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247518495&idx=1&sn=c9f248c5f3f6c32802c76b6b1ed8e247&chksm=ea94b875dde33163ad619a2669636190d521db9292d6b488cb2d39f88259ee0cc20e49d86431&scene=21#wechat_redirect)  
  
  
  
  
**原文链接**  
  
  
https://thehackernews.com/2024/02/critical-flaws-found-in-connectwise.html  
  
  
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
  
