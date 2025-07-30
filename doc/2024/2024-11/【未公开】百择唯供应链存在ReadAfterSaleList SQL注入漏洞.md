#  【未公开】百择唯供应链存在ReadAfterSaleList SQL注入漏洞   
原创 xioy  我吃饼干   2024-11-21 00:02  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Sf7NlfS2U5xFyEE4z57XQ7wSLuiamExVFOOibFicstjibiaXjBJB4ib4z9lPpUoNqVy1kkgkEl2qaH7HH4X9pt0zAPUg/640?wx_fmt=gif&from=appmsg "")  
  
免责声明  
  
  
1. 本文所涉及的任何技术、信息或工具，仅供学习和参考之用。请勿利用本文提供的信息从事任何违法活动或不当行为。  
  
1. 任何因使用本文所提供的信息或工具而导致的损失、后果或不良影响，均由使用者个人承担责任，与本文作者无关。    
  
1. 作者不对任何因使用本文信息或工具而产生的损失或后果承担任何责任。   
  
1. 使用本文所提供的信息或工具即视为同意本免责声明，并承诺遵守相关法律法规和道德规范。  
  
  
  
  
**1**  
  
**漏洞描述**  
  
  
百择唯供应链存在ReadAfterSaleList SQL注入漏洞，未经身份验证的攻击者通过漏洞，执行任意代码从而获取到服务器权限。  
  
  
**2**  
  
**漏洞复现**  
  
  
首页  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Sf7NlfS2U5xgMe6g2T4kvicTPBWx5Em859G4lbHZ7X5tUUq40JibYPZPYgZ8m9O7ru0vGOkr3Vf7YN5hlsny7XxQ/640?wx_fmt=png&from=appmsg "")  
  
  
  
需要注册账号，替换包内的Cookie，登录后在订单管理-返修退换货功能处产生数据包  
  
  
sqlmap验证  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Sf7NlfS2U5xgMe6g2T4kvicTPBWx5Em85wHXyaM8NKzPoV2oE6PgBTibfib8K3hPEE1pDUwXn5xmibDKmKfFEwveZg/640?wx_fmt=png&from=appmsg "")  
  
  
**3**  
  
**网络测绘**  
  
  
body="/Content/Css/_SiteCss/"  
  
  
**4**  
  
**漏洞POC**  
  
  
后台回复：241121  
  
本文已同步至TNT文库  
  
  
往期文章推荐  
  
[【技术分享】小程序Appid、AppSecret泄露漏洞总结](http://mp.weixin.qq.com/s?__biz=MzkzODY2ODA0OA==&mid=2247485881&idx=1&sn=7ba2c314a504ba37953ee8754f64eb7c&chksm=c2fdf0c6f58a79d0162be4727fde7b1c1466d9301f17070fff27130cc2579abfa50a2955121a&scene=21#wechat_redirect)  
  
  
[【技术分享】巧妙利用file协议然后疯狂杀戮](http://mp.weixin.qq.com/s?__biz=MzkzODY2ODA0OA==&mid=2247485664&idx=1&sn=42148a8fbeb2063dc1d5d1f3f1e3755a&chksm=c2fdf19ff58a78893c620cf01a2e09bbd8e60e090d6173923f1d64d5dfd7b8f86a355e0e51b1&scene=21#wechat_redirect)  
  
  
[【技术分享】记一次TXT的存储型XSS奇葩案例](http://mp.weixin.qq.com/s?__biz=MzkzODY2ODA0OA==&mid=2247484891&idx=1&sn=1b3d11b0cc913956fb1bbeb85352a34c&chksm=c2fdfca4f58a75b2fc0c477d357ee2e47fd8369227a8f43b834d0c4e20ee4e752b8dfff52a28&scene=21#wechat_redirect)  
  
  
[【技术分享】记一次从信息泄露到重置任意用户密码的渗透过程](http://mp.weixin.qq.com/s?__biz=MzkzODY2ODA0OA==&mid=2247484421&idx=1&sn=6c88587f4f793b98dd4d610580cc0bc6&chksm=c2fdfd7af58a746caaecc5d870375aaf70366dfacafe293548a3217747ea160ca945c90f00c9&scene=21#wechat_redirect)  
  
  
  
**项**  
  
**目**  
  
**承**  
  
**接**  
  
  
团队中的师傅们都来自国内安全厂商在职的一线工程师，均具有良好的职业素养与丰富的从业经验。  
  
  
**渗透测试**  
  
Web渗透、APP渗透、小程序渗透、内网渗透  
  
  
**CTF**  
  
培训、竞赛、解题、AWD竞赛服务  
  
  
**考证**  
  
NISP考证、CISP考证  
  
**TNT文库**  
  
所有文章第一时间会发布在文库中，文库中的内容全部免费开放。  
  
访问密码每周都会更换，最新访问密码请在公众号的菜单栏：  
资源获取-漏洞文库中获取。  
  
  
  
**edusrc邀请码**  
  
免费不限量提供edusrc邀请码，请在公众号的菜单栏：  
资源获取-edusrc邀请码中获取。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Sf7NlfS2U5xFyEE4z57XQ7wSLuiamExVFPrAj3cz2WcBuKGDLlvrymDVfrM6O7sEyazgyicfE2Aiae7snhCxlFiayQ/640?wx_fmt=gif&from=appmsg "")  
  
**END**  
  
**点个「在看」 我的零食分你一半**  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Sf7NlfS2U5xFyEE4z57XQ7wSLuiamExVF7TBSGZtt9STZ9wnfI9LO4866pcBGia57FbQ0QibsTYyZefPX7Uv0xMdQ/640?wx_fmt=gif&from=appmsg "")  
  
  
