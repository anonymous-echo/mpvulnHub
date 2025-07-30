#  【漏洞复现】Apache OFBiz系统存在ProgramExport命令执行漏洞   
 我吃饼干   2024-08-07 15:33  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Sf7NlfS2U5xFyEE4z57XQ7wSLuiamExVFOOibFicstjibiaXjBJB4ib4z9lPpUoNqVy1kkgkEl2qaH7HH4X9pt0zAPUg/640?wx_fmt=gif&from=appmsg "")  
  
免责声明  
  
  
1. 本文所涉及的任何技术、信息或工具，仅供学习和参考之用。请勿利用本文提供的信息从事任何违法活动或不当行为。  
  
1. 任何因使用本文所提供的信息或工具而导致的损失、后果或不良影响，均由使用者个人承担责任，与本文作者无关。    
  
1. 作者不对任何因使用本文信息或工具而产生的损失或后果承担任何责任。   
  
1. 使用本文所提供的信息或工具即视为同意本免责声明，并承诺遵守相关法律法规和道德规范。  
  
  
  
  
**1**  
  
**漏洞描述**  
  
  
Apache OFBiz是美国阿帕奇（Apache）基金会的一套企业资源计划（ERP）系统。该系统提供了一整套基于Java的Web应用程序组件和工具。Apache OFBiz 18.12.14及之前版本存在安全漏洞，该漏洞源于存在授权错误漏洞，从而导致未经身份验证的端点可执行屏幕渲染代码。  
  
  
**2**  
  
**漏洞复现**  
  
  
首页  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Sf7NlfS2U5xkxM33MFTk6LL5icAKJOwwphmRnPb64neLnSUibib679pdhnW8zea95L9MA3G1ib3bLN6GHgI9ibWrSLQ/640?wx_fmt=png&from=appmsg "")  
  
  
bp发包  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Sf7NlfS2U5xkxM33MFTk6LL5icAKJOwwpqnibohQIvpqbvicUXQFCjKE2XgjACQEHzsibId5WR6co3Yib4iahnBQiaHBA/640?wx_fmt=png&from=appmsg "")  
  
  
**3**  
  
**网络测绘**  
  
  
app="Apache_OFBiz"  
  
  
**4**  
  
**漏洞POC**  
  
  
后台回复：240807  
  
本文已同步至TNT文库  
  
  
往期文章推荐  
  
[【资源分享】最新BurpSuite2024.7专业中英文开箱即用版下载](http://mp.weixin.qq.com/s?__biz=MzkzODY2ODA0OA==&mid=2247485596&idx=1&sn=d1bd47b6ab11740ef46fbbd5423e83b9&chksm=c2fdf1e3f58a78f56e41ceff571fb9f06edfeccdebb5536d3144f99134e65e8f1f0d19dd1b6c&scene=21#wechat_redirect)  
  
  
[【技术分享】记一次从弱口令到多个getshell的渗透过程](http://mp.weixin.qq.com/s?__biz=MzkzODY2ODA0OA==&mid=2247484856&idx=1&sn=172e197f6328cf487b610f024a2ec960&chksm=c2fdfcc7f58a75d115053b800e6bafc62e52858a5f0e043f6e8dc2be0860ec51f2dee6356be2&scene=21#wechat_redirect)  
  
  
[【技术分享】记一次商城主动给我0元购资格的渗透记录](http://mp.weixin.qq.com/s?__biz=MzkzODY2ODA0OA==&mid=2247485363&idx=1&sn=70023430a35f6c52fe0215a0097d2b5f&chksm=c2fdfeccf58a77da16f7c3e0f825d2dd32575b0f3130cd80aa726cb7a5299128e315bda4fd5a&scene=21#wechat_redirect)  
  
  
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
  
  
