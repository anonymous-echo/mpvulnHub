> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247523354&idx=2&sn=8ef63c9db7a5e73748eab7c71b2b5595

#  WordPress Motors 主题漏洞被大规模用于劫持管理员账号  
Bill Toulas  代码卫士   2025-06-23 10:07  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Az5ZsrEic9ot90z9etZLlU7OTaPOdibteeibJMMmbwc29aJlDOmUicibIRoLdcuEQjtHQ2qjVtZBt0M5eVbYoQzlHiaw/640?wx_fmt=gif "")  
    
聚焦源代码安全，网罗国内外最新资讯！  
  
**编译：代码卫士**  
  
**黑客正在利用位于 WordPress 主题 “Motors” 中的一个严重提权漏洞CVE-2025-4322，劫持管理员账号并完全控制目标网站。**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/oBANLWYScMTPEZXW7XQVO7Mrz8icbdjXhdMLL7gBFX6YRFoy5ms7jsZtVSia0xxDngNtQFIjicvudACenEWN8rHMw/640?wx_fmt=png&from=appmsg "")  
  
  
这起恶意活动由 Wordfence 公司发现，后者在上个月提醒用户注意该漏洞的严重性，督促用户立即升级。Motors 由 StylemixThemes 公司开发，在汽车相关网站中是非常热门的 WordPress 主题。它在 EnvatoMarket 上的销售量已达到22460件，受到活跃社区用户的支持。  
  
该提权漏洞在2025年5月2日被发现，由 Wordfence 公司在5月19日报送，影响 5.6.67及之前版本。该漏洞是因为在密码更新过程中的用户身份验证不当造成的，可导致未认证攻击者随意更改管理员密码。虽然StylemixThemes 在2025年5月14日发布Motors 5.6.68版本修复了该漏洞，但很多用户在 Wordfence 披露漏洞时未能应用该更新，因此易受提权利用风险。  
  
正如 Wordfence 公司在一份新的 writeup 中提到的那样，攻击始于5月20日，即他们公开披露详情的一天后。研究人员在2025年6月7日观测到大规模攻击，Wordfence 声称拦截了2.31万次攻击尝试。  
  
  
**攻击流程和攻陷迹象**  
  
  
  
  
  
该漏洞位于 Motors 主题的“登录注册”小部件中，而该小部件也包括密码恢复功能。  
  
攻击者首先通过特殊构造的 POST 请求刺探 /login-register、/account、/reset-password、/signin等定位到放置该小部件的 URL，直到获得点击为止。该请求在恶意值 “hash_check” 中包含无效的UTF-8字符，导致密码重置逻辑中的哈希比对错误地成功。该POST 主体中包含一个 “stm_new_password” 值用于重置用户密码，针对通常与管理员用户相对应的用户ID。  
  
截止目前从这些攻击中观察到的由攻击者设置的密码包括：  
  
- Testtest123!@#  
  
- rzkkd$SP3znjrn  
  
- Kurd@Kurd12123  
  
- owm9cpXHAZTk  
  
- db250WJUNEiG  
  
  
  
攻击者一旦获得访问权限，就会作为管理员登录到 WordPress 仪表盘并创建新的管理员账号实现持久性。此类账号的突然出现，加上现有的管理员被锁（密码无法起作用）是该漏洞遭利用的迹象。Wordfence 公司还列出了发动这些攻击的多个IP地址，并建议WordPress 网站所有人将这些地址列入拦截名单。  
  
****  
代码卫士试用地址：  
https://codesafe.qianxin.com  
  
开源卫士试用地址：https://oss.qianxin.com  
  
  
  
  
  
  
  
  
  
  
  
  
  
**推荐阅读**  
  
[黑客滥用 WordPress MU-Plugins 隐藏恶意代码](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247522638&idx=2&sn=c6153c2985c3c2631de3f8b8da79f10d&scene=21#wechat_redirect)  
  
  
[W3 Total Cache 插件漏洞导致100万WordPress站点遭暴露](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247522104&idx=2&sn=eb5266f7ac15b9afa33c145e179f4b25&scene=21#wechat_redirect)  
  
  
[12年来最严重的 WordPress 漏洞，可大规模接管管理员权限](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247521513&idx=1&sn=b60ee79ea2fbcfeaae560373faa7a2cf&scene=21#wechat_redirect)  
  
  
[WordPress 插件被安后门，用于发动供应链攻击](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247519884&idx=2&sn=394599c6e622c656ae34d0c38cb671fa&scene=21#wechat_redirect)  
  
  
[WordPress 插件 Forminator 中存在严重漏洞，影响30多万站点](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247519350&idx=1&sn=44cdd16335bfd4e16c8f57397e448771&scene=21#wechat_redirect)  
  
  
  
  
  
**原文链接**  
  
https://www.bleepingcomputer.com/news/security/wordpress-motors-theme-flaw-mass-exploited-to-hijack-admin-accounts/  
  
  
  
题图：  
Pixabay Licen  
se  
  
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
  
