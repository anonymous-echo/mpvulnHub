#  Mailcow Mail Server 在多个漏洞，可导致RCE攻击   
THN  代码卫士   2024-06-19 17:33  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Az5ZsrEic9ot90z9etZLlU7OTaPOdibteeibJMMmbwc29aJlDOmUicibIRoLdcuEQjtHQ2qjVtZBt0M5eVbYoQzlHiaw/640?wx_fmt=gif "")  
  
   
聚焦源代码安全，网罗国内外最新资讯！  
  
**编译：代码卫士**  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/oBANLWYScMSUwib82z7h4GCic0d11DibARPX3ibOCYNNAq9WjiciakFj8aiaMgaE5X5ticubrandicPziaZn0TFXrsCWdbaQ/640?wx_fmt=gif&from=appmsg "")  
  
**Mailcow 开源邮箱服务器套件中存在两个漏洞，可被恶意人员用于在可疑实例上实现任意代码执行后果。**  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/oBANLWYScMSUwib82z7h4GCic0d11DibARPIMyPriblDZlIUnic2E3pR1HjWCWMFAKbJboicwicpGAEMJUDHVW2IkWicJg/640?wx_fmt=gif&from=appmsg "")  
  
  
这两个漏洞影响 Mailcow 2024-04（2024年4月4日发布）之前的所有版本，由SonarSource 公司在2024年3月22日披露。  
  
这两个漏洞均为中危级别，如下：  
  
- CVE-2024-30270（CVSS评分6.7）：影响函数 “rspamd_maps()”的路径遍历漏洞，可导致攻击者在服务器上执行任意命令，通过 “www-data” 用户覆写任意文件。  
  
- CVE-2024-31204（CVSS评分6.8）：跨站脚本漏洞，当例外处理机制不在DEV_MODE 中运行时会触发。  
  
  
  
第二个漏洞产生的原因在于，系统将例外详情保存在会话数组中单并未进行正确清理或编码。这些详情随后被渲染到HTML中并在用户浏览器的 JavaScript 块中执行，并未对HTML实体进行正确逃逸。该缺陷可导致XSS攻击，攻击者可通过特殊构造的输入触发例外，将恶意脚本注入管理员面板，从而在管理员上下文中劫持会话并执行权限操作。  
  
换句话说，恶意人员可结合利用这两个漏洞控制 Malicow 服务器上的账户并获得对敏感数据的访问权限以及执行命令。在理论攻击场景中，攻击者可构建包含CSS背景镜像的HTML邮件，触发XSS payload 执行。  
  
研究员 Paul Gerste 表示，“攻击者可组合利用这两个漏洞在易受攻击的 Malicow 实例的管理员面板服务器上，执行任意代码。实现该攻击的要求是管理员用户在登录到管理员面板时需查看恶意邮件，受害者无需点击右键中的链接或者与邮件进行任何交互，而只需在查看邮件后继续使用管理员面板即可。”  
  
  
  
****  
****  
代码卫士试用地址：  
https://codesafe.qianxin.com  
  
开源卫士试用地址：https://oss.qianxin.com  
  
  
  
  
  
  
  
  
  
  
  
**推荐阅读**  
  
[开源AI框架 Ray 的0day已用于攻陷服务器和劫持资源](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247519162&idx=1&sn=3872fcc82018e2c561d9e4e7574f0c8e&chksm=ea94bad0dde333c6d504e2c7680caabb4badc973dd03223bab93d5b62e5469c4db22d966adf9&scene=21#wechat_redirect)  
  
  
[开源的IT监控软件Icinga web 中存在两个漏洞，可被用于攻陷服务器](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247511800&idx=1&sn=0f335367280974447c6dea4d856bc39b&chksm=ea949f92dde31684607d46322cc43b6250fcfe1d328aee28eae6304ec2e5d82577b9209cd75e&scene=21#wechat_redirect)  
  
  
[CISA：攻击者正在利用开源Zabbix服务器中的多个漏洞！](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247510695&idx=2&sn=295672c634bf9739529ccf7735124e13&chksm=ea949bcddde312dbfc90da2b4f555827b0b06304190bf56439b16c8f52d641640223d3ae5085&scene=21#wechat_redirect)  
  
  
[热门开源CI/CD解决方案 GoCD 中曝极严重漏洞，可被用于接管服务器并执行任意代码](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247508832&idx=1&sn=bac2576345afca50ce02e42e2b32162b&chksm=ea94920adde31b1c9de180a18739a4121c8a470d0bf9c29051e309927a9fec05601b1e7d7596&scene=21#wechat_redirect)  
  
  
[开源的代理服务器HAProxy 易遭严重的 HTTP 请求走私攻击](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247507788&idx=3&sn=57a31cb649788c04a8f3cedc547d8e8c&chksm=ea94ee26dde36730ac46f670d5524d800229b30c8e50c5afd1310a1bc7e43a7d3fefe6e25921&scene=21#wechat_redirect)  
  
  
  
  
**原文链接**  
  
  
https://thehackernews.com/2024/06/mailcow-mail-server-flaws-expose.html  
  
  
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
  
