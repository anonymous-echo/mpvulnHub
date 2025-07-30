#  开源web应用中存在三个XSS漏洞，可导致系统遭攻陷   
Jessica Haworth  代码卫士   2022-08-03 17:40  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Az5ZsrEic9ot90z9etZLlU7OTaPOdibteeibJMMmbwc29aJlDOmUicibIRoLdcuEQjtHQ2qjVtZBt0M5eVbYoQzlHiaw/640?wx_fmt=gif "")  
  
   
聚焦源代码安全，网罗国内外最新资讯！  
  
**编译：代码卫士**  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/oBANLWYScMQZlfZPYlNMLcY0Au5oOjicKq4xyY0Go7dZ4qYibQezy2l674IcBypDSYKrYt7HM0UvSWBZwWoA6BXQ/640?wx_fmt=gif "")  
  
**PT Swarm 公司的研究人员在热门的开源开发应用Evaluation CMS、FUDForum 和 GitBucket中发现了三个跨站脚本 (XSS) 漏洞，它们可导致远程代码执行后果。**  
  
传统的XSS攻击可导致攻击者在受害者浏览器中执行攻击者的JavaScript 代码，从而导致cookie遭窃取、重定向到钓鱼站点等。  
  
Web 安全研究员 Aleksey Solovev 表示，自己的研究与“在管理员面板中结合执行XSS攻击的可能性和内置文件管理器（或执行SQL查询）如何可导致系统遭完全攻陷”有关。  
  
  
**三个威胁**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/oBANLWYScMQZlfZPYlNMLcY0Au5oOjicKh6ogmsEmwFnXMVibvpP3EARxiaTSo3gQBDe8r1ygbx8icQ1BPIWkgV0NA/640?wx_fmt=png "")  
  
  
  
第一个漏洞位于 Evolution CMS v3.1.8中，可导致攻击者在管理员面板的多个地方执行反射型XSS。Solovev 指出，“攻击者可试图强制系统管理员通过社工点击恶意链接，从而导致在受攻击浏览器中执行恶意 JavaScript 代码。攻击者可使用内置文件管理器覆写可执行文件，完全攻陷系统。”  
  
第二个漏洞位于 FUDforum v3.1.1中，可导致恶意人员以私密信息中附加文件的名义执行存储型XSS攻击。Solovev 表示，“攻击者可以附加文件的名义向具有恶意payload 的管理员发送私密信息。当管理员读取该消息时，其浏览器将执行 JavaScript 代码，并且通过使用内置文件管理器可创建可执行文件，导致攻击者在服务器上执行命令。”  
  
第三个漏洞位于 GitBucket v 4.37.1中，可导致攻击者在“多个地方”执行存储型XSS 攻击。攻击者必须在公共库中创建一个issue，并将 JavaScript 代码注入该任务中。这一事件将展示在常规推送和攻击者资料中。而这些地方正是对带有恶意加载器的任务名称的不安全展示，从而导致在查看这些页面的所有人的浏览器中执行 JavaScript 代码。Solovev 解释称，“在管理员面板，可执行基于 H2 Database Engine 的 SQL 代码，而且已存在相关exploit 可在服务器上执行命令。攻击者可利用这些点攻击管理员并获得在服务器上执行命令的能力。”  
  
  
**补丁已发布**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/oBANLWYScMQZlfZPYlNMLcY0Au5oOjicKh6ogmsEmwFnXMVibvpP3EARxiaTSo3gQBDe8r1ygbx8icQ1BPIWkgV0NA/640?wx_fmt=png "")  
  
  
  
虽然这三个漏洞均未获得CVE编号，但已由项目维护人员修复。  
  
Solovev 表示，发现这些漏洞的最大困难之处在于发现执行XSS攻击的可能性。他解释称，“接下来的步骤更加容易，因为攻击者已经拥有管理面板中文件管理器形式的合法功能的exploit。”  
  
更多详情可见：  
https://swarm.ptsecurity.com/researching-open-source-apps-for-xss-to-rce-flaws/  
。  
  
  
****  
****  
  
代码卫士试用地址：  
https://codesafe.qianxin.com  
  
开源卫士试用地址：  
https://oss.qianxin.com****  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
**推荐阅读**  
  
[](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247513172&idx=1&sn=5c228a525bd6eb94d24f697d88af3c6d&chksm=ea94853edde30c2897319ed8aac13685ecca7d05bf4ecdee1d9b30c9d7f4faf24df0c1a993d2&scene=21#wechat_redirect)  
[在线阅读版：《2022中国软件供应链安全分析报告》全文](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247513174&idx=1&sn=e474d1ea23ed7cce10e2ae2f872fc003&chksm=ea94853cdde30c2a963cfa00a536764ea55cdee7ba6ef4a7716a28f82a97ca630dc271ee5224&scene=21#wechat_redirect)  
  
  
[奇安信发布《2022中国软件供应链安全分析报告》 谁会成为下一个Log4j2？](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247513172&idx=1&sn=5c228a525bd6eb94d24f697d88af3c6d&chksm=ea94853edde30c2897319ed8aac13685ecca7d05bf4ecdee1d9b30c9d7f4faf24df0c1a993d2&scene=21#wechat_redirect)  
  
  
[在线阅读版：《2021中国软件供应链安全分析报告》全文](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247505380&idx=1&sn=01d2f5af200abc6bb20411ee8f17b6b5&chksm=ea94e48edde36d98f20b66aecf9f359e49226b411872bcea527fcca0a5de018f407415313800&scene=21#wechat_redirect)  
  
  
[开源软件 LibreOffice 修复多个与宏、密码等相关的漏洞](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247513283&idx=1&sn=5fbd02e0f95926cab449829326e0a8a1&chksm=ea9485a9dde30cbf0fb5e64dcbabdcbc1486306bbf9305df01d0f12022f30b84421fe09b167c&scene=21#wechat_redirect)  
  
  
[](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247512788&idx=1&sn=e187454b1e7105eca3d4a6988c305073&chksm=ea9483bedde30aa831b27a1729e393da823f28bb3b86c526f3c936e95d2d9c1d928b50b2db9d&scene=21#wechat_redirect)  
  
[LibreOffice、OpenOffice 漏洞可导致黑客欺骗已签名文档](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247508311&idx=2&sn=899f14c24e31f33cfc90889201aa3be1&chksm=ea94903ddde3192b9459d6bb8641bdbbf1603b8562da53544018a29dcc8895b7df2c33cc1223&scene=21#wechat_redirect)  
  
  
[补丁打补丁：利用3个新漏洞绕过 LibreOffice 2个严重缺陷的补丁](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247490605&idx=2&sn=eff58c7e253fd743170fc500cf54ed0e&chksm=ea972d47dde0a451f09ae849b3d65db601a52ca1bf35093546efb613d5e6e04df0cb1980222f&scene=21#wechat_redirect)  
  
  
[LibreOffice 被曝漏洞，打开文档即导致电脑被黑](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247490492&idx=2&sn=34c3adb5c2c8b1946fb8ad2db49e66a3&chksm=ea972ad6dde0a3c062edccc5f5ace2b2c4b1b0773a593277f484e340e2b30da7c079e0c60799&scene=21#wechat_redirect)  
  
  
  
  
**原文链接**  
  
https://portswigger.net/daily-swig/trio-of-xss-bugs-in-open-source-web-apps-could-lead-to-complete-system-compromise  
  
  
题图：  
Pixabay License  
‍  
  
  
  
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
