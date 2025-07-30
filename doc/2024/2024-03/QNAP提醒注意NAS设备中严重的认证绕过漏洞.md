#  QNAP提醒注意NAS设备中严重的认证绕过漏洞   
Bill Toulas  代码卫士   2024-03-11 17:54  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Az5ZsrEic9ot90z9etZLlU7OTaPOdibteeibJMMmbwc29aJlDOmUicibIRoLdcuEQjtHQ2qjVtZBt0M5eVbYoQzlHiaw/640?wx_fmt=gif "")  
  
   
聚焦源代码安全，网罗国内外最新资讯！  
  
**编译：代码卫士**  
  
**QNAP提醒称，NAS 软件产品包括 QTS、QuTS hero、QuTScloud和myQNAPcloud 中存在多个漏洞，可导致攻击者访问设备。**  
  
  
  
QNAP披露了三个漏洞，它们可导致认证绕过、命令注入和SQL注入后果。虽然后两类漏洞要求攻击者在目标系统上进行认证，从而大大降低了风险，但第一类漏洞CVE-2024-21899则可在无需认证的情况下遭远程执行，且被标记为“低复杂度”。  
  
这三个漏洞如下：  
  
- CVE-2024-21899：不当认证机制可导致越权用户通过网络（远程）攻陷系统安全。  
  
- CVE-2024-21900：该漏洞可导致认证用户通过网络在系统上执行任意命令，从而导致越权系统访问权限或控制。  
  
- CVE-2024-21901：GIA漏洞可导致认证管理员通过网络注入恶意SQL代码，从而攻陷数据库完整性并操纵其内容。  
  
  
  
这些漏洞影响QNAP操作系统的多个版本，包括QTS 5.1.x、QTS 4.5.x、QuTS hero h5.1.x、QuTS hero h4.5.x、QuTScloud c5.x和myQNAPcloud 1.0.x 服务。  
  
建议用户升级至如下已修复这些漏洞的版本：  
  
- QTS 5.1.3.2578 build 20231110 及后续版本  
  
- QTS 4.5.4.2627 build 20231225 及后续版本  
  
- QuTS hero h5.1.3.2578 build 20231110 及后续版本  
  
- QuTS hero h4.5.4.2626 build 20231225 及后续版本  
  
- QuTScloud c5.1.5.2651 及后续版本  
  
- myQNAPcloud 1.0.52 (2023/11/24) 及后续版本  
  
  
  
对于QTS、QuTS hero和QuTSchool 而言，用户必须以管理员身份登录，导航至“控制面板＞系统＞固件更新”，并点击“检查更新”来启动自动化安装流程。  
  
要更新 myQNAPcloud，则以管理员身份登录，打开“App 中心”，点击搜索框，输入 “myQNAPcloud” + ENTER 键。更新将会出现在结果中。点击“更新”按钮以启动。  
  
NAS 设备通常存储企业和个人的大量有价值数据，包括敏感的个人信息、知识财产和关键的业务数据。同时，这些数据并未得到密切监控，仍然是联网状态且暴露到互联网，并可使用过期的操作系统/固件。  
  
为此，NAS设备通常称为数据盗取和勒索的目标。某些勒索组织此前专门攻击QNAP设备如DeadBolt、Checkmate和Qlocker。这些黑客组织对NAS用户发动大量攻击，有时候会利用0day exploit来攻击完全修复的设备。  
  
对于NAS设备所有人而言，最佳实践是保持更新软件，而更好的方法是不要讲这类设备暴露到互联网。  
  
****  
  
代码卫士试用地址：  
https://codesafe.qianxin.com  
  
开源卫士试用地址：https://oss.qianxin.com  
  
  
  
  
  
  
  
  
  
  
  
  
**推荐阅读**  
  
[QNAP 修复多款产品中的多个高危漏洞](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247518617&idx=2&sn=6cbff27b3d2e598b07c8c757f85efbc9&chksm=ea94b8f3dde331e5928e7d56a7a350a64cc7d3b6e1dba9a6de9674d23f7150e1049b476b6c01&scene=21#wechat_redirect)  
  
  
[CISA：FXC 路由器和 QNAP NVR 漏洞已遭在野利用](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247518480&idx=1&sn=372723a1263ca0cbc9c63dfe1a68c98e&chksm=ea94b87adde3316c512751cc1c30531707c9315f39b8bfbad0271fe66291a58f6b5256d714fc&scene=21#wechat_redirect)  
  
  
[QNAP 修复两个严重的命令注入漏洞](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247518080&idx=2&sn=71583bf9067a3f7b1848503bf006dce0&chksm=ea94b6eadde33ffcf50e87af86318d2deea11f68e675ee8426e0d50b1d32679ca1c6499c3222&scene=21#wechat_redirect)  
  
  
[QNAP正在紧急修复两个0day，影响全球超8万设备](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247516164&idx=2&sn=00deb0a15fae5034e3bbde0e1407178b&chksm=ea94b16edde33878ac23c8677c44d1e95a6307fec34807fd13ba32689de740186ca370c72df0&scene=21#wechat_redirect)  
  
  
[QNAP 提醒用户修复 NAS 设备中的高危 Linux Sudo 漏洞](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247516096&idx=3&sn=82f067c61adcd0aa4a98ca6165d9c9d3&chksm=ea948eaadde307bc40d0015e6feadf0f1264ab387fd2b2500439ce984d5722ddf2e79da15ca4&scene=21#wechat_redirect)  
  
  
  
  
**原文链接**  
  
  
https://www.bleepingcomputer.com/news/security/qnap-warns-of-critical-auth-bypass-flaw-in-its-nas-devices/#google_vignette  
  
  
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
  
