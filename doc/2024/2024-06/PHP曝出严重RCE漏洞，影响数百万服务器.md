#  PHP曝出严重RCE漏洞，影响数百万服务器   
看雪学苑  看雪学苑   2024-06-12 18:34  
  
PHP是一种广泛用于Web开发的流行开源脚本语言。  
最近安全公司DEVCORE在Windows版PHP中发现了一个严重远程代码执行（RCE）漏洞，所有在Windows操作系统上以CGI模式安装的PHP都受影响，可能危害全球数百万服务器。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8Fgp5LpLicJzyZBcAObibW18fdek6K7qc1dqviap898e0KefeUCiaibdfibuKAkicfBgDvnrZDH5xzqT0tag/640?wx_fmt=png&from=appmsg "")  
  
  
  
根据DEVCORE公告，该漏洞与另一个漏洞CVE-2012-1823有着深刻联系。——PHP团队在Windows操作系统编码转换的Best-Fit功能中存在疏漏，使得攻击者可以通过特定字符序列绕过先前对CVE-2012-1823的补丁保护。因此，  
未经身份验证的攻击者可以通过参数注入攻击在远程PHP服务器上执行任意代码，从而允许其完全控制受影响的服务器。  
  
  
DEVCORE研究人员Orange Tsai于2024年5月7日向PHP开发团队报告了CVE-2024-4577漏洞。对此的补丁已于2024年6月6日发布。据Shadowserver和GreyNoise的研究人员报告，自漏洞披露以来，有多个恶意行为者正在尝试利用该漏洞。  
  
  
DEVCORE在公告中表示，截至目前，已经验证当Windows运行在以下语言环境时，未经授权的攻击者可以直接在远程服务器上执行任意代码：繁体中文、简体中文和日语。对于运行在其他语言环境的Windows，目前无法完全枚举和消除所有潜在的利用场景。因此，建议所有用户都将PHP更新到最新版本以确保安全。公告中还指出，由于PHP CGI是一个过时且存在问题的架构，建议迁移到更安全的架构，如Mod-PHP、FastCGI或PHP-FPM。  
  
  
DEVCORE研究人员说道：“这个漏洞非常简单，但这也正是其有意思的地方——谁会想到一个已审查通过并被证明安全的补丁在过去12年中竟然可以被绕过，仅仅是因为一个微小的Windows功能？”  
  
  
  
编辑：左右里  
  
资讯来源：DEVCORE  
  
转载请注明出处和本文链接  
  
  
  
﹀  
  
﹀  
  
﹀  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/Uia4617poZXP96fGaMPXib13V1bJ52yHq9ycD9Zv3WhiaRb2rKV6wghrNa4VyFR2wibBVNfZt3M5IuUiauQGHvxhQrA/640?wx_fmt=jpeg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/1UG7KPNHN8E9S6vNnUMRCOictT4PicNGMgHmsIkOvEno4oPVWrhwQCWNRTquZGs2ZLYic8IJTJBjxhWVoCa47V9Rw/640?wx_fmt=gif "")  
  
**球分享**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/1UG7KPNHN8E9S6vNnUMRCOictT4PicNGMgHmsIkOvEno4oPVWrhwQCWNRTquZGs2ZLYic8IJTJBjxhWVoCa47V9Rw/640?wx_fmt=gif "")  
  
**球点赞**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/1UG7KPNHN8E9S6vNnUMRCOictT4PicNGMgHmsIkOvEno4oPVWrhwQCWNRTquZGs2ZLYic8IJTJBjxhWVoCa47V9Rw/640?wx_fmt=gif "")  
  
**球在看**  
  
****  
****  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/1UG7KPNHN8FxuBNT7e2ZEfQZgBuH2GkFjvK4tzErD5Q56kwaEL0N099icLfx1ZvVvqzcRG3oMtIXqUz5T9HYKicA/640?wx_fmt=gif "")  
  
戳  
“阅读原文  
”  
一起来充电吧！  
  
