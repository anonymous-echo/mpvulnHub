#  联想UEFI漏洞影响数百万台笔记本电脑   
看雪学苑  看雪学苑   2022-04-20 18:11  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/1UG7KPNHN8FU1VewsrAqFyYf4ibXXx7nK6M3Hib1PKuHHLib8EjmvibaPCyriaa4s7CdLBQC1cClGEmEAbPI97IXz7g/640?wx_fmt=jpeg "")  
  
编辑：左右里  
  
  
4月18日，联想发布了一份安全公告，公布了影响其100多种笔记本电脑型号的三个统一可扩展固件接口（UEFI）安全漏洞，这些漏洞使攻击者能够在受影响的设备上部署和执行固件植入。成功利用这些漏洞可能允许攻击者禁用 SPI 闪存保护或安全启动，继而能够安装持久性恶意软件。  
  
  
这三个漏洞由ESET研究人员Martin Smolár于2021年10月11日向联想报告，已分配编号为CVE-2021-3970、CVE-2021-3971和CVE-2021-3972。联想已于2022年4月12日发布了相关补丁。  
  
  
联想在其公告中描述的三个漏洞的摘要如下：  
  
CVE-2021-3970 由于某些联想笔记本型号中的验证不足，LenovoVariable SMI Handler中存在一个潜在漏洞，使得具有本地访问权限和提升权限的攻击者有可能执行任意代码。  
  
CVE-2021-3971 在某些联想笔记本设备上的旧制造过程中使用的驱动程序被错误地包含在 BIOS 映像中，使其可能存在一个潜在漏洞，导致具有提升权限的攻击者能够通过修改 NVRAM 变量来修改固件保护区。  
  
CVE-2021-3972 在某些联想笔记本设备上，在制造过程中使用的驱动程序存在一个潜在漏洞被错误地未停用，因此具有提升权限的攻击者有可能通过修改 NVRAM 变量来修改安全启动设置。  
  
  
“UEFI威胁可能非常隐蔽和危险，它们在启动过程的早期执行，然后将控制权转移到操作系统，这意味着它们可以绕过堆栈中几乎所有可能阻止其操作系统有效负载执行的安全措施和缓解措施。”报告漏洞的ESET研究人员Martin Smolár如此说道。  
  
  
联想已发布了漏洞涉及的笔记本电脑型号的完整列表，受影响的用户应尽快按照官方说明更新系统固件版本。  
  
  
联想公告：  
  
  
https://support.lenovo.com/us/en/product_security/LEN-73440  
  
ESET研究报告：  
  
https://www.welivesecurity.com/2022/04/19/when-secure-isnt-secure-uefi-vulnerabilities-lenovo-consumer-laptops/  
  
  
  
资讯来源：联想官网、ESET  
  
转载请注明出处和本文链接  
  
  
  
**每日涨知识**  
  
零信任  
  
零信任并不是不信任，而是作为一种新的身份认证和访问授权理念，不再以网络边界来划定可信或者不可信，而是默认不相信任何人、网络以及设备，采取动态认证和授权的方式，把访问者所带来的网络安全风险降到最低。  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/b96CibCt70iaaJcib7FH02wTKvoHALAMw4fricE7hlQia8Mv9LbS3iceibFUeClFzhZpVU0A1sP0hd8HJPpNdnFv2Ok3w/640?wx_fmt=gif "")  
  
  
推荐文章++++  
  
* [Beanstalk DeFi平台遭攻击损失1.82亿美元](http://mp.weixin.qq.com/s?__biz=MjM5NTc2MDYxMw==&mid=2458438388&idx=3&sn=cf12f71f39cb6c809a3d93a6c0a8661d&chksm=b18ffa7e86f87368810388bd99a1fb2bf3dbbe366d8f007551e0a87f1289bac3e834dd17389c&scene=21#wechat_redirect)  
  
  
* [GitHub封禁俄罗斯开发人员账户](http://mp.weixin.qq.com/s?__biz=MjM5NTc2MDYxMw==&mid=2458438261&idx=2&sn=0c4ae140957a9ea126ce8516fb36c1cf&chksm=b18ffaff86f873e952f9e966e9e53529540728396c3c4f5decb3416ea81b3c68ecab013acef6&scene=21#wechat_redirect)  
  
  
* [FBI认为史上最大加密货币盗窃案是朝鲜黑客所为](http://mp.weixin.qq.com/s?__biz=MjM5NTc2MDYxMw==&mid=2458437941&idx=3&sn=5dba7075033d75dc5ac8d6efefe45212&chksm=b18ff9bf86f870a93dfd16fa360aec8be4c6f7fbac8b69b1022f8c4655b003e98e5f1a825e59&scene=21#wechat_redirect)  
  
  
* [美国加密货币专家因协助朝鲜规避美国制裁而获刑五年](http://mp.weixin.qq.com/s?__biz=MjM5NTc2MDYxMw==&mid=2458437828&idx=2&sn=2d2ee4a8b3923519bce7486eea71ae99&chksm=b18ff84e86f871589025709b53ca98dec1735a8f22dd9a52e31c87982c2ff336302f34057ddf&scene=21#wechat_redirect)  
  
  
* [欧洲刑警组织关闭世界最大黑客论坛之一RaidForums](http://mp.weixin.qq.com/s?__biz=MjM5NTc2MDYxMw==&mid=2458437802&idx=3&sn=799bb21f41b0823cfe4b13003bad3c1d&chksm=b18ff82086f871362acc72fc90c09f2622309629ebfc26921913f49834f1652caabe7ece49b2&scene=21#wechat_redirect)  
  
  
* [索尼和乐高向Epic Games投资20亿美元以协助开拓元宇宙](http://mp.weixin.qq.com/s?__biz=MjM5NTc2MDYxMw==&mid=2458437627&idx=2&sn=d9f326d4eeafa0ba4d7770bf5f8a6ec4&chksm=b18ff77186f87e672d0b1c2e1f2e0cb0e9ad298beed03df98c547eee1d6a655601d94941cb79&scene=21#wechat_redirect)  
  
  
* [损害美国超10亿美元的黑客组织乌克兰籍成员被捕](http://mp.weixin.qq.com/s?__biz=MjM5NTc2MDYxMw==&mid=2458437469&idx=2&sn=5b072342e53fc9607a53ba0c3d5bc0c7&chksm=b18ff7d786f87ec13b80f8dca8cf1571d7849343299c9514e6fa5b966799454208f6840b5ab2&scene=21#wechat_redirect)  
  
  
  
  
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
