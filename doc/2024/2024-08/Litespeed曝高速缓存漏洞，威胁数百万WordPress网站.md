#  Litespeed曝高速缓存漏洞，威胁数百万WordPress网站   
小薯条  FreeBuf   2024-08-22 19:02  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/qq5rfBadR38jUokdlWSNlAjmEsO1rzv3srXShFRuTKBGDwkj4gvYy34iajd6zQiaKl77Wsy9mjC0xBCRg0YgDIWg/640?wx_fmt=gif "")  
  
  
近日，有研究人员在插件的用户模拟功能中发现了未经身份验证的权限升级漏洞 (CVE-2024-28000)，该漏洞是由 LiteSpeed Cache 6.3.0.1 及以下版本中的弱散列检查引起的。这个漏洞可能会让攻击者在创建恶意管理员账户后接管数百万个网站。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR39JWkgKTqMmZIuwHGu9Kv8h8AxzzrfBIJmEJFRkgh8zflKYOot9W1zFgic3jZK88ibwI9mUKVkVSloQ/640?wx_fmt=webp&from=appmsg "")  
  
  
  
LiteSpeed Cache 是开源的，也是最流行的 WordPress 网站加速插件，拥有超过 500 万的活跃安装量，支持 WooCommerce、bbPress、ClassicPress 和 Yoast SEO。  
  
  
本月初，安全研究员John Blackbourn向Patchstack的漏洞悬赏计划提交了该漏洞。LiteSpeed团队开发了补丁，并在 8月13日发布的LiteSpeed Cache 6.4版本中一并提供。  
  
  
一旦有攻击者成功利用该漏洞，任何未经身份验证的访问者都可以获得管理员级别的访问权限，从而通过安装恶意插件、更改关键设置、将流量重定向到恶意网站、向访问者分发恶意软件或窃取用户数据等方式，从而完全控制运行易受攻击的 LiteSpeed Cache 版本的网站。  
  
  
Patchstack 安全研究员Rafie Muhammad本周三（9月21日）解释称：目前我们能够确定，暴力攻击会遍历安全散列的所有 100 万个已知可能值，并将它们传递到 litespeed_hash cookie 中，即使以相对较低的每秒 3 个请求的速度运行，也能在几小时到一周内以任何给定用户 ID 的身份访问网站。  
  
  
唯一的先决条件是需要知道管理员级用户的 ID，并将其输入 litespeed_role cookie。确定这样一个用户的难度完全取决于目标网站，在许多情况下，用户 ID 为 1 就能成功。  
  
  
虽然开发团队在上周发布了解决这一关键安全漏洞的版本，但根据 WordPress 官方插件库的下载统计显示，该插件的下载次数仅略高于 250 万次，这可能导致一半以上使用该插件的网站受到攻击。  
  
  
今年早些时候，攻击者利用 LiteSpeed Cache 的一个未经验证的跨站脚本漏洞（CVE-2023-40000）创建了恶意管理员用户，并获得了对脆弱网站的控制权。  
  
  
今年 5 月，Automattic 的安全团队 WPScan 曾发布警告称，威胁者在看到来自一个恶意 IP 地址的 120 多万次探测后曾在4月对目标进行了大量扫描。  
  
  
他们强烈建议用户尽快用最新的 Litespeed Cache 补丁版本更新自己的网站。Wordfence威胁情报主管Chloe Chamberland今天也警告称：这个漏洞被利用的风险性极高。  
  
  
今年 6 月，Wordfence 威胁情报团队还报告称，一名威胁行为者在 WordPress.org 上至少后门了五个插件，并添加了恶意 PHP 脚本，以便在运行这些插件的网站上创建具有管理员权限的账户。  
  
  
【  
FreeBuf粉丝交流群招新啦！  
  
在这里，拓宽网安边界  
  
甲方安全建设干货；  
  
乙方最新技术理念；  
  
全球最新的网络安全资讯；  
  
群内不定期开启各种抽奖活动；  
  
FreeBuf盲盒、大象公仔......  
  
扫码添加小蜜蜂微信回复「加群」，申请加入群聊  
】  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR3ich6ibqlfxbwaJlDyErKpzvETedBHPS9tGHfSKMCEZcuGq1U1mylY7pCEvJD9w60pWp7NzDjmM2BlQ/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/oQ6bDiaGhdyodyXHMOVT6w8DobNKYuiaE7OzFMbpar0icHmzxjMvI2ACxFql4Wbu2CfOZeadq1WicJbib6FqTyxEx6Q/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qq5rfBadR3icEEJemUSFlfufMicpZeRJZJ61icYlLmBLDpdYEZ7nIzpGovpHjtxITB6ibiaC3R5hoibVkQsVLQfdK57w/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
> https://www.bleepingcomputer.com/news/security/litespeed-cache-bug-exposes-millions-of-wordpress-sites-to-takeover-attacks/  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qq5rfBadR3icEEJemUSFlfufMicpZeRJZJ7JfyOicficFrgrD4BHnIMtgCpBbsSUBsQ0N7pHC7YpU8BrZWWwMMghoQ/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
[](http://mp.weixin.qq.com/s?__biz=Mzg2MTAwNzg1Ng==&mid=2247494753&idx=1&sn=a9ee1d680adf601e9ee212fc3841387f&chksm=ce1f16fef9689fe8ad2926bc3739025b04955e5c29fee949f44be9fe8262d8723110eb50b6b9&scene=21#wechat_redirect)  
  
[](http://mp.weixin.qq.com/s?__biz=Mzg2MTAwNzg1Ng==&mid=2247494714&idx=1&sn=fe28fee45c1508a1645fd04c2b18ca82&chksm=ce1f16a5f9689fb3996529f7738a1b7dc3960f3fc5bd31c7d1505dbd3a179d5b3bfd6c66e5f3&scene=21#wechat_redirect)  
  
[](https://mp.weixin.qq.com/s?__biz=MjM5NjA0NjgyMA==&mid=2651253272&idx=1&sn=82468d927062b7427e3ca8a912cb2dc7&scene=21#wechat_redirect)  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/qq5rfBadR3icF8RMnJbsqatMibR6OicVrUDaz0fyxNtBDpPlLfibJZILzHQcwaKkb4ia57xAShIJfQ54HjOG1oPXBew/640?wx_fmt=gif&wxfrom=5&wx_lazy=1&tp=webp "")  
  
