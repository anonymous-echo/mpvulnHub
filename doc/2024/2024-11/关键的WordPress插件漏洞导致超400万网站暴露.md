#  关键的WordPress插件漏洞导致超400万网站暴露   
bug胤  FreeBuf   2024-11-19 11:35  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/oQ6bDiaGhdyoFWEgZIHic7sqnootFEuOic7RlQNGhKY6d2ZESG3WpiaTMRlD0z4xO6mQrTZjkWHCkMpO2QtCfUJH6g/640?wx_fmt=gif&from=appmsg&wxfrom=5&wx_lazy=1&tp=webp "")  
  
  
据Wordfence安全研究员István Márton披露，一个关键的认证绕过了漏洞被暴露在了WordPress的Really Simple Security（以前称为Really Simple SSL）插件中，如果此漏洞被利用，攻击者可以远程获得易受攻击网站的完全管理权限。  
  
  
这个漏洞被追踪为CVE-2024-10924（CVSS评分：9.8），影响插件的免费和付费版本。该软件安装在超过400万个WordPress网站上。这个漏洞是可以脚本化的，意味着它可以被转换成大规模的自动化攻击针对WordPress网站。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qq5rfBadR39uD8TzUAG6icPT99CvicxqoBSkNWtqpz4GykYkgUZosXLbOZSBaz720OESmAoeZZOUKGNTCMopP8kA/640?wx_fmt=png&from=appmsg "")  
  
  
这个漏洞在2024年11月6日披露，在一周后发布的9.1.2版本中已被修补。  
可能是有被滥用的风险促使插件维护者与WordPress合作，在公开披露之前强制更新了所有运行此插件的网站。  
  
  
根据Wordfence的说法，这个认证绕过漏洞存在于9.0.0至9.1.1.1版本中，起因是在一个名为“check_login_and_get_user”的函数中不正确的用户检查错误处理，添加双因素认证的一个特性做得不够安全，使得未经认证的攻击者可以在双因素认证启用时，通过一个简单的请求获得对任何用户账户的访问权限，包括管理员账户。  
  
  
成功利用这个漏洞可能会有严重的后果，因为它可能允许恶意行为者劫持WordPress网站，并进一步将它们用于犯罪目的。  
  
  
这一信息是Wordfence在透露了WPLMS学习管理系统（WordPress LMS，CVE-2024-10470，CVSS评分：9.8）中的另一个关键缺陷几天后发布的，该缺陷可能允许未经认证的威胁者读取和删除任意文件。  
  
  
具体来说，4.963之前的版本由于文件路径验证和权限检查不足，这使得未经认证的攻击者能够读取和删除服务器上的任何任意文件，包括网站的wp-config.php文件。删除wp-config.php文件会使网站进入设置状态，允许攻击者通过将其连接到他们控制的数据库来发起对网站的接管。  
  
  
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
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR3ich6ibqlfxbwaJlDyErKpzvETedBHPS9tGHfSKMCEZcuGq1U1mylY7pCEvJD9w60pWp7NzDjmM2BlQ/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&retryload=2&tp=webp "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/oQ6bDiaGhdyodyXHMOVT6w8DobNKYuiaE7OzFMbpar0icHmzxjMvI2ACxFql4Wbu2CfOZeadq1WicJbib6FqTyxEx6Q/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qq5rfBadR3icEEJemUSFlfufMicpZeRJZJ61icYlLmBLDpdYEZ7nIzpGovpHjtxITB6ibiaC3R5hoibVkQsVLQfdK57w/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&retryload=2&tp=webp "")  
> https://thehackernews.com/2024/11/urgent-critical-wordpress-plugin.html  
  
  
>   
>   
>   
>   
>   
>   
>   
>   
>   
>   
>   
>   
>   
>   
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qq5rfBadR3icEEJemUSFlfufMicpZeRJZJ7JfyOicficFrgrD4BHnIMtgCpBbsSUBsQ0N7pHC7YpU8BrZWWwMMghoQ/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
[](https://mp.weixin.qq.com/s?__biz=MjM5NjA0NjgyMA==&mid=2651302087&idx=1&sn=29d91904d6471c4b09f4e574ba18a9b2&chksm=bd1c3a4c8a6bb35aa4ddffc0f3e2e6dad475257be18f96f5150c4e948b492f32b1911a6ea435&token=21436342&lang=zh_CN&scene=21#wechat_redirect)  
  
[](https://mp.weixin.qq.com/s?__biz=MjM5NjA0NjgyMA==&mid=2651302006&idx=1&sn=18f06c456804659378cf23a5c474e775&scene=21#wechat_redirect)  
  
[](https://mp.weixin.qq.com/s?__biz=MjM5NjA0NjgyMA==&mid=2651253272&idx=1&sn=82468d927062b7427e3ca8a912cb2dc7&scene=21#wechat_redirect)  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/qq5rfBadR3icF8RMnJbsqatMibR6OicVrUDaz0fyxNtBDpPlLfibJZILzHQcwaKkb4ia57xAShIJfQ54HjOG1oPXBew/640?wx_fmt=gif&wxfrom=5&wx_lazy=1&tp=webp "")  
  
