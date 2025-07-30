#  严重PHP漏洞使威联通设备面临远程代码执行风险   
看雪学苑  看雪学苑   2022-06-24 18:08  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8FXDJaaLWyZx7MHTRFKyc5Dy6hjdXricFDS1m76FMpBjt0y008KYBaiceZ4fByDdPicv8zicxiceQ9k1BA/640?wx_fmt=png "")  
  
  
编辑：左右里  
  
  
台湾网络附属存储（NAS）设备制造商威联通QNAP于周三表示，它正在修复一个已经存在三年的关键PHP漏洞（编号为CVE-2019-11043，CVSS评分9.8），该漏洞可能被滥用以实现远程代码执行。  
  
  
遭披露的该漏洞的影响范围为：PHP版本低于7.1.33的7.1.x，低于7.2.24的7.2.x，低于7.3.11的7.3.x，并且nginx配置不正确。在 FPM 设置的某些配置中，可能会触发与为 FCGI 协议数据保留的内存空间相关的缓冲区溢出漏洞，从而导致远程代码执行。  
  
  
CVE-2019-11043 漏洞会影响使用以下 QNAP 操作系统版本的设备：  
  
QTS 5.0.x 及更高版本；  
  
QTS 4.5.x 及更高版本；  
  
QuTS hero h5.0.x 及更高版本；  
  
QuTS hero h4.5.x 及更高版本；  
  
QuTScloud c5.0.x 及更高版本。  
  
  
要利用这个漏洞，需要nginx和php-fpm都在运行。威联通指出，QTS、QuTS hero 和 QuTScloud 在默认情况下没有安装 nginx，因此NAS 设备在默认配置中不受影响。但如果用户已经在 NAS 上安装并运行 nginx 和 php-fpm，则很可能受到影响。  
  
  
威联通表示已解决以下操作系统版本中的漏洞：  
  
QTS 5.0.1.2034 build 20220515 及更高版本；  
  
QuTS hero h5.0.0.2069 build 20220614 及更高版本。  
  
  
并将尽快发布其余操作系统版本的安全更新。  
  
  
值得注意的是，据报道最近存在针对威联通网络附属存储 （NAS） 设备的新 ech0raix 勒索软件活动。在5月份，威联通也警告了客户有新一波DeadBolt勒索软件攻击，并敦促他们安装最新更新。  
  
  
除了敦促客户升级到最新版本的QTS或QuTS hero操作系统，威联通还建议这些设备不要暴露在互联网上。  
  
  
  
  
资讯来源：thehackernews  
  
转载请注明出处和本文链接  
  
  
  
**每日涨知识**  
  
暗链  
  
也称黑链，是黑帽SEO的作弊手法之一。目的就是利用高权重网站外链来提升自身站点排名。暗链是由攻击者入侵网站后植入的，且在网页上不可见或极易被忽略。但是搜索引擎仍然可以通过分析网页的源代码收录这些链接，以此迅速提高自身网站权重，获得高额流量。  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/b96CibCt70iaaJcib7FH02wTKvoHALAMw4fricE7hlQia8Mv9LbS3iceibFUeClFzhZpVU0A1sP0hd8HJPpNdnFv2Ok3w/640?wx_fmt=gif "")  
  
  
推荐文章++++  
  
* [Lookout发现在哈萨克斯坦使用的Android间谍软件](http://mp.weixin.qq.com/s?__biz=MjM5NTc2MDYxMw==&mid=2458454336&idx=2&sn=c0495714be01d0b4e12ae41d5429ec0f&chksm=b18e39ca86f9b0dc355bf35cb16a3f579abfedb2db831c498e387a819d33defc49c99b91df82&scene=21#wechat_redirect)  
  
  
* [德国指控俄罗斯黑客对北约智库进行网络间谍攻击](http://mp.weixin.qq.com/s?__biz=MjM5NTc2MDYxMw==&mid=2458454249&idx=2&sn=8d82cbc1766f772753808e100dfa77ff&chksm=b18e386386f9b1756f7d09d8bbe85123d87399a17c46ab9c8f6bf89824cb33bda5faa36cc498&scene=21#wechat_redirect)  
  
  
* [热搜爆了！学习通数据库疑发生信息泄露，超1.7亿数据被非法售卖](http://mp.weixin.qq.com/s?__biz=MjM5NTc2MDYxMw==&mid=2458453650&idx=2&sn=2210c6ffd79a76eb6e3523ff11a81fd8&chksm=b18e361886f9bf0e42212dda09bf8dd0966232329e35c3b78a36ecf78cf46ae0485342c42cc8&scene=21#wechat_redirect)  
  
  
* [Claroty披露西门子工业网络管理系统15个漏洞](http://mp.weixin.qq.com/s?__biz=MjM5NTc2MDYxMw==&mid=2458453618&idx=3&sn=894833c98103a5d1549c7bd43509c3a0&chksm=b18e36f886f9bfeebb81a9dc3cb0232d1d37994cab8d0695e93d96bb0c73497fab11fcb92ae7&scene=21#wechat_redirect)  
  
  
* [抓捕两千人！国际刑警组织打击电信和社会工程学诈骗](http://mp.weixin.qq.com/s?__biz=MjM5NTc2MDYxMw==&mid=2458453196&idx=3&sn=f92c29eb5f0a74bdbd100365b96e987e&chksm=b18e344686f9bd5094ac02cc70156bf8c5a92b9cbc94c2057d81fe041fa3a3cc81aa9325f9de&scene=21#wechat_redirect)  
  
  
* [2022年暗网黑市商品现状](http://mp.weixin.qq.com/s?__biz=MjM5NTc2MDYxMw==&mid=2458452682&idx=2&sn=d02fbc760fad7cc7f54cb98216fb6cbb&chksm=b18e324086f9bb56f17bbfd63324b39e05f642d802a17ee86f6d98160e97da93ffc8e89f36b7&scene=21#wechat_redirect)  
  
  
* [美国国防承包商计划收购间谍软件公司NSO](http://mp.weixin.qq.com/s?__biz=MjM5NTc2MDYxMw==&mid=2458452452&idx=2&sn=7bbcd78d5bf9ea84a49fd199fe79ad2e&chksm=b18e316e86f9b8786e30f3abea85b2e5cce5de0260cbfff326ded9588f173ccef300938ba1bc&scene=21#wechat_redirect)  
  
  
  
  
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
