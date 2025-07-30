#  Chrome存在高危漏洞！谷歌紧急发布安全补丁   
看雪学苑  看雪学苑   2023-04-17 17:59  
  
谷歌浏览器的用户请注意，为修补一个可能已遭利用的0day漏洞，谷歌紧急发布了Chrome的安全更新。为避免遭受损失，受影响的用户应尽快自动或手动安装该浏览器的最新版本。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8HTES0RMj0ULurgRvw7oun3icnrGuey0cpmXqJ99gQAgX8OjrjicMsrVLKuick7OjeDteSdw6CknKF7A/640?wx_fmt=png "")  
  
  
据了解，该漏洞（CVE-2023-2033）是一个存在于Chrome浏览器V8 JavaScript引擎中的类型混淆漏洞。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8HTES0RMj0ULurgRvw7oun3EE0IbqZtN7bwfPe3CEtW5luVX1CZNuu0F5xC6PEicU8zraiafiaQiccibGA/640?wx_fmt=png "")  
  
  
NIST的国家漏洞数据库（NVD）上写道：“112.0.5615.121版本之前的Google Chrome V8中的类型混淆使远程攻击者有可能通过特制的HTML页面利用堆损坏进行攻击。（Chromium安全严重性：高）”  
  
  
类型混淆漏洞通常允许攻击者通过读写缓冲区边界外的内存来触发浏览器崩溃，也可被恶意网页利用从而执行任意代码，进而劫持用户设备。特别需要注意的是，谷歌在安全公告中表示此漏洞很可能已经被黑客利用。  
  
  
我们目前无法得知关于此漏洞的更多详情，直到大部分用户安装好最新的安全更新之前，谷歌不会对此进行过多透露。  
  
  
建议谷歌浏览器用户立即升级到最新版本112.0.5615.121，另外基于 Chromium 的浏览器（例如Microsoft Edge、Brave、Opera 和 Vivaldi）的用户最好也在修复程序可用时立即进行更新。  
  
  
更新步骤：浏览器右上角点开Chrome 菜单>帮助>关于 Google Chrome  
  
检查是否已更新为最新版本112.0.5615.121。  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/M0Q2njNHVd6GKBcnbSfIlhp5oico6HA6SLoYWzCofSyM20CQMWATdDh21vLQ0zNT2ubyTMgPTWHDDqQDZghicEicg/640?wx_fmt=png "")  
  
看雪版主有话说  
  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/1UG7KPNHN8HTES0RMj0ULurgRvw7oun3icFHCstovevyOeviasURibQrvjbiaZCsJP6wGRQU5TvtMz5slvoicTTBb9g/640?wx_fmt=jpeg "")  
  
**个人Blog**  
：  
https://www.v4ler1an.com/  
  
**微信公众号**  
：  
有毒的猫  
  
**github**  
：  
https://github.com/AlexsanderShaw  
> 有毒（英文id：Ash），看雪论坛二进制漏洞板块版主，看雪二进制漏洞小组组长，养生型CTF选手，主要专注二进制安全研究，涉及Windows和Linux平台下的协议漏洞分析和挖掘、安全设备分析和漏洞挖掘、Fuzzing等，目前聚焦于虚拟化环境安全攻防实战研究。  
  
  
  
  
谷歌的Chrome浏览器目前在全球的市场份额达60%以上，遍布各个操作系统平台，其安全问题一直备受安全研究员和Hackers的关注。谷歌专门设立了针对Chrome浏览器的安全研究团队以及设立了多项Chrome安全研究奖项，希望以此来完善Chrome浏览器及其附属产品的安全属性。但是根据实际情况来看，针对Chrome浏览器的恶意攻击和非法利用，从未停止。  
  
  
虽然在安全厂商和安全研究者的努力下，普通用户的安全防护意识在逐步提高，但是针对浏览器的攻击手法成功率依然很高。针对Chrome浏览器的各种攻击，有的是利用Nday漏洞进行实现，说明有的用户并没有对Chrome浏览器进行及时的安全更新；有的是利用1day和0day漏洞进行攻击，说明官方和有关安全厂商的响应速度还不够，导致Hackers在安全补丁发布前就已经开展了漏洞的利用和传播，Chrome的各种在野攻击报告可以充分说明该问题。本次爆出的CVE-2023-2033漏洞，在安全补丁发布和大面积更新前，就被发现已经被Hackers使用。  
  
  
做好针对浏览器攻击的安全防护，是一个需要多角度、多渠道共同努力去解决的问题。从使用用户和企业角度来说，要有意识地去主动提高浏览器的自我使用安全意识，并尽可能做到安全补丁的及时更新；从安全厂商角度来说，要主动实现第三方防护策略，在浏览器自身无法进行安全防护的情况下，完成抵御浏览器攻击的安全托底；从浏览器厂商角度来说，要进一步扩大安全问题搜集途径，优化响应流程、提升响应速度，争取跑在Hackers前面。  
  
  
  
编辑：左右里  
  
资讯来源：Google、NIST  
  
转载请注明出处和本文链接  
  
  
**每日涨知识**  
  
Rootkit  
  
Rootkit 是一种程序／工具，用作夺取系统的根目录／管理员身份接达权。Rootkit 亦指  
没有通过正常授权及／或认证过程的恶意入侵。  
  
  
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
  
