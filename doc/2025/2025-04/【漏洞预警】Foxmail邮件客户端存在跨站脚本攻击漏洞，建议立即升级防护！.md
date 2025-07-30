#  【漏洞预警】Foxmail邮件客户端存在跨站脚本攻击漏洞，建议立即升级防护！   
原创 52  易云安全应急响应中心   2025-04-11 07:28  
  
![](https://mmbiz.qpic.cn/mmbiz_png/xufCTymBicsiciatQaIFEfGAbOTvMBuiaswvYicsJIx1Mfq5JGWLzL1NibxJ8lJVI8JTJXCp3NGOF0xX2iavDcCPbIpdA/640?wx_fmt=png "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/BV0ictYJptb0uC1vhWtPz1TYt5eWmZHymCg8tg0wXYWzYIYcS9z2Ric98RtttspEjXocTlOuciblr2iaQkliaxJInfw/640?wx_fmt=png "")  
  
  
  
漏洞预警  
  
![](https://mmbiz.qpic.cn/mmbiz_png/M5Df0SpicpuTgoRpOzcK6u0eich9iaaaTG4IkeqIqRCfJsxXHsd8w5Bv2qicjibKXcWDviaBvAdEvWdxsu4Vw4jXGpfQ/640?wx_fmt=png "")  
  
  
共/筑/网/络/安/全  
  
![](https://mmbiz.qpic.cn/mmbiz_png/9VfBEZAAlCdiaLkskRWZia0oSibVNXA6EzFFebibptK3guAvdNZ6azxPz4aoKFdDgIqXYnsq920h6tcDbnjjBH83lg/640?wx_fmt=png "")  
  
  
  
1、漏洞描述  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Gib2Yy5m2znEEuxecMNQ27OZwmdicvRkvicctYibNH30S4dYH0cS4dwmAl81AmSvJiaic8wudohwcRSPfUK6c6oeN0Yw/640?wx_fmt=png "")  
  
近日，易云科技监测到一则Foxmail邮件客户端跨站脚本攻击  
漏洞。  
  
Foxmail是我国知名电子邮件客户端之一，其上市时间自1997年第一版公测开始至今已28年，Foxmail电子邮件客户端在2005年3月16日被腾讯公司收购，由腾讯公司运行维护，支持 Windows 和 macOS 操作系统 。  
  
1.漏洞编号：  
QVD-2025-13936 ,   
CNVD-2025-06036  
  
  
2.发现时间：2025-4-11  
  
3.漏洞类型：跨站脚本  
  
4.漏洞等级：高危  
  
5.PoC/EXP：未公开  
  
6.在野利用：是  
  
2、漏洞危害  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Gib2Yy5m2znEEuxecMNQ27OZwmdicvRkvicctYibNH30S4dYH0cS4dwmAl81AmSvJiaic8wudohwcRSPfUK6c6oeN0Yw/640?wx_fmt=png "")  
  
**攻击者可利用该漏洞构造包含恶意指令代码的电子邮件，受害者在使用Foxmail打开浏览电子邮件时，无需额外点击，恶意指令代码即被用户主机加载并执行，继而主机终端即被控，具有较高的攻击隐蔽性。该漏洞利用方式简单且具备规模化利用的条件，建议受影响用户尽快修复。**  
  
3、受影响版本  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Gib2Yy5m2znEEuxecMNQ27OZwmdicvRkvicctYibNH30S4dYH0cS4dwmAl81AmSvJiaic8wudohwcRSPfUK6c6oeN0Yw/640?wx_fmt=png "")  
  
受漏洞影响的软件版本为：  
  
version<7.2.25.374 (windows)  
  
4、处置建议  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Gib2Yy5m2znEEuxecMNQ27OZwmdicvRkvicctYibNH30S4dYH0cS4dwmAl81AmSvJiaic8wudohwcRSPfUK6c6oeN0Yw/640?wx_fmt=png "")  
  
针对此漏洞,腾讯公司已紧急发布新版本修复该漏洞，建议受影响的单位和用户立即将Foxmail升级至最新版本：  
  
https://www.foxmail.com/  
  
鉴于攻击者常通过社会工程学手段（如伪装邮件标题、内容或附件）诱导用户点击，特别提醒用户：  
不要打开  
无法确认发件人身份或内容等来源不明的邮件，  
做好相关安全防范措施  
。  
  
  
5、参考链接  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Gib2Yy5m2znEEuxecMNQ27OZwmdicvRkvicctYibNH30S4dYH0cS4dwmAl81AmSvJiaic8wudohwcRSPfUK6c6oeN0Yw/640?wx_fmt=png "")  
  
```
https://mp.weixin.qq.com/s/2spz-3jU7Sk15G44EuA9qg
```  
  
  
  
声明告知  
  
本文仅供技术分享之用，请勿进行任何非法测试。对于因传播和利用本公众号"易云安全应急响应中心"所提供的信息而导致的后果和损失，使用者将承担全部责任。本公众号及作者对此不承担任何法律责任。如有侵权，请及时告知，我们将立即删除并致以诚挚的歉意。  
  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/55LhWNqR1eEIvTRaeSGqOic2WdN4owxXx4UzauQgeevfp7WbH82nic0ict9rBIHza7ZkYRxXupK0a8IIPDyicUpjPg/640 "")  
  
END  
  
  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/6aVaON9Kibf6qHRdibQTh7Bic33HXRicZowtjiavqOsjjNTNWNtssMJtfSYn6uT1PgnaWWnMlSPevI96XXRdM4tibYqQ/640?wx_fmt=other&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
**淮安易云科技有限公司-****网络安全部******  
  
我们致力于保障客户的网络安全，监控事件并采取适当措施，设计和实施安全策略，维护设备和软件，进行漏洞扫描和安全审计,团队协调处理网络攻击、数据泄露等安全事故，并负责安全服务项目实施，包括风险评估、渗透测试、安全扫描、安全加固、应急响应、攻防演练、安全培训等服务，确保客户在网络空间中的安全。  
  
**易云安全应急响应中心**  
  
专业的信息安全团队，给你最安全的保障。定期推送  
漏洞预警、技术分享文章和网络安全知识，让各位了解学习安全知识，普及安全知识、提高安全意识。  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/US10Gcd0tQHDte6ZzXiclrYUTCQHiak0k38kaD0O6NSfpyrRicr2rspyQicXCp6I4iagSbNbaKt2IiboYfRyUpnDZrtQ/640?wx_fmt=other&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/NuIcic2jibgNJzwoZYCo6ThfOoeX410mwuDxnOnv5za18VZJ7ib30pic2NSNnicziaONicvs1C9yMDr6zV40ADD9yPP7Q/640?wx_fmt=gif "")  
  
  
扫描二维码  
  
获取更多精彩  
  
欢迎关注我们  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/gMiabmiaticAtSia0prnfkWIj7vlIkbFPGibN2sUrBbqFSpgHDHhz9s0ic6smsEy0Dae8bnOUPibYNuuj4gwOyqjiac9ow/640?wx_fmt=jpeg&from=appmsg "")  
  
  
  
  
  
往期推荐  
  
  
  
[具身智能 | 揭秘颠覆未来的"肉身觉醒"革命！](https://mp.weixin.qq.com/s?__biz=MzkyNDcwMTAwNw==&mid=2247534820&idx=1&sn=5c277f54ad07fbd7634a220c9167c002&scene=21#wechat_redirect)  
  
  
[倒计时18天！网络交易数据报送新规即将落地，平台责任再升级](https://mp.weixin.qq.com/s?__biz=MzkyNDcwMTAwNw==&mid=2247534800&idx=1&sn=071644a273a8c8058e3ed9f8029b68b3&scene=21#wechat_redirect)  
  
  
[AI融入软件供应链：技术革新与安全挑战的双重变奏](https://mp.weixin.qq.com/s?__biz=MzkyNDcwMTAwNw==&mid=2247534748&idx=1&sn=858bb1ad0e7f65627faf5e4fbfbf4bed&scene=21#wechat_redirect)  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/eGU4MMop1ayFNFNmlvqbFaePA7KqafKnD4pSCwWiaraQgOAVxyAibx7D3gT50kRH8DwGI3o7UtWVf8GcicFAojVibg/640?wx_fmt=png "")  
  
分享  
  
![](https://mmbiz.qpic.cn/mmbiz_png/7cUAzic3icWt6QMNQOdQgXW3C1eibMpRQ0iaKdosJVfTyqG1DiaFfMwb4JcibsVZgSlHYOsf6RYxaC89icJ5NPeZj9BTg/640?wx_fmt=png "")  
  
收藏  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/e04oVjfBibI5Sh4ibn3ZUnjKq2p5KiaSfeXXowibTf2LTcicOr9MzlhcFwicibZoaUNV9lXqa7Y6kvZ3VlQaicDKibSnP1Q/640?wx_fmt=png "")  
  
点赞  
  
![](https://mmbiz.qpic.cn/mmbiz_png/SWHoXLyU1HicHlRus0FhAT214iaCKLGiaMexopjrq99ic7TStGL2WH7EF4ibpM681GFxvRVF61IE589II3KpXahdNsg/640?wx_fmt=png "")  
  
在看  
  
