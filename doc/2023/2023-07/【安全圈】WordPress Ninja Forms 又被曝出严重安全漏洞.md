#  【安全圈】WordPress Ninja Forms 又被曝出严重安全漏洞   
 安全圈   2023-07-29 19:00  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/aBHpjnrGylgSxa9I02IBd3bgLEhwfJCeRibw3LEjMujeAhD2CvyiaVCZJVHGHODbkPx3pViaX0sAibZsDun6sicUzdQ/640?wx_fmt=jpeg "")  
  
  
**关键词**  
  
  
  
窃取数据  
  
  
  
Bleeping Computer 网站披露，WordPress 表单构建插件 Ninja Forms 存在三个安全漏洞，攻击者可以通过这些漏洞实现权限提升并窃取用户数据  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGyljicDusIicPZ9ickwkWRK1BDwAoDmYmA2ucRveIVsdELs3xkBB9HUgI41TgeicvdPxpdEibLo3eia5vsZeQ/640?wx_fmt=png "")  
  
2023 年 6 月 22 日，Patchstack 的研究人员向插件开发者 Saturday Drive 报告了这三个漏洞详情，并警告称漏洞会影响 NinjaForms 3.6.25 及以上版本。  
  
2023 年 7 月 4 日，Saturday Drive 发布新版本 3.6.26 修复了漏洞问题，但根据 WordPress.org 统计数据显示只有大约一半的 NinjaForms 用户下载最新版本。（大约 40 万个网站仍未更新，可能存在被攻击的风险）  
## 漏洞详情  
  
Patchstack 发现的第一个漏洞是 2CVE-2023-37979，该漏洞是一个基于 POST 的反射 XSS（跨站点脚本）漏洞，允许未经身份验证的用户通过诱骗特权用户访问特制的网页，以此提升权限并窃取信息。  
  
第二个漏洞和第三个漏洞分别被跟踪为 CVE-2023-38393 和 CVE-2023-3 8386，允许订阅服务器和贡献者导出用户在受影响的 WordPress 网站上提交的所有数据。  
  
值得一提的是，以上漏洞都高度危险，尤其是 CVE-2023-38393 更是如此。任何支持会员资格和用户注册的网站，一旦使用易受攻击的 Ninja Forms 插件版本，都容易因该漏洞而发生大规模数据泄露事件。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGyljicDusIicPZ9ickwkWRK1BDwAVAg3XoCBoyO4LJ9v6icq7u2klKrTX51h1YuhR2BfmPlNLesUgM3yCibQ/640?wx_fmt=png "")  
  
  
包含 CVE-2023-38393 的处理功能  
  
Saturday Drive 在 3.6.26 版本中应用的修补程序主要包括为损坏的访问控制问题添加权限检查，以及防止触发已识别 XSS 的功能访问限制。  
  
Patchstack 报告中包含了三个漏洞的详细技术信息，因此对于懂技术的威胁攻击者来说，利用这些漏洞应该是得心应手。为防止网络攻击者利用这些漏洞，Patchstack 公开披露漏洞的时间推迟了三周多，并一再督促Ninja Form用户尽快进行修补。  
  
最后，建议所有使用 Ninja Forms 插件的网站管理员尽快更新到 3.6.26 或以上版本，如果发现未更新的用户，管理员应该从用户的网站禁用插件，直到其应用最新补丁。  
  
  
   END    
  
  
阅读推荐  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGyljicDusIicPZ9ickwkWRK1BDwAw8l90agW2iaHBkA6Vc2nwlI636UiaYvGGichf2J1BWf3yDxlGNxMHYHOw/640?wx_fmt=png "")  
[【安全圈】因网络安全事件中存在违规行为，一证券公司被警示！](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652040612&idx=1&sn=e57733c5b5ea2fb304fdfad05011d923&chksm=f36fc1e4c41848f2eb0b905e89d138b343dca310500099859107fa2a87e71719dbda27c6c850&scene=21#wechat_redirect)  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGyljicDusIicPZ9ickwkWRK1BDwASH2n4lrBl7ohuxRmpYN43YRfKKBjJSDHicUBufA1ibmlYc7z4jVuY3hw/640?wx_fmt=png "")  
[【安全圈】全球92万台！RouterOS漏洞曝光：设备面临大规模攻击](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652040612&idx=2&sn=f0543a5651872e75d69b8047d73e12b0&chksm=f36fc1e4c41848f23937fef04ce89aa8feeb7e76df05da12a8b662261747e2c5ba507a59c608&scene=21#wechat_redirect)  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGylgZ82bWqvTicJ5n8qeIYHF7jibYJmGc15cRoMcd3qMPS9MG0c7Wo03tZVIrZX5ibr6Oc5R09g1cmiaBgg/640?wx_fmt=png "")  
[【安全圈】警惕这种恶意广告，正通过谷歌和必应搜索广告传播](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652040612&idx=3&sn=4d94c75937254d8d2ea4be80fdb61185&chksm=f36fc1e4c41848f2fb3e41f45b05eb454c578992bd739ffe53f9e2746ce7e324e6e5ad4c7e0d&scene=21#wechat_redirect)  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGyljicDusIicPZ9ickwkWRK1BDwAgwfibkLibWbnuTxuQfZIvuho6AlWTia6nLVVQLeIlicxb2EClIepCAhXRQ/640?wx_fmt=png "")  
[【安全圈】美国SEC要求上市公司在确定网络攻击属于重大事件后的四个工作日内披露信息](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652040612&idx=4&sn=0e66bb7b59832ef1ffeabdc165f067f2&chksm=f36fc1e4c41848f25c9fe2ac5205252c80db34256b5ac8f77a41643b3905573a5f22b55c09a3&scene=21#wechat_redirect)  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/aBHpjnrGylgeVsVlL5y1RPJfUdozNyCEft6M27yliapIdNjlcdMaZ4UR4XxnQprGlCg8NH2Hz5Oib5aPIOiaqUicDQ/640?wx_fmt=gif "")  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/aBHpjnrGylgeVsVlL5y1RPJfUdozNyCEDQIyPYpjfp0XDaaKjeaU6YdFae1iagIvFmFb4djeiahnUy2jBnxkMbaw/640?wx_fmt=png "")  
  
**安全圈**  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/aBHpjnrGylgeVsVlL5y1RPJfUdozNyCEft6M27yliapIdNjlcdMaZ4UR4XxnQprGlCg8NH2Hz5Oib5aPIOiaqUicDQ/640?wx_fmt=gif "")  
  
  
←扫码关注我们  
  
**网罗圈内热点 专注网络安全**  
  
**实时资讯一手掌握！**  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/aBHpjnrGylgeVsVlL5y1RPJfUdozNyCE3vpzhuku5s1qibibQjHnY68iciaIGB4zYw1Zbl05GQ3H4hadeLdBpQ9wEA/640?wx_fmt=gif "")  
  
**好看你就分享 有用就点个赞**  
  
**支持「****安全圈」就点个三连吧！**  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/aBHpjnrGylgeVsVlL5y1RPJfUdozNyCE3vpzhuku5s1qibibQjHnY68iciaIGB4zYw1Zbl05GQ3H4hadeLdBpQ9wEA/640?wx_fmt=gif "")  
  
  
  
