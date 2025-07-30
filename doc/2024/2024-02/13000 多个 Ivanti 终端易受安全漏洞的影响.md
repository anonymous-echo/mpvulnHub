#  13000 多个 Ivanti 终端易受安全漏洞的影响   
疯狂冰淇淋  FreeBuf   2024-02-18 18:56  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/qq5rfBadR38jUokdlWSNlAjmEsO1rzv3srXShFRuTKBGDwkj4gvYy34iajd6zQiaKl77Wsy9mjC0xBCRg0YgDIWg/640?wx_fmt=gif&wxfrom=5&wx_lazy=1 "")  
  
  
Bleepingcomputer网站消息，数千个Ivanti Connect Secure和Policy Secure终端仍然易受到一个多月前首次披露的多个安全漏洞的影响。目前，这些漏洞已由供应商逐步修复。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR3ib92iaKAg1Us7QhPfQGrs7bCDvky7hxwVMnOav7eFB2ta8uwrW4SJ0qcerbJxXQLhJbMYIBI0PibINw/640?wx_fmt=jpeg&from=appmsg "")  
  
  
影响终端的漏洞包括CVE-2024-22024、CVE-2023-46805、CVE-2024-21887、CVE-2024-21893和CVE-2024-21888。它们的严重程度从高到关键不等，涉及的问题包括身份验证绕过、服务器端请求伪造、任意命令执行和命令注入问题。在这些漏洞被威胁行为者大规模利用之前，已有报告称一些漏洞被国家支持的威胁行为者所利用。  
  
  
上周，CVE-2024-22024漏洞首次披露，该漏洞是Ivanti Connect Secure、Policy Secure和ZTA网关的SAML组件中的一个XXE漏洞，它允许威胁行为者在未授权的情况下访问受限资源。  
  
  
目前，尚未确认有活跃的利用漏洞情况，供应商建议如果没有补丁可用，那么立即应用现有的安全更新或缓解措施至关重要。  
  
  
Akamai发布的报告中提到，已经针对这一特定漏洞发起扫描，2024年2月11日有24万个请求和80个IP尝试发送有效载荷。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR3ib92iaKAg1Us7QhPfQGrs7bCeUQUP4ZUXs0OFyQ4xjHlpjDMUu8iboB4gndswqJYcDuTJiaYcUOiaIbyw/640?wx_fmt=jpeg&from=appmsg "")  
  
  
威胁监测服务公司Shadowserver报告称，其互联网扫描显示有3900多个Ivanti终端易受到CVE-2024-22024漏洞攻击，其中大多数（1262个）终端位于美国。该公司观察到大约有1000个Ivanti终端仍然易受CVE-2024-21887漏洞的攻击，它允许经过认证的管理员通过发送特制的请求在易受攻击的设备上执行任意命令。  
  
  
2024年1月10日，该漏洞与CVE-2023-46805作为零日漏洞被首次披露，后者是一个认证绕过问题。  
  
  
Macnica的安全研究员Yutaka Sejiyama向BleepingComputer分享了他的Shodan扫描结果，报告显示截至2024年2月15日00:15 UTC，共有13636台Ivanti服务器还未应用针对CVE-2024-21893、CVE-2024-21888、CVE-2023-46805和CVE-2024-21887的补丁。2024年1月31日，Ivanti针对这4个漏洞发布了安全更新版本。  
  
  
根据研究员的说法，共有24239台Ivanti服务器暴露在互联网上，这意味着超过一半的服务器依然没有打补丁。  
  
  
关于CVE-2024-22024，该漏洞在2024年2月8日被披露并得到修复，Sejiyama的研究显示，截至2月15日，全球有77.3%的服务器已经打上了补丁，但仍有5496台服务器暴露于这个危险的未授权访问漏洞之下。  
  
  
不幸的是，影响Ivanti产品的这些漏洞在短时间内被连续披露，管理员几乎没有时间准备并应用这些补丁。这不仅增加了修复工作的复杂性，还提高了Ivanti系统因长时间处于脆弱状态而面临的风险，为威胁行为者提供了大量潜在受害者的清单。  
  
  
【  
FreeBuf粉丝交流群招新啦！  
  
在这里，拓宽网安边界  
  
甲方安全建设干货；  
  
乙方最新技术理念；  
  
全球最新的网络安全资讯；  
  
群内不定期开启各种抽奖活动；  
  
FreeBuf盲盒、大象公仔......  
  
扫码添加小蜜蜂微信回复“加群”，申请加入群聊  
】  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR3ich6ibqlfxbwaJlDyErKpzvETedBHPS9tGHfSKMCEZcuGq1U1mylY7pCEvJD9w60pWp7NzDjmM2BlQ/640?wx_fmt=jpeg&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/oQ6bDiaGhdyodyXHMOVT6w8DobNKYuiaE7OzFMbpar0icHmzxjMvI2ACxFql4Wbu2CfOZeadq1WicJbib6FqTyxEx6Q/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qq5rfBadR3icEEJemUSFlfufMicpZeRJZJ61icYlLmBLDpdYEZ7nIzpGovpHjtxITB6ibiaC3R5hoibVkQsVLQfdK57w/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
> https://www.bleepingcomputer.com/news/security/over-13-000-ivanti-gateways-vulnerable-to-actively-exploited-bugs/  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qq5rfBadR3icEEJemUSFlfufMicpZeRJZJ7JfyOicficFrgrD4BHnIMtgCpBbsSUBsQ0N7pHC7YpU8BrZWWwMMghoQ/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
[](https://mp.weixin.qq.com/s?__biz=Mzg2MTAwNzg1Ng==&mid=2247492374&idx=1&sn=0b847c8f0f000881d8efc5c646ef4181&scene=21#wechat_redirect)  
  
[](http://mp.weixin.qq.com/s?__biz=Mzg2MTAwNzg1Ng==&mid=2247492331&idx=1&sn=406428ff5a9e185e658948e896b0b4a8&chksm=ce1f1874f9689162105cf92ee082dcafbd164bbe3fb15d3bde4d4c8328c2ac2d3526fd006d84&scene=21#wechat_redirect)  
  
[](https://mp.weixin.qq.com/s?__biz=MjM5NjA0NjgyMA==&mid=2651253272&idx=1&sn=82468d927062b7427e3ca8a912cb2dc7&scene=21#wechat_redirect)  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/qq5rfBadR3icF8RMnJbsqatMibR6OicVrUDaz0fyxNtBDpPlLfibJZILzHQcwaKkb4ia57xAShIJfQ54HjOG1oPXBew/640?wx_fmt=gif&wxfrom=5&wx_lazy=1 "")  
  
