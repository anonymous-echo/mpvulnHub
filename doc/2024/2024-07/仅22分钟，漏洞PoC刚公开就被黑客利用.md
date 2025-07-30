#  仅22分钟，漏洞PoC刚公开就被黑客利用   
Zicheng  FreeBuf   2024-07-15 19:01  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/qq5rfBadR38jUokdlWSNlAjmEsO1rzv3srXShFRuTKBGDwkj4gvYy34iajd6zQiaKl77Wsy9mjC0xBCRg0YgDIWg/640?wx_fmt=gif "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR39ckx0sicrgribVw5qeZgSUvG9djIC0KEZkAiaN2lEv2yNjh747UOcDUFtxnF46cxwzjmseiabBZIAVUw/640?wx_fmt=jpeg&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR39ckx0sicrgribVw5qeZgSUvGQRy7xTIm0iahyYGNAXcQxIdKBfaRwl596zYiarIpXjDicNlDjgUoRl8kQ/640?wx_fmt=jpeg&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_svg/0pygn8iaZdEfON2XFbCe9JcEWQURZOgDn0uRrlxvHsA9tVzkuTY5d5J9r23E2kYg9O1pqvnhuGUv3J4cpPZpQBPeQStb7V2pz/640?wx_fmt=svg&from=appmsg "")  
  
左右滑动查看更多  
  
![](https://mmbiz.qpic.cn/mmbiz_svg/0pygn8iaZdEfON2XFbCe9JcEWQURZOgDn0uRrlxvHsA9tVzkuTY5d5J9r23E2kYg9O1pqvnhuGUv3J4cpPZpQBPeQStb7V2pz/640?wx_fmt=svg&from=appmsg "")  
  
  
  
根据 Cloudflare 发布的 2024 年应用安全报告，攻击者正越发快速地利用被公开的漏洞，甚至仅在公开后 22 分钟就将可用的概念验证（PoC）漏洞武器化。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR39ckx0sicrgribVw5qeZgSUvGqkvNq4zGRRpCmVqENtu7bzrqKZYQe9HtL2nXPias2C7mzoZ6icZDNb2A/640?wx_fmt=jpeg "")  
  
  
报告涵盖了 2023 年 5 月至 2024 年 3 月期间的活动，并突出强调了新出现的威胁趋势。期间针对性最强的漏洞是 Apache 产品中的 CVE-2023-50164 和 CVE-2022-33891，Coldfusion 中的 CVE-2023-29298、CVE-2023-38203 和 CVE-2023-26360，以及 MobileIron 中的 CVE-2023-35082。  
  
  
武器化速度加快的一个典型例子是JetBrains TeamCity 中的身份验证绕过漏洞 CVE-2024-27198，最快的攻击者在 PoC 发布 22 分钟后就部署了漏洞，使防御者基本上没有补救时机。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qq5rfBadR39ckx0sicrgribVw5qeZgSUvG86qV2ThQXias6DCkS5TYcnGlUfHF8PaZyuxj4nRDzOibTbqJlib8IaEqQ/640?wx_fmt=png&from=appmsg "")  
  
速度最快的攻击者仅在PoC发布22分钟后就实施了漏洞利用  
  
  
Cloudflare 在报告中解释称，攻击者利用已披露漏洞的速度往往快于防御者创建 WAF 规则或创建和部署补丁以缓解攻击的速度，这是由于特定的攻击者专门从事某些漏洞类别的研究，深入了解如何快速利用新披露的漏洞。  
  
  
Cloudflare表示，应对这种速度的唯一方法是利用人工智能辅助来快速制定有效的检测规则。  
  
  
**6.8% 的互联网流量是 DDoS**  
  
  
  
Cloudflare报告中另一个令人震惊的亮点是，每天所有互联网流量的6.8%是分布式拒绝服务（DDoS）流量。与前1年前（2022年-2023年）记录到的 6% 相比，这是一个显著的增长，表明 DDoS 攻击的总量有所增加。  
  
  
Cloudflare表示，在大型全球攻击事件中，恶意流量可能占所有HTTP流量的12%。  
  
  
报告还揭露了网络攻击次数的大幅增长，仅在2024 年第一季度，Cloudflare 平均每天阻止 2090 亿次网络威胁，同比增加了86.6%。  
  
  
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
> https://www.bleepingcomputer.com/news/security/hackers-use-poc-exploits-in-attacks-22-minutes-after-release/  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qq5rfBadR3icEEJemUSFlfufMicpZeRJZJ7JfyOicficFrgrD4BHnIMtgCpBbsSUBsQ0N7pHC7YpU8BrZWWwMMghoQ/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qq5rfBadR39ckx0sicrgribVw5qeZgSUvGAbrkJwVibKeINtxWQDic2HoJpvY5WBKTtgMujQrnpAXibSzIILBN2rp7Q/640?wx_fmt=png&from=appmsg "")  
  
[](http://mp.weixin.qq.com/s?__biz=Mzg2MTAwNzg1Ng==&mid=2247494575&idx=1&sn=d99b29888ba04e4e30fec8dc05be0bf9&chksm=ce1f1130f9689826eb8673fb7320d774fe4166f2a0029f738fb54188539a8044183b62f1cef0&scene=21#wechat_redirect)  
  
[](https://mp.weixin.qq.com/s?__biz=MjM5NjA0NjgyMA==&mid=2651253272&idx=1&sn=82468d927062b7427e3ca8a912cb2dc7&scene=21#wechat_redirect)  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/qq5rfBadR3icF8RMnJbsqatMibR6OicVrUDaz0fyxNtBDpPlLfibJZILzHQcwaKkb4ia57xAShIJfQ54HjOG1oPXBew/640?wx_fmt=gif&wxfrom=5&wx_lazy=1&tp=webp "")  
  
