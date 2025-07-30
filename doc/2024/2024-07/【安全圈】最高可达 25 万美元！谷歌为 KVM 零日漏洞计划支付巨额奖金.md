#  【安全圈】最高可达 25 万美元！谷歌为 KVM 零日漏洞计划支付巨额奖金   
 安全圈   2024-07-04 19:01  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGylgOvEXHviaXu1fO2nLov9bZ055v7s8F6w1DD1I0bx2h3zaOx0Mibd5CngBwwj2nTeEbupw7xpBsx27Q/640?wx_fmt=png&from=appmsg "微信图片_20230927171534.png")  
  
  
**关键词**  
  
  
  
系统漏洞  
  
  
> 2023 年 10 月，为提高基于内核的虚拟机（KVM）管理程序的安全性，谷歌推出一项新的漏洞奖励计划（VRP）——kvmCTF。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGyliaDLQW996nP0FknIKIIsrFDEpGogw6zzvHQhTiaPsFgYxVYQ3Z6iaYAEibeMes2BqsasBXpLPQnGU5Ng/640?wx_fmt=jpeg&from=appmsg "")  
> 据悉，KVM 是一个开源管理程序，目前已有超过 17 年的发展历史，是消费者和企业环境中的一个重要组件，为安卓和谷歌云平台提供动力。作为 KVM 的积极和重要贡献者，谷歌开发了 kvmCTF 作为一个协作平台，帮助识别和修复安全漏洞。  
  
  
与谷歌针对 Linux 内核安全漏洞的 kernelCTF 漏洞奖励计划一样，kvmCTF 的重点是基于内核的虚拟机（KVM）管理程序中的虚拟机可触及安全漏洞，参加该计划的安全研究人员将获得一个可控的实验室环境，以便其展示其捕获可利用安全漏洞的标志。  
  
值得注意的是，与其他漏洞奖励计划不同，kvmCTF 仅仅专注于零日安全漏洞，不会奖励针对已知漏洞的漏洞利用。kvmCTF 的奖励级别如下：  
> 完全虚拟机逃逸：25 万美元；任意内存写入：100000 美元；任意内存读取：50000 美元；相对内存写入：50000 美元；拒绝服务：20000 美元；相对内存读取：10000 美元。  
  
  
谷歌软件工程师 Marios Pomonis 表示，参赛者可以预约访问客户虚拟机的时间段，并尝试执行客户对主机攻击，但是其攻击的目的必须是利用主机内核 KVM 子系统中的零日漏洞。如果攻击成功，“攻击者”将获得一个标志，以证明其成功利用了安全漏洞。kvmCTF 计划会根据攻击的严重程度决定奖励金额的大小。（注意：只有在上游补丁发布后，谷歌才会收到已发现零日漏洞的详细信息，以确保与开源社区同步共享信息）  
  
最后，谷歌方面强调，在开始参与 kvmCTF 计划前，参与者必须查看、了解清楚 kvmCTF 的各项规则，其中包括有关预订时间段、连接到客户虚拟机、获取标志、将各种 KASAN 违规行为映射到奖励层级的信息，以及报告漏洞的详细说明。  
  
  
END  
  
  
阅读推荐  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGyliaDLQW996nP0FknIKIIsrFDibZEsOM03aUUYwTqhZA82GWKABZAPsBicW1Aac8bDnAqmf2vDXLtXd6Q/640?wx_fmt=jpeg "")  
[【安全圈】可获 root 权限，思科 NX-OS 零日漏洞修复已发布](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652062520&idx=1&sn=fe43c7a39bc5a06b1c4e2934de8517d3&chksm=f36e6f78c419e66eb25c48ea0339a6f5741303ec3bc98d3ccd0573700ecddfbbb7d4fc4bb35c&scene=21#wechat_redirect)  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGylg5HmJHohtKbicUic2JlWJ2xGHufmrtVGbQhpMfGrA4AZxWWTX7XwgqA0lHPQS50TdQlZoPy1UiaPuMw/640?wx_fmt=jpeg&from=appmsg "")  
[【安全圈】Windows 修复漏洞遭利用，推送恶意脚本](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652062520&idx=2&sn=764d34aa1130ed7f83bd837c6a514c0e&chksm=f36e6f78c419e66e413059b9aaa771ab1b665e91d98232c678435a787fa8d94713d0da0c9480&scene=21#wechat_redirect)  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGylg5HmJHohtKbicUic2JlWJ2xGIIkVKm4WbdN2wsKVTd0tHQiacN8F9t39dJ625FCiaNb4nhGJCT4dib8Vg/640?wx_fmt=jpeg&from=appmsg "")  
[【安全圈】巴基斯坦 CapraRAT 间谍软件伪装成热门应用程序威胁印度 Android 用户](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652062520&idx=3&sn=cd92e458da23905410eb6214c8aeddef&chksm=f36e6f78c419e66efacfa38611d38f8a4f09ee2185cffe39a40e5038f26d70cdc5eb690b3827&scene=21#wechat_redirect)  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGyliaDLQW996nP0FknIKIIsrFD3VwzNKKXfrFofVmNpN9FDv7oicUk0TrIOG4Hzqrq8Dt0nF0qZEOwlkw/640?wx_fmt=jpeg "")  
[【安全圈】Juniper 警告存在严重身份验证绕过漏洞（CVE-2024-2973，CVSS 评分为 10）](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652062520&idx=4&sn=33ecb849545820707a62bfcb0b8c9a95&chksm=f36e6f78c419e66eebbbded12a5cc5f0ec54f274fdd57fa651a96f8090a6cf2cb8b0bddfd7b0&scene=21#wechat_redirect)  
                                                            
  
  
  
  
  
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
  
