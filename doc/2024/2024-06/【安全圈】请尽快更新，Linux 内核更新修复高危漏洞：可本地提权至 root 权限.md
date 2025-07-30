#  【安全圈】请尽快更新，Linux 内核更新修复高危漏洞：可本地提权至 root 权限   
 安全圈   2024-06-01 19:00  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGylgOvEXHviaXu1fO2nLov9bZ055v7s8F6w1DD1I0bx2h3zaOx0Mibd5CngBwwj2nTeEbupw7xpBsx27Q/640?wx_fmt=png&from=appmsg "微信图片_20230927171534.png")  
  
  
**关键词**  
  
  
  
系统漏洞  
  
  
美国网络安全与基础设施安全局（CISA）今天更新其已知漏洞（KEV）目录，要求联邦机构在 2024 年 6 月 20 日之前打上补丁，修复追踪编号为 CVE-2024-1086 的 Linux 内核权限提升漏洞。  
  
CVE-2024-1086 是一个高危 use-after-free 漏洞，于 2024 年 1 月 31 日首次披露，存在于 netfilter: nf_tables 组件中，相关漏洞代码于 2014 年 2 月的一项提交并入。  
  
Netfilter 是 Linux 内核提供的一个框架，允许进行各种与网络有关的操作，如数据包过滤、网络地址转换（NAT）和数据包混淆。  
  
造成该漏洞的原因是 "nft_verdict_init ()" 函数允许将正值用作钩子判定中的下拉错误，从而导致 "nf_hook_slow ()" 函数在 NF_DROP 与类似 NF_ACCEPT 的下拉错误一起发出时执行双重释放。  
  
黑客可以利用 CVE-2024-1086，在本地设备上提升权限，最高可以获得 root 级别访问权限。  
  
Linux 多个稳定版目前已经修复，安全圈附上相关版本如下：  
- v5.4.269 及更高版本  
  
- v5.10.210 及更高版本  
  
- v6.6.15 及更高版本  
  
- v4.19.307 及更高版本  
  
- v6.1.76 及更高版本  
  
- v5.15.149 及更高版本  
  
- v6.7.3 及更高版本  
  
  
  
   END    
  
  
阅读推荐  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGyljIcoiaBDoGQ3rfbOWqAeZYmfyTZMAqcwicAEVCibBu9nbOia2xJfo4PMtdobC5zerL0lbn1PRzgWv4EA/640?wx_fmt=webp&from=appmsg "")  
[【安全圈】境外谍报人员用假身份在网络平台寻猎！国家安全部披露窃密案](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652060928&idx=1&sn=c9d4c54f8bb010157a94b779ed3f6763&chksm=f36e1140c4199856038ff5eecaaa0af154f46aaaead0fa83715f5517977e0219ea5439abb98a&scene=21#wechat_redirect)  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGyljIcoiaBDoGQ3rfbOWqAeZYmIDXicJRPTd1vciax52EgQfv35elA7EicjCXiaa5ZQbBAVH4P1x3JPgxxJw/640?wx_fmt=png&from=appmsg "")  
[【安全圈】请警惕 Office 破解器，黑客用于分发“全家桶”恶意软件](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652060928&idx=2&sn=7738462e41eb46eb60816dbca657245e&chksm=f36e1140c41998568f0172179e621eaf66755edac81f1cf1ebe6a4b3888eaffc9931d3d68a55&scene=21#wechat_redirect)  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGyljIcoiaBDoGQ3rfbOWqAeZYmIfkfplK0EAkszyt47ILPuFdeQMgKL8lAluPAW8qMCB4hU1bcMia9N4Q/640?wx_fmt=jpeg "")  
[【安全圈】50 万客户受影响，拍卖行佳士得遭遇网络攻击](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652060928&idx=3&sn=24f10216dbeb39f96a37eb26b5ab8707&chksm=f36e1140c41998568960dfb19fe952a1f06da66829aee3a3a9eca69308b069033f7b7db6118d&scene=21#wechat_redirect)  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGyljIcoiaBDoGQ3rfbOWqAeZYmdGOhiaBV8ZKHJvj5CtUwClsegTptbsQPdn98o5n21Aj36IkGezYUdtg/640?wx_fmt=png&from=appmsg "")  
[【安全圈】美国最大票务网站 Ticketmaster 遭黑客入侵，消息称 5.6 亿客户信息流向暗网黑市](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652060928&idx=4&sn=f2d8dc93a6155a2a92a8db3148b35d5b&chksm=f36e1140c4199856cfdf7f6fe9794fdcf8c26069bf14ff1852b6b70a22ccbb9c5ea601a621df&scene=21#wechat_redirect)  
  
  
  
  
  
  
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
  
