#  【安全圈】现已修复！阿里云SQL 数据库曝两个关键漏洞   
 安全圈   2023-04-21 19:02  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/aBHpjnrGyljsJVJHhaCOeUkoze16FrNjE24yjZVib01Tl7diaq0PGm6wazJMuo3K51rsrhdiagwEDicqXQtmMQlIJQ/640?wx_fmt=jpeg "")  
  
**关键词**  
  
  
  
漏洞  
  
  
  
近日，The Hacker News 网站披露，阿里云 ApsaraDB RDS for PostgreSQL 和 AnalyticDB for PostgreQL 数据库爆出两个关键漏洞。潜在攻击者能够利用这两个漏洞破坏租户隔离保护，访问其它客户的敏感数据。  
![](https://mmbiz.qpic.cn/mmbiz_jpg/aBHpjnrGyljTubIXdbemJ554QB3reRAqAU8yJ2CmiavvHCGFxnlSrGmOJFOOJj5a0nJBEUMMRGkYTibddHWS6ibibw/640?wx_fmt=jpeg "")  
  
云安全公司 Wiz 在与 The Hacker News 分享的一份报告中表示，这两个漏洞可能允许未经授权的攻击者访问阿里云客户的 PostgreSQL 数据库，并对两个数据库服务进行供应链攻击，从而导致对阿里巴巴数据库服务的 RCE。  
  
值得一提的是，早在 2022 年 12 月阿里云就收到了漏洞报告，并于 2023 年 4 月 12 日部署了缓解措施，此外没有证据表明这些漏洞已经被野外被利用了。  
  
据悉，这不是第一次在云服务中发现 PostgreSQL 漏洞，其它云服务厂商与曾出现过。去年，Wiz 在其他多家头部云厂商中也发现了类似问题。  
## 攻击者利用漏洞可访问其它用户数据  
  
从 Wiz 研究人员透漏出的信息来看，一旦潜在攻击者成功利用 AnalyticDB 的权限升级漏洞和 ApsaraDB RDS 的远程代码执行漏洞后，便可在容器中提升权限至 root，“逃到”底层的 Kubernetes 节点，并最终获得对 API 服务器的未授权访问。  
  
不仅如此，获得上述权限后，攻击者可以从 API 服务器中检索与容器注册表相关的凭据，并推送恶意映像，以控制属于共享节点上其它租户的客户数据库。  
![](https://mmbiz.qpic.cn/mmbiz_jpg/aBHpjnrGyljTubIXdbemJ554QB3reRAq9jSiaGTVLZnEdfZTgzQZf8QxSueRHPqTPmqtKL9eeibOicvMBPbCXL0pQ/640?wx_fmt=jpeg "")  
  
据悉，这不是第一次在云服务中发现 PostgreSQL 漏洞，其它云服务厂商与曾出现过。去年，Wiz 在 Azure Database for PostgreSQL Flexible Server（ExtraReplica）和 IBM Cloud Databases for PostgreQL（Hell’s Keychain）中发现了类似问题。  
  
近几年，网络犯罪分子频频盯上云服务，从 Palo Alto Networks Unit 42 发布的《云威胁报告》的内容来看，威胁攻击者目前非常善于利用错误配置、弱凭证、缺乏认证、未修补的漏洞和恶意的开放源码软件（OSS）包等云服务常见问题。  
  
然而在如此危险的网络环境下，76% 的组织没有对控制台用户执行 MFA 多因素认证，58% 的组织没有对根/管理员用户执行 MFA。  
  
  
  
  
   END    
  
  
阅读推荐  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/aBHpjnrGyljTubIXdbemJ554QB3reRAqab0DQecx5e5ib7Bjmg8Z5GQEClJ57DBTgbRjicJ4QSYiaNaPtnSBhfzyQ/640?wx_fmt=jpeg "")  
[【安全圈】全国首例：长沙一男子植入“戒酒芯片”，管用 5 个月](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652032676&idx=1&sn=9a4b287138977c589ba952ff0efb2904&chksm=f36fe2e4c4186bf20204e3cf731bb312cf995dd78926c152b47288323ba1b46ada3ef8adaf2f&scene=21#wechat_redirect)  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/aBHpjnrGyljR5lKraSf9jwLZCNgibbBD3HmUweiajPbOXsAPHZibX7mPT4lwFAURzYc25JvzLl2faLAJH5ltDLgZg/640?wx_fmt=png "")  
[【安全圈】击穿24款杀毒软件，Money Message勒索病毒肆虐全网](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652032584&idx=1&sn=eb70ec73c5ec975d3380dd1b4354629a&chksm=f36fe208c4186b1e7a6d8eec303a68844444d99cc409dec88ba69cb080d0717150b35bfde912&scene=21#wechat_redirect)  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/aBHpjnrGylia0fH2qvzBGgJFjCAiaxicR7By1r8gx6KjAxyibUDcspBsC04ZZgHUXOkquiaVHicQtMFm9pVd09991Tmg/640?wx_fmt=png "")  
[【安全圈】元宇宙对隐私的“嗜血”变本加厉，西门子处境极其危险](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652030409&idx=3&sn=f0ed1e90be21ec20acf4e292d370dc2a&chksm=f36fe989c418609f395b2d771f88413c9213561a925c09bfd92a44f0909f40be3f571b86f878&scene=21#wechat_redirect)  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/aBHpjnrGylia0fH2qvzBGgJFjCAiaxicR7BMLPC5NbISyic99moCdnib521cGoTFCVQ42WrOCCMWDXvGnZpHB9Db7AA/640?wx_fmt=png "")  
[【安全圈】人美声甜 GPT，数学题哪里不会讲哪里](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652030409&idx=2&sn=90e658f20ef737f7b5e5b01ed5ec65a2&chksm=f36fe989c418609f55a385596c83266489845317fa6e009ecf007bc50164f6a802403fdc403c&scene=21#wechat_redirect)  
  
  
  
[【安全](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652030093&idx=4&sn=e988dc890e595695befbdb177d11b98c&chksm=f36fe8cdc41861dbd78f5270a42fca19c1d45cb375ef4469e8a36bef1f42620f990d03714872&scene=21#wechat_redirect)  
  
  
‍  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/aBHpjnrGylgeVsVlL5y1RPJfUdozNyCEft6M27yliapIdNjlcdMaZ4UR4XxnQprGlCg8NH2Hz5Oib5aPIOiaqUicDQ/640?wx_fmt=gif&wxfrom=5&wx_lazy=1 "")  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/aBHpjnrGylgeVsVlL5y1RPJfUdozNyCEDQIyPYpjfp0XDaaKjeaU6YdFae1iagIvFmFb4djeiahnUy2jBnxkMbaw/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
**安全圈**  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/aBHpjnrGylgeVsVlL5y1RPJfUdozNyCEft6M27yliapIdNjlcdMaZ4UR4XxnQprGlCg8NH2Hz5Oib5aPIOiaqUicDQ/640?wx_fmt=gif&wxfrom=5&wx_lazy=1 "")  
  
  
←扫码关注我们  
  
**网罗圈内热点 专注网络安全**  
  
**实时资讯一手掌握！**  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/aBHpjnrGylgeVsVlL5y1RPJfUdozNyCE3vpzhuku5s1qibibQjHnY68iciaIGB4zYw1Zbl05GQ3H4hadeLdBpQ9wEA/640?wx_fmt=gif "")  
  
**好看你就分享 有用就点个赞**  
  
**支持「****安全圈」就点个三连吧！**  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/aBHpjnrGylgeVsVlL5y1RPJfUdozNyCE3vpzhuku5s1qibibQjHnY68iciaIGB4zYw1Zbl05GQ3H4hadeLdBpQ9wEA/640?wx_fmt=gif "")  
  
  
