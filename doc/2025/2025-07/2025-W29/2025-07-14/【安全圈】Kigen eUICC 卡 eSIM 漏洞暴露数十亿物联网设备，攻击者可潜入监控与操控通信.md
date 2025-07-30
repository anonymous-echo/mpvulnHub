> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652070655&idx=4&sn=376e25a95b8df163247e3bc4e44ec424

#  【安全圈】Kigen eUICC 卡 eSIM 漏洞暴露数十亿物联网设备，攻击者可潜入监控与操控通信  
 安全圈   2025-07-14 11:00  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGylgOvEXHviaXu1fO2nLov9bZ055v7s8F6w1DD1I0bx2h3zaOx0Mibd5CngBwwj2nTeEbupw7xpBsx27Q/640?wx_fmt=other&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
**关键词**  
  
  
  
安全漏洞  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGylj36aZkXSpokWicU6IbwrvWu24KwyUmK8ibzVqPrfibjPq2cQexnvETevFDibytLk1VqDia9o2yCdyDO2Q/640?wx_fmt=png&from=appmsg "")  
  
安全研究人员近日披露，一种新型攻击技术可利用 eSIM 技术中的关键缺陷，对全球范围内的智能设备构成严重威胁。该漏洞存在于 Kigen 公司生产的 eUICC（嵌入式通用集成电路卡）中。根据该公司官网，截至 2020 年 12 月，已有超过 20 亿张物联网设备 SIM 卡由其平台启用。  
  
漏洞由波兰安全研究机构 Security Explorations 披露，Kigen 向其支付了 3 万美元漏洞赏金。  
  
eSIM，即嵌入式 SIM，是通过写入 eUICC 芯片的软件形式内嵌于设备之中的数字 SIM 卡，支持用户无需物理 SIM 卡即可激活运营商服务。eUICC 软件更是具备远程配置、运营商切换和 SIM 管理等高级功能，广泛应用于智能手机、物联网终端与工业设备。  
  
研究指出，此次漏洞源于 GSMA TS.48 Generic Test Profile 规范（6.0 及更早版本），该规范主要用于 eSIM 产品的无线电合规性测试。其设计缺陷允许攻击者绕过验证机制，安装恶意 JavaCard 应用程序（applet）。Kigen 表示，TS.48 v7.0 已于上月发布，已对该问题做出修复，旧版本也已被弃用。  
  
成功利用该漏洞需满足一系列前提条件，包括攻击者必须能物理接触目标设备，并使用公开的默认测试密钥完成恶意软件注入。然而，一旦得手，攻击者将有能力提取 Kigen eUICC 的身份证书，从而解锁任意移动网络运营商（MNO）的 eSIM 配置文件，包括明文下载资料、访问机密信息、甚至对配置文件进行修改与植入至任意设备中，绕过运营商审计机制。  
  
Security Explorations 进一步指出，此次漏洞延续了其 2019 年对 Oracle Java Card 虚拟机的安全研究成果，曾发现多个可导致持久性后门部署的漏洞，部分问题同时影响 Gemalto 品牌的 SIM 卡。尽管 Oracle 当时否认其生产版本受到影响，但此次发现证明这些漏洞确实存在于现实产品中，且具备可被武器化的潜力。  
  
更令人担忧的是，该类攻击技术已完全在国家级黑客组织能力范围内。一旦得手，攻击者可将后门潜伏于设备底层，秘密监视所有通信行为。  
  
研究报告指出，攻击者甚至可以修改已下载的 eSIM 配置，使运营商彻底失去控制权——无法远程更新、禁用、甚至监控该配置的状态或行为。这意味着仅通过破解一张 eUICC 或窃取一份 eUICC 证书，攻击者就可能获取全球任意运营商用户的 eSIM 配置，并伪装成正常通信过程完成窃听和控制。  
  
Security Explorations 表示，此次发现暴露了当前 eSIM 架构在根信任链设计上的核心弱点，也为未来国家级攻击、间谍渗透与物联网威胁敲响警钟。随着 eSIM 在智能手机、工业控制、智能汽车等关键领域的广泛应用，该漏洞的潜在影响不容低估。  
  
  
 END   
  
  
阅读推荐  
  
  
[【安全圈】OpenAI 即将推出集成 AI 智能体的 Chromium 浏览器，挑战 Chrome 市场主导地位](https://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652070639&idx=1&sn=f8fe5c05daa266c8470e771cba01275f&scene=21#wechat_redirect)  
  
  
  
[【安全圈】PerfektBlue：四项蓝牙协议栈漏洞危及数百万车辆，可被远程执行代码](https://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652070639&idx=2&sn=f98a8cececf06db2add503959abb412c&scene=21#wechat_redirect)  
  
  
  
[【安全圈】印度背景黑客组织 DoNot APT 使用 LoptikMod 恶意软件攻击欧洲外交部](https://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652070639&idx=3&sn=bbaf04680a16d1922d1ac51d26b48f5a&scene=21#wechat_redirect)  
  
  
  
[【安全圈】Trendyol 披露 Meta  存在漏洞：Prompt Injection 成功率高达 50%](https://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652070639&idx=4&sn=4e7c93291c55d089867addbbd0436070&scene=21#wechat_redirect)  
  
  
  
  
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
  
  
