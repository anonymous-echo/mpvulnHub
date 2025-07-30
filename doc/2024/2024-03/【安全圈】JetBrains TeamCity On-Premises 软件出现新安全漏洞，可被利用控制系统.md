#  【安全圈】JetBrains TeamCity On-Premises 软件出现新安全漏洞，可被利用控制系统   
 安全圈   2024-03-05 19:01  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGylgOvEXHviaXu1fO2nLov9bZ055v7s8F6w1DD1I0bx2h3zaOx0Mibd5CngBwwj2nTeEbupw7xpBsx27Q/640?wx_fmt=png&from=appmsg "微信图片_20230927171534.png")  
  
  
**关键词**  
  
  
  
安全漏洞  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGylheQ3FZNU8OmcJicDzs4XxOtia13btbIQHzXsRGibROkhzfrVg6yibJMSnwp6UIA0YzJv9Egg87DUdbFw/640?wx_fmt=jpeg&from=appmsg "")  
  
  
JetBrains TeamCity On-Premises 软件中披露了一对新的安全漏洞，威胁参与者可能会利用这些漏洞来控制受影响的系统。  
  
追踪为 CVE-2024-27198（CVSS 评分：9.8）和 CVE-2024-27199（CVSS 评分：7.3）的缺陷已在版本 2023.11.4 中得到解决。它们会影响 2023.11.3 之前的所有 TeamCity On-Premises 版本。  
  
JetBrains在周一发布的一份公告中表示：“这些漏洞可能使未经身份验证的攻击者能够通过HTTP（S）访问TeamCity服务器，从而绕过身份验证检查并获得对该TeamCity服务器的管理控制权。  
  
TeamCity Cloud 实例已经针对这两个缺陷进行了修补。网络安全公司 Rapid7 于 2024 年 2 月 20 日发现并报告了这些问题，该公司表示，CVE-2024-27198 是一种绕过身份验证的案例，允许未经身份验证的远程攻击者完全破坏易受攻击的服务器。  
  
  
该公司指出：“破坏 TeamCity 服务器可以让攻击者完全控制所有 TeamCity 项目、构建、代理和工件，因此是定位攻击者执行供应链攻击的合适载体。  
  
CVE-2024-27199 也是一个身份验证绕过缺陷，源于一个路径遍历问题，该问题可能允许未经身份验证的攻击者通过“/app/https/settings/uploadCertificate”端点将易受攻击的 TeamCity 服务器中的 HTTPS 证书替换为他们选择的证书，甚至更改 HTTPS 服务侦听的端口号。  
  
威胁参与者可利用此漏洞，通过更改 HTTPS 端口号或上传无法通过客户端验证的证书来对 TeamCity 服务器执行拒绝服务。或者，如果客户端信任上传的证书，则可以将其用于中间对手方案。  
  
“这种身份验证绕过允许在没有身份验证的情况下访问有限数量的经过身份验证的端点，”Rapid7 谈到了这个缺点。  
  
“未经身份验证的攻击者可以利用此漏洞修改服务器上有限数量的系统设置，并泄露来自服务器的有限数量的敏感信息。”  
  
  
近一个月前，JetBrains 发布了包含另一个漏洞（CVE-2024-23917，CVSS 评分：9.8）的修复程序，该漏洞还可能使未经身份验证的攻击者获得对 TeamCity 服务器的管理控制权。  
  
由于 JetBrains TeamCity 的安全漏洞去年遭到朝鲜和俄罗斯威胁行为者的积极利用，用户必须采取措施立即更新他们的服务器。  
  
  
  
  
   END    
  
  
阅读推荐  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGylheQ3FZNU8OmcJicDzs4XxOtDfA0VNe1TckXKPPYibXpo0T4AkvUfRHRo7sECgzEDxbEJ16pYJ8TetA/640?wx_fmt=jpeg "")  
[【安全圈】不背单词APP遭遇黑客攻击崩了！网友心痛：打卡要断了！](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652055141&idx=1&sn=832b16415cf3ea694d2cb3f52b403d08&chksm=f36e0a25c419833316db44c7c12743c2e2af42866964b49a40eb9f86d035df2e2af8b869a9c6&scene=21#wechat_redirect)  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGylheQ3FZNU8OmcJicDzs4XxOt98jvdJgjChbXcfzg8ictDIlqep9fkkVVLQpIYfD4FWA76you5Y8fdJw/640?wx_fmt=jpeg "")  
[【安全圈】利用AI编造“假通报”，2人被罚！](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652055141&idx=2&sn=a92e447e14c3d2b909f3f4f7b3d87ab2&chksm=f36e0a25c41983334c256b4d7cb68b44e982f3c32384ba190c9157e9bb7630a1f54b9be4977d&scene=21#wechat_redirect)  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGylheQ3FZNU8OmcJicDzs4XxOtEHZWUicLOMfvWg0NIVWERJSccn47PzYpIWZEtk2viaeJYS0qqCcwEicrg/640?wx_fmt=jpeg "")  
[【安全圈】短时间内非法获利3.5万元！3 人利用变脸软件帮人解封账号被罚](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652055141&idx=3&sn=1fadb3cd31b0b5a75ec9a06956538100&chksm=f36e0a25c41983337d47e67bc8cb4449e5dc293adb2f1e2771748c9012ba43e6bedc92999b82&scene=21#wechat_redirect)  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGylheQ3FZNU8OmcJicDzs4XxOtB8icJicRBbatxu18f77YLRd1uWMw3YAQZp7rVlADf5ibAVibtRjFynqYhQ/640?wx_fmt=jpeg "")  
[【安全圈】执法部门采取强有力手段，BlackCat 勒索软件网站已关闭](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652050429&idx=4&sn=0960ca950a61d6f7c2ad13f6a505af75&chksm=f36e3fbdc419b6ab40d8090bab5907c08298925ec11fd20dd83ae32b41797a6265b091b8653e&scene=21#wechat_redirect)  
  
  
  
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
  
  
