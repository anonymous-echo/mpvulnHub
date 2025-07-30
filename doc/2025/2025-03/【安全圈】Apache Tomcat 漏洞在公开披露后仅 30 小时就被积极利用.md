#  【安全圈】Apache Tomcat 漏洞在公开披露后仅 30 小时就被积极利用   
 安全圈   2025-03-18 19:02  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGylgOvEXHviaXu1fO2nLov9bZ055v7s8F6w1DD1I0bx2h3zaOx0Mibd5CngBwwj2nTeEbupw7xpBsx27Q/640?wx_fmt=other&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
**关键词**  
  
  
  
安全漏洞  
  
  
![Apache Tomcat 漏洞](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGyljJ8ibSlAvEEWEHwFwpUn3XxpnLmdWQdm9J0wb7tx1OM6ObKAovnV9bUUMlpomDSsWia0xtSeyS1BIw/640?wx_fmt=other&from=appmsg "")  
  
  
最近披露的一个影响 Apache Tomcat 的安全漏洞在公开披露仅 30 小时后就被公开概念验证 (PoC)发布，并遭到广泛利用。  
  
该漏洞编号为CVE-2025-24813，影响以下版本 -  
- Apache Tomcat 11.0.0-M1 至 11.0.2  
  
- Apache Tomcat 10.1.0-M1 至 10.1.34  
  
- Apache Tomcat 9.0.0-M1 至 9.0.98  
  
它涉及在满足特定条件时执行远程代码或泄露信息的情况 -  
- 为默认 servlet 启用写入（默认情况下禁用）  
  
- 支持部分 PUT（默认启用）  
  
- 安全敏感上传的目标 URL，是公开上传的目标 URL 的子目录  
  
- 攻击者知道正在上传的安全敏感文件的名称  
  
- 安全敏感文件也通过部分 PUT 上传  
  
成功利用该漏洞可能允许恶意用户查看安全敏感文件或通过 PUT 请求向这些文件中注入任意内容。  
  
此外，如果以下所有条件都成立，攻击者可以实现远程代码执行 -  
- 为默认 servlet 启用写入（默认情况下禁用）  
  
- 支持部分 PUT（默认启用）  
  
- 应用程序使用 Tomcat 基于文件的会话持久性和默认存储位置  
  
- 应用程序包含一个可能被反序列化攻击利用的库  
  
在上周发布的公告中，项目维护人员表示该漏洞已在 Tomcat 版本 9.0.99、10.1.35 和 11.0.3 中得到解决。  
  
但令人担忧的是，据 Wallarm 称，该漏洞已在野外遭到利用。  
  
该公司表示：“此次攻击利用了 Tomcat 的默认会话持久机制及其对部分 PUT 请求的支持。”  
  
“该漏洞分为两个步骤：攻击者通过 PUT 请求上传序列化的 Java 会话文件。攻击者通过在 GET 请求中引用恶意会话 ID 来触发反序列化。”  
  
换句话说，攻击需要发送一个 PUT 请求，其中包含一个 Base64 编码的序列化 Java 有效负载，该负载被写入 Tomcat 的会话存储目录，随后在反序列化过程中通过发送带有指向恶意会话的 JSESSIONID 的 GET 请求来执行。  
  
Wallarm 还指出，该漏洞很容易利用，无需身份验证。唯一的先决条件是 Tomcat 使用基于文件的会话存储。  
  
“虽然此漏洞滥用了会话存储，但更大的问题是 Tomcat 中的部分 PUT 处理，这允许将几乎任何文件上传到任何地方，”它补充道。“攻击者很快就会开始改变策略，上传恶意 JSP 文件，修改配置，并在会话存储之外植入后门。”  
  
建议运行受影响版本的 Tomcat 的用户尽快更新其实例以减轻潜在威胁。  
  
来源：https://thehackernews.com/2025/03/apache-tomcat-vulnerability-comes-under.html  
  
  
  END    
  
  
阅读推荐  
  
  
[【安全圈】 DeepSeek R1 可被操纵用来创建恶意软件](https://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652068535&idx=1&sn=63954c2e32a50239182fa1bc7bb4f4d9&scene=21#wechat_redirect)  
  
  
  
[【安全圈】AI 成为网络犯罪分子高速执行攻击的强大工具](https://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652068535&idx=2&sn=298c1acc1123e932ed63aac7d0f0abcc&scene=21#wechat_redirect)  
  
  
  
[【安全圈】100 多家汽车经销商遭 ClickFix 网页攻击，导致 SectopRAT 恶意软件安装](https://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652068535&idx=3&sn=d89cd6c7f38d627e8162a9e0f4f0e90d&scene=21#wechat_redirect)  
  
  
  
[](https://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652068401&idx=1&sn=5600b75d725f6e90a4cbfddf6a7e10cc&scene=21#wechat_redirect)  
[【安全圈】315晚会曝光偷信息“黑洞”，平台一天处理百亿条数据](https://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652068519&idx=1&sn=caf7880c3563cbc8019913736627788b&scene=21#wechat_redirect)  
  
  
  
  
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
  
  
