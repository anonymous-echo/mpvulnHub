#  【安全圈】PHP XXE 注入漏洞让攻击者读取配置文件和私钥   
 安全圈   2025-03-13 19:00  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGylgOvEXHviaXu1fO2nLov9bZ055v7s8F6w1DD1I0bx2h3zaOx0Mibd5CngBwwj2nTeEbupw7xpBsx27Q/640?wx_fmt=other&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
**关键词**  
  
  
  
安全漏洞  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGylgJJuqW5y6mSvR0HmSw8A5ErXByrfSZgcaD7PrglN7NgqTWQXUM6HUu9CFFmL51olaCbbYtIt4wog/640?wx_fmt=png&from=appmsg "")  
  
安全研究人员发现 PHP 应用程序存在一个复杂的 XML 外部实体 (XXE) 注入漏洞，该漏洞可能允许攻击者访问敏感配置文件和私钥。  
  
该漏洞由研究员 Aleksandr Zhurnakov 发现，会影响在 XML 处理期间使用某些 libxml 标志的 PHP 应用程序，即使采取了标准安全措施，也可能暴露关键的服务器端信息。  
  
该漏洞使攻击者能够绕过旨在防止 XXE 攻击的多种安全机制，包括用于在 XML 解析期间阻止外部网络连接的 LIBXML_NONET 标志。  
  
即使开发人员遵循看似安全的编码实践，这种攻击媒介仍然有效。  
  
PT Swarm 的分析师发现，攻击链涉及一系列复杂的绕过，这些绕过共同造成了他们所描述的“几乎不可能的 XXE 漏洞”。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGylgJJuqW5y6mSvR0HmSw8A5EiaW9tnqONdcgZdNZTlFMviaP1vU3onfga2npplRM0cb9r1XKj5MPCLYw/640?wx_fmt=png&from=appmsg "")  
  
他们的分析表明，这次攻击对身份提供者和身份验证系统尤其具有破坏性。  
  
该漏洞的技术核心涉及利用 PHP 的 libxml 扩展处理 XML 参数实体的方式。  
  
研究中发现的一个易受攻击的代码模式涉及使用带有 LIBXML_DTDLOAD 标志的 loadXML 函数，如以下代码片段所示：  
```
$doc = new \DOMDocument();
$doc->loadXML($_POST['user_input']);
$xml = $doc->saveXML();
$doc = new \DOMDocument('1.0', 'UTF-8');
$doc->loadXML($xml, LIBXML_DTDLOAD | LIBXML_NONET);
```  
  
利用过程涉及制作一个特殊的 DOCTYPE 声明来绕过过滤机制。  
  
然后，攻击者可以使用 PHP 包装器技术结合参数实体滥用来读取本地文件并窃取其内容。  
## 现实世界的影响  
  
该漏洞已在 SimpleSAMLphp (CVE-2024-52596) 中被发现，它允许未经授权的用户读取配置文件并访问用于签署 SAML 断言的私钥。  
  
这实际上允许完全绕过配置为身份提供者的 SimpleSAMLphp 安装的身份验证机制。  
  
该漏洞尤其令人担忧的是，它不需要 LIBXML_NOENT 或 LIBXML_DTDVALID 标志，而这些标志通常是 XXE 利用所必需的。  
  
它还演示了使用数据：协议与 PHP 过滤器结合绕过网络限制的技术。  
  
安全专家建议立即更新受影响的应用程序并实施适当的 XML 解析配置，使用 PHP 8.4.0 中引入的 LIBXML_NO_XXE 标志明确禁用 DTD 处理。  
  
来源：https://cybersecuritynews.com/php-xxe-injection-vulnerability/  
  
  
  
  END    
  
  
阅读推荐  
  
  
[【安全圈】美国政府称 2024 年美国人因欺诈损失创纪录 125 亿美元](https://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652068449&idx=1&sn=7aa71495a16a8590c5a5dbaf2a299a09&scene=21#wechat_redirect)  
  
  
  
[【安全圈】朝鲜 Lazarus 黑客通过 npm 软件包感染数百人](https://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652068449&idx=2&sn=bbe1548572f3323cc8067fa2bc9bdf6b&scene=21#wechat_redirect)  
  
  
  
[【安全圈】瑞士关键行业面临新的 24 小时网络攻击报告规则](https://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652068449&idx=3&sn=cbceff6b7d8cacc138082e8b186207c7&scene=21#wechat_redirect)  
  
  
  
[](https://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652068401&idx=1&sn=5600b75d725f6e90a4cbfddf6a7e10cc&scene=21#wechat_redirect)  
[【安全圈】SideWinder APT 利用增强的工具集瞄准海事和核能领域](https://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652068449&idx=4&sn=90a8bf33c53d8d8882985f1e9798ea93&scene=21#wechat_redirect)  
  
  
  
  
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
  
  
