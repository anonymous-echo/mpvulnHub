#  【安全圈】ChatGPT 漏洞遭超一万个 IP 地址主动利用，美国政府机构惨遭攻击   
 安全圈   2025-03-19 19:01  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGylgOvEXHviaXu1fO2nLov9bZ055v7s8F6w1DD1I0bx2h3zaOx0Mibd5CngBwwj2nTeEbupw7xpBsx27Q/640?wx_fmt=other&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
**关键词**  
  
  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGyljzqjty0LB6Jpoj53rnCvneRBzQ9jD8J9LMrkZlspySkrbUX3ickDuHXqB7KYxaCRlFuhMWNThVhDg/640?wx_fmt=png&from=appmsg "")  
  
  
攻击者正在积极利用 OpenAI 的 ChatGPT 基础设施中的一个服务器端请求伪造（SSRF）漏洞。该漏洞被标识为 CVE-2024-27564，尽管其被归类为中等严重程度，但已成为一个重大威胁。  
  
根据网络安全公司 Veriti 的研究，这个漏洞已在众多实际攻击中被利用，这表明威胁行为者即便面对中等程度的安全漏洞，也能设法攻破复杂的人工智能系统。  
  
大规模的攻击利用  
  
这些攻击的规模尤其令人担忧。Veriti 的研究发现，仅在一周内，就有超过 10479 次攻击尝试来自一个恶意 IP 地址。这些数字表明，存在一场针对使用 OpenAI 技术的组织的协同且持续的攻击行动。美国遭受的攻击最为集中，占比 33%，德国和泰国各占 7%。  
  
主要攻击实施情况  
  
其他受影响的地区包括印度尼西亚、哥伦比亚和英国，这表明了该威胁的全球范围。研究人员在报告中指出：“这种攻击模式表明，任何漏洞都不容小觑 —— 攻击者会利用他们能找到的任何弱点。” 攻击趋势显示，2025 年 1 月攻击数量激增，随后在 2 月和 3 月有所下降，这可能表明攻击者改变了策略，或者是受到了安全措施的影响。  
  
服务器端请求伪造漏洞  
  
CVE-2024-27564 被归类为服务器端请求伪造漏洞，攻击者可借此将恶意 URL 注入输入参数。这种技术迫使 ChatGPT 应用程序代表攻击者发出非预期的请求。服务器端请求伪造漏洞通常在用户输入数据被用于创建请求而未进行适当验证时出现。在这种情况下，攻击者可以操纵参数来控制来自其他服务器甚至同一服务器的请求。  
  
该漏洞明确影响 ChatGPT 的 pictureproxy.php 组件，相关情况在提交记录 f9f4bbc 中得以识别。通过操纵 “url” 参数，攻击者可以发起任意请求，有可能绕过安全控制。  
  
风险因素详情  
  
受影响产品：ChatGPT（提交记录 f9f4bbc 中的 pictureproxy.php 组件）、OpenAI 的 ChatGPT 基础设施  
  
影响：发出任意请求、暴露敏感信息  
  
利用前提：可进行远程利用  
  
CVSS 3.1 评分：6.5（中等）  
  
金融机构已成为此次攻击行动的主要目标。银行和金融科技公司高度依赖人工智能驱动的服务和 API 集成，这使它们特别容易受到服务器端请求伪造攻击。这些组织面临潜在后果，包括数据泄露、未经授权的交易、监管处罚以及严重的声誉损害。  
  
建议  
  
或许最令人担忧的是，在分析的组织中，35% 由于其入侵预防系统（IPS）、Web 应用防火墙（WAF）和传统防火墙配置错误而未得到保护。安全专家建议各组织立即实施以下几种缓解策略：  
  
1.审查并纠正 IPS、WAF 和防火墙配置，以确保针对 CVE-2024-27564 的防护。  
  
2.实施严格的输入验证，防止恶意 URL 注入。  
  
3.监控日志，查找来自已知恶意 IP 地址的攻击尝试。  
  
4.考虑进行网络分段，隔离处理 URL 获取的组件。  
  
5.在风险评估流程中优先关注人工智能相关的安全漏洞。  
  
这一事件再次表明，国家支持的和犯罪性质的威胁行为者越来越多地将人工智能系统作为恶意攻击目标。正如最近一份报告所披露的，自 2024 年初以来，攻击者已在 20 多起事件中试图滥用 ChatGPT 进行有害活动。对 CVE-2024-27564 的利用强烈警示我们，即便中等严重程度的漏洞，一旦被坚决的攻击者利用，也可能带来重大风险。  
  
来源：https://cybersecuritynews.com/chatgpt-vulnerability-actively-exploited/  
  
  
  END    
  
  
阅读推荐  
  
  
[【安全圈】Telegram CEO 暂时离开法国，刑事调查仍在进行中](https://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652068550&idx=1&sn=115d0e1f205867e30e417c8478cf3d73&scene=21#wechat_redirect)  
  
  
  
[【安全圈】Apache Tomcat 漏洞在公开披露后仅 30 小时就被积极利用](https://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652068550&idx=2&sn=a11b6f875b76d50d5ffce23fbd07880f&scene=21#wechat_redirect)  
  
  
  
[【安全圈】SANS 研究所警告新型云原生勒索软件攻击](https://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652068550&idx=3&sn=090726d7d1004579b28e56c214ce8f0d&scene=21#wechat_redirect)  
  
  
  
[](https://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652068401&idx=1&sn=5600b75d725f6e90a4cbfddf6a7e10cc&scene=21#wechat_redirect)  
[【安全圈】PHP 遭多重安全漏洞 “围攻”，应用程序风险骤增](https://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652068550&idx=4&sn=2c40ebea61f1937556e695b2be5f2873&scene=21#wechat_redirect)  
  
  
  
  
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
  
  
