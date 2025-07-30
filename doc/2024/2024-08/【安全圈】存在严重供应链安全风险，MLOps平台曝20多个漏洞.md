#  【安全圈】存在严重供应链安全风险，MLOps平台曝20多个漏洞   
 安全圈   2024-08-27 19:00  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGylgOvEXHviaXu1fO2nLov9bZ055v7s8F6w1DD1I0bx2h3zaOx0Mibd5CngBwwj2nTeEbupw7xpBsx27Q/640?wx_fmt=png&from=appmsg "微信图片_20230927171534.png")  
  
  
**关键词**  
  
  
  
安全漏洞  
  
  
网络安全研究人员警告称，在发现20多个漏洞后，机器学习（ML）软件供应链存在安全风险，这些漏洞可能被利用来针对MLOps平台。这些漏洞被描述为固有和实现方面的缺陷，可能会产生严重后果，从任意代码执行到加载恶意数据集。![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGyljjSpP53aQcBEzuvYlWdnLxiboFUeUfuoSl8ibWPt4MnBBh9UTMpKEPGHIBVa4JzKAeicCssA5Kp092g/640?wx_fmt=jpeg&from=appmsg "")  
  
  
MLOps平台提供了设计和执行ML模型管道的能力，模型注册表作为存储和版本训练ML模型的存储库。然后可以将这些模型嵌入到应用程序中，或允许其他客户端使用API（即模型即服务）查询它们。  
  
JFrog研究人员在一份详细报告中表示：“固有漏洞是由技术中所使用的底层格式和过程引起的。”固有漏洞的一些例子包括利用ML模型运行攻击者选择的代码，这是通过利用模型在加载时支持自动代码执行的事实（例如Pickle模型文件）。  
  
这种行为也扩展到某些数据集格式和库，它们允许自动代码执行，从而在仅加载公开可用的数据集时就可能为恶意软件攻击敞开大门。另一个固有漏洞涉及JupyterLab（前身为Jupyter Notebook），这是一个基于Web的交互式计算环境，使用户能够执行代码块（或单元格）并查看相应的结果。  
  
简单来说，攻击者可以输出恶意JavaScript代码，使其在当前JupyterLab笔记本中添加一个新单元格，将Python代码注入其中并执行它。特别是在利用跨站脚本（XSS）漏洞的情况下，这一点尤其明显。JFrog表示，它发现了一个MLFlow的XSS漏洞（CVE-2024-27132，CVSS评分：7.5），可导致在JupyterLab中执行客户端代码。  
  
研究人员说：“我们从这项研究中的一个主要收获是，我们需要将ML库中的所有XSS漏洞视为潜在的任意代码执行，因为用户可能会将这些ML库与Jupyter Notebook一起使用。”  
  
第二类漏洞涉及实现弱点，例如MLOps平台中缺乏身份验证，可能会允许具有网络访问权限的威胁行为者通过滥用ML管道功能获得代码执行能力。这些威胁并非理论上的，以经济利益为动机的对手可能滥用这些漏洞，如在未打补丁的Anyscale Ray（CVE-2023-48022，CVSS评分：9.8）的情况下，部署加密货币矿工。  
  
第二种实现漏洞是针对Seldon Core的容器逃逸，使攻击者能够超越代码执行，在云环境中横向移动并访问其他用户的模型和数据集，方法是将恶意模型上传到推理服务器。它们不仅可以被武器化，在组织内部渗透、传播，还可以威胁服务器。  
  
Palo Alto Networks Unit 42详细说明了开源LangChain生成式AI框架中的两个现已修复的漏洞（CVE-2023-46229和CVE-2023-44467），这两个漏洞可能允许攻击者执行任意代码和访问敏感数据。  
  
上个月，Trail of Bits还揭示了Ask Astro中的四个问题，这是一个检索增强生成（RAG）开源聊天机器人应用程序，可能导致聊天机器人输出中毒、文档摄取不准确和潜在的拒绝服务（DoS）。  
  
正如安全问题在人工智能驱动的应用程序中被暴露出来一样，人们也在设计技术来用最终目标欺骗大型语言模型（LLMs）产生易受攻击的代码来毒害训练数据集。  
  
康涅狄格大学的一位学者表示：“与最近将恶意负载嵌入代码的可检测或不相关部分的攻击不同，CodeBreaker利用LLMs（例如GPT-4）进行复杂的负载转换（不影响功能），确保微调的毒害数据和生成的代码都可以规避强大的漏洞检测。”  
  
参考来源：https://thehackernews.com/2024/08/researchers-identify-over-20-supply.html  
  
END  
  
  
阅读推荐  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/78XNpK3Wmsc6iavNSdvObuJKxloJnAMLA18cpuj6JibPUd6icftkrl6CdKtvw5sBX1asLjP0LpAegNDYLTXSHBIXg/640?wx_fmt=other "")  
[【安全圈】社交媒体“电报”创始人在法国被捕](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652063868&idx=1&sn=751ec0f140427c77e7d21f9134652532&chksm=f36e643cc419ed2ae5e313835b73031ef67065e8aded0d5242fd873b1896cc1c677d14dd8d6a&scene=21#wechat_redirect)  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGyljjSpP53aQcBEzuvYlWdnLxKb7Eibej2mrVCEX1rblRwzbOfnzBM3JwJap6boxSe3n8pzfMtgnDDug/640?wx_fmt=jpeg "")  
[【安全圈】网络身份证是强制，会影响正常上网？公安部详细回应](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652063868&idx=2&sn=e0e51cc3262a54328e4fee1482c882f1&chksm=f36e643cc419ed2a36eb00a524a91605bcd28b782d15ab7fb662c206140dca0df3a38bac1c1a&scene=21#wechat_redirect)  
  
  
【安全圈】网络身份证是强制，会影响正常上网？公安部详细回应  
  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGyliayCUW1gpZNIJwcvP62FicibwMbkUfquibHtHOgV66Ee7padQYEzoQeRoBBtVOhMPSx9sytmicCNMSBQw/640?wx_fmt=jpeg "")  
[【安全圈】又一全新恶意软件曝光！专门针对Windows、Linux 和 macOS 用户](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652063868&idx=3&sn=49fcaba0be0679106cf8d489b525753c&chksm=f36e643cc419ed2ade897b23b9fba16e6ab1d7e4167ffcbfd90b6edb469943c52ac0c971a570&scene=21#wechat_redirect)  
                 
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGyljZ1jGTpY6rXdUMmVLxZZbEXdxmAa2uOQDt7ZaIlnjC2uLqSYK2w0lGtT44wd9ZuFdvnRD0RPfaxg/640?wx_fmt=jpeg&from=appmsg "")  
[【安全圈】新型 Linux 恶意软件 “sedexp ”利用 Udev 规则隐藏信用卡盗刷器](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652063868&idx=4&sn=a18540bc0e59a8eabff6f3f9f433c306&chksm=f36e643cc419ed2ad6053bcd8bed5e40dc4b7237e79f9eb369052531aee4088ce718f5f7ec7e&scene=21#wechat_redirect)  
                            
  
  
  
  
  
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
  
