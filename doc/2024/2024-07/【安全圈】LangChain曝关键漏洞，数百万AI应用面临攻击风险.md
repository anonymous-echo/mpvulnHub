#  【安全圈】LangChain曝关键漏洞，数百万AI应用面临攻击风险   
 安全圈   2024-07-26 19:00  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGylgOvEXHviaXu1fO2nLov9bZ055v7s8F6w1DD1I0bx2h3zaOx0Mibd5CngBwwj2nTeEbupw7xpBsx27Q/640?wx_fmt=png&from=appmsg "微信图片_20230927171534.png")  
  
  
**关键词**  
  
  
  
安全漏洞  
  
  
LangChain是一个流行的开源生成式人工智能框架，其官网介绍，有超过一百万名开发者使用LangChain框架来开发大型语言模型（LLM）应用程序。LangChain的合作伙伴包括云计算、人工智能、数据库和其他技术开发领域的许多知名企业。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGylhEmsMAdDu33EjgdXjUGwQkh6RwYblOzeyicNYicZaPHYAIVMhiakx63Aaf8Waibf4pLM5u8YlMdmzguQ/640?wx_fmt=jpeg&from=appmsg "")  
  
近日，来自Palo Alto Networks的研究人员详细描述了LangChain中的两个重大安全漏洞。  
  
这些漏洞被识别为CVE-2023-46229和CVE-2023-44467，它们有可能允许攻击者执行任意代码和访问敏感数据。鉴于有一百多万名开发者依赖LangChain，这一发现给众多AI驱动的应用程序带来了重大安全风险。  
## CVE-2023-46229：服务器端请求伪造（SSRF）  
  
在LangChain 0.0.317之前的版本中，存在一个通过精心设计的站点地图实现的SSRF漏洞。利用该漏洞，攻击者可以从内网获取敏感信息，并可能绕过访问控制。Palo Alto Networks在2023年10月13日发现了这一问题，并立即通知了LangChain团队。该漏洞已在版本0.0.317中通过拉取请求langchain#11925得到修复。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGylhEmsMAdDu33EjgdXjUGwQkAicnzJVoXzQFgUiajgVZuSUUfml1ajiayuric6lS4V29byxiaibLlfK9RVGg/640?wx_fmt=jpeg&from=appmsg "")  
## CVE-2023-44467：LangChain实验中的严重提示注入  
  
CVE-2023-44467是一个严重提示注入漏洞，影响0.0.306之前的LangChain实验版本。LangChain实验是一个专为研究和试验而设计的Python库，包含可能被恶意提示利用的集成。这个漏洞影响了PALChain功能，这是一个通过程序辅助语言模型（PAL）增强语言模型生成代码解决方案的能力的功能。  
  
该漏洞允许攻击者利用PALChain的处理能力进行提示注入，使他们能够执行有害的命令或代码。这种利用可能导致未经授权的访问或操纵，带来重大的安全风险。Palo Alto Networks在2023年9月1日识别出这一问题，并及时通知了LangChain开发团队，后者在第二天在LangChain实验PyPI页面上发布了警告。  
  
随着对大型语言模型（LLM）应用需求的增加，LangChain的受欢迎程度在最近几个月急剧上升。其丰富的预构建组件和集成库使其成为开发者的首选工具。然而，这种广泛的应用也意味着这些漏洞的潜在影响被放大。  
  
Palo Alto Networks的研究人员强烈建议使用LangChain的开发者和组织将LangChain更新到最新的修补版本，以确保应用安全。  
  
参考来源：https://securityonline.info/critical-flaws-in-langchain-expose-millions-of-ai-apps-to-attack/  
  
  
END  
  
  
阅读推荐  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGylhickkwIrLIB3GAHnldD5X9krF8cwzia67GeRdXJ5DGHWcvNlmUwEYKV1iaGguvbVxtmBHZvPs1Wic0MA/640?wx_fmt=jpeg "")  
[【安全圈】这家网络公司开始聘用黑客？](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652063086&idx=1&sn=8b841b8242dff0f3af24fad49b952555&chksm=f36e692ec419e03882e468149cd84bb3bca83dc01adefb881762171e95f162781888daef50d8&scene=21#wechat_redirect)  
                                      
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGylhickkwIrLIB3GAHnldD5X9kjxbNcicHYj7FOklgiarSLrXGdFJhSmtsbHack2G1Ibnnn8uib77a8ttLA/640?wx_fmt=jpeg "")  
[【安全圈】Crowdstrike蓝屏事件自查结果：错在流程而非人](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652063086&idx=2&sn=afcd1063623156c29769141ffa615a68&chksm=f36e692ec419e0384b2b7e668a91f93453fce5abdab9616d7f3dcbcc30a96ce7b4fd3611e744&scene=21#wechat_redirect)  
          
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGylhickkwIrLIB3GAHnldD5X9kVGxv8k3TQzKdbT8IN2buJLWickC74g2WKcicfibPzj2HVAljpPialUqaDQ/640?wx_fmt=jpeg "")  
[【安全圈】史上最大规模的数字盗版泄密事件：1000万用户因虚假Z-Library导致机密信息泄露](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652063086&idx=3&sn=5732f3cf80a7316954fc8c9c85bb06c4&chksm=f36e692ec419e0389e237580eba7c2403888b435cba1ae69a629d8c950727f0d6273f60d7e81&scene=21#wechat_redirect)  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGylhickkwIrLIB3GAHnldD5X9kxL3GDjmaH7wvh73LhGzibQS4EfLAuicwCTgRcwbkhUOMExQSzcugd9Qg/640?wx_fmt=jpeg "")  
[](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652063065&idx=4&sn=96fc3e573519081fbd49937334e2bdf4&chksm=f36e6919c419e00f3be7624ee0417191b17aa3f119197ded57e995671d7fefbef3d6a1a00393&scene=21#wechat_redirect)  
[【安全圈】R0bl0ch0n TDS——新型附属欺诈计划波及1.1亿用户](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652063086&idx=4&sn=4cb1efc9ece7cc4641fdb5a422dac737&chksm=f36e692ec419e0382853b4f9ee3dc8dd2aa290b4761f2ab797eb8933813dec5295cb4cfcb621&scene=21#wechat_redirect)  
  
  
  
  
  
  
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
  
