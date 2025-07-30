> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652070714&idx=2&sn=49209de3fb35fbb8e54342a5c92305c5

#  【安全圈】美政府用的“Signal 替代品”TeleMessage SGNL 爆出严重漏洞，堆内存泄露已被黑客利用  
 安全圈   2025-07-18 11:00  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGylgOvEXHviaXu1fO2nLov9bZ055v7s8F6w1DD1I0bx2h3zaOx0Mibd5CngBwwj2nTeEbupw7xpBsx27Q/640?wx_fmt=other&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
**关键词**  
  
  
  
TeleMessage  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGyljGlY2SLBuPPQRzpyypCpBW2EQN5PUeCjsQB9U0prToXIXTWolGBMZGKXsBVzOOxvrspAHY8n2L1g/640?wx_fmt=png&from=appmsg "")  
  
以色列开发的通信应用TeleMessage SGNL近日曝出严重安全漏洞。这款作为Signal替代品被美国政府机构及监管企业采用的软件，由于配置不当导致系统敏感数据暴露在公开网络中，无需登录即可访问。  
  
安全公司GrayNoise研究人员发现，部分TeleMessage SGNL实例使用了过时的Spring Boot框架版本，致使诊断接口/heapdump默认开放。该接口会生成约150MB的内存快照，其中可能包含用户名、密码、会话信息等本应加密的敏感数据。尽管新版Spring Boot已默认关闭此接口，但监测显示截至2025年5月5日仍有TeleMessage服务端保持危险配置。  
  
该漏洞被标记为CVE-2025-48927，已于7月14日被美国网络安全和基础设施安全局（CISA）列入已知遭利用漏洞目录。据监测，7月16日前已有至少11个IP地址试图直接利用该漏洞盗取内存数据。更值得警惕的是，过去90天内超过2000个IP地址对Spring Boot执行器端点进行了探测扫描，其中1500余次针对/health接口——这是攻击者常用于识别易受攻击系统的侦察手段。  
  
令人忧虑的是，这款以安全通信为卖点的产品已非首次出现重大纰漏。2025年5月，匿名黑客就曾入侵其系统窃取410GB敏感数据，导致相关漏洞（CVE-2025-47729）被紧急列入CISA高危清单。随后泄密组织"DDoSecrets"更将全部失窃数据公开存档。  
  
根据CISA强制操作指令，所有联邦机构须在2025年7月22日前完成补丁安装或停用受影响系统。安全专家强烈建议：在确认补丁生效前，处理敏感通信的环境应限制访问或临时停用该应用。使用TeleMessage或Spring Boot构建内部服务的企业也应立即检查是否存在类似配置风险。  
  
  
  END    
  
  
阅读推荐  
  
  
[【安全圈】某公募基金惊现“S级信息安全事故” 薪资数据大规模信息泄露](https://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652070700&idx=1&sn=0bfcf5f70f4bd4aec9db6c615bca621a&scene=21#wechat_redirect)  
  
  
  
[【安全圈】微软 Windows Hello 企业版曝缺陷，黑客可“换脸”伪装登录](https://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652070700&idx=2&sn=a934035086c04e95f8977d0d34fad88e&scene=21#wechat_redirect)  
  
  
  
[【安全圈】SquidLoader 恶意软件袭击香港金融机构，攻击或蔓延新澳](https://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652070700&idx=3&sn=ec89b81506c7e793dd2e6459ec36fbb7&scene=21#wechat_redirect)  
  
  
  
[【安全圈】清华蓝莲花团队打造国产 WAF SafeLine，在全球初创与自建实验室圈层爆火](https://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652070688&idx=1&sn=db50e99685efddba0087e6eef1b624ef&scene=21#wechat_redirect)  
  
  
  
  
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
  
  
