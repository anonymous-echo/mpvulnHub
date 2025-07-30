#  【安全圈】Play勒索团伙利用SimpleHelp漏洞实施双重勒索  
 安全圈   2025-06-08 11:00  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGylgOvEXHviaXu1fO2nLov9bZ055v7s8F6w1DD1I0bx2h3zaOx0Mibd5CngBwwj2nTeEbupw7xpBsx27Q/640?wx_fmt=other&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
**关键词**  
  
  
  
勒索  
  
  
**美国联邦调查局（FBI）最新通报：Play勒索软件团伙已攻击全球900多家机构，并升级双重勒索手段**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGylgicxr3aiaf60xFibD7DNRaMGjXXhc69IqWkFwtVXQ6ibwb8qlVcP1dmAvXw4ssFpWic0Em5hKGYglXx0g/640?wx_fmt=png&from=appmsg "")  
  
美国联邦调查局（FBI）周三发布警告称，与Play勒索软件相关的犯罪团伙已对全球**超过900家企业及机构**  
实施攻击，并在双重勒索（窃取数据+加密勒索）行动中开发了多项新手段——包括利用远程访问工具**SimpleHelp的安全漏洞**  
（若企业未及时修补）。  
  
这一特定勒索软件变种**去年曾位列针对关键基础设施攻击的前五名**  
。根据FBI、美国网络安全与基础设施安全局（CISA）及澳大利亚网络安全中心（ACSC）联合发布的最新安全通告，该团伙的攻击活动不仅未见收敛，反而变本加厉：**先窃取并加密敏感数据，再以公开数据为要挟索要赎金**  
。  
### 勒索手段升级：邮件联系+电话恐吓  
  
通告指出，Play勒索软件的勒索信**不再直接注明赎金金额或支付方式**  
，而是要求受害者通过电子邮件与攻击者联系。更值得警惕的是，该团伙还采用**心理操控战术**  
——  
- **频繁致电受害者**  
，威胁若不支付赎金就公开被盗数据；  
  
- 电话可能转接至企业内部多个号码，包括**公开渠道获取的客服或技术支持电话**  
（如帮助台）。  
  
FBI与盟国机构在6月4日更新的预警中表示："这些电话可能被转接至组织内的多个号码，包括通过开源情报获取的客服或技术支持联系方式。"  
### 新增攻击特征与防御建议  
  
此次通告详细披露了Play勒索软件的最新战术、技术与程序（TTPs），并提供了当前可用的**入侵指标（IoC）**  
，帮助网络安全团队加强防御。关键发现包括：  
- **勒索信中会提供独特的联系邮箱**  
（如@gmx.de或@web.de域名）；  
  
- 攻击者会利用SimpleHelp等远程工具的漏洞，若企业未打补丁则极易中招。  
  
### 背景补充：双重勒索的威胁  
  
Play团伙的攻击模式是当前勒索软件的典型套路：  
1. **窃取数据**  
：入侵后先下载敏感文件；  
  
1. **加密系统**  
：锁定企业数据索要赎金；  
  
1. **双重威胁**  
：即使支付赎金，仍可能公开数据以施压其他受害者。  
  
FBI等机构呼吁企业：  
- 立即修补SimpleHelp等远程工具的漏洞；  
  
- 监控异常邮件和电话威胁；  
  
- 定期备份数据并测试恢复流程。  
  
  END    
  
  
阅读推荐  
  
  
[【安全圈】刑事拘留！江苏一男子破解无人机禁飞限高](https://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652070055&idx=1&sn=8d82fcbefb07cba0ce31b9d2c9ce28da&scene=21#wechat_redirect)  
  
  
  
[【安全圈】奢侈时尚品牌卡地亚遭遇网络攻击 客户数据被泄露](https://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652070055&idx=2&sn=dc80894346d8d9a4dfc2ce2e6dba2198&scene=21#wechat_redirect)  
  
  
  
[【安全圈】热门 Chrome 扩展陷 HTTP 和硬编码密钥双重漏洞](https://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652070055&idx=3&sn=6b9ef71bf3e0c60b87ab26c126ce970f&scene=21#wechat_redirect)  
  
  
  
[【安全圈】阿里云 aliyuncs.com 域名故障导致全国网站访问异常](https://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652070040&idx=1&sn=2607d571d2383520da9725b92d2c9691&scene=21#wechat_redirect)  
  
  
  
  
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
  
  
