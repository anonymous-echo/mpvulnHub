#  【安全圈】AI 平台 Replicate 曝“跨租户攻击”安全隔离漏洞，用户自训练人工智能模型可被黑客入侵   
 安全圈   2024-05-29 19:00  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGylgOvEXHviaXu1fO2nLov9bZ055v7s8F6w1DD1I0bx2h3zaOx0Mibd5CngBwwj2nTeEbupw7xpBsx27Q/640?wx_fmt=png&from=appmsg "微信图片_20230927171534.png")  
  
  
**关键词**  
  
  
  
信息窃取  
  
  
安全公司 Wiz 近日发布报告，宣称开源 AI 模型共享平台 Replicate 存在重大漏洞，黑客可通过恶意模型进行“跨租户攻击”（IT之家注：即利用存在于多租户环境中的安全漏洞访问 / 干扰其他租户的数据资源），从而导致平台用户训练的 AI 模型内部机密数据泄露。  
  
安全公司声称，Replicate 平台出现“跨租户攻击”漏洞的主要原因是该平台为提升 AI 模型推论（inference）效率推出的模型容器化格式 Cog，  
虽然相关格式能够显著改善模型与效率，不过 Replicate 平台忽略了 Cog 格式中的安全隔离机制。  
  
IT之家获悉，黑客可以将经过训练后的恶意模型打包成 Cog 容器，并通过 Replicate 的用户操作界面与容器互动，最终成功进行了一系列远程执行代码（RCE）攻击测试，获得了容器的 root 权限。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGyljLf2ftBSr2vwqoks7W2LJK0RmxA0Xj9ExapRMlzfCsCELDpurwk5ycb6EmIiam1kxVjicnvWQyBTCQ/640?wx_fmt=png&from=appmsg "AI 平台 Replicate 曝“跨租户攻击”安全隔离漏洞，用户自训练人工智能模型可被黑客入侵")  
  
此后，研究人员还对 Replicate 平台的基础设施进一步调查，利用当前容器的 TCP 连接成功访问到另一台容器，并通过名为 rshijack 的工具将特定数据成功注入至 TCP 连接中，从而绕过了平台的身份验证步骤，成功访问到其他用户的 AI 模型。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGyljLf2ftBSr2vwqoks7W2LJKZxaBPjry6AKh6bXqyhjz7iafLib305V9zaoFgfIzOUZ9lb9pRQKpnh6A/640?wx_fmt=png&from=appmsg "AI 平台 Replicate 曝“跨租户攻击”安全隔离漏洞，用户自训练人工智能模型可被黑客入侵")  
  
研究人员指出，黑客可以利用相关漏洞轻松获取其他用户自用的 AI 模型，能够自由从相关模型问答记录中提取用户隐私数据，还能够自由下载 / 修改用户模型内容，对平台存在严重危害。  
  
  
   END    
  
  
阅读推荐  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGylguTGqL1Z9Ew4uEfILSDVOicTHabKM5fbEKhfYsPHCEsicSPibEoLU9fjndMicWnUwjMasnR1Q4s9icL6A/640?wx_fmt=jpeg&from=appmsg "")  
[【安全圈】在最近的 MITRE 网络攻击中，黑客创建恶意虚拟机以逃避检测](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652060682&idx=1&sn=49aa32da7966310e02bffb5f5219f26f&chksm=f36e104ac419995c31dcf0cac42b2faaf9598c8c6d1eda161484316e476f07bda4e356805cfd&scene=21#wechat_redirect)  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGylguTGqL1Z9Ew4uEfILSDVOic7kxVPVzSxLMOM4QChBtadfib9gg09Z2tq91RqZrP9bHRPibmyVFQuBIw/640?wx_fmt=jpeg "")  
[【安全圈】Check Point VPN 设备遭遇黑客攻击](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652060682&idx=2&sn=7b8791571bfb1f3ee722304db71cef19&chksm=f36e104ac419995c7c35f640c140d9c72bb50a09970c13270ed9b972988211ca2782a3a7f89d&scene=21#wechat_redirect)  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGyljLf2ftBSr2vwqoks7W2LJKWxRFHhtXy29btibsia547OicDytJBgLU512D4SbJXxiaFwGE9pVFFAEwdA/640?wx_fmt=jpeg "")  
[【安全圈】Windows 版 Arc 浏览器“人红是非多”，黑客已经利用其网络钓鱼](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652060682&idx=3&sn=e59ab9b698cb5d629381f9b6a665ad28&chksm=f36e104ac419995c4215057d80ba9aef50a15ac58203bc5426e64b636fb3f2093ecd328d4858&scene=21#wechat_redirect)  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGyljLf2ftBSr2vwqoks7W2LJKChYTJtI58bKA2jsicvr9QibfJHZZzRiaX4Tdsibr8A9mSaRGQHVicIO0KEg/640?wx_fmt=jpeg "")  
[【安全圈】新型恶意软件 Gipy 出现，针对人工智能语音生成器应用程序](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652060682&idx=4&sn=7dbec6d413c8ad495b3ebf18bf4c3305&chksm=f36e104ac419995ce7c77db9a2d875de03cbb6fdd99e88b0ab0b3fac400f69bf9cdd81c7bceb&scene=21#wechat_redirect)  
  
  
  
  
  
  
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
  
