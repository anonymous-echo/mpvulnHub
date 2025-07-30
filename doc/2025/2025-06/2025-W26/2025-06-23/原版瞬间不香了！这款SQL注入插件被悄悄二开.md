> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzkzNDI5NjEzMQ==&mid=2247484903&idx=1&sn=7625c60e3e5bdc390647f5f13ee218a1

#  原版瞬间不香了！这款SQL注入插件被悄悄二开  
原创 跟着斯叔唠安全  跟着斯叔唠安全   2025-06-23 23:00  
  
免责声明  
：  
请勿利用文章内的相关技术从事非法测试，由于传播、利用此文所提供的信息或者工具而造成的任何直接或者间接的后果及损失，均由使用者本人负责，所产生的一切不良后果与文章作者无关。该文章仅供学习用途使用。  
  
  
1  
  
Start  
  
    之前分享过一个非常好用的sql注入挖掘burp插件[又是安全报告？那是因为你没用上这个。。。](https://mp.weixin.qq.com/s?__biz=MzkzNDI5NjEzMQ==&mid=2247484298&idx=1&sn=1c91d08b0d0d28d5597c312ee64178a0&scene=21#wechat_redirect)  
虽然本身插件很好用，但是输出的报告稍稍有点简约，看起来不是那么的人性化  
  
![](https://mmbiz.qpic.cn/mmbiz_png/pKCicPnn24UZ9zQxwbDs9Pe2Cogl2pbiaTz7fEDVw55NUzQ6kXTCcJlW2CYFXevAGruiay8t6d04eIoErkTIWXlQA/640?wx_fmt=png&from=appmsg "")  
  
  
2  
  
Action  
  
    圈子里的群友最近给他二开了一下，  
优化内容包括：  
  
1、增加了日志  
  
2、优化了生成后的报告  
  
3、SSRF增加了对ceye的支持（  
修改/resources/app.config文件中的配置  
）  
  
    看看现在的报告长啥样，顺眼多了有木有  
  
![](https://mmbiz.qpic.cn/mmbiz_png/pKCicPnn24UZ9zQxwbDs9Pe2Cogl2pbiaTOBJKFBURBibFt1uoDMwIMLXN4GLeUmicEhknd0VnJO7mxUiaHYaBVlS3A/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/pKCicPnn24UZ9zQxwbDs9Pe2Cogl2pbiaT9CHk7fEQNf8TP9SN6wnk4N2iaLxvib872cRQconN8IXBFVkLLaRia5EYw/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/pKCicPnn24UZ9zQxwbDs9Pe2Cogl2pbiaTgxhibTBmzmdbo3D2ISReI4HuLibqyRjgYxddnjm16qftMI9eIicA401Aw/640?wx_fmt=png&from=appmsg "")  
  
    二开工具放在圈子啦，需要的师傅可以进圈自取喔～  
  
  
3  
  
End  
  
🚀 **新圈子上线 | 高质量安全内容持续更新中！**  
  
我最近在纷传上建立了一个全新的安全技术圈子，主要聚焦于 **WEB安全、APP安全、代码审计、漏洞分享**  
 等核心方向。目前圈子刚刚建立，内容还不算多，但会**持续高频更新**  
，只分享真正有价值、有深度的干货文章。  
  
📚 圈子中包含：  
- 高质量原创或精选的安全技术文章  
  
- 公众号历史付费内容免费查看（如：小程序RPC、APP抓包解决方案）  
  
- 一些只在圈子内分享的独家思路和实战经验  
  
- 不定期分享0/1day  
  
![](https://mmbiz.qpic.cn/mmbiz_png/pKCicPnn24UaQw8cfe5zo87XFXicicayuia9gvdmBnX6lOnSygn4NFJlzqeyxyes0uIYicDwGwh3rbAYicdwYFhK3Ang/640?wx_fmt=png&from=appmsg "")  
  
  
  
  
