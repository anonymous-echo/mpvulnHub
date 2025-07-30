#  【安全圈】FortiWLM 曝关键漏洞，攻击者可获得管理员权限   
 安全圈   2024-12-22 11:00  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGylgOvEXHviaXu1fO2nLov9bZ055v7s8F6w1DD1I0bx2h3zaOx0Mibd5CngBwwj2nTeEbupw7xpBsx27Q/640?wx_fmt=other&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
**关键词**  
  
  
  
安全漏洞  
  
  
Fortinet 披露了 Fortinet Wireless Manager （FortiWLM） 中的一个严重漏洞，该漏洞允许远程攻击者通过特制的 Web 请求执行未经授权的代码或命令来接管设备。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGyljhwIGlibiakO7ePnPiaOItbvyA35WwEnLOIGUWS3ia2EMUE1VtYFYJbwsQnFL5RFTibicG1eticpHrYb73A/640?wx_fmt=jpeg&from=appmsg "")  
  
FortiWLM 是一种集中式管理工具，用于监控、管理和优化无线网络，被政府机构、医疗保健组织、教育机构和大型企业使用。  
  
该漏洞被跟踪为 CVE-2023-34990，是一个相对路径遍历缺陷，评分高达 9.6。Horizon3 研究员 Zach Hanley 于 2023 年 5 月发现并披露了该漏洞。但在数月后仍未修复。于是 Hanley 决定于 2024 年 3 月 14 日在一篇关于他发现的其他 Fortinet 漏洞的技术文章中披露相关信息和 POC。尽管研究人员公开警告，但缺少 CVE编号以及安全公告意味着大多数用户没有充分意识到风险。  
  
该漏洞会影响 FortiWLM 8.6.0 到 8.6.5 和 8.5.0 到 8.5.4 版本 。当 'op_type' 设置为 'upgradelogs' 时，通过在 'imagename' 参数中使用目录遍历技术，攻击者可以从系统中读取敏感的日志文件。这些日志通常包含管理员会话 ID，可用于劫持管理员会话并获得特权访问权限，从而允许威胁行为者接管设备。  
  
根据12月18日发布的安全公告，漏洞已在 2023 年 9 月底发布的 FortiWLM 版本 8.6.6 和 8.5.5 中修复。但Fortinet直到最近才正式发布该漏洞的安全通告。  
  
换言之，该漏洞作为零日漏洞持续了大约四个月的时间，鉴于 FortiWLM 部署在关键环境中，可能成为攻击者的目标，通过远程入侵导致整个网络中断和敏感数据泄露。因此，强烈建议 FortiWLM 管理员在可用更新可用时应用所有可用更新。  
  
参考来源：  
Fortinet warns of FortiWLM bug giving hackers admin privileges  
  
  
  END    
  
  
阅读推荐  
  
  
[【安全圈】“共享充电器”竟能为旅馆刷好评？揭秘灰黑产交易](https://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652066803&idx=1&sn=80728ed4cd49abaf5f88c997e42aa82f&scene=21#wechat_redirect)  
  
  
  
[【安全圈】年终盘点：2024年影响最大的10个云中断事件](https://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652066803&idx=2&sn=1401ba363c05488dd39bd7e03972736f&scene=21#wechat_redirect)  
  
  
  
[【安全圈】大众车载系统暴出12个安全漏洞，黑客可轻松接管车内信息！](https://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652066803&idx=3&sn=dca3ffae63a4a135b0aaae997fee9b6d&scene=21#wechat_redirect)  
  
  
  
  
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
  
  
  
