#  【安全圈】ViciousTrap 利用思科漏洞操控全球 5,300 台设备构建蜜罐监控网络   
 安全圈   2025-05-26 11:00  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGylgOvEXHviaXu1fO2nLov9bZ055v7s8F6w1DD1I0bx2h3zaOx0Mibd5CngBwwj2nTeEbupw7xpBsx27Q/640?wx_fmt=other&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
**关键词**  
  
  
  
安全漏洞  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGyljqBk9O2vW6khYBjiaL72X7ic1f2DNUv4BPOlWuhGuVsVsuldhPyoFM1vz9B7teXG5JEH0fc3ygOGHQ/640?wx_fmt=png&from=appmsg "")  
  
名为“ViciousTrap”的攻击者团伙被曝已攻陷全球 84 个国家近 5,300 台网络边缘设备，并将其构建成一个类似蜜罐的监控网络。  
  
网络安全研究人员指出，该团伙利用思科多款小型企业路由器（包括 RV016、RV042、RV042G、RV082、RV320 和 RV325）中的严重安全漏洞（CVE-2023-20118）大规模入侵设备，并将其整合进一个受控的蜜罐网络。其中感染最严重的地区是中国澳门，共有约 850 台设备被控制。  
  
根据 Sekoia 本周四发布的分析报告，该攻击链以名为“NetGhost”的 shell 脚本为核心，它会将受害设备的特定端口流量重定向至攻击者控制的蜜罐式基础设施，从而实现网络流量的拦截与监视。值得注意的是，该漏洞此前也曾被法国网络安全公司归因于另一波名为“PolarEdge”的僵尸网络攻击。  
  
虽然目前尚无直接证据表明 ViciousTrap 与 PolarEdge 存在关联，但研究人员认为，ViciousTrap 背后的攻击者很可能正在通过攻陷多种暴露在互联网中的设备（如 SOHO 路由器、SSL VPN、防护监控设备及 BMC 控制器等）搭建一个大规模的蜜罐体系。受影响的设备来自 50 多个品牌，包括 Araknis Networks、ASUS、D-Link、Linksys 和 QNAP 等。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGyljqBk9O2vW6khYBjiaL72X7ic6RhK0WM9BdTqbXLUW3u446PJm9XWsrSHvVqqA33JN1hqY6RicQiaAgfg/640?wx_fmt=png&from=appmsg "")  
  
研究人员表示，这种蜜罐结构可以帮助攻击者监测各种环境中的攻击行为，捕捉非公开的或零日漏洞利用行为，甚至复用其他攻击者的入侵成果。  
  
整个攻击流程大致如下：攻击者首先利用 CVE-2023-20118 漏洞，通过 ftpget  
 命令下载并执行一个初始的 Bash 脚本，该脚本随后从外部服务器获取 wget  
 工具。接着，攻击者再次利用该思科漏洞，执行第二阶段脚本——即 NetGhost 脚本。该脚本会将网络流量重定向至攻击者控制的第三方基础设施，从而实现中间人攻击（AitM）。它还具备自删除功能，以减少被取证发现的可能性。  
  
Sekoia 指出，所有此次利用该漏洞的攻击行为最初均来自同一个 IP 地址（101.99.91[.]151），最早可追溯至 2025 年 3 月。到 4 月，该攻击者开始重用曾在 PolarEdge 僵尸网络中使用过的一款未公开的 Web Shell，进一步支持了他们构建蜜罐网络的推测。  
  
研究员 Felix Aimé 和 Jeremy Scion 表示：“攻击者通过 NetGhost 脚本建立的重定向机制，使其成为网络流量的无声观察者，能够采集攻击尝试，甚至是 Web Shell 的访问数据。”  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGyljqBk9O2vW6khYBjiaL72X7icUwtZ1jVNAzrWTMaM5k4GrEibnPj7j7DfE0bRA9iaRCWK0icpOicYeW8EQA/640?wx_fmt=png&from=appmsg "")  
  
截至本月，攻击活动还扩展到了华硕路由器，不过攻击源 IP 已变更为 101.99.91[.]239。虽然目前在新受感染设备上尚未发现蜜罐部署行为，但所有相关 IP 地址都位于马来西亚，属于托管服务商 Shinjiru 所运营的自治系统 AS45839。  
  
从技术特征与基础设施的弱重叠情况来看，该攻击组织可能具有中文背景。研究人员指出，攻击所涉及的流量大量转发至台湾和美国的基础设施，也进一步加强了这一推测。  
  
Sekoia 最后总结称，尽管 ViciousTrap 的最终意图尚不明确，但可以高度确定其目前正在搭建一个以蜜罐为核心的全球监控网络。  
  
  
  END    
  
  
阅读推荐  
  
  
[【安全圈】美国起诉与勒索软件攻击有关的Qakbot僵尸网络领导人](https://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652069814&idx=1&sn=55315ce70af7e756bc81036d3ab03200&scene=21#wechat_redirect)  
  
  
  
[【安全圈】警方在全球打击行动中逮捕了270名暗网供应商和买家](https://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652069814&idx=2&sn=4cc21b93ac0eef3c3791ae5c524b40d5&scene=21#wechat_redirect)  
  
  
  
[【安全圈】打印机制造商Procolled数月来一直提供恶意软件驱动程序](https://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652069814&idx=3&sn=1ae16215ca2bb8677fe32b72a17c1cbc&scene=21#wechat_redirect)  
  
  
  
[【安全圈】19岁学生入侵窃取 7000 万师生信息](https://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652069801&idx=1&sn=5e72992a2b6a88a8894dd59cf89d63a4&scene=21#wechat_redirect)  
  
  
  
  
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
  
  
