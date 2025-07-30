> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652070555&idx=4&sn=a0045b414dc83b5ccab5d88ec4c10558

#  【安全圈】《使命召唤：二战》曝严重漏洞，PC玩家遭远程黑客攻击，游戏被紧急下线  
 安全圈   2025-07-08 11:02  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGylgOvEXHviaXu1fO2nLov9bZ055v7s8F6w1DD1I0bx2h3zaOx0Mibd5CngBwwj2nTeEbupw7xpBsx27Q/640?wx_fmt=other&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
**关键词**  
  
  
  
安全漏洞  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGylhiciatPreSa7EgZRv5ZBPU9uQdBAzCB45QWXOmkKur4ic6ghW5VWcTVCEQpwt9A1iaodFql2asZM1iblA/640?wx_fmt=png&from=appmsg "")  
  
2025年7月，一场突如其来的安全危机席卷《使命召唤：二战》PC端。因存在严重的远程代码执行（RCE）漏洞，该游戏目前已被开发团队紧急下线。此次漏洞使得恶意玩家能够在多人对战中，未经受害者允许远程操控其电脑，引发广泛关注与担忧。  
  
《使命召唤》开发团队在周六宣布，PC 版本《使命召唤：二战》因“收到相关问题报告”而暂时停止服务。最初外界普遍以为是技术性故障，但很快有安全研究人员和玩家社区揭露：这是一起极其严重的安全事件。  
  
据悉，该漏洞允许攻击者在对战过程中远程执行恶意代码，操控其他玩家的电脑。这种控制能力无需物理接触，也不需要受害玩家执行任何操作，使攻击过程具备高度隐蔽性和破坏性。  
  
有受害玩家报告称，在游戏过程中，他们的电脑突然弹出命令行窗口，或被强制打开记事本显示嘲讽文字，甚至在对局中被远程关机或篡改桌面壁纸显示不雅图像。该漏洞专门影响 Windows 平台用户，主机版因系统封闭性未受波及。  
  
问题的根源指向《使命召唤：二战》所采用的 P2P（点对点）联网架构。在该架构中，其中一名玩家的电脑将被用作临时服务器，这就可能为攻击者留下系统漏洞利用的入口。利用 P2P 模式实现远程代码执行，意味着攻击者可以借由对战关系直接访问受害者的系统资源。  
  
值得注意的是，该游戏近日刚刚被加入微软 Game Pass 游戏订阅服务，成为漏洞被大规模利用的潜在触发点。而老玩家早已习惯对这类“年久失修”的 COD 旧作保持谨慎，Steam 版本的安全问题曾多次被社区曝光，却鲜有彻底解决。  
  
此次事件再次暴露出 COD 系列部分旧作在网络安全层面的长期隐患。虽然玩家社群普遍期望动视更新其反作弊系统“Ricochet”，但目前尚未确认未来更新是否将包括对该 RCE 漏洞的修复。  
  
安全专家呼吁玩家在官方补丁发布前立即暂停游玩该作，尤其是通过 Game Pass 或微软商城下载的版本。同时建议用户及时更新 Windows 补丁，保持杀毒软件实时运行，并持续关注动视官方的安全通告。  
  
此次事件不仅仅是一次游戏服务中断，更是对整个平台用户信息安全与数据完整性的严重威胁。它再次提醒广大用户：即使是大型发行商出品的成熟游戏，也可能在未经充分维护的状态下，演变为入侵者控制他人电脑的“跳板”。  
  
  
 END   
  
  
阅读推荐  
  
  
[【安全圈】微软“偷偷”推送KB5001716更新引争议，强制升级条款已被删除](https://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652070540&idx=1&sn=48ecf66383a1648eab6a10583072a177&scene=21#wechat_redirect)  
  
  
  
[【安全圈】俄罗斯逮捕为乌克兰情报部门工作的黑客，涉嫌攻击关键基础设施](https://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652070540&idx=2&sn=561ca5216c2640cce631af8f41f0443f&scene=21#wechat_redirect)  
  
  
  
[【安全圈】警惕！境外势力入侵校园广播](https://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652070540&idx=3&sn=1581962bd3e92c58293d071cd47d8cd7&scene=21#wechat_redirect)  
  
  
  
[【安全圈】Cisco 紧急修复 Unified CM 中存在的严重 Root 账户漏洞](https://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652070540&idx=4&sn=6fe8ab50588c2035d0ee523bcf26b3ea&scene=21#wechat_redirect)  
  
  
  
  
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
  
  
