#  【安全圈】苹果数据传输面临漏洞威胁： 新的Wireshark剖析器揭开面纱   
 安全圈   2023-05-09 19:02  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/aBHpjnrGyljsJVJHhaCOeUkoze16FrNjE24yjZVib01Tl7diaq0PGm6wazJMuo3K51rsrhdiagwEDicqXQtmMQlIJQ/640?wx_fmt=jpeg "")  
  
**关键词**  
  
  
  
黑客  
  
  
  
新的Wireshark Dissector在社区内引发了极大的兴趣和讨论，研究人员对苹果数据传输过程的安全性表示担忧。黑客可能试图抓取包含与苹果iOS和iOS用户数据相关的敏感信息的网络数据包。  
  
这种潜在的安全风险导致了一种新的Continuity Wireshark剖析器的开发，旨在抓取iOS设备在两个或多个设备之间进行苹果数据传输时的蓝牙协议数据。  
  
Cyber Express团队已经就潜在泄露的问题与苹果公司进行了接触。然而，目前尚未收到官方回应。  
## 新的Wireshark Dissector  
  
苹果iOS设备以其与其他苹果设备的无缝整合和数据交换而闻名。这种苹果数据传输是通过iOS的iBeacon技术进行的，它允许设备之间进行无线通信。  
  
由Guilherme Rambo（Insidegui）开发并在Netspooky/Dissector资源库中共享的 "Continuity "剖析器，专门用于分析iOS设备之间的苹果数据传输。  
  
Wireshark是一个广泛使用的网络协议分析器，为安全专家提供了一个检查和剖析网络流量的高效工具。  
  
Continuity Protocol Dissector增强了Wireshark的能力，允许分析人员检查广告信标的内容，并从苹果制造数据中提取有价值的信息。  
  
据研究人员称，Continuity Protocol Dissector据称可以从外部接口捕获数据包，然后可以在以后使用Wireshark或tshark（Wireshark插件的命令行对应）进行分析。  
## 为迭代更新做好准备  
  
新的Wireshark Dissector在社区内引发了极大的兴趣和讨论，让人们看到了苹果数据传输过程中的潜在漏洞。  
  
这个工具使安全分析人员能够使用Wireshark插件或其命令行对应的tshark进行蓝牙流量捕捉和分析。  
  
通过利用这个剖析器，并使用显示过滤器 "acble "关注连续性协议数据，分析师可以更好地了解iOS设备之间的通信，并确定苹果数据传输中的任何潜在安全漏洞。  
  
Continuity Protocol Dissector继续发展，定期发布更新，以解决协议中的变化和扩展，并支持新的消息类型。  
  
虽然目前还在进一步更新中，但该剖析器为分析苹果BLE广告信标协议提供了大量功能。  
  
要深入研究苹果连续性协议并分析苹果BLE广告信标协议，感兴趣的人可以访问Netspooky/Dissectors仓库中由Guilherme Rambo（又名Insidegui）维护的GitHub仓库。  
  
通过随时了解情况并采取积极措施解决潜在的安全风险，用户可以帮助确保 Apple 数据传输过程的安全，并为更安全的数字环境做出贡献。  
  
  
   END    
  
  
阅读推荐  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/aBHpjnrGyliavGLlka4ryB5YcPwZDUbQeOk2HTbEldxIlI1jSbFSO9UwQAaaibqictAlMu21nrGBicO8DMgwpQwHicQ/640?wx_fmt=png "")  
[【安全圈】只要一部“诺基亚”，15秒就能偷走一辆车](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652033652&idx=1&sn=797b61c94be70a0742295f127ceb2e62&chksm=f36ffe34c4187722a97beeb2d21605a276ab2fb97b4f42228590a2acbe65c11ecba4d51aa68b&scene=21#wechat_redirect)  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/aBHpjnrGyliavGLlka4ryB5YcPwZDUbQeq0aKa6eVzjIj15eoicmiaianu46Dxr1epA4MRsevou9P2iaztK3FibV9XIQ/640?wx_fmt=png "")  
[【安全圈】三星电子为何禁止AI工具？](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652033607&idx=1&sn=94ed923ad31b5356baf15324f363b43a&chksm=f36ffe07c4187711262c0fc19fb8d3c22cad8dbb2e75e17ca5b80e9339ca9eedf09183c2d729&scene=21#wechat_redirect)  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/aBHpjnrGyliavGLlka4ryB5YcPwZDUbQenwqbibUKIuCN8UtaugwpO91c8KHEzd8WPmsKbPeWfxHuyVxoEkkZEXw/640?wx_fmt=png "")  
[【安全圈】百度文库接入“文心一言”，15 秒即可帮你创作一篇文档！](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652033526&idx=1&sn=8e7773fe007e75a24d99c4c659cabaff&chksm=f36ffdb6c41874a0e3c8d2f8fee9a1b1475aa87f5eab82ec06607f52ff67bc0e8c605a795039&scene=21#wechat_redirect)  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/aBHpjnrGyliavGLlka4ryB5YcPwZDUbQeibkKnzYctYHKOyI8UIOjicDJx2d7J5icVtP21s0FFx29YPgP94axRkmsg/640?wx_fmt=png "")  
[【安全圈】男子雇佣“黑客”恢复聊天记录，4000元换来的却是一只插座](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652033652&idx=2&sn=c5b599489b78290d83ffeeb5d2a638bf&chksm=f36ffe34c4187722e8d90c9ecce2c7215efcede47f4395be2b5527625861131bc8823b6b4a77&scene=21#wechat_redirect)  
  
  
  
[【安全](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652030093&idx=4&sn=e988dc890e595695befbdb177d11b98c&chksm=f36fe8cdc41861dbd78f5270a42fca19c1d45cb375ef4469e8a36bef1f42620f990d03714872&scene=21#wechat_redirect)  
  
  
‍  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/aBHpjnrGylgeVsVlL5y1RPJfUdozNyCEft6M27yliapIdNjlcdMaZ4UR4XxnQprGlCg8NH2Hz5Oib5aPIOiaqUicDQ/640?wx_fmt=gif&wxfrom=5&wx_lazy=1 "")  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/aBHpjnrGylgeVsVlL5y1RPJfUdozNyCEDQIyPYpjfp0XDaaKjeaU6YdFae1iagIvFmFb4djeiahnUy2jBnxkMbaw/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
**安全圈**  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/aBHpjnrGylgeVsVlL5y1RPJfUdozNyCEft6M27yliapIdNjlcdMaZ4UR4XxnQprGlCg8NH2Hz5Oib5aPIOiaqUicDQ/640?wx_fmt=gif&wxfrom=5&wx_lazy=1 "")  
  
  
←扫码关注我们  
  
**网罗圈内热点 专注网络安全**  
  
**实时资讯一手掌握！**  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/aBHpjnrGylgeVsVlL5y1RPJfUdozNyCE3vpzhuku5s1qibibQjHnY68iciaIGB4zYw1Zbl05GQ3H4hadeLdBpQ9wEA/640?wx_fmt=gif "")  
  
**好看你就分享 有用就点个赞**  
  
**支持「****安全圈」就点个三连吧！**  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/aBHpjnrGylgeVsVlL5y1RPJfUdozNyCE3vpzhuku5s1qibibQjHnY68iciaIGB4zYw1Zbl05GQ3H4hadeLdBpQ9wEA/640?wx_fmt=gif "")  
  
  
