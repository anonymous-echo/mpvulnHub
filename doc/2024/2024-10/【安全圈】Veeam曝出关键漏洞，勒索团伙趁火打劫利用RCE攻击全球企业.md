#  【安全圈】Veeam曝出关键漏洞，勒索团伙趁火打劫利用RCE攻击全球企业   
 安全圈   2024-10-11 19:01  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGylgOvEXHviaXu1fO2nLov9bZ055v7s8F6w1DD1I0bx2h3zaOx0Mibd5CngBwwj2nTeEbupw7xpBsx27Q/640?wx_fmt=png&from=appmsg "微信图片_20230927171534.png")  
  
  
**关键词**  
  
  
  
勒索软件  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGylhnDHDVAe6opKibJQic1Q8NrGgAGjs88iaMaZ6HaOu2rQMMJEt4LVGFRGJ6KSknPm5EJucIjP7c5mQLw/640?wx_fmt=jpeg&from=appmsg "")  
  
勒索软件团伙现在利用一个关键的安全漏洞，让攻击者在易受攻击的 Veeam Backup & Replication (VBR) 服务器上获得远程代码执行 (RCE)。  
  
Code White安全研究员Florian Hauser发现，该安全漏洞（现在被追踪为CVE-2024-40711）是由未受信任数据的反序列化弱点引起的，未经认证的威胁行为者可以利用该漏洞进行低复杂度攻击。  
  
Veeam 于 9 月 4 日披露了该漏洞并发布了安全更新，而 watchTowr Labs 则于 9 月 9 日发布了一份技术分析报告。不过，watchTowr Labs 将概念验证利用代码的发布时间推迟到了 9 月 15 日，以便管理员有足够的时间确保服务器安全。  
  
企业将 Veeam 的 VBR 软件作为数据保护和灾难恢复解决方案，用于备份、恢复和复制虚拟机、物理机和云计算机，从而导致了这一延迟。这也使其成为恶意行为者寻求快速访问公司备份数据的热门攻击目标。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGylhnDHDVAe6opKibJQic1Q8NrGnCIGfkJJTtSHRIHW3NeXHa8grk5VOv8zib3g1NTfjjrNuvia4T6tHXeA/640?wx_fmt=jpeg&from=appmsg "")  
  
正如 Sophos X-Ops 事件响应人员在上个月发现的那样，CVE-2024-40711 RCE 漏洞很快被发现，并在 Akira 和 Fog 勒索软件攻击中被利用，与之前泄露的凭证一起，向本地管理员和远程桌面用户组添加“点”本地帐户。  
  
在一个案例中，攻击者投放了Fog勒索软件。同一时间段的另一起攻击则试图部署 Akira 勒索软件。Sophos X-Ops表示：所有4起案件中的迹象都与早期的Akira和Fog勒索软件攻击重叠。  
  
在每起案件中，攻击者最初都是使用未启用多因素身份验证的受损 VPN 网关访问目标。其中一些 VPN 运行的是不支持的软件版本。  
  
在Fog勒索软件事件中，攻击者将其部署到未受保护的Hyper-V服务器上，然后使用实用程序rclone外泄数据。  
## 这并非勒索软件攻击针对的首个Veeam漏洞  
  
去年，即 2023 年 3 月 7 日，Veeam 还修补了备份与复制软件中的一个高严重性漏洞（CVE-2023-27532），该漏洞可被利用来入侵备份基础架构主机。  
  
几周后的3月下旬，芬兰网络安全和隐私公司WithSecure发现CVE-2023-27532漏洞部署在与FIN7威胁组织有关的攻击中，FIN7威胁组织因与Conti、REvil、Maze、Egregor和BlackBasta勒索软件行动有关而闻名。  
  
几个月后，同样的Veeam VBR漏洞被用于古巴针对美国关键基础设施和拉美IT公司的勒索软件攻击。  
  
Veeam表示，其产品已被全球超过55万家客户使用，其中包括至少74%的全球2000强企业。  
  
参考来源：Akira and Fog ransomware now exploit critical Veeam RCE flaw (bleepingcomputer.com)  
  
  
END  
  
  
阅读推荐  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGyliaEQFic5fXxFib2BUvlzqYQJz4RAk6ibl9EA8hxkWBkU4kExoqSdhEIKwyb1mszy0VqicJZpkLt7sBK0w/640?wx_fmt=png "")  
[【安全圈】 微软已修复Word自动删除文件问题 请各位重启Word或使用命令行修复](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652065105&idx=1&sn=10c376f4ec8aaeb9f70061c53fb6ca98&chksm=f36e6111c419e8071ff5f06a133faf65b2c0cca1900a11dcf4700dc23ce47835c5d11a626830&scene=21#wechat_redirect)  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGyliaEQFic5fXxFib2BUvlzqYQJzMaK9Qb20KVsCtD0I9qc2jHgs58Rz2GETrenOT94Txfib8shqlEiaglfw/640?wx_fmt=jpeg "")  
[【安全圈】Internet Archive 遭遇黑客攻击，导致 3100 万用户数据泄露](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652065105&idx=2&sn=2da49c20338b3002ab1297319299af19&chksm=f36e6111c419e807845ac66cff18994a328629966c2b413ee6fabee6037e5913685dc480eca2&scene=21#wechat_redirect)  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGyliaEQFic5fXxFib2BUvlzqYQJz4GmVcCe5esmiceKonf29fBL7dKotc2xbXvpibxbOwLb6nLYzpsFXSxuw/640?wx_fmt=jpeg "")  
[【安全圈】DumpForums论坛黑客声称从网络安全公司 Dr.Web 窃取了 10TB 数据](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652065105&idx=3&sn=d0ce1215f3b42342b33a8e605130d7d7&chksm=f36e6111c419e80724412c09f2781cb77ee2c352135f8873d43ffd741621ab6c16e9782171d6&scene=21#wechat_redirect)  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGyliaEQFic5fXxFib2BUvlzqYQJzxAqTbZUGnYgSMeywibAFPjGwj0f2Xut7fA5VKWnGssbxQicMicHySVugA/640?wx_fmt=other "")  
[【安全圈】微软发现文件托管服务在商业电子邮件妥协攻击中的使用越来越多](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652065105&idx=4&sn=99c192e299edb2f31774af7f91c22a0d&chksm=f36e6111c419e807116cb9573a3be5576d409d5823888239323f6b39d75e22b3b0a0cf2e06f2&scene=21#wechat_redirect)  
  
  
  
  
  
  
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
  
  
  
