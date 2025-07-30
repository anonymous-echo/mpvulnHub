> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652070451&idx=4&sn=1ae1f2640c97ff21fa27bdfc9eefb3dd

#  【安全圈】危险警告！D-Link 多款路由器曝出严重漏洞，建议立即停用  
 安全圈   2025-07-01 11:00  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGylgOvEXHviaXu1fO2nLov9bZ055v7s8F6w1DD1I0bx2h3zaOx0Mibd5CngBwwj2nTeEbupw7xpBsx27Q/640?wx_fmt=other&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
**关键词**  
  
  
  
安全漏洞  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGyliaic2t0ANMvs3ibiccV9FyPgVRmq93FxupsTgaHDheVo6FCM6Ot7zLdaY9kONH76ic24icOI2UdDTZe4GA/640?wx_fmt=png&from=appmsg "")  
  
最近，网络安全研究人员披露：**D-Link DIR-816 系列无线路由器存在多项高危漏洞**  
，可被远程攻击者控制，执行任意代码，完全接管你的网络。  
  
最严重的问题在于——**这些漏洞无法修复！**  
## 01｜受影响设备：D-Link DIR-816 系列路由器（非美版）  
  
无论是哪个硬件版本或固件版本，只要你使用的是 **D-Link DIR-816（非美国地区）路由器**  
，**都存在严重风险**  
。  
  
而且，D-Link 官方早已将该型号列为 **“生命周期结束”（End-of-Life）产品**  
，不会再发布任何安全补丁。这意味着这些漏洞是**永久性的**  
。  
## 02｜六个严重漏洞，总分高达 9.8  
  
研究人员共发现 **6 个严重漏洞**  
，其中 4 个为“**缓冲区溢出**  
”漏洞（CVSS 评分高达 9.8），2 个为“**命令注入**  
”漏洞（评分 7.3）。攻击者可通过网页管理界面远程发起攻击，**无需物理接触设备**  
：  
<table><thead><tr><th><section><span leaf="" style="color:rgba(0, 0, 0, 0.9);font-size:17px;font-family:&#34;mp-quote&#34;, &#34;PingFang SC&#34;, system-ui, -apple-system, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;line-height:1.6;letter-spacing:0.034em;font-style:normal;font-weight:normal;">漏洞编号</span></section></th><th><section><span leaf="" style="color:rgba(0, 0, 0, 0.9);font-size:17px;font-family:&#34;mp-quote&#34;, &#34;PingFang SC&#34;, system-ui, -apple-system, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;line-height:1.6;letter-spacing:0.034em;font-style:normal;font-weight:normal;">类型</span></section></th><th><section><span leaf="" style="color:rgba(0, 0, 0, 0.9);font-size:17px;font-family:&#34;mp-quote&#34;, &#34;PingFang SC&#34;, system-ui, -apple-system, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;line-height:1.6;letter-spacing:0.034em;font-style:normal;font-weight:normal;">危险评分</span></section></th><th><section><span leaf="" style="color:rgba(0, 0, 0, 0.9);font-size:17px;font-family:&#34;mp-quote&#34;, &#34;PingFang SC&#34;, system-ui, -apple-system, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;line-height:1.6;letter-spacing:0.034em;font-style:normal;font-weight:normal;">简介</span></section></th></tr></thead><tbody><tr><td><section><span leaf="" style="color:rgba(0, 0, 0, 0.9);font-size:17px;font-family:&#34;mp-quote&#34;, &#34;PingFang SC&#34;, system-ui, -apple-system, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;line-height:1.6;letter-spacing:0.034em;font-style:normal;font-weight:normal;">CVE-2025-5622</span></section></td><td><section><span leaf="" style="color:rgba(0, 0, 0, 0.9);font-size:17px;font-family:&#34;mp-quote&#34;, &#34;PingFang SC&#34;, system-ui, -apple-system, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;line-height:1.6;letter-spacing:0.034em;font-style:normal;font-weight:normal;">缓冲区溢出</span></section></td><td><section><span leaf="" style="color:rgba(0, 0, 0, 0.9);font-size:17px;font-family:&#34;mp-quote&#34;, &#34;PingFang SC&#34;, system-ui, -apple-system, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;line-height:1.6;letter-spacing:0.034em;font-style:normal;font-weight:normal;">9.8</span></section></td><td><section><span leaf="" style="color:rgba(0, 0, 0, 0.9);font-size:17px;font-family:&#34;mp-quote&#34;, &#34;PingFang SC&#34;, system-ui, -apple-system, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;line-height:1.6;letter-spacing:0.034em;font-style:normal;font-weight:normal;">通过无线参数构造溢出</span></section></td></tr><tr><td><section><span leaf="" style="color:rgba(0, 0, 0, 0.9);font-size:17px;font-family:&#34;mp-quote&#34;, &#34;PingFang SC&#34;, system-ui, -apple-system, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;line-height:1.6;letter-spacing:0.034em;font-style:normal;font-weight:normal;">CVE-2025-5623</span></section></td><td><section><span leaf="" style="color:rgba(0, 0, 0, 0.9);font-size:17px;font-family:&#34;mp-quote&#34;, &#34;PingFang SC&#34;, system-ui, -apple-system, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;line-height:1.6;letter-spacing:0.034em;font-style:normal;font-weight:normal;">缓冲区溢出</span></section></td><td><section><span leaf="" style="color:rgba(0, 0, 0, 0.9);font-size:17px;font-family:&#34;mp-quote&#34;, &#34;PingFang SC&#34;, system-ui, -apple-system, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;line-height:1.6;letter-spacing:0.034em;font-style:normal;font-weight:normal;">9.8</span></section></td><td><section><span leaf="" style="color:rgba(0, 0, 0, 0.9);font-size:17px;font-family:&#34;mp-quote&#34;, &#34;PingFang SC&#34;, system-ui, -apple-system, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;line-height:1.6;letter-spacing:0.034em;font-style:normal;font-weight:normal;">利用 QoS 功能地址参数</span></section></td></tr><tr><td><section><span leaf="" style="color:rgba(0, 0, 0, 0.9);font-size:17px;font-family:&#34;mp-quote&#34;, &#34;PingFang SC&#34;, system-ui, -apple-system, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;line-height:1.6;letter-spacing:0.034em;font-style:normal;font-weight:normal;">CVE-2025-5624</span></section></td><td><section><span leaf="" style="color:rgba(0, 0, 0, 0.9);font-size:17px;font-family:&#34;mp-quote&#34;, &#34;PingFang SC&#34;, system-ui, -apple-system, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;line-height:1.6;letter-spacing:0.034em;font-style:normal;font-weight:normal;">缓冲区溢出</span></section></td><td><section><span leaf="" style="color:rgba(0, 0, 0, 0.9);font-size:17px;font-family:&#34;mp-quote&#34;, &#34;PingFang SC&#34;, system-ui, -apple-system, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;line-height:1.6;letter-spacing:0.034em;font-style:normal;font-weight:normal;">9.8</span></section></td><td><section><span leaf="" style="color:rgba(0, 0, 0, 0.9);font-size:17px;font-family:&#34;mp-quote&#34;, &#34;PingFang SC&#34;, system-ui, -apple-system, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;line-height:1.6;letter-spacing:0.034em;font-style:normal;font-weight:normal;">同上</span></section></td></tr><tr><td><section><span leaf="" style="color:rgba(0, 0, 0, 0.9);font-size:17px;font-family:&#34;mp-quote&#34;, &#34;PingFang SC&#34;, system-ui, -apple-system, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;line-height:1.6;letter-spacing:0.034em;font-style:normal;font-weight:normal;">CVE-2025-5630</span></section></td><td><section><span leaf="" style="color:rgba(0, 0, 0, 0.9);font-size:17px;font-family:&#34;mp-quote&#34;, &#34;PingFang SC&#34;, system-ui, -apple-system, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;line-height:1.6;letter-spacing:0.034em;font-style:normal;font-weight:normal;">缓冲区溢出</span></section></td><td><section><span leaf="" style="color:rgba(0, 0, 0, 0.9);font-size:17px;font-family:&#34;mp-quote&#34;, &#34;PingFang SC&#34;, system-ui, -apple-system, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;line-height:1.6;letter-spacing:0.034em;font-style:normal;font-weight:normal;">9.8</span></section></td><td><section><span leaf="" style="color:rgba(0, 0, 0, 0.9);font-size:17px;font-family:&#34;mp-quote&#34;, &#34;PingFang SC&#34;, system-ui, -apple-system, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;line-height:1.6;letter-spacing:0.034em;font-style:normal;font-weight:normal;">利用局域网设置中的 IP 参数</span></section></td></tr><tr><td><section><span leaf="" style="color:rgba(0, 0, 0, 0.9);font-size:17px;font-family:&#34;mp-quote&#34;, &#34;PingFang SC&#34;, system-ui, -apple-system, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;line-height:1.6;letter-spacing:0.034em;font-style:normal;font-weight:normal;">CVE-2025-5620</span></section></td><td><section><span leaf="" style="color:rgba(0, 0, 0, 0.9);font-size:17px;font-family:&#34;mp-quote&#34;, &#34;PingFang SC&#34;, system-ui, -apple-system, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;line-height:1.6;letter-spacing:0.034em;font-style:normal;font-weight:normal;">命令注入</span></section></td><td><section><span leaf="" style="color:rgba(0, 0, 0, 0.9);font-size:17px;font-family:&#34;mp-quote&#34;, &#34;PingFang SC&#34;, system-ui, -apple-system, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;line-height:1.6;letter-spacing:0.034em;font-style:normal;font-weight:normal;">7.3</span></section></td><td><section><span leaf="" style="color:rgba(0, 0, 0, 0.9);font-size:17px;font-family:&#34;mp-quote&#34;, &#34;PingFang SC&#34;, system-ui, -apple-system, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;line-height:1.6;letter-spacing:0.034em;font-style:normal;font-weight:normal;">在 IPSec 配置中植入命令</span></section></td></tr><tr><td><section><span leaf="" style="color:rgba(0, 0, 0, 0.9);font-size:17px;font-family:&#34;mp-quote&#34;, &#34;PingFang SC&#34;, system-ui, -apple-system, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;line-height:1.6;letter-spacing:0.034em;font-style:normal;font-weight:normal;">CVE-2025-5621</span></section></td><td><section><span leaf="" style="color:rgba(0, 0, 0, 0.9);font-size:17px;font-family:&#34;mp-quote&#34;, &#34;PingFang SC&#34;, system-ui, -apple-system, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;line-height:1.6;letter-spacing:0.034em;font-style:normal;font-weight:normal;">命令注入</span></section></td><td><section><span leaf="" style="color:rgba(0, 0, 0, 0.9);font-size:17px;font-family:&#34;mp-quote&#34;, &#34;PingFang SC&#34;, system-ui, -apple-system, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;line-height:1.6;letter-spacing:0.034em;font-style:normal;font-weight:normal;">7.3</span></section></td><td><section><span leaf="" style="color:rgba(0, 0, 0, 0.9);font-size:17px;font-family:&#34;mp-quote&#34;, &#34;PingFang SC&#34;, system-ui, -apple-system, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;line-height:1.6;letter-spacing:0.034em;font-style:normal;font-weight:normal;">在 QoS 设置中注入系统命令</span></section></td></tr></tbody></table>  
这些攻击手段都可以让黑客远程执行恶意指令，**全面控制你的路由器**  
，进而窃听流量、篡改DNS、发起网络攻击等。  
## 03｜这款路由器没得救了  
  
更糟糕的是，**D-Link 官方不会修复这些漏洞**  
，因为：  
- DIR-816 系列已经停止支持；  
  
- 不再提供任何固件更新；  
  
- 所有版本都“无药可救”。  
  
D-Link 官方的建议非常明确：“立即停用并更换 DIR-816 路由器！”  
## 04｜你该怎么做？  
  
 **立刻检查你的家中或办公室是否使用了 D-Link DIR-816 路由器。**  
  
 **如果在用，请尽快更换为仍在支持的新品路由器。**  
建议选择具备活跃固件更新、明确安全承诺的大品牌设备。  
  
 **数据备份 + 设置恢复。**  
更换路由器前，可提前备份设置（如账号密码、端口映射），更换后手动重新配置。  
## 05｜这不是第一次，也不会是最后一次  
  
在物联网（IoT）快速普及的当下，**老旧路由器的安全问题已成为黑客攻击的重要入口**  
。相比操作系统或手机更新频繁，很多家庭和中小企业对网络设备的“漏洞风险”往往缺乏关注。  
  
但实际上，一台过时的路由器，就等于你家或公司网络的大门**永远不上锁**  
。  
## 写在最后  
  
**这不是危言耸听，而是一个真实且迫切的安全警告。**  
  
当厂商都放弃了这些设备，黑客反而还在不断寻找新的利用方式。与其冒着被入侵的风险，不如**花几百元换一台新路由器，远离隐患。**  
  
  
 END   
  
  
阅读推荐  
  
  
[【安全圈】美国监管机构已介入调查特斯拉在奥斯汀试运行的无人驾驶出租车](https://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652070437&idx=1&sn=fcaa00f37a3ba7365378a824c81d394e&scene=21#wechat_redirect)  
  
  
  
[【安全圈】全球银行业遭遇复杂DDoS攻击浪潮，亚太地区成重灾区](https://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652070437&idx=2&sn=1df700fe258190eee7c53dea02c69536&scene=21#wechat_redirect)  
  
  
  
[【安全圈】警惕 TikTok 热门视频传播盗版软件教程，实为窃密木马诱饵](https://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652070437&idx=3&sn=f58a7bf8c726187fd3620432575a291f&scene=21#wechat_redirect)  
  
  
  
[【安全圈】Pro-Iranian黑客组织“Cyber Fattah”泄露2024年沙特运动会数据](https://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652070437&idx=4&sn=70c8063e1fc95a9b199b2f1965124e26&scene=21#wechat_redirect)  
  
  
  
  
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
  
  
