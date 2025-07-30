#  【安全圈】iOS 出现新严重漏洞，仅需一行代码即可导致 iPhone 崩溃   
 安全圈   2025-05-06 11:03  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGylgOvEXHviaXu1fO2nLov9bZ055v7s8F6w1DD1I0bx2h3zaOx0Mibd5CngBwwj2nTeEbupw7xpBsx27Q/640?wx_fmt=other&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
**关键词**  
  
  
  
安全漏洞  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGylgY6eeZKvCDeL2Xbs1JicUaY7GjcxQT8EYrjxWQf85iaWXDnAicELzK1ibCPoR0H8ALa0ib5a8JO7J7Zicg/640?wx_fmt=png&from=appmsg "")  
  
iOS 中的一个严重漏洞可能允许恶意应用程序仅使用一行代码即可永久禁用 iPhone。  
  
该漏洞的编号为 CVE-2025-24091，利用操作系统的 Darwin 通知系统触发无限重启循环，导致设备“变砖”，需要进行完整的系统还原。  
## iOS Darwin 通知漏洞  
##   
  
该漏洞利用了 Darwin 通知，这是 CoreOS 层内的一种低级消息传递机制，允许进程传达系统范围的事件。 与 NSNotificationCenter 或 NSDistributedNotificationCenter 等更常见的通知系统不同，Darwin 通知是 Apple 操作系统中在基础层面上运行的旧式 API 的一部分。  
  
Darwin 通知更加简单，因为它们是 CoreOS 层的一部分。它们提供了一种低级机制，用于在 Apple 操作系统的进程之间进行简单的消息交换。发现该漏洞的安全研究员 Guilherme Rambo 解释道。  
  
这个严重缺陷的根源在于，iOS 上的任何应用程序都可以发送敏感的系统级 Darwin 通知，而无需特殊权限或授权。最危险的是，这些通知可以触发强大的系统功能，包括进入“正在恢复”模式。  
## 单行漏洞利用  
##   
  
该漏洞利用非常简单——只需一行代码即可触发该漏洞：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGylgY6eeZKvCDeL2Xbs1JicUaYr7uQ0lXlqYibkEnqRuaVDtjaHf9SevFjGJJxjANOWhnuTveeF3HEzVw/640?wx_fmt=png&from=appmsg "")  
  
执行此代码后，设备会强制进入“正在恢复”状态。由于实际恢复过程并未发生，因此该过程必然会失败，提示用户重启设备。研究人员创建了一个名为“VeryEvilNotify”的概念验证攻击，并在一个小部件扩展中实现了此漏洞。  
  
研究人员指出：  “iOS 会定期在后台唤醒 Widget 扩展程序。”  
  
“由于系统中小部件的使用非常广泛，当安装并启动包含小部件扩展的新应用程序时，系统非常渴望执行其小部件扩展”。  
  
通过将漏洞利用程序放置在发送通知后反复崩溃的小部件中，研究人员创建了一种在每次重启后都会触发的持续性攻击，从而形成了一个无限循环，导致设备无法使用。  
  
<table><tbody><tr><td><strong><font><font><span leaf="" style="color:rgba(0, 0, 0, 0.9);font-size:17px;font-family:&#34;mp-quote&#34;, -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;line-height:1.6;letter-spacing:0.034em;font-style:normal;font-weight:normal;">风险因素</span></font></font></strong></td><td><strong><font><font><span leaf="" style="color:rgba(0, 0, 0, 0.9);font-size:17px;font-family:&#34;mp-quote&#34;, -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;line-height:1.6;letter-spacing:0.034em;font-style:normal;font-weight:normal;">细节</span></font></font></strong></td></tr><tr><td><font><font><span leaf="" style="color:rgba(0, 0, 0, 0.9);font-size:17px;font-family:&#34;mp-quote&#34;, -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;line-height:1.6;letter-spacing:0.034em;font-style:normal;font-weight:normal;">受影响的产品</span></font></font></td><td><font><font><span leaf="" style="color:rgba(0, 0, 0, 0.9);font-size:17px;font-family:&#34;mp-quote&#34;, -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;line-height:1.6;letter-spacing:0.034em;font-style:normal;font-weight:normal;">iOS（运行 iOS/iPadOS 18.3 之前版本的 iPhone 和 iPad）</span></font></font></td></tr><tr><td><font><font><span leaf="" style="color:rgba(0, 0, 0, 0.9);font-size:17px;font-family:&#34;mp-quote&#34;, -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;line-height:1.6;letter-spacing:0.034em;font-style:normal;font-weight:normal;">影响</span></font></font></td><td><font><font><span leaf="" style="color:rgba(0, 0, 0, 0.9);font-size:17px;font-family:&#34;mp-quote&#34;, -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;line-height:1.6;letter-spacing:0.034em;font-style:normal;font-weight:normal;">拒绝服务（DoS）</span></font></font></td></tr><tr><td><font><font><span leaf="" style="color:rgba(0, 0, 0, 0.9);font-size:17px;font-family:&#34;mp-quote&#34;, -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;line-height:1.6;letter-spacing:0.034em;font-style:normal;font-weight:normal;">漏洞利用前提条件</span></font></font></td><td><font><font><span leaf="" style="color:rgba(0, 0, 0, 0.9);font-size:17px;font-family:&#34;mp-quote&#34;, -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;line-height:1.6;letter-spacing:0.034em;font-style:normal;font-weight:normal;">任何沙盒应用程序或小部件扩展都可以触发此漏洞；无需特殊权限</span></font></font></td></tr><tr><td><font><font><span leaf="" style="color:rgba(0, 0, 0, 0.9);font-size:17px;font-family:&#34;mp-quote&#34;, -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;line-height:1.6;letter-spacing:0.034em;font-style:normal;font-weight:normal;">CVSS 3.1 评分</span></font></font></td><td><font><font><span leaf="" style="color:rgba(0, 0, 0, 0.9);font-size:17px;font-family:&#34;mp-quote&#34;, -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;line-height:1.6;letter-spacing:0.034em;font-style:normal;font-weight:normal;">高</span></font></font></td></tr></tbody></table>## 缓解措施  
##   
  
苹果通过为敏感的 Darwin 通知实施新的授权系统，解决了 iOS 18.3 中的漏洞。研究人员获得了 17,500 美元的漏洞赏金。  
  
具体来说，系统通知现在需要前缀“com.apple.private.restrict-post”，并且发送进程必须拥有“com.apple.private.darwin-notification.restrict-post.<notification>”形式的受限权限。  
  
这并不是苹果系统中第一个与达尔文相关的漏洞。此前，卡巴斯基实验室发现了一个“达尔文核弹”漏洞，该漏洞可能允许远程攻击者通过特制的网络数据包发起拒绝服务攻击。  
  
强烈建议所有 iPhone 用户立即更新至 iOS 18.3 或更高版本。运行早期版本的设备仍然容易受到此攻击，该攻击可能通过 App Store 或其他分发渠道中看似无害的应用程序或小部件进行部署。该案例凸显了移动操作系统中持续存在的安全挑战，即使是简单且被忽视的遗留 API，如果保护不当，也可能带来重大风险。  
  
来源：  
https://cybersecuritynews.com/ios-critical-vulnerability-brick-iphones/  
  
  
  
  END    
  
  
阅读推荐  
  
  
[【安全圈】某机关工作人员用扫描APP加网盘致127份涉密文件遭泄露！！](https://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652069446&idx=1&sn=cdb886ad48aa07b1291c56c13b3a291e&scene=21#wechat_redirect)  
  
  
  
[【安全圈】微软Telnet服务器被曝0-Click漏洞：无密码即可控制系统](https://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652069446&idx=2&sn=b093a02905ad8999ac398713a11bd267&scene=21#wechat_redirect)  
  
  
  
[【安全圈】网安公司CEO因非法控制医院电脑被逮捕](https://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652069446&idx=3&sn=71724284d0e78496375f89e77e21a8b6&scene=21#wechat_redirect)  
  
  
  
  
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
  
  
