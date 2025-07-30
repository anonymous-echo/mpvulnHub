#  【安全圈】TP-Link 漏洞：Wi-Fi 凭据面临泄露风险   
 安全圈   2025-04-13 11:00  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGylgOvEXHviaXu1fO2nLov9bZ055v7s8F6w1DD1I0bx2h3zaOx0Mibd5CngBwwj2nTeEbupw7xpBsx27Q/640?wx_fmt=other&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
**关键词**  
  
  
  
安全漏洞  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGylhlF1sHmCwZibr500dtvWOV0eZHcCRn1SU9BQCnwpudQex0UfAicOQ1KsOWdJlDLMFCWEy70RzaS6EQ/640?wx_fmt=png&from=appmsg "")  
  
TP-Link Tapo H200 V1 物联网智能集线器存在一个严重漏洞，该漏洞可能会让用户的 Wi-Fi 凭据暴露给攻击者。  
  
该漏洞编号 CVE-2025-3442，其根源在于该设备的固件以明文形式存储敏感信息，这使得能够实际接触到该设备的攻击者可以获取这些信息。该漏洞被归类为 CWE-312（敏感信息明文存储），原因是设备的固件以明文形式存储 Wi-Fi 凭据。  
  
这一严重的疏忽使得能够实际接触到设备的攻击者可以提取并分析固件的二进制数据，从而有可能危及 Wi-Fi 网络的安全。  
  
**TP-Link IoT Smart Hub 漏洞**  
  
根据 CERT-In 的评估，该漏洞会影响运行固件版本 1.4.0 或更早版本的 TP-Link Tapo H1 V1.4.0 Smart Hub 设备。  
  
其严重程度被评定为中等，通用漏洞评分系统（CVSS）基础得分为 4.4 分。虽然攻击途径需要实际接触设备以及具备提取和分析固件的技术知识，这限制了它被广泛利用的可能性，但对于受影响的用户来说，潜在影响仍然很大。  
  
“出现这个问题是因为固件没有对设备用于连接用户无线网络的 Wi-Fi 凭据进行加密或混淆处理。” 熟悉该漏洞的安全专家解释道。  
  
一旦攻击者获取了这些凭据，他们就可以加入网络，窃听通信内容，并且有可能对其他已连接的设备发动攻击。  
  
TP-Link Tapo H200 Smart Hub 是连接和控制各种智能家居设备（包括运动传感器、门磁传感器和灯光开关）的核心设备。  
  
它使用户能够创建自动化程序、监控家庭安全，并通过移动应用程序或语音助手远程控制 IoT 设备。  
  
孟买的安全研究人员 Shravan Singh、Ganesh Bakare 和 Abhinav Giridhar 负责任地披露了该漏洞。  
  
他们的发现凸显了 IoT 安全领域持续存在的挑战，尤其是在凭据管理方面。  
  
以下是该漏洞的概述：  
<table><tbody><tr><td data-colwidth="187" width="187"><strong><b><span leaf="" style="color:rgba(0, 0, 0, 0.9);font-size:17px;font-family:&#34;mp-quote&#34;, -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;line-height:1.6;letter-spacing:0.034em;font-style:normal;font-weight:normal;">风险因素</span></b></strong></td><td data-colwidth="644" width="644"><strong><b><span leaf="" style="color:rgba(0, 0, 0, 0.9);font-size:17px;font-family:&#34;mp-quote&#34;, -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;line-height:1.6;letter-spacing:0.034em;font-style:normal;font-weight:normal;">详情</span></b></strong></td></tr><tr><td data-colwidth="187" width="187"><section><span leaf="" style="color:rgba(0, 0, 0, 0.9);font-size:17px;font-family:&#34;mp-quote&#34;, -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;line-height:1.6;letter-spacing:0.034em;font-style:normal;font-weight:normal;">受影响产品</span></section></td><td data-colwidth="644" width="644"><section><span leaf="" style="color:rgba(0, 0, 0, 0.9);font-size:17px;font-family:&#34;mp-quote&#34;, -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;line-height:1.6;letter-spacing:0.034em;font-style:normal;font-weight:normal;">TP-Link Tapo H200 V1 物联网智能集线器（固件版本 1.4.0 或更早版本）</span></section></td></tr><tr><td data-colwidth="187" width="187"><section><span leaf="" style="color:rgba(0, 0, 0, 0.9);font-size:17px;font-family:&#34;mp-quote&#34;, -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;line-height:1.6;letter-spacing:0.034em;font-style:normal;font-weight:normal;">影响</span></section></td><td data-colwidth="644" width="644"><section><span leaf="" style="color:rgba(0, 0, 0, 0.9);font-size:17px;font-family:&#34;mp-quote&#34;, -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;line-height:1.6;letter-spacing:0.034em;font-style:normal;font-weight:normal;">Wi-Fi 凭据暴露，导致未经授权的网络访问</span></section></td></tr><tr><td data-colwidth="187" width="187"><section><span leaf="" style="color:rgba(0, 0, 0, 0.9);font-size:17px;font-family:&#34;mp-quote&#34;, -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;line-height:1.6;letter-spacing:0.034em;font-style:normal;font-weight:normal;">利用前提条件</span></section></td><td data-colwidth="644" width="644"><section><span leaf="" style="color:rgba(0, 0, 0, 0.9);font-size:17px;font-family:&#34;mp-quote&#34;, -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;line-height:1.6;letter-spacing:0.034em;font-style:normal;font-weight:normal;">实际接触该设备，以及具备提取和分析固件的技术知识</span></section></td></tr><tr><td data-colwidth="187" width="187"><section><span leaf="" style="color:rgba(0, 0, 0, 0.9);font-size:17px;font-family:&#34;mp-quote&#34;, -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;line-height:1.6;letter-spacing:0.034em;font-style:normal;font-weight:normal;">CVSS 3.1 评分</span></section></td><td data-colwidth="644" width="644"><section><span leaf="" style="color:rgba(0, 0, 0, 0.9);font-size:17px;font-family:&#34;mp-quote&#34;, -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;line-height:1.6;letter-spacing:0.034em;font-style:normal;font-weight:normal;">4.4 分（中等严重程度）</span></section></td></tr></tbody></table>  
****  
**缓解措施**  
  
为缓解这一漏洞，CERT-In 建议立即采取以下几项措施。用户应将其 Smart Hub 的固件升级到 1.5.0 版本。  
  
此外，用户应限制对设备的实际接触，监控网络活动以发现未经授权的连接，如果怀疑设备已被入侵，应考虑更改 Wi-Fi 密码。  
  
对于安全要求较高的环境，专家建议通过将 IoT 设备放置在单独的网络或虚拟局域网（VLAN）中来实施网络分段，以遏制潜在的安全漏洞。  
  
这一事件凸显了 IoT 安全领域的一个根本性挑战：设备需要凭据才能访问网络，但又必须连接到网络才能安全地获取凭据。传统的设备入网方法往往涉及繁琐且不安全的流程，会导致敏感信息暴露。  
  
  
   END   
  
  
阅读推荐  
  
  
[【安全圈】军工研究院保密员被判无期](https://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652069034&idx=1&sn=255d379ee8d7c7932c4bad98af623ced&scene=21#wechat_redirect)  
  
  
  
[【安全圈】在校大学生滥用AI被抓](https://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652069034&idx=2&sn=7ba359c368ee8d44043e1bf88bce7164&scene=21#wechat_redirect)  
  
  
  
[【安全圈】微软4月安全更新：修复125个漏洞，12个存在高利用风险](https://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652069034&idx=3&sn=b2c1459405fd108b2d8796be35f685ea&scene=21#wechat_redirect)  
  
  
  
[【安全圈】美团崩了，客服回应正在修复系统](https://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652069020&idx=1&sn=022ed79cce0b038cf559d886b23da2af&scene=21#wechat_redirect)  
  
  
  
[【安全圈】邮件攻击再升级：Microsoft Office 365 用户面临凭据窃取与恶意软件双重危机](https://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652069020&idx=2&sn=0e35bc95a241b190fd76aeb61fd1ccfb&scene=21#wechat_redirect)  
  
  
  
  
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
  
  
