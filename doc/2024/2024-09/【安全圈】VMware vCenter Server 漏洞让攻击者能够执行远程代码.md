#  【安全圈】VMware vCenter Server 漏洞让攻击者能够执行远程代码   
 安全圈   2024-09-18 19:00  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGylgOvEXHviaXu1fO2nLov9bZ055v7s8F6w1DD1I0bx2h3zaOx0Mibd5CngBwwj2nTeEbupw7xpBsx27Q/640?wx_fmt=png&from=appmsg "微信图片_20230927171534.png")  
  
  
**关键词**  
  
  
  
安全漏洞  
  
  
据Cyber Security News消息，VMware 披露了两个影响其 vCenter Server 和 Cloud Foundation 产品的关键安全漏洞，这些漏洞可能允许攻击者执行远程代码并提升权限。该公司敦促客户立即修补受影响的系统。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGylguXyao8qLTDpAhrpWyrGdHtjbFLiahibic0tYD0K2XEo41KeRFgxtWDliaWApAJGjOG9o7p1mPlxiaXmQ/640?wx_fmt=jpeg&from=appmsg "")  
  
其中一个漏洞被追踪为 CVE-2024-38812，是在 vCenter Server 中实施 DCERPC 协议时存在的堆溢出漏洞，CVSS 评分高达 9.8。根据 VMware 的公告，具有网络访问权限的攻击者对易受攻击的 vCenter Server可以通过发送特制网络数据包来触发此漏洞，从而导致远程代码执行。  
  
另一个漏洞被追踪为CVE-2024-38813，属 vCenter Server 中的权限提升缺陷，CVSS 评分7.5，可能允许攻击者通过发送恶意网络数据包将权限升级到 root。  
  
这两个漏洞都会影响 VMware vCenter Server 7.0 和 8.0 版本，以及 VMware Cloud Foundation 4.x 和 5.x 版本。  
  
VMware 已发布修补程序来解决这些缺陷，并强烈建议客户尽快应用这些更新。对于 vCenter Server，用户应尽快升级到8.0 U3b 或 7.0 U3s 版本，Cloud Foundation 客户应应用 KB88287 中引用的异步修补程序。  
  
该公司表示，到目前为止还没有发现任何对这些漏洞的野外利用。但是，鉴于 vCenter Server 在管理虚拟化环境方面的关键性质，这些缺陷可能成为攻击者的诱人目标。  
  
据悉，这两个漏洞由参加中国2024“矩阵杯”网络安全大赛的TZL研究人员发现，并在事后向 VMware 进行了报告。  
  
今年6月，VMware 曾修复了一个类似的 vCenter Server 远程代码执行漏洞 （CVE-2024-37079），该漏洞可通过特制数据包进行攻击。  
  
  
END  
  
  
阅读推荐  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGylguXyao8qLTDpAhrpWyrGdHTo2hby0p445o089tcsRZb2SHbqicZ80PZzS2mUGB3gBiaPtgEU9qhBHA/640?wx_fmt=jpeg "")  
[【安全圈】小米摄像头里惊现陌生男子说话!小米回应来了](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652064483&idx=1&sn=a23aa7b778084750615f37c245eed619&chksm=f36e66a3c419efb560f8dca0735fa5afe955f8a8da16e00a89b8f7e96c77d5ef9781a249e6ec&scene=21#wechat_redirect)  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGylguXyao8qLTDpAhrpWyrGdHKZNq9KmYMzEBwlcl93l9ibJcObLACoDwvoImY3I74PUhibuPDVYENfnA/640?wx_fmt=jpeg "")  
[【安全圈】115 网盘回应故障：服务器遭遇恶意网络攻击，“终止服务”系谣言](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652064483&idx=2&sn=59205321bd49a843db7e6335dac27647&chksm=f36e66a3c419efb5c75343945fa0943a8701784408de8eb6cbc1a8bfd08d966da277f8106b13&scene=21#wechat_redirect)  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGylguXyao8qLTDpAhrpWyrGdHvlZpkwGia9sic96uQotplBa5I1H8rMIqE0Vc9aXrydq2ykhbeLpibrZnQ/640?wx_fmt=jpeg "")  
[【安全圈】表弟遭“表哥”诈骗 1.5 万元，宁夏一起 AI 换脸诈骗案细节曝光](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652064483&idx=3&sn=135f9b6a7a9e8fb0dfe2a3f1d997aa90&chksm=f36e66a3c419efb5838d0801b682c02b1319d05e1166218972645e68208c83e9685c315f3473&scene=21#wechat_redirect)  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGylguXyao8qLTDpAhrpWyrGdHArXcdT6ricDHWJ29rrxJP1NJJzf6ANVfb7vo55397oG7OkX458NHwPA/640?wx_fmt=jpeg "")  
[【安全圈】虚拟货币交易发生纠纷，买家起诉后，法院判了](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652064483&idx=4&sn=96ffc8a524be62a883fdd3ab09b6382f&chksm=f36e66a3c419efb520c2fdde5d78508f9eb005217d3ace1bc6da8491afc697fa78643d05dc94&scene=21#wechat_redirect)  
                
  
  
  
  
  
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
  
  
  
