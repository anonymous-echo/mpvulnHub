#  【安全圈】UEFI启动固件曝出大量漏洞，数百万台计算机面临数据泄漏风险   
 安全圈   2024-01-20 19:01  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGylgOvEXHviaXu1fO2nLov9bZ055v7s8F6w1DD1I0bx2h3zaOx0Mibd5CngBwwj2nTeEbupw7xpBsx27Q/640?wx_fmt=png&from=appmsg "微信图片_20230927171534.png")  
  
**关键词**  
  
  
  
数据泄漏  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGylh8EibTnpJxMCIp1oZs3Ya00O4icYU1VqmfrJzJGMhR92ZTFAicBZtf5aTvGlDN5GyibVXicPkDum4aWMA/640?wx_fmt=png&from=appmsg "")  
  
不久前，安全公司Quarkslab揭示了一系列影响UEFI固件（负责启动操作系统的核心软件）的九个安全漏洞，这一组漏洞被合称为Pixie Fail。这些九个漏洞都存在于TianoCoreEFI开发套件II(EDK II)中，它们的利用可能导致远程代码执行、拒绝服务(DoS)攻击、DNS缓存中毒和敏感信息泄露等安全威胁。  
  
  
这些漏洞影响到了众多公司的UEFI固件，包括AMI、英特尔、Insyde以及Phoenix Technologies等。这一事实意味着数百万台计算机面临潜在的风险。UEFI（统一可扩展固件接口）是一种新一代的主板启动引导模式，被视为传统BIOS的继任者，具备图形化用户界面以及更快的启动速度。由于微软Windows 11将UEFI安全启动列为强制要求，UEFI正在逐渐取代BIOS，成为现代Windows操作系统计算机的主要启动方式。  
  
  
**漏洞详情**  
  
EDK II整合了自己的TCP/IP堆栈（NetworkPkg），以在初始预启动执行环境（PXE，发音为“pixie”）阶段启用网络功能，在操作系统尚未运行时执行管理任务。  
  
换而言之，EDKII是一个客户端-服务器接口，用于从网络接口卡(NIC)启动设备，并允许管理员远程配置和启动尚未加载操作系统的联网计算机。  
  
作为UEFI固件的一部分，PXE代码包含在主板上或NIC固件只读存储器(ROM)中：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGylh8EibTnpJxMCIp1oZs3Ya00pUrVpdRIpNOX5nM8rJHVJKu9JW9TQ1Mu94U0l9rTDTNhXRV1XmSscw/640?wx_fmt=png&from=appmsg "")  
  
Quarkslab在EDKII的TCP/IP堆栈（NetworkPkg）中发现的问题包括溢出错误、越界读取、无限循环以及使用弱伪随机数生成器(PRNG)，这些问题会导致DNS和DHCP中毒攻击、信息泄漏、拒绝服务、IPv4和IPv6层的数据插入攻击，漏洞列表如下：  
- CVE-2023-45229（CVSS分数：6.5）-处理DHCPv6通告消息中的IA_NA/IA_TA选项时出现整数下溢  
  
- CVE-2023-45230（CVSS分数：8.3）-DHCPv6客户端中通过长服务器ID选项发生缓冲区溢出  
  
- CVE-2023-45231（CVSS分数：6.5）-处理带有截断选项的ND重定向消息时出现越界读取  
  
- CVE-2023-45232（CVSS分数：7.5）-解析Destination Options标头中的未知选项时出现无限循环  
  
- CVE-2023-45233（CVSS分数：7.5）-解析Destination Options标头中的PadN选项时出现无限循环  
  
- CVE-2023-45234（CVSS分数：8.3）-处理DHCPv6通告消息中的DNS服务器选项时出现缓冲区溢出  
  
- CVE-2023-45235（CVSS分数：8.3）-处理来自DHCPv6代理广告消息的服务器ID选项时出现缓冲区溢出  
  
- CVE-2023-45236（CVSS评分：5.8）-可预测的TCP初始序列号  
  
- CVE-2023-45237（CVSS评分：5.3）-使用弱伪随机数生成器  
  
CERT协调中心(CERT/CC)在一份公告中表示：“这些漏洞的影响和可利用性取决于特定的固件版本和默认PXE启动配置。”  
  
“本地网络内的攻击者（在某些情况下是远程攻击者）可以利用这些漏洞来执行远程代码、发起DoS攻击、进行DNS缓存中毒或提取敏感信息。”  
  
  
  
   END    
  
  
阅读推荐  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGylh8EibTnpJxMCIp1oZs3Ya0051r7IJm4aicYgUlwjNszJQDCew2ibqoG8bZ72ovHcPh5sj20X05ART0w/640?wx_fmt=jpeg "")  
[【安全圈】富士康集成技术公司遭遇黑客攻击，威胁其支付百万赎金或被公开数据](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652052513&idx=1&sn=991c6143b0bd6ac8ecae44b3525fca2b&chksm=f36e3061c419b9772aec6d65d59144f44893aee0748652a39fe574249c4830882bc58e92210f&scene=21#wechat_redirect)  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGylh8EibTnpJxMCIp1oZs3Ya00vbnSxmqMee016cZibM0yKC4H40wb2EGI4a7kENchTVUHlvrVOII9zQw/640?wx_fmt=jpeg "")  
[【安全圈】因配置错误和安全漏洞，丰田保险公司客户信息遭泄露](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652052513&idx=2&sn=b0a5d07f59d75edef89bc1c7052de1ff&chksm=f36e3061c419b977332edb7a6145811241b15a7e61a9759592a776e74a6e57c50e2e703ef843&scene=21#wechat_redirect)  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGylh8EibTnpJxMCIp1oZs3Ya00CRMss99yqL7VV3iadPmiaNxxAeswYDa71cUNbh5kAdjNRyY83mRbwaow/640?wx_fmt=png&from=appmsg "")  
[【安全圈】2.83G ！知名国防企业萨博公司内部数据遭泄露](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652052513&idx=3&sn=df055ccfe238b60eae30abbaa55c1a04&chksm=f36e3061c419b97709b68435f2da97ec2a3d6de406d1ad24e25527d0628783fec5ee0b82309a&scene=21#wechat_redirect)  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGylh8EibTnpJxMCIp1oZs3Ya00sPMXlXG5KpagsIhfIDSbuNTcUulXdyss5JxmZSic5eNgIBjkRXuQePA/640?wx_fmt=jpeg "")  
[【安全圈】CISA 警告 Ivanti EPMM 漏洞正在被广泛利用](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652052513&idx=4&sn=dd56c5eb73fdfbb54c49b7bb7128aaf8&chksm=f36e3061c419b977e44376f0c27224f874c1e6361b5df34021fe5ac622c0f6bb9031af236432&scene=21#wechat_redirect)  
  
  
  
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
  
  
