#  【安全圈】微软警告称 Windows Hyper-V 零日漏洞正受到利用   
 安全圈   2024-07-11 19:01  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGylgOvEXHviaXu1fO2nLov9bZ055v7s8F6w1DD1I0bx2h3zaOx0Mibd5CngBwwj2nTeEbupw7xpBsx27Q/640?wx_fmt=png&from=appmsg "微信图片_20230927171534.png")  
  
  
**关键词**  
  
  
  
安全漏洞  
  
  
微软7月补丁日推出大量更新，以修复 Windows 生态系统中的安全漏洞，并警告称攻击者已经在野利用 Windows Hyper-V 权限提升漏洞。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGyliaIGjAYuDSicY1zEVhHQmJDfZIFWReru7j0pibepNVDeHzcvyicBYcNswB0OiaAq8cSibMMfxiaxWfRHZpg/640?wx_fmt=jpeg&from=appmsg "")  
  
微软在一份公告中表示：“成功利用此漏洞的攻击者可以获得系统权限”，并将 Hyper-V 问题标记为“检测到利用”类别。  
  
编号为CVE-2024-38080的 Windows Hyper-V 漏洞的 CVSS 严重性评分为 7.8/10。  
  
微软没有分享有关观察到的攻击的任何其他细节或任何数据或遥测数据来帮助防御者寻找感染迹象。  
  
另外，微软紧急呼吁关注 Windows MSHTML 平台欺骗漏洞 ( CVE-2024-38112 )，该漏洞也被标记为在野外被利用。  
> 微软表示：“要成功利用此漏洞，攻击者需要在利用之前采取额外措施来准备目标环境。攻击者必须向受害者发送一个恶意文件，受害者必须执行该文件。”  
  
  
这两个被利用的  
0day  
漏洞是微软7月补丁日发布的一大批补丁的重点，补丁修复了 Windows 生态系统中超过 140 个漏洞。在记录的 143 个漏洞中，有 5 个被评为严重，这是微软的最高严重等级。  
  
各个漏洞类别的漏洞数量如下：  
- 26 个特权提升漏洞  
  
- 24 个安全功能绕过漏洞  
  
- 59 个  
远程代码执行漏洞  
  
- 9 个信息泄露漏洞  
  
- 17 个拒绝服务漏洞  
  
- 7 个欺骗漏洞  
  
安全专家敦促 Windows 系统管理员特别注意 Microsoft Office SharePoint 中的一个严重远程代码执行漏洞 – CVE-2024-38023，该漏洞很可能被攻击者利用。  
  
Office SharePoint 漏洞可能允许具有站点所有者权限或更高权限的经过身份验证的攻击者将特制的文件上传到目标 SharePoint 服务器并制作专门的 API 请求来触发文件参数的反序列化。  
  
微软证实：“这将使攻击者能够在 SharePoint Server 的上下文中执行远程代码执行”，并指出具有站点所有者权限的经过身份验证的攻击者可以利用此漏洞注入任意代码并在 SharePoint Server 的上下文中执行此代码。  
  
微软补丁还为 Windows 图像组件和 Windows 桌面远程许可中的严重远程代码执行漏洞提供了保障。  
  
微软发布补丁的同一天，软件制造商 Adobe 也发布了针对 Adobe Premiere Pro、  
Adobe InDesign 和 Adobe Bridge 产品线安全缺陷的严重性补丁。  
  
Adobe 公司警告称：“成功利用此漏洞可能会导致任意代码执行。”Adobe 组件相关漏洞会影响 Windows 和 macOS 用户。  
  
  
END  
  
  
阅读推荐  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/dkwuWwLoRK9LecmctJ7PZpjbm5yykVQrEXCibr50aWRdf0h4Uamm346mvDtM75rhGibYM8MwCHaKIV4nArRspYpA/640?wx_fmt=other "")  
[【安全圈】不正当抓取高德地图“拥堵延时指数”，被判赔偿1250万](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652062714&idx=1&sn=83d0f85beffb166e77ceaaf9ce257782&chksm=f36e6fbac419e6acf95105a083618935cf06c9d6025e58fe5b5fa1f7a651e660c4c233cb4f08&scene=21#wechat_redirect)  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGyliav1dicSq0RTRo5q3UVhSGKmKcQ6WEhiaogw7064u8KQmLRtDPvxoaeD4RSTpth9H0jE8RIQh9pj2yw/640?wx_fmt=jpeg "")  
[【安全圈】微软或将为子公司违规行为支付85亿美元罚款](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652062714&idx=2&sn=a9a7dcf36577f8f2205120b6ede0bd8c&chksm=f36e6fbac419e6ac992ffcaa29d5ee680a1b031d14d27b73de2e6a227750da588fb65d0aefe6&scene=21#wechat_redirect)  
           
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGyliav1dicSq0RTRo5q3UVhSGKmicpBLeXkgibRfEGmq99AYT4nUAjlIU5vltoqEuicnpCS8ZogvqbiaVriaLA/640?wx_fmt=jpeg "")  
[【安全圈】RADIUS身份验证协议惊现三十年的漏洞，CERT呼吁紧急关注](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652062714&idx=3&sn=20195cf983f3cb8215a3c59511a3f685&chksm=f36e6fbac419e6ac6dd5872ae812a5d462a0164587076598f58f31f5cb9708a782b2174af7e1&scene=21#wechat_redirect)  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGyliav1dicSq0RTRo5q3UVhSGKm5aiaNTtQds9kIftAEuOZmbunecs9vCBJNY1NHB4xlusX9P66H4GM9cQ/640?wx_fmt=jpeg "")  
[【安全圈】新型APT组织CloudSorcerer瞄准俄罗斯政府](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652062714&idx=4&sn=02aa0946b5fd9def74c5cc4fafc38175&chksm=f36e6fbac419e6ac581247e05b51d297045e851930d2603dae2a9f8e5055eb0d6e50025af05d&scene=21#wechat_redirect)  
            
  
  
  
  
  
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
  
