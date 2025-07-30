#  【漏洞预警】：紧急！H3C GR-3000AX代码执行漏洞或成内网渗透跳板   
原创 52  易云安全应急响应中心   2025-04-23 07:35  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/jh6wChayy6pEMf8LaFbbghgd6kFhmZMMueZicicT5DSwjSPKaP4H588pe8gicbA6HP78PlEibv3S9gWyG0zLjAdy6Q/640?wx_fmt=gif "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/gTsGxaRgdp1Kh6Wcmqs25jdAibYsX5kmOEgsHx491y0WjJIRcePKo7utxtjKgO291jw6RgsCcM8ib8iaicoFNX7eoA/640?wx_fmt=png "")  
  
点击上方蓝字  
关注我们  
  
![](https://mmbiz.qpic.cn/mmbiz_png/e3fsAtee7NfvV03bALWicIRC9ONMxfVtp8MLLJ6p9R4BSGXMI5acslsX4nJenqKG3rFc3aJSSJ7sCzkNoLvic4sg/640?wx_fmt=png "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/5X70R0fF5e4FFPleNdVv2RxYjmxzubcw17k8wUxRibtd4IKlJPX9WicaDn7OGIH4UN9rYpia9Dgzm5JJ48V8reOyg/640?wx_fmt=gif "")  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/gMiabmiaticAtTVS0RD8icXq59ZN22GjKvOyYG2n7ODNVP12fgz7aiaAiaJiaqobEUMmEgECGM9NJB63fLicTesgsCm3icg/640?wx_fmt=png&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/xufCTymBicsiciatQaIFEfGAbOTvMBuiaswvYicsJIx1Mfq5JGWLzL1NibxJ8lJVI8JTJXCp3NGOF0xX2iavDcCPbIpdA/640?wx_fmt=png "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/BV0ictYJptb0uC1vhWtPz1TYt5eWmZHymCg8tg0wXYWzYIYcS9z2Ric98RtttspEjXocTlOuciblr2iaQkliaxJInfw/640?wx_fmt=png "")  
  
  
  
漏洞预警  
  
![](https://mmbiz.qpic.cn/mmbiz_png/M5Df0SpicpuTgoRpOzcK6u0eich9iaaaTG4IkeqIqRCfJsxXHsd8w5Bv2qicjibKXcWDviaBvAdEvWdxsu4Vw4jXGpfQ/640?wx_fmt=png "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/9VfBEZAAlCdiaLkskRWZia0oSibVNXA6EzFFebibptK3guAvdNZ6azxPz4aoKFdDgIqXYnsq920h6tcDbnjjBH83lg/640?wx_fmt=png "")  
  
  
1、漏洞描述  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Gib2Yy5m2znEEuxecMNQ27OZwmdicvRkvicctYibNH30S4dYH0cS4dwmAl81AmSvJiaic8wudohwcRSPfUK6c6oeN0Yw/640?wx_fmt=png "")  
  
近日，易云科技监测到一则H3C GR-3000AX远程代码执行漏洞。  
  
H3C GR-3000AX 是新华三（H3C）推出的一款高性能企业级 Wi-Fi 6 无线路由器。产品  
支持多场景组网，  
支持 Wi-Fi 6（802.11ax）标准，双频并发速率达 3000Mbps（2.4GHz 574Mbps + 5GHz 2402Mbps），并支持 160MHz 大频宽，适合高密度终端接入。  
内置高通企业级芯片，配备 4 根外置高增益天线和独立 PA/LNA 信号放大器，覆盖范围广且穿墙能力强；  
提供多 WAN 口接入（最多 4 个）、负载均衡、链路备份，保障网络稳定性。  
  
1.漏洞编号：  
CVE-2025-3854  
  
2.发现时间：2025-4-23  
  
3.漏洞类型：远程代码执行  
  
4.漏洞等级：高危  
  
5.PoC/EXP：未公开  
  
6.在野利用：否  
  
2、漏洞危害  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Gib2Yy5m2znEEuxecMNQ27OZwmdicvRkvicctYibNH30S4dYH0cS4dwmAl81AmSvJiaic8wudohwcRSPfUK6c6oeN0Yw/640?wx_fmt=png "")  
  
H3C GR-300０AX V100R0０6及更早版本中存在高危远程代码执行漏洞，攻击者可利  
用该漏洞在同一内网内，无需授权远程执  
行恶意指令，可能导致网络设备被接管或内网渗透。该漏洞利用门槛低且危害连锁性强，  
建议相关用户紧急排查修复  
。  
  
3、受影响版本  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Gib2Yy5m2znEEuxecMNQ27OZwmdicvRkvicctYibNH30S4dYH0cS4dwmAl81AmSvJiaic8wudohwcRSPfUK6c6oeN0Yw/640?wx_fmt=png "")  
  
H3C GR-3000AX: V100R006及以下版本。     
  
4、处置建议  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Gib2Yy5m2znEEuxecMNQ27OZwmdicvRkvicctYibNH30S4dYH0cS4dwmAl81AmSvJiaic8wudohwcRSPfUK6c6oeN0Yw/640?wx_fmt=png "")  
  
针对此漏洞,官方已经发布了漏洞修复版本,请前往H3C官方网站下载最新的固件更新,补丁编号为V100R007。  
  
下载地址：https://www.h3c.com/cn/Service/Document_Software/Software_Download/Consume_product/,安装步骤请参考官方文档。  
  
5、参考链接  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Gib2Yy5m2znEEuxecMNQ27OZwmdicvRkvicctYibNH30S4dYH0cS4dwmAl81AmSvJiaic8wudohwcRSPfUK6c6oeN0Yw/640?wx_fmt=png "")  
  
```
https://mp.weixin.qq.com/s/D9fkyr36RZF3LVoh3l1zNA
```  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/Gjzq8xnQKEV0l6dDbjlSQv0HZ8EvGaTPQxhVdg1v07h5gy6vSlnjEBAQTgZPvjyzH9yAlRlkraemufMwgr2A6w/640?from=appmsg&wx_fmt=gif "")  
  
  
免责声明  
  
本文仅供技术分享之用，请勿进行任何非法测试。对于因传播和利用本公众号"易云安全应急响应中心"所提供的信息而导致的后果和损失，使用者将承担全部责任。本公众号及作者对此不承担任何法律责任。如有侵权，请及时告知，我们将立即删除并致以诚挚的歉意。  
  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Gib2Yy5m2znEEuxecMNQ27OZwmdicvRkvictVWdVVfMA9mb2auhgAL5yLwm0icpkbsKI5t6c70ibw9yFTF9Psw0vAoA/640?wx_fmt=png "")  
  
END  
  
![](https://mmbiz.qpic.cn/mmbiz_png/mj9AGZCb1794ic7m1GChnu5strxcIIHSz63SYez7xYvLy0HL3ichHt3oyhX2ghYKibKic3kDxIs0DyBfJLDdOqxJBA/640?wx_fmt=png "")  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/6aVaON9Kibf6qHRdibQTh7Bic33HXRicZowtjiavqOsjjNTNWNtssMJtfSYn6uT1PgnaWWnMlSPevI96XXRdM4tibYqQ/640?wx_fmt=other&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
**淮安易云科技有限公司-****网络安全部******  
  
我们致力于保障客户的网络安全，监控事件并采取适当措施，设计和实施安全策略，维护设备和软件，进行漏洞扫描和安全审计,团队协调处理网络攻击、数据泄露等安全事故，并负责安全服务项目实施，包括风险评估、渗透测试、安全扫描、安全加固、应急响应、攻防演练、安全培训等服务，确保客户在网络空间中的安全。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/US10Gcd0tQHDte6ZzXiclrYUTCQHiak0k38kaD0O6NSfpyrRicr2rspyQicXCp6I4iagSbNbaKt2IiboYfRyUpnDZrtQ/640?wx_fmt=other&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/6aVaON9Kibf6qHRdibQTh7Bic33HXRicZowtjiavqOsjjNTNWNtssMJtfSYn6uT1PgnaWWnMlSPevI96XXRdM4tibYqQ/640?wx_fmt=other&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
**易云安全应急响应中心**  
  
专业的信息安全团队，给你最安全的保障。定期推送  
漏洞预警、技术分享文章和网络安全知识，让各位了解学习安全知识，普及安全知识、提高安全意识。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/US10Gcd0tQHDte6ZzXiclrYUTCQHiak0k38kaD0O6NSfpyrRicr2rspyQicXCp6I4iagSbNbaKt2IiboYfRyUpnDZrtQ/640?wx_fmt=other&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/dTxkmqQ6SznicxdpxUKbBLoJzSlpvNfyfeGn8PIB1Wx5kSbhECECnibDwEYfQrkyyjQibSo1zMUX5sJo4KzcibF9GQ/640?wx_fmt=gif "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/b96CibCt70iaacU9xqCuIQia8mZiaTMod2IN9AChx36cA68kz5OEIiafWY2ntLy087rDibJJtdhx6ewb2ico3hc2hl3HA/640?wx_fmt=png "")  
  
扫描二维码  
  
获取更多精彩  
  
壹伴编辑器  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/gMiabmiaticAtSia0prnfkWIj7vlIkbFPGibN2sUrBbqFSpgHDHhz9s0ic6smsEy0Dae8bnOUPibYNuuj4gwOyqjiac9ow/640?wx_fmt=jpeg "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/b96CibCt70iaacU9xqCuIQia8mZiaTMod2INniajhTc48WZfuY7PCw9UA4DKrNZOicLsdP89LD2hpwGoI3umV1WxrkNw/640?wx_fmt=png "")  
  
  
往期推荐  
  
  
  
[【网络安全保卫战 】三名美国特工被我国警方悬赏通缉！](https://mp.weixin.qq.com/s?__biz=MzkyNDcwMTAwNw==&mid=2247534855&idx=1&sn=69d0e58c0425e64d2a9a1a5696fe48e1&scene=21#wechat_redirect)  
  
  
[【漏洞预警】Foxmail邮件客户端存在跨站脚本攻击漏洞，建议立即升级防护！](https://mp.weixin.qq.com/s?__biz=MzkyNDcwMTAwNw==&mid=2247534828&idx=1&sn=e9c2cc00e07c9dbaf6239c626a8a4abc&scene=21#wechat_redirect)  
  
  
[深度解读 | 第十个全民国家安全教育日，聚焦网络安全防线构建](https://mp.weixin.qq.com/s?__biz=MzkyNDcwMTAwNw==&mid=2247534846&idx=1&sn=ee00075a712ea2304e597157416e6a0b&scene=21#wechat_redirect)  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/iaic181R2RnYicpic6GbdiazMpqiaIrCaa2fbjKHtn8kiayKGGBeW0icqgpfzNqmibShxqsn2DMDggpaxnKjrY1sCWZXWng/640?wx_fmt=png "")  
  
转发  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ItKicuUNQ9EMVAsW4tKUASR3dbCFrBib4ibY05IeDzhxf9b1KMxjzLaukAYt0NfYLchE5eibmaSHibiamfT9wDQibytww/640?wx_fmt=png "")  
  
收藏  
  
![](https://mmbiz.qpic.cn/mmbiz_png/jwUk1NOJTytvIJd6VYGIIp4cA0qNKtMv7tAziatxhK4whicjTxAPklWUEfjejWvRbEbJjKDoRhZpUaPaEibpFYbcQ/640?wx_fmt=png "")  
  
点赞  
  
![](https://mmbiz.qpic.cn/mmbiz_png/K2CMDET8V6nLGsmoNxVfZytJuZzowIia6LuVg70JTa2jGiaozMwyvhG9eKOKVa5rzaj1QOgfPm4a2lsEJ7GN7zCQ/640?wx_fmt=png "")  
  
在看  
  
