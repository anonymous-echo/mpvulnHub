#  【漏洞复现】PHP-CGI Windows平台远程代码执行漏洞   
原创 Sec探索者  Sec探索者   2024-06-16 12:17  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Melo944GVOJECe5vg2C5YWgpyo1D5bCkJrGicxw4mL5UYpL9RmBdKdft5iatHZicb4BrxO3ENyQOEVKKDeSwTG2Jw/640?wx_fmt=other&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "组 61 拷贝 2.png")  
  
点击蓝字，关注Sec探索者，一起探索网络安全技术  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Melo944GVOJECe5vg2C5YWgpyo1D5bCkYN4sZibCVo6EFo0N9b7Kib4I4N6j6Y10tynLOdgov9ibUmaNwW5yeoCbQ/640?wx_fmt=other&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Melo944GVOJECe5vg2C5YWgpyo1D5bCkhic5lbbPcpxTLtLccZ04WhwDotW7g2b3zBgZeS5uvFH4dxf0tj0Rutw/640?wx_fmt=other&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Melo944GVOJECe5vg2C5YWgpyo1D5bCk524CiapZejYicic1Hf8LPt8qR893A3IP38J3NMmskDZjyqNkShewpibEfA/640?wx_fmt=other&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
请勿利用文章内的相关技术从事非法测试，由于传播、利用此文所提供的信息而造成的任何直接或者间接的后果及损失，均由使用者本人负责，作者不为此承担任何责任。如有侵权烦请告知，我们会立即删除并致歉。谢谢！  
  
**01******  
  
**漏洞描述**  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Melo944GVOJECe5vg2C5YWgpyo1D5bCkEPVCSE8TicyQLuettC2pcGgfe3PY8L2lHia8ZWLcNr1Fz7p3pb69Voow/640?wx_fmt=gif&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1 "")  
  
  
2024年6月，PHP官方发布新版本，修复了 PHP-CGI 中一个远程代码执行漏洞。鉴于该漏洞无前置条件，易于利用，且默认情况下可获取操作系统权限，建议所有使用受影响版本的企业尽快升级修复，以确保安全。该漏洞可在受影响的环境下执行任意PHP代码，从而获取操作系统权限。最严重的情况下，这可能导致服务器的完全接管，敏感数据泄露，甚至将服务器转化为发起其他攻击的跳板。  
  
  
**02******  
  
**漏洞环境**  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Melo944GVOJECe5vg2C5YWgpyo1D5bCkEPVCSE8TicyQLuettC2pcGgfe3PY8L2lHia8ZWLcNr1Fz7p3pb69Voow/640?wx_fmt=gif&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1 "")  
  
  
影响范围：  
  
PHP 8.3 < 8.3.8  
  
PHP 8.2 < 8.2.20  
  
PHP 8.1 < 8.1.29  
  
其他版本官方已停止维护，可根据实际情况采取相应的缓解措施。  
  
FOFA语法：  
  
header="Xampps_info" || body="/xampps.jpg" || (header="location http" && header="xampp") || body="content=\"Kai Oswald Seidler" || title="XAMPP for" || title="XAMPP Version" || body="font-size: 1.2em; color: red;\">New XAMPP"  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Melo944GVOL7GLvwFtCZuibcnvL0PibFzjV3GHicCp4f8wGMEShWMiaZwSReBG2bQdcYNsy6lCZ8O6sxQlmlDuv2xQ/640?wx_fmt=png&from=appmsg "")  
  
  
**03******  
  
**漏洞复现**  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Melo944GVOJECe5vg2C5YWgpyo1D5bCkEPVCSE8TicyQLuettC2pcGgfe3PY8L2lHia8ZWLcNr1Fz7p3pb69Voow/640?wx_fmt=gif&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1 "")  
  
  
构造payload发送请求  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Melo944GVOL7GLvwFtCZuibcnvL0PibFzjajUq8sY9Dibq3icV5mD4rCSlzIz663d0ukZfLamqGPiaw2mWE2UZUpdfQ/640?wx_fmt=png&from=appmsg "")  
  
  
**04******  
  
**漏洞修复建议**  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Melo944GVOJECe5vg2C5YWgpyo1D5bCkEPVCSE8TicyQLuettC2pcGgfe3PY8L2lHia8ZWLcNr1Fz7p3pb69Voow/640?wx_fmt=gif&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1 "")  
  
  
升级修复方案  
  
官方已发布新版本修复漏洞，建议访问官方页面（  
https://www.php.net/  
）获取安全版本。  
  
  
**05******  
  
**检测工具**  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Melo944GVOJECe5vg2C5YWgpyo1D5bCkEPVCSE8TicyQLuettC2pcGgfe3PY8L2lHia8ZWLcNr1Fz7p3pb69Voow/640?wx_fmt=gif&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1 "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/Melo944GVOL7GLvwFtCZuibcnvL0PibFzjpFmkxvic4xDa5tLW9DUwYPOibbEuL5nVxQY9VcmZhNS58jQ2QpAVNmaw/640?wx_fmt=other&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/Melo944GVOL7GLvwFtCZuibcnvL0PibFzjhkbpibpfFs6DvhsfUbRUCq15O1Cdic14ibd3Fu386ogpF2rBEShbwjMUA/640?wx_fmt=other&from=appmsg "")  
  
  
**06******  
  
**圈子服务介绍**  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Melo944GVOJECe5vg2C5YWgpyo1D5bCkEPVCSE8TicyQLuettC2pcGgfe3PY8L2lHia8ZWLcNr1Fz7p3pb69Voow/640?wx_fmt=gif&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1 "")  
  
  
无论你是新手还是行业老手，我们都致力于为你提供最新、最优质的安全资源和交流平台。立即加入Sec探索者专属的内部圈子，与我们一起探索安全领域的无尽可能性！以下是我们圈子为内部成员提供的核心服务：  
  
**1、最新漏洞情报：**  
  
提供最新的漏洞情报，第一时间复现和分析互联网暴露的重点高危漏洞，确保大家能第一时间掌握最新的漏洞动态  
  
**2、内部漏洞知识库：**  
漏洞知识库正在持续建设中，我们将会提供详细的漏洞复现教程和poc，帮助大家深入理解漏洞的工作原理和利用方式。所有漏洞都是我们自己成功复现才会添加到知识库中，减少大家试错时间成本，我们将收集相对完整的漏洞信息、漏洞描述、分析以及针对每个漏洞的利用方法和防护建议，致力于打造一个全面且专业的漏洞知识库。   
  
**3、漏洞综合利用工具：**  
提供多种漏洞利用工具，这些工具经过内部严格测试和大家的反馈，确保其有效性和安全性。无论大家是在进行渗透测试、漏洞验证，还是其他安全研究，这些工具都能为大家提供强有力的支持。  
  
**4、会员账号共享：**  
我们提供空间测绘高级会员账号，方便大家用于资产收集；提供CMD5会员服务，用于解密MD5哈希值；我们提供短信接码平台，帮助大家在各种网络活动中进行手机号码验证。  
  
**5、圈子互动：**  
每个人都可以成为内部圈子中的一员，这里有志同道合的朋友，大家可以相互分享经验、探讨问题，共同进步。无论大家在使用工具、访问知识库，还是进行其他活动中遇到问题，都可以随时联系我们，我们将竭诚为大家服务。  
  
**6、更多资源分享：**  
我们会分享最新的安全资源，包括报告、工具、代码样本等，让大家始终能够获得前沿的信息和资源。随着成员人数的增加，我们提供的资源也会越来越多。我们将不断丰富和更新我们的服务内容，以满足大家不断增长的需求。   
  
加入内部圈子（好的资源永远都在小圈子里面），我们期待与大家一起共同成长，探索网络安全的无限可能！   
  
![](https://mmbiz.qpic.cn/mmbiz_png/Melo944GVOJZUDB5jYwF0xYbdDUNSGMhTEW0yJr8VKyalq6lSoYZfb3ibTftMlDKegjb0mViajZTPINjicTXUcicDw/640?wx_fmt=png&from=appmsg "")  
  
  
  
也欢迎各位师傅们进我们公开的交流群，有任何技术问题都可以在群内进行交流讨论，进群方式如下  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Melo944GVOIOyOhEZkrWlcianYlTNGEkfJEF11Yn0qaX7ZiaJb41nIVoBIRxkRbRZZKnibkOCtU3tz7rzKzhicWpibA/640?wx_fmt=other&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/Melo944GVOIoFwyAA0ACwDMtpMoricB1Kzzs8yibZoLEuzHJicbULwe1bsha86W6mr3D6XNcqzzkhMktNfY7CZNhg/640?wx_fmt=jpeg&from=appmsg "")  
  
**pitaya**  
  
  
微信号：  
Ff39959  
  
需要进群请加运营备注   
加群  
 哦  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Melo944GVOIOyOhEZkrWlcianYlTNGEkfPibJvibwNCZnfziaYeyoC2cwp0lAyGv1WEYKHgNhp0JdCj6motcL74vtA/640?wx_fmt=other&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Melo944GVOIOyOhEZkrWlcianYlTNGEkfxOuWBhteCiaRdaHtePHhJMovro0Xia8kibfibrTD6TZPkMibu0pzvicIzHLg/640?wx_fmt=gif&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1 "")  
  
  
