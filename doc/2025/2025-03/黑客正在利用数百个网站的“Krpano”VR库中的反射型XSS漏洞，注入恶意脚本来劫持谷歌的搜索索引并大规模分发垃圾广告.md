#  黑客正在利用数百个网站的“Krpano”VR库中的反射型XSS漏洞，注入恶意脚本来劫持谷歌的搜索索引并大规模分发垃圾广告   
 Ots安全   2025-03-01 11:20  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/bL2iaicTYdZn7gtxSFZlfuCW6AdQib8Q1onbR0U2h9icP1eRO6wH0AcyJmqZ7USD0uOYncCYIH7ZEE8IicAOPxyb9IA/640?wx_fmt=gif "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/rWGOWg48tadqfhCXR9kpXZ6YDO4WJAZEqKC5xR0ic4ricBBbDMUVIX30dauG0wAVVzia6okrCDXicAPGQVrMFhxD0w/640?wx_fmt=webp&from=appmsg "")  
  
我是如何意外发现互联网上最常被利用的 XSS 漏洞之一的  
  
我的故事开头可能和许多技术博客的读者一样熟悉——又是一个独自坐在电脑前，平淡无奇的夜晚。出于纯粹的学习目的，我打开了一个 Chrome 隐身窗口，进入 Google，输入了“色情”一词。由于我在这个领域的持续研究，我对常见的搜索结果非常熟悉。但这次，一些不寻常的东西引起了我的注意——第三行出现了一个新网站，列在耶鲁大学的域名下，标题为：“++[S*X@Porn-xnxx-Videos!…] 泰米尔性感学生。”这激起了我的好奇心，但原因可能和你想象的不一样。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/rWGOWg48tadqfhCXR9kpXZ6YDO4WJAZEibdAhGKf1oTibjP97bCrQnxFhSK2ib7Z21tQNt0aHI4loCtKGLL3H7udg/640?wx_fmt=webp&from=appmsg "")  
  
耶鲁大学进军色情行业了吗？  
  
我几乎可以肯定该网站已被黑客入侵，但我仍然不确定是如何入侵的。我首先想到的是子域名接管——这是一种常见的攻击，攻击者劫持指向未使用资产的废弃CNAME 记录，以在原始域名下托管恶意内容。我之前在Guardio 的研究中探索过这种技术，在那里我创造了“Subdomailing”一词。  
  
为了验证我的理论，我点击了链接，看看它会带我去哪里。页面最初加载的看起来像是一个合法的平台，但很快就将我重定向到一个随机的色情广告。  
  
```
https://virtualtour.quantuminstitute.yale.edu/?id=yuxs&xml=https://staging-prep-cms.scouts.org.uk/lnk/video/?video=video-xx-indain-girl-xxx-xxxxxxx-xvid-60159.html
```  
  
  
检查原始 URL 时，我们发现了以下几点：子域名暗示该网站与虚拟旅游有关，并且xml参数包含一个看起来可疑的 URL——这绝对需要深入研究。  
  
出于好奇，我尝试再次打开相同的 URL，但不带参数——突然，我发现自己身处耶鲁大学量子力学研究所。快速参观了一下，令人印象深刻的地方。如果你对量子计算感兴趣，值得一看。但老实说，我从来没有真正理解过叠加——一个比特怎么能同时是 0 和 1？说真的，这是怎么回事？😂  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/rWGOWg48tadqfhCXR9kpXZ6YDO4WJAZEWO5QMngVM616EnST0enrQ0QDgTehU3XVDbkxnBEFlfZCibx5NtDiaW5Q/640?wx_fmt=webp&from=appmsg "")  
  
……总之，回到正题。  
  
逆向载荷  
  
该参数显然是关键因素，因此我考虑了开放重定向xml 的可能性。我将参数值修改为 https://www.example.com，希望进行重定向——但页面却抛出了错误：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/rWGOWg48tadqfhCXR9kpXZ6YDO4WJAZE3aHG3NzuYibUffNIE1QDYkzD2qzlgg0zicR9S0w3G6xmpbDPjwczMoRw/640?wx_fmt=webp&from=appmsg "")  
  
那时，我知道这不仅仅是一个简单的重定向。我甚至还没有检查原始xml参数——当我检查时，有一件事引人注目：该 URL 属于英国童子军官方网站，这似乎很可疑。快速的 DNS 检查证实了我的怀疑——子域名已通过废弃的 Azure 帐户被劫持，就像我之前解释的那样。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rWGOWg48tadqfhCXR9kpXZ6YDO4WJAZEibiciaRjLicjCzwibADbcnVT6pAibBMgnSt0keiauCg2iaJ5yPuBuMcaNiciacKA/640?wx_fmt=png&from=appmsg "")  
  
然后，我检查了URL 的响应内容，看看里面有什么：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rWGOWg48tadqfhCXR9kpXZ6YDO4WJAZEAz3JZ0R0ssp0AI9L1z7ScOCBeFtkeItX2e3ltXyGFMlWLb1sl0BtJA/640?wx_fmt=png&from=appmsg "")  
  
响应是一个 XML 文档，其中的onloaded事件包含一个执行Base64 编码负载的eval函数- 这是恶意 XSS（跨站点脚本）负载最经典的指标之一。  
  
那一刻，我感到一阵兴奋——这是我第一次在野外发现一个被主动利用的XSS。别误会我的意思——我强烈反对这样的恶意活动，但我内心的研究人员忍不住庆祝😂。  
  
除了 XSS 之外，主标签<krpano>还揭示了支持我进行量子研究所虚拟之旅的底层技术。  
> Krpano是一种流行的框架，用于托管&nbsp;360°&nbsp;图像和视频，可创建交互式虚拟游览和虚拟现实体验。它支持各种格式，包括千兆像素图像和鱼眼投影，并允许通过&nbsp;XML&nbsp;和&nbsp;JavaScript&nbsp;进行自定义。  
  
  
这意味着XSS 要么存在于框架本身中，要么存在于网站的实现中。  
  
出于好奇，我很想知道有效载荷到底做了什么，于是我对其进行了解码：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/rWGOWg48tadqfhCXR9kpXZ6YDO4WJAZEfCzsXOUqKBF3yrp8glTDsvr9YFdezQiazrQMJ7lLjZxeWeHIibtD9EnA/640?wx_fmt=webp&from=appmsg "")  
  
该脚本并没有什么特别复杂之处——只是它从另一个被盗资产（这次是volvo.com ）中获取目标 URL ，并使用该id参数来识别广告活动。  
  
此时，我甚至还没有完全开始调查，就已经发现了来自三个主要组织的三项被滥用资产。就在那时，我意识到——这不仅仅是一些在 Telegram 上销售服务的随机黑客。我正在与一个真正的攻击者打交道——他拥有大量被盗资产，并且行动有条不紊。  
  
Zero Day 还是 One Day?  
  
逆向这个 XSS 的过程很有趣。起初，我假设外部 XML 加载是 Krpano 库的预期功能，漏洞在于 XML 的解析方式。因此，我开始调试混淆的库，寻找真相的来源。经过 30 分钟的挖掘，我终于做了我从一开始就应该做的事情——查看文档。结果就在那里：  
  
XMLonloaded属性？一个已记录的功能。  
  
外部xml参数？一个设计选择 - 应该在生产中禁用。  
  
我遇到了一个关键的配置设置- passQueryParameter。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/rWGOWg48tadqfhCXR9kpXZ6YDO4WJAZE4PzUX7Op3duqRGY6icTureuTYlJOBAXsh8NbSI9Vicf2n6ZyURJjWUZg/640?wx_fmt=webp&from=appmsg "")  
  
此设置控制是否将托管网站的查询参数直接传递到 Krpano 的配置中。问题是什么？多年来，它一直由 Krpano 的默认安装启用。这意味着，如果易受攻击的网站未明确禁用它，任何攻击者都可以注入任意 XML，从而导致反射型 XSS。  
  
深入挖掘后，我发现了CVE-2020-24901。描述与我观察到的完全一致：由设置导致的反射型 XSSpassQueryParameter。虽然原始 POC使用了不同的参数，xml但也提到了该参数。那么，这是一天之内发生的吗？是的。但不知何故，它逃过了太多网站，正如您将要看到的那样。  
  
鞋匠的孩子们赤脚行走  
  
在这个Krpano 论坛帖子中，一位用户提出了对该 CVE 的担忧——距离该 CVE 披露整整一年。Krpano 的开发人员淡化了这个问题，声称这是一个滥用案例，而不是安全漏洞。然而，他们确实提到，从版本开始1.20.10，他们限制passQueryParameter使用允许列表以试图防止 XSS。  
  
但问题就在这里。  
  
明确将xml参数添加到允许列表仍然会保留 相同的 XSS 风险，并且此配置仍然可供使用。  
  
现在，最好的部分来了。  
  
在浏览 Krpano 的文档时，我注意到他们在自己的网站上托管了 360° 游览框架的现场示例。自然而然，我检查了他们的实现……你猜怎么着？他们也存在漏洞。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/rWGOWg48tadqfhCXR9kpXZ6YDO4WJAZEEG2qHcy0AiaH1mTDUeBHHfhjJibwiajxZhWMQsnfIHA2It71Vibl4z5QWQ/640?wx_fmt=webp&from=appmsg "")  
  
一个简单的 XSS 为大规模广告活动提供了支持    
  
破解了漏洞的技术层面后，我改变了思路——我想了解整体情况。这次攻击活动有多广泛？有多少其他网站被利用了？这时我突然有了一个想法。与其盲目地追寻线索，为什么不使用我的老朋友Google Dorking 呢？  
  
```
inurl:xml=https AND inurl:id=
```  
  
  
就这样，我 打开了潘多拉盒子。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/rWGOWg48tadqfhCXR9kpXZ6YDO4WJAZEu5rN9tbyJKYDEqysTaKESIOFAezk2238xuQGYvOsNEGR2NlGLZP6aQ/640?wx_fmt=webp&from=appmsg "")  
  
这次活动的规模之大让我措手不及。通过几次 Google 搜索，我发现了数千条广告，分布在350 多个被利用的网站上— — 而且不是随便哪个网站。  
  
政府门户网站。全州网站。美国顶尖大学。大型连锁酒店。新闻媒体。汽车经销商。财富 500 强企业。所有这些都被劫持并被重新用作 SEO 工具，以传播垃圾邮件、广告和可疑促销。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rWGOWg48tadqfhCXR9kpXZ6YDO4WJAZE2GJkCkUXI93cSsMcg5sGCl2oSkgPxSicah1YQRr0c9icgrPyNpqNPlHg/640?wx_fmt=png&from=appmsg "")  
  
这些网站大多数都非常受欢迎，每月有数百万访问者，有些网站访问量多次，提供不同类型的广告。  
  
而且不再只是色情广告。我发现了膳食补充剂、在线赌场、虚假新闻网站——每一种可疑的广告，我们都会本能地毫不犹豫地关闭。但真正的惊喜是什么？其中一些被劫持的页面甚至没有推送广告——它们被用来增加 YouTube 观看次数。  
  
这不仅仅是一次垃圾邮件行动，这是对受信任域名的大规模滥用。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/rWGOWg48tadqfhCXR9kpXZ6YDO4WJAZEHFVEvOaG1ibWxsKerc8yxYmU7m2AdyGstrPVUNqPKRmfkIbONHgrR3Q/640?wx_fmt=webp&from=appmsg "")  
  
我还分析了 xml 参数值。有些是常见的嫌疑对象：廉价的一次性域名，使用隐私保护的 WHOIS 信息注册，因此无法追踪所有者。但其他呢？劫持主要网站的子域名。  
  
针对 SEO 投毒的 XSS   
  
这次活动的一切都彰显出SEO 专家的风采。最大的证据之一就在本博客的开头——我展示了他们如何将广告推到Google 搜索结果的第三行，而 Google 搜索结果中搜索最多的词条之一就是“色情”。当然，利用耶鲁大学的域名在提升可信度方面发挥了重要作用，但实现这种级别的排名操纵仍不是一件容易的事。   
  
除此之外，反射型 XSS 的概念本身就被用来在 SEO 结果中推广……这是我以前从未见过的，至少在这种规模上是从未见过的。反射型 XSS 是一个有趣的漏洞，但它本身需要用户交互，而最大的挑战之一是让人们点击你的反射型 XSS 链接。因此，使用搜索引擎作为 XSS 的分发平台是一种非常有创意且很酷的方法。  
  
这些家伙从他们入侵的每个网站榨干了每一滴水。以犹他州的官方网站为例——在我搜索时，它有超过 100 个索引垃圾邮件结果。   
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/rWGOWg48tadqfhCXR9kpXZ6YDO4WJAZE7dicEzoUIvHHvEMHvTcu3AdTz93jbQUr1gslvpajXuEal8zxlueWvQQ/640?wx_fmt=webp&from=appmsg "")  
  
请记住，我的数据仅限于 Google Dorks，这意味着他们可能已经对同一页面进行了数百次不同的广告索引，超出了我所能看到的范围。  
  
他们不只是注入链接，还对链接进行优化：  
- 控制标题、描述和预览图像。  
  
- 在标题中使用随机字符串使每个结果都独一无二。  
  
- 添加了虚假的评论数量和星级评定。  
  
我无法准确估计此次活动产生了多少点击量，但从其规模来看，数百万并不夸张。   
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/rWGOWg48tadqfhCXR9kpXZ6YDO4WJAZE5ga8DUDaFVXVPjr7Ge9IMeKPyESBlvql6mZ9fchMjPn1WnkDH3zpOA/640?wx_fmt=webp&from=appmsg "")  
  
但还有一个问题一直困扰着我……   
  
为什么仅广告重定向？  
  
出于某种原因，我一直认为利用 XSS 的最佳方法是直接攻击易受攻击的网站及其用户群 — 窃取 Cookie、会话令牌或代表用户执行操作。然而，在这种情况下，我发现的只是JavaScript 执行简单的重定向，仅此而已 🤔。  
  
通过逻辑思考，我发现他们选择这种方法可能有两个原因：  
  
他们可能是一家不正当的广告公司，对到处投放广告比直接发起网络攻击更感兴趣。这可能是他们最有效的盈利策略。  
  
他们的行动处于法律的灰色地带——虽然他们的做法不道德，但他们并不是彻头彻尾的犯罪分子。如果他们窃取用户数据或发起全面攻击，那么行动就会升级为引起执法和调查的事件。然而，他们所做的只是分发广告。  
  
但是，在挖掘被抓取的网站时，我偶然发现了更大的东西——一个每月访问量超过 5 亿的网站，而且受到了特殊对待。  
  
CNN——不仅仅是重定向  
  
这不仅仅是又一个高流量网站被入侵的案例。是什么让它如此引人注目？点击恶意链接并没有将我重定向到其他地方——它让我直接进入 cnn.com，进入看似合法的 CNN 文章。相同的域名，相同的结构——只是内容是土耳其语的，标题是“最可靠的在线赌场”。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rWGOWg48tadqfhCXR9kpXZ6YDO4WJAZEqicLebZsrGeRHeDN9iaegUHc11Exbfhwpqw6Iic1829iaqjHqvfaopQOJQ/640?wx_fmt=png&from=appmsg "")  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rWGOWg48tadqfhCXR9kpXZ6YDO4WJAZEawPPB8piaA6iazyhkSODl0TtMKID4B3MNwFXI3pRx7ze8CMaIeXFcp8g/640?wx_fmt=png&from=appmsg "")  
  
这是确凿的证据，证明攻击者清楚地知道自己手中握着什么。他们没有使用廉价的重定向（这很浪费），而是直接将赌场宣传嵌入 CNN 的域名中，伪装成一篇真实的文章。他们不仅劫持了流量，而且还将信任武器化。  
  
深入挖掘后发现，xml 有效载荷托管在这个“无可疑”域名“jqeury.store”上。该域名的主页提供了指向同一 CNN 漏洞的多个实例的链接列表，每个实例都提供赌场文章的不同变体。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/rWGOWg48tadqfhCXR9kpXZ6YDO4WJAZEP4BP9JJv8h1t8ic8Fyk7z5jZQhNUibm88htrdrCl9k51D5xfH5sdPicHA/640?wx_fmt=webp&from=appmsg "")  
  
但事情并没有就此结束。一些链接还指向巴基斯坦最大的新闻网站“geo.tv”。打开这些链接后，我们发现了同样的伎俩——将虚假文章注入易受攻击的端点，全部宣传同一个赌场。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/rWGOWg48tadqfhCXR9kpXZ6YDO4WJAZEyOp2qZCJtCSO5uZws0n3S4oXdObPyzeeUWKOo8huV11qF6ra1dLLpQ/640?wx_fmt=webp&from=appmsg "")  
  
负责任的披露  
  
这场活动的幕后黑手仍然是个谜，但从我所看到的情况来看，很多线索表明它是由一个阿拉伯组织运营的——基于我在调查过程中发现的广告、模式和随机线索。无论如何，我都不在乎；这对执法部门来说是个问题。然而，我能做的是尽量减少损失，联系受影响最大的品牌。  
  
我打算报告尽可能多的被利用的情况。但我没想到这竟然如此困难。我亲自发现了300 多个被利用的域名，但大多数都没有漏洞披露程序。我花了数小时追踪联系电子邮件和提交表格，但我的大多数报告都无果而终——被埋在未读收件箱中或被退回，没有任何回复。  
  
不过，还是有收获的。一些报告通过了审核，让我获得了美国卫生与公众服务部和欧盟计算机应急响应小组 (CERT-EU) 等主要组织的认可。一些易受攻击的资产甚至得到了修复——其中一些要归功于我的披露，另一些则纯属巧合。  
  
正是在那时，我决定开设自己的博客，以揭示被忽视的攻击媒介并吸引更广泛的受众。如果说这次经历有什么值得强调的话，那就是这些问题远远超出了少数被利用的域的范围——而且除非有人发出足够的声音，否则这些问题不会得到解决。  
  
Krpano 的回应  
  
在报告任务的同时，我还联系了 Krpano 的开发人员，在他们自己的网站上强调了易受攻击的实现，并对XML 参数的处理表示担忧。该库的主要开发人员 Klaus 迅速而专业地回复了我的报告，认真对待了我的报告。几周内，他在版本中实施了修复1.22.4，限制通过 XML 参数加载外部资源——有效地关闭了这个攻击媒介。  
  
向 Klaus 致以崇高的敬意 👑  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rWGOWg48tadqfhCXR9kpXZ6YDO4WJAZEicfmwhRhkfbB1stpHQ1PFx1KUSm8aNsyhhs25z8qyQq8mdnzAPcQTuQ/640?wx_fmt=png&from=appmsg "")  
  
  
  
  
感谢您抽出  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWgdSBqOibtgiaYWjL4pkRXwycNnFvFYVgXoExRy0gqCkqvrAghf8KPXnwQaYq77HMsjcVka7kPcBDQw/640?wx_fmt=gif "")  
  
.  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWgdSBqOibtgiaYWjL4pkRXwycd5KMTutPwNWA97H5MPISWXLTXp0ibK5LXCBAXX388gY0ibXhWOxoEKBA/640?wx_fmt=gif "")  
  
.  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWgdSBqOibtgiaYWjL4pkRXwycU99fZEhvngeeAhFOvhTibttSplYbBpeeLZGgZt41El4icmrBibojkvLNw/640?wx_fmt=gif "")  
  
来阅读本文  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWge7Mibiad1tV0iaF8zSD5gzicbxDmfZCEL7vuOevN97CwUoUM5MLeKWibWlibSMwbpJ28lVg1yj1rQflyQ/640?wx_fmt=gif "")  
  
**点它，分享点赞在看都在这里**  
  
  
