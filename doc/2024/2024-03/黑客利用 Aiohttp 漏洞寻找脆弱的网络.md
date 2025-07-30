#  黑客利用 Aiohttp 漏洞寻找脆弱的网络   
 塞讯安全验证   2024-03-28 13:30  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/D3YzQzbXJGa5T3KbjCkDpCMwufXftdVQoXaKmiaEqlBsIE48lrEcEncBEcUuVZ2pTan2UTxPhrfEp6Pg7ZLic7Og/640?wx_fmt=gif "")  
  
勒  
索软件攻击团伙 ShadowSyndicate 近期被观察到正在扫描存在 CVE-2024-23334漏洞的服务器，这是aiohttp Python库中的一个目录遍历漏洞。  
  
Aiohttp 是一个构建在 Python 异步 I/O 框架 Asyncio 之上的开源库，可以在没有传统的基于线程的网络的情况下处理大量并发HTTP请求。  
  
技术公司、Web 开发人员、后端工程师和数据科学家使用它来构建高性能 Web 应用程序和服务，以聚合来自多个外部 API 的数据。  
  
2024年1月28日，aiohttp 发布了版本 3.9.2，解决了 CVE-2024-23334问题，这是一个高严重性的路径遍历漏洞，影响 3.9.1 及更早版本的所有 aiohttp 版本，允许未经身份验证的远程攻击者访问有漏洞的服务器上的文件。  
  
该漏洞是由于当静态路由的“follow_symlinks”设置为“True”时验证不充分，从而允许未经授权访问服务器静态根目录之外的文件。  
  
2024年2月27日，一名研究人员在 GitHub 上发布了 CVE-2024-23334 的概念验证 (PoC) 漏洞利用，并于3月初在 YouTube 上发布了一段详细的视频，分步展示了漏洞攻击说明。  
  
据称，从2月29日开始，针对 CVE-2024-23334 的利用尝试就被捕获，并以更高的速度持续到 3 月。  
  
扫描尝试来自五个 IP 地址，Group-IB 在其2023年9月的一份报告中标记了其中一个 ，并将其与 ShadowSyndicate 勒索软件攻击者联系起来。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/D3YzQzbXJGYocz7BANkhfDnu8HJwQ2ZOpeP56PHrClAFD5sHOITNBFr4tbhiaF9mzPJpopVINEkia0MA32apDpkA/640?wx_fmt=jpeg&from=appmsg "")  
  
观察到的攻击 IP  
  
ShadowSyndicate 是一个机会主义、 以经济目的为动机的攻击者，自2022年7月以来一直活跃，与 Quantum、Nokoyawa、BlackCat/ALPHV、Cl0p、Royal、Cactus 和 Play 等勒索软件有不同程度的关联。  
  
Group-IB 认为该攻击者是与多个勒索软件运营机构合作的附属机构。  
  
发现表明攻击者可能正在使用 aiohttp 库的易受攻击版本对服务器进行扫描。目前尚不清楚这些扫描是否会导致进一步入侵。  
  
关于攻击面，Cyble 的互联网扫描仪 ODIN 显示，全球大约有44,170个暴露在互联网上的 aiohttp 实例。大多数（15.8%）位于美国，其次是德国（8%）、西班牙（5.7%）、英国、意大利、法国、俄罗斯和中国。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/D3YzQzbXJGYocz7BANkhfDnu8HJwQ2ZOmSs5f7dFGlJnZvr22ibicAcIOVolkXDTqicfaBA3c0CXHy2u6qVVZnubA/640?wx_fmt=png&from=appmsg "")  
  
公开的 aiohttp 实例 (Cyble)  
  
由于无法识别互联网暴露的实例的版本，因此很难确定存在漏洞的aiohttp服务器的数量。  
  
不幸的是，由于各种各样的实际问题，开源库经常在过时的版本中使用很长一段时间，这使得定位和修补它们变得复杂。  
  
这使得它们对于攻击者来说更有价值，因此即使在安全更新发布多年后，攻击者还是会对此进行利用。  
  
针对该漏洞利用的攻击模拟规则已经加入到塞讯安全度量验证平台中，如果您的环境中也在使用Aiohttp，您可以在塞讯安全度量验证平台中搜索关键词**“Aiohttp”**或  
**“CVE-2024-23334”**获取相关攻击模拟验证动作，从而验证您的安全防御体系是否能够有效应对该漏洞，平台以业界独有方式确保您的验证过程安全无害。  
  
塞讯验证建议采用了Aiohttp库的组织在不清楚自身是否存在漏洞的情况下，尽快对自身的防御准备做好提前验证，才能够做好主动防御，降低被入侵的风险。  
  
如需  
了解更多信息，欢迎拨打官方电话400-860-6366或发送邮件至mkt@validations.cn联系我们。  
您也可以扫描下方二维码添加官方客服，我们将竭诚为您服务。  
  
**用持续验证   建长久安全**  
  
****  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/D3YzQzbXJGZ6X2NtUtFjicOPdYZbdXy10MvHQBIuSJGLDTSiaPRQTib1ZHKqLjibLs8Jm9fIYaCBpzUfFj1Efibvtvw/640?wx_fmt=gif&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
**长按图片扫码添加【官方客服】**  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/D3YzQzbXJGZc61MO7yLs2nJa9K6ndfaocica0SmniasTB10oR41lBMfPRlT9mtF0ku3GdRO30Mj4UMs0YCw8Y0cQ/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
[](http://mp.weixin.qq.com/s?__biz=Mzk0MTMzMDUyOA==&mid=2247496428&idx=1&sn=6c5120c3d108b2c26ef32bb15adc86a7&chksm=c2d6abe3f5a122f5151eba32f1eca823200af30417a434e464bb3289a4f04c112a2cd99f572f&scene=21#wechat_redirect)  
  
[](http://mp.weixin.qq.com/s?__biz=Mzk0MTMzMDUyOA==&mid=2247496428&idx=2&sn=d182dd4d9d9ac3c2831d2315fa4f14fb&chksm=c2d6abe3f5a122f531aa1ab683b865b26ec5a9c4e68e6326ebb75f4b597e87cc06eec145f48f&scene=21#wechat_redirect)  
  
[](http://mp.weixin.qq.com/s?__biz=Mzk0MTMzMDUyOA==&mid=2247496440&idx=1&sn=4c508a648920bafe2a626d326365163f&chksm=c2d6abf7f5a122e1cdc5487f15ff3e1201f14dc83099ee7ebaf83baf5747cdc9dd797a02681e&scene=21#wechat_redirect)  
  
塞讯验证是国内网络安全度量验证平台开创者，率先提出利用真实自动化APT攻击场景来持续验证安全防御有效性概念, 旨在用安全验证技术来帮助客户实现365天持续评估自身安全防御体系效果，已在金融、高科技、关键信息基础设施等重点行业多家标杆客户中获得商业化落地验证。  
  
核心团队均来自于全球知名网络安全公司和APT研究机构，拥有业界突出的安全研究与APT组织追踪能力。两大研发团队分别位于上海和杭州，致力于为客户打造最优秀的安全验证产品。我们在北京、上海、深圳、杭州均设有分支机构，服务可覆盖全国各个角落。  
  
关注【塞讯安全验证】，了解  
塞讯安全度量验证平台以及更多安全资讯  
  
  
  
关注【塞讯业务可观测】，  
了解最前沿的业务观测与IT运营相关技术、观点及趋势  
  
  
  
