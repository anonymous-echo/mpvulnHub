#  API漏洞自动化测试、安全工作流编排-星阑科技在Kcon黑客大会进行精彩分享   
 星阑科技   2022-09-06 13:54  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Cc8QqLUKOeiaFHTFtiatmEIxZQcXOHfyr6GOBM88IeMm28ybjSAHEJKicuQxPxN5L5NFZ5mza2NOnuokf9ant2fUQ/640?wx_fmt=gif "")  
  
  
近日，由知道创宇出品的第11届KCon 黑客大会（以下简称 KCon 2022）正式在云端拉开帷幕，为线上观众呈现一场火热的网络安全攻防技术盛宴。**星阑科技安全研发工程师周阳、安全工程师吕竭以“自动化API漏洞Fuzz实战”为主题，带来了一场API漏洞挖掘实战技巧分享。星阑科技安全专家汤青松的“蜻蜓安全”成功入选“兵器谱”，并给大家展示了“蜻蜓安全”的技能及使用技巧。**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Cc8QqLUKOehiaJkhRfSFyLI2mPfva3ia2DAVWnqLLa3pF50x8sRQYfNrcH8322iaFgkpD2ibdkLUUjwkJPibAlTv6JQ/640?wx_fmt=png "")  
  
KCon黑客大会，是国际网络安全圈富有活力与影响力的网络安全攻防前沿技术交流平台。自创办以来一直秉承着追求干货、乐于分享的精神，力求为每一位热爱网络安全技术研究的伙伴打造一个尽情展示、尽情交流的舞台。本届KCon以“+1 进阶，护航未来”为主题，期望通过这一年一度的技术前沿分享盛会，不断为护航未来网络空间安全贡献“+1”的力量，助力网络安全技术发展的不断进阶！为了保证高质量的议题分享，KCon议题评选综合考量了大众评选与顾问专家评审的结果，星阑科技议题能从众多议题脱颖而出成功入选，也代表了业内专业人士对星阑技术实力的认可。  
  
**自动化API漏洞挖掘**  
  
技术分享现场，周阳首先介绍了API安全问题产生的背景及攻击面，他表示：在现代IT应用架构中，API通信如“血液”般承载了绝大多数的应用数据交换，并以每年60%以上的增速发展。从企业漏洞风险角度以及红蓝对抗角度来看，大规模分布式系统及复杂应用架构带来API数量迅猛增长、基于API-First理念构建的研发流程，极短的迭代周期导致API变动跟踪困难、传统Web Fuzz工具无法深入挖掘API风险，需要新的自动化手段加速API弱点的暴露过程等都是近年来导致API安全问题频发的原因。  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/Cc8QqLUKOehiaJkhRfSFyLI2mPfva3ia2DJFcKurj0jueK5PKEZeuLZKQ7Pj0K5umL0Inoh3z1C9JPhupwB3efIg/640?wx_fmt=jpeg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/Cc8QqLUKOehiaJkhRfSFyLI2mPfva3ia2DP0CxcqY7yDXg8ESbrGZuRndCeicIzWLhCTCThKNnubx8YZuZdibPpnCQ/640?wx_fmt=jpeg "")  
  
  
随后，吕竭向大家介绍了传统Web Fuzz方法的弊端，她表示：传统Web Fuzz方法基于爬虫的web扫描器和基于字典的爆破工具获取到的API路径有限、其次，参数结构具有复杂性，传统Web Fuzz是基于GET/POST协议解析Form表单，然而API存在多种协议格式、多层嵌套的参数结构、参数内编码等场景，不能满足API漏洞挖掘场景的需求、最后，在命中率上，传统Web Fuzz工具生成的请求参数值不够精确，效率比较低下。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Cc8QqLUKOehiaJkhRfSFyLI2mPfva3ia2DFPaopZWpf9t1bYVVL7hZwjoNv5gWLEhMf3oH1XTd8picDz3OsIwoHow/640?wx_fmt=png "")  
  
  
面对传统Web Fuzz方法存在的一些弊端，会上，吕竭分享了一种自动化API采集-解析-Fuzz的方法，并针对API的协议复杂性、参数结构复杂性、请求序列依赖等问题给出自动化测试思路，并通过具体的API Auto Fuzz所发现的漏洞案例阐述这一过程。  
  
**兵器谱：蜻蜓安全工作台**  
  
为了鼓励国内安全自动化工具的发展，展示更多黑客及安全人员们的安全自动化研究成果，自2016年起，KCon黑客大会便引入“兵器谱”展示环节。过去几届 KCon 黑客大会现场，已有四十多件“安全神兵利器”受到千余名参会者的观摩与试用，并获得媒体朋友们的广泛关注。今年，星阑科技安全专家汤青松的“蜻蜓安全工作台”成功入选“兵器谱”。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Cc8QqLUKOehiaJkhRfSFyLI2mPfva3ia2DxJZSJIaicWAIInZlu55ubPggRL4X7HAb5PXTKQyU5wo9HCSicCYMGjNA/640?wx_fmt=png "")  
  
蜻蜓安全工作台是一个安全工具编排平台，旨在将安全工程师日常工作中涉及到的各种工具、流程进行自动化编排，从而提升每一位安全工程师的工作效率。平台集成市面上主流的安全工具，并按照工作场景进行编排。会上，汤青松向观众演示了“蜻蜓安全”的使用方法。  
  
作为网络安全行业的新兴力量，星阑科技始终坚持在安全攻防与新兴领域的技术研究，紧跟网络安全产业的发展机遇，致力于研发出高质量的网络安全产品与最佳解决方案。未来，星阑科技技术团队还将继续同行业内权威安全专家共同探讨专业性技术，并不断提高团队技术能力进行更加深入的安全研究，继续努力分享更多具有权威性和前瞻性的技术研究成果，与众多安全厂商一同，共创网络安全发展新未来。  
  
  
**往期 · 推荐**  
  
  
  
[](http://mp.weixin.qq.com/s?__biz=Mzg5NjEyMjA5OQ==&mid=2247494626&idx=1&sn=0b99352a797f99061548130f8458b87f&chksm=c007467ef770cf68476e77f2b37825a622deae5406a376496acd7c822a8a4aa44ffd21607f8e&scene=21#wechat_redirect)  
  
[](http://mp.weixin.qq.com/s?__biz=Mzg5NjEyMjA5OQ==&mid=2247494550&idx=1&sn=a23741fb29235466e4a73d08b978c259&chksm=c007460af770cf1c7b46a4a12845f54b27c808efd087c06ca92dec8798eaee66e86b065fb57a&scene=21#wechat_redirect)  
  
[](http://mp.weixin.qq.com/s?__biz=Mzg5NjEyMjA5OQ==&mid=2247494546&idx=1&sn=ebe058d1c624dad60ec6763a58c7c80b&chksm=c007460ef770cf18bd444f87900999eccecb15cd7b7a3e402c056bbba0f95462239246b364ab&scene=21#wechat_redirect)  
  
[](http://mp.weixin.qq.com/s?__biz=Mzg5NjEyMjA5OQ==&mid=2247494458&idx=1&sn=20eee58546cde347f3f7f60e9a85a532&chksm=c00746a6f770cfb07dc9d575584db3e3b984bcc2a1668183a3bee948110b3ac201097761ff5b&scene=21#wechat_redirect)  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Cc8QqLUKOehwcHoxicoOah5mxDjLHMZ9RHUxNeibERphRXOj3AEupxt7JyOt3LF1RmmWQibYmicTv2DxM93iaEJhLxw/640?wx_fmt=gif&wxfrom=5&wx_lazy=1 "")  
  
