> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzUyOTc3NTQ5MA==&mid=2247500047&idx=1&sn=666884e039408d7814148dbdb174012d

#  隐匿转发，精准打点，通过 Sharp4TranPort 实现内网边界的端口转发  
专攻.NET安全的  dotNet安全矩阵   2025-07-09 01:12  
  
![图片](https://mmbiz.qpic.cn/mmbiz_gif/NO8Q9ApS1YibJO9SDRBvE01T4A1oYJXlTBTMvb7KbAf7z9hY3VQUeayWI61XqQ0ricUQ8G1FykKHBNwCqpV792qg/640?wx_fmt=gif&from=appmsg&wxfrom=5&wx_lazy=1&tp=webp "")  
  
在内网渗透过程中，红队成员常面临目标系统服务仅对内网开放的局限，如远程桌面、数据库服务等无法直接通过公网访问。此时，端口转发技术成为突破封锁的关键手段，本文介绍一款基于 .NET 实现的轻量级端口转发工具 **Sharp4TranPort.exe**  
。该工具使用 
```
TcpClient
```

  
 和 
```
NetworkStream
```

  
 实现数据的双向透明转发，不依赖第三方库，支持灵活的命令行参数配置，是 .NET 平台下红队实战利器之一。  
  
**01. 工具基本介绍**  
  
  
  
Sharp4TranPort.exe  
 是一款用于 TCP 流量转发的控制台工具，其核心逻辑是将来自本地端口的连接请求，转发到指定的远程目标 IP 和端口，实现在客户端和远程服务之间建立一个桥梁。  
  
![图片](https://mmbiz.qpic.cn/mmbiz_jpg/NO8Q9ApS1Y8kibtnLibEauOQeS4VpNJRS54ILt3UgPKbvlOP6ezRRxLOTgyWkSAqfpVMlicUsqbR5GsTH8eULxJ3Q/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
**02. 工具实战用法**  
  
  
  
Sharp4TranPort.exe  
 命令格式如下所示。  
  

```
Sharp4TranPort.exe -a pf -lp <本地监听端口>-rh <远程主机IP>-rp <远程主机端口>

```

  
  
参数 -a pf	动作（pf = Port Forward），-lp	本地监听端口，-rh	远程主机 IP表示目标服务器，-rp	远程主机端口，代表目标服务。  
  

```
Sharp4TranPort.exe -a pf -lp 8899-rh 192.168.101.86-rp 3389

```

  
  
该命令将在当前主机上监听 
```
8899
```

  
 端口，将所有接入流量原封不动地转发至目标主机 
```
192.168.101.86
```

  
 的 
```
3389
```

  
 端口，也就是远程桌面服务。  
  
此时，只需在攻击机上打开远程桌面客户端（mstsc），输入地址：  
  

```
localhost:8899

```

  
  
即可连接到目标主机 
```
192.168.101.86
```

  
 的 RDP 服务，实现远程控制，如下图所示。  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/NO8Q9ApS1Y8fyLiakm8t93u82zoDnZzmgN9EvBtkhJ2HF2LcgQaGZrvV00Q3OCLmCcAuVK9j4Jy7miaKd68uQy9g/640?wx_fmt=png&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1 "")  
  
综上，**Sharp4TranPort.exe**  
 是红队后渗透阶段的重要组件之一，在目标权限受限、服务封闭的场景中尤为关键。其灵活配置、纯托管代码实现使其适配性强，能快速集成进 C2、WebShell、计划任务等多种攻击载体中。文章涉及的工  
具已  
打包在星球，感兴趣的朋友可以加入自取。  
  
**03.NET安全扩展学习**  
  
  
  
以上相关的知识点已收录于  
新书《.NET安全攻防指南》，全书共计25章，总计1010页，分为上下册，横跨.NET Web代码审计与红队渗透两大领域。  
  
  
**上册深入剖析.NET Web安全审计的核心技术，帮助读者掌握漏洞发现与修复的精髓；下册则聚焦于.NET逆向工程与攻防对抗的实战技巧，揭秘最新的对抗策略与技术方法。**  
  
  
**04. 技术精华内容**  
  
  
  
从漏洞分析到安全攻防，我们涵盖了 .NET 安全各个关键方面，为您呈现最新、最全面的 .NET 安全知识，下面是公众号发布的精华文章集合，推荐大伙阅读！  
  
[](https://mp.weixin.qq.com/s?__biz=MzUyOTc3NTQ5MA==&mid=2247499267&idx=2&sn=1462cf23c9a8568cc80705d2d3a1a69e&scene=21#wechat_redirect)  
  
  
![图片](https://mmbiz.qpic.cn/mmbiz_jpg/NO8Q9ApS1Y8A7Qhn1ssuqNzv0iceS7ZhOuZ0AO4P1eFeG2xTdR2V6GWibiaxO2RenUJzrwOfvsdqofibI6H2uY0CLQ/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
[](http://mp.weixin.qq.com/s?__biz=MzUyOTc3NTQ5MA==&mid=2247493952&idx=4&sn=db68011fb075c1d02268811163646b53&chksm=fa5947adcd2ecebbb1ca6659f289a5e344e37d1136fe0bd9272b5578e4c71bb19bb250e934d3&scene=21#wechat_redirect)  
  
  
[](http://mp.weixin.qq.com/s?__biz=MzUyOTc3NTQ5MA==&mid=2247495167&idx=1&sn=9280c55fdc7c9146e549be470cf9f120&chksm=fa594312cd2eca04bfe8fd1fd3890b389d9c700b9b69d897f919addac399bab4f4d2e55f6b4f&scene=21#wechat_redirect)  
  
  
[](http://mp.weixin.qq.com/s?__biz=MzUyOTc3NTQ5MA==&mid=2247490722&idx=2&sn=c9807daa5548e139a0c67303cb26882a&chksm=fa5ab24fcd2d3b59a85be03e69c655ffd644e8458bc2ec3f572da4b40b43e5003fda756f35b4&scene=21#wechat_redirect)  
  
  
  
[](http://mp.weixin.qq.com/s?__biz=MzUyOTc3NTQ5MA==&mid=2247490703&idx=2&sn=e7db1ff662e5b41d9a1806fbdf33e204&chksm=fa5ab262cd2d3b7470f029b9a07d1dd3611e63be910b01a601144efe7d84b5f016f488a354cf&scene=21#wechat_redirect)  
  
  
  
[](http://mp.weixin.qq.com/s?__biz=MzUyOTc3NTQ5MA==&mid=2247490700&idx=2&sn=e8a865ada7c743e77fb9e953c5da74b1&chksm=fa5ab261cd2d3b7736387eddfc8524a378a1604552d0c9b55476646f9e8275f48818aab8acad&scene=21#wechat_redirect)  
  
  
  
[](http://mp.weixin.qq.com/s?__biz=MzUyOTc3NTQ5MA==&mid=2247488736&idx=2&sn=d24aaa297c51eb620ccdf67af513086d&chksm=fa5aba0dcd2d331bbb22f3f5657199d718c90efed42fcb9cb67ec23d342f887c117e4858f1cb&scene=21#wechat_redirect)  
  
  
**05. 加入安全社区**  
  
  
  
目前dot.Net安全矩阵星球已成为中国.NET安全领域最知名、最专业的技术知识库之一，超 **1200+**  
 成员一起互动学习。星球主题数量近 **600+**  
，精华主题   
230+  
，PDF文档和压缩包   
300+   
。从Web应用到PC端软件应用，无论您是初学者还是经验丰富的开发人员，都能在这里找到对应的实战指南和最佳实践。  
  
![图片](https://mmbiz.qpic.cn/mmbiz_jpg/NO8Q9ApS1Y9AiaXibTRdEnEfYuQx76FjZVjmyEWtIaDuDePFFmyRqggiaq2k47pLoib9GZtUCOhaP40WPlhvbiaKZVg/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
## 20+专栏文章  
  
星球文化始终认为授人以鱼不如授人以渔！星球整理出**20+**  
个专题栏目涵盖 **.NET安全 点、线、面、体等知识范围**  
，助力师傅们实战攻防！其中主题包括.NET  内网攻防、漏洞分析、内存马、代码审计、预编译、反序列化、WebShell免杀、命令执行、工具库等等。  
  
![图片](https://mmbiz.qpic.cn/mmbiz_jpg/NO8Q9ApS1Y8xRheDpQ7NsESosdNZUopa90SJRuwnLy9uZV4icrXiaZlJPQlYJWXTw8HCrF9oTcE3DDgrdFnXo2BA/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
## 海量资源和工具  
  
截至当前，dot.Net安全矩阵星球社区汇聚了   
**600+**  
 个实用工具和高质量PDF学习资料。这些资源涵盖了攻防对抗的各个方面，在实战中能够发挥显著作用，为对抗突破提供强有力的支持。  
  
![图片](https://mmbiz.qpic.cn/mmbiz_jpg/NO8Q9ApS1Y8xRheDpQ7NsESosdNZUopaqVZW8XsALVA4FNiaj32q8npN82VSeqSKb4fQvLiczFNs0099VRFVQwPA/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
![图片](https://mmbiz.qpic.cn/mmbiz_jpg/NO8Q9ApS1Y8xRheDpQ7NsESosdNZUopa63ZXbX3YXLwoeNnjStcRtTbU9hoe6ecO5hhkj2apG1I6tKlkpz5GaQ/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
## 专属成员交流群  
  
我们还有多个成员专属的  
**内部星球陪伴群**  
，加入的成员可以通过在群里提出问题或参与论的方式来与其他成员交流思想和经验。此外还可以通过星球或者微信群私聊向我们进行提问，以获取帮助迅速解决问题。  
  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/NO8Q9ApS1Y8xRheDpQ7NsESosdNZUopaAiaouHb6HYza539m9v0ykDoD2JezaArDZBPlJInuabf6XsduzVcjZ0Q/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
## 已入驻的大咖们  
  
星球汇聚了各行业安全攻防技术大咖，并且每日分享.NET安全技术干货以及交流解答各类技术等问题，社区中发布很多  
**高质量的.NET安全资源**  
，可以说市面上很少见，都是干货。  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/NO8Q9ApS1YibEkb2HkMVuw4d7qjcTYUtl04w8xDiaUaJxticro644uWw5XuJ6ZXCNXCticjYWjpXNmp3omQHUNFRPg/640?wx_fmt=png&from=appmsg&wxfrom=5&wx_lazy=1&tp=webp "")  
## 欢迎加入我们  
  
dotNet安全矩阵星球从创建以来一直聚焦于.NET领域的安全攻防技术，定位于高质量安全攻防星球社区，也得到了许多师傅们的支持和信任，通过星球深度连接入圈的师傅们，一起推动.NET安全高质量的向前发展。  
**星球门票后期价格随着内容和质量的不断沉淀会适当提高，因此越早加入越好！**  
  
![图片](https://mmbiz.qpic.cn/mmbiz_jpg/NO8Q9ApS1Y8xRheDpQ7NsESosdNZUopag09JtYcKpucjZPAlfeqC1ovcQvhrkemAzbURDaVF3InmpQshiatDnyQ/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
