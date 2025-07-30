#  利用 3000 条大字典 MachineKeys 爆破 ViewState 反序列化漏洞   
原创 专攻.NET安全的  dotNet安全矩阵   2025-03-07 08:39  
  
![图片](https://mmbiz.qpic.cn/mmbiz_gif/NO8Q9ApS1YibJO9SDRBvE01T4A1oYJXlTBTMvb7KbAf7z9hY3VQUeayWI61XqQ0ricUQ8G1FykKHBNwCqpV792qg/640?wx_fmt=gif&from=appmsg&wxfrom=5&wx_lazy=1&tp=webp "")  
  
MachineKeys  
 负责加密和解密敏感数据，确保服务器端的安全性。然而，一旦这些密钥被泄露，攻击者便可解密受保护的数据，并可能用 ViewState  
 反序列化漏洞执行恶意代码。Sharp4DotNetBurst  
 正是这样一款针对 .NET  
 环境 MachineKeys  
 的爆破工具，  
内置了 3000 条已知泄露的密钥，可用于尝试解密目标服务器的 ViewState  
 数据。本文将详细介绍 Sharp4DotNetBurst  
 的原理、使用方法以及相应的安全防护措施。  
  
**01. MachineKeys**  
  
  
  
MachineKeys  
 是 IIS 服务器中用于加密和解密敏感数据（如 ViewState、Forms Authentication Tickets 和其他 ASP.NET 安全相关数据）的密钥存储文件。如果攻击者能够获得正确的 MachineKey  
，就可以解密受保护的数据，甚至伪造恶意数据来进行反序列化攻击。常见的配置demo如下：  
  
```
<system.web>   <machineKey validationKey="AABBCCDDEEFF00112233445566778899AABBCCDDEEFF00112233445566778899" decryptionKey="112233445566778899AABBCCDDEEFF001122334455667788" validation="SHA1" decryption="AES" /></system.web>
```  
  
  
**02. 工具基本介绍**  
  
  
  
Sharp4DotNetBurst  
 是一款专门用于爆破远程主机 MachineKeys  
 的工具，该工具内置了 3000 条已知泄露的 MachineKeys  
，可用于尝试解密目标网站的 ViewState 数据，从而触发 ViewState 反序列化漏洞。此工具的核心目的是在 IIS 服务器上识别弱 MachineKeys  
，并利用这些密钥解密 ViewState，从而进一步进行漏洞利用。  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/NO8Q9ApS1YibYIyHiblwtfoJZIRhGRSNVuoS2QvQVX4m4nBHQO8FibDbO4zpDicEbDTwe1L44fteXHBJkEiaRhbmjLg/640?wx_fmt=jpeg&from=appmsg "")  
  
**03. 工具实战用法**  
  
  
  
该工具主要通过字典爆破的方式，使用内置的   
3000 条 MachineKeys  
 来解密加密的 ViewState 数据。如果目标服务器使用的 MachineKey  
 存在于字典中，则可以成功解密，并进一步进行反序列化攻击，可能导致代码执行。  
## 3.1 使用方法  
  
```
Sharp4DotNetBurst.exe --keypath MachineKeys.txt \                      --encrypteddata FKpYW56MFezy6wDm2/Cdy+c91Ki/J76QIqp9VCJfJLY6EolEbJuTRZTgpdJzUvgd2753UnF0LTlKOutQg7LusOQj11Q= \                      --decrypt \                      --purpose=viewstate \                      --IISDirPath "/" \                      --TargetPagePath "/About.aspx"
```  
  
  
此处的参数 --keypath MachineKeys.txt 表示指定 MachineKeys 字典文件路径。  
## 3.2 字典价值  
  
该工具的核心优势在于内置的   
3000   
条已知泄露的 MachineKeys  
，这使得它能够在短时间内高效破解大量目标服务器的 MachineKey  
。这些密钥可能来源于历史泄露的配置文件、GitHub 公开项目、论坛讨论等。因此，该字典的质量和丰富程度，直接影响了爆破的成功率。部分展示图如下所示。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/NO8Q9ApS1YibYIyHiblwtfoJZIRhGRSNVuoD7t2fDCiaElZezkk1mc45xldffvic0zicvttMfZFbJakh7icFP1iaeNJzg/640?wx_fmt=png&from=appmsg "")  
  
综上  
所述  
，  
Sharp4DotNetBurst  
 是一个极具实战价值的工具，其内置的 3000 条 MachineKeys  
 让它在特定攻击场景下变得十分有效。对于安全研究人员而言，该工具可以帮助测试 IIS 服务器的安全性，并检测是否存在弱 MachineKey  
 配置。文章涉及的工具已  
打包在星球，感兴趣的朋友可以加入自取。  
  
**04. 技术精华内容**  
  
  
  
从漏洞分析到安全攻防，我们涵盖了 .NET 安全各个关键方面，为您呈现最新、最全面的 .NET 安全知识，下面是公众号发布的精华文章集合，推荐大伙阅读！  
  
[](https://mp.weixin.qq.com/s?__biz=MzUyOTc3NTQ5MA==&mid=2247497498&idx=2&sn=00900a0c29c85b41fe6a586d7e5c3571&scene=21#wechat_redirect)  
  
  
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
  
![图片](https://mmbiz.qpic.cn/mmbiz_jpg/NO8Q9ApS1YibEfvTKP231YekyMbc9jeicFuh0aAYDSicAg36pkFaC2P1KW0L5NV1HOssmysrPnrP1fzr2rFOmy8lA/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
## 欢迎加入我们  
  
dotNet安全矩阵星球从创建以来一直聚焦于.NET领域的安全攻防技术，定位于高质量安全攻防星球社区，也得到了许多师傅们的支持和信任，通过星球深度连接入圈的师傅们，一起推动.NET安全高质量的向前发展。  
**星球门票后期价格随着内容和质量的不断沉淀会适当提高，因此越早加入越好！**  
  
![图片](https://mmbiz.qpic.cn/mmbiz_jpg/NO8Q9ApS1Y8xRheDpQ7NsESosdNZUopag09JtYcKpucjZPAlfeqC1ovcQvhrkemAzbURDaVF3InmpQshiatDnyQ/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
