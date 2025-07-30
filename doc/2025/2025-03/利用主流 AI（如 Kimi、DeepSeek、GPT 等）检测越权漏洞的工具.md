#  利用主流 AI（如 Kimi、DeepSeek、GPT 等）检测越权漏洞的工具   
 黑白之道   2025-03-29 10:09  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/3xxicXNlTXLicwgPqvK8QgwnCr09iaSllrsXJLMkThiaHibEntZKkJiaicEd4ibWQxyn3gtAWbyGqtHVb0qqsHFC9jW3oQ/640?wx_fmt=gif "")  
  
## 工具介绍  
  
PrivHunterAI一款通过被动代理方式，利用主流 AI（如 Kimi、DeepSeek、GPT 等）检测越权漏洞的工具。其核心检测功能依托相关 AI 引擎的开放 API 构建，支持 HTTPS 协议的数据传输与交互。  
## 工作流程  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/icZ1W9s2Jp2UF4KMuJ3FxKOOxSibFVR0sRcUU4wk16FB5kDEIAG7ZbJGicEMp6XyZLmK8wiax3UbQCFsptEP922VicA/640?wx_fmt=png&from=appmsg&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
## 使用方法  
1. 下载源代码 或 Releases；  
  
1. 编辑根目录下的config.json  
文件，配置AI  
和对应的apiKeys  
（只需要配置一个即可）；（AI的值可配置qianwen、kimi、hunyuan、gpt、glm 或 deepseek） ；  
  
1. 配置headers2  
（请求B对应的headers）；可按需配置suffixes  
、allowedRespHeaders  
（接口后缀白名单，如.js）；  
  
1. 执行go build  
编译项目，并运行二进制文件（如果下载的是Releases可直接运行二进制文件）；  
  
1. 首次启动程序后需安装证书以解析 HTTPS 流量，证书会在首次启动程序后自动生成，路径为 ~/.mitmproxy/mitmproxy-ca-cert.pem。安装步骤可参考 Python mitmproxy 文档：  
About Certificates  
。  
  
1. BurpSuite 挂下级代理 127.0.0.1:9080  
（端口可在mitmproxy.go  
 的Addr:":9080",  
 中配置）即可开始扫描；  
  
1. 终端和web界面均可查看扫描结果，前端查看结果请访问127.0.0.1:8222  
 。  
  
## 输出效果  
  
持续优化中，目前输出效果如下：  
1. 终端输出：  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/icZ1W9s2Jp2UF4KMuJ3FxKOOxSibFVR0sRHH4HKWiaKGzdP6BurSjGLa7JotTAawBNBwLFJHUCAIeW4WJSpJzM3SQ/640?wx_fmt=png&from=appmsg&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
1. 前端输出（访问127.0.0.1:8222）：  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/icZ1W9s2Jp2UF4KMuJ3FxKOOxSibFVR0sRh4gPLXIYw762tBXxZaEDK0LiaKUkeFoaM1IAXa66ibADvbibvOLmgLZnw/640?wx_fmt=png&from=appmsg&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
  
## 工具获取  
  
  
  
https://github.com/Ed1s0nZ/PrivHunterAI  
  
> **文章来源：夜组安全**  
  
  
  
黑白之道发布、转载的文章中所涉及的技术、思路和工具仅供以安全为目的的学习交流使用，任何人不得将其用于非法用途及盈利等目的，否则后果自行承担！  
  
如侵权请私聊我们删文  
  
  
**END**  
  
  
