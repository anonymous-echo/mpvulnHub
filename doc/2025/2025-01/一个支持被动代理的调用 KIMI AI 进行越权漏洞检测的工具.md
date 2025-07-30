#  一个支持被动代理的调用 KIMI AI 进行越权漏洞检测的工具   
 黑白之道   2025-01-21 01:53  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/3xxicXNlTXLicwgPqvK8QgwnCr09iaSllrsXJLMkThiaHibEntZKkJiaicEd4ibWQxyn3gtAWbyGqtHVb0qqsHFC9jW3oQ/640?wx_fmt=gif "")  
  
  
## 工具介绍  
  
利用工作之余（摸鱼）时间花 2 小时完成的小工具，简易版支持通过被动代理调用 KIMI AI 进行越权漏洞检测，检测能力依赖 KIMI API 实现。目前功能较为基础，尚未优化输出，也未加入扫描失败后的重试机制等功能。  
## 工作流程  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/icZ1W9s2Jp2UkECj8peRvFCP3Hia0iatFVic7uAWNcibic4Ay92J8t7E7UHDsflmWYGfR0TV37XD2yGe3Nl6XfSibeMQQ/640?wx_fmt=other&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
## 使用方法  
1. 下载源代码；  
  
1. 编辑config.go文件，配置apiKey（Kimi的API秘钥） 和cookie2（响应2对应的cookie），可按需配置suffixes（接口后缀白名单，如.js）；  
  
1. go build编译项目，并运行二进制文件；  
  
1. BurpSuite 挂下级代理 127.0.0.1:9080（端口可在mitmproxy.go 的Addr:":9080", 中配置）即可开始扫描。  
  
## 效果  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/icZ1W9s2Jp2UkECj8peRvFCP3Hia0iatFVic4kgVVPQOgbjscn2icUsv7QyRaTZxPOric3W5PLbCZvfd77RucW0tTfgg/640?wx_fmt=other&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
## 工具获取  
  
  
  
https://github.com/Ed1s0nZ/PrivHunterAI  
  
> **文章来源：夜组安全**  
  
  
  
黑白之道发布、转载的文章中所涉及的技术、思路和工具仅供以安全为目的的学习交流使用，任何人不得将其用于非法用途及盈利等目的，否则后果自行承担！  
  
如侵权请私聊我们删文  
  
  
**END**  
  
  
