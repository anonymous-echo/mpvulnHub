#  基于 BurpSuite 新版 MontoyaAPI 的 SSRF 漏洞自动探测插件   
 黑白之道   2025-02-15 01:26  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/3xxicXNlTXLicwgPqvK8QgwnCr09iaSllrsXJLMkThiaHibEntZKkJiaicEd4ibWQxyn3gtAWbyGqtHVb0qqsHFC9jW3oQ/640?wx_fmt=gif "")  
  
  
## 工具介绍  
  
Auto-SSRF是一款基于BurpSuite MontoyaApi的自动SSRF漏洞探测插件, 捕获BurpSuite 流经Passive Audit、Proxy、Repeater的流量进行SSRF漏洞探测分析。  
## 运行原理  
1. 捕获参数中存在URL链接特征的请求包  
  
1. 参数值替换为BurpSuite Collaborator的payload(类似DNSLOG)  
  
1. 重新发包, 并监听BurpSuite Collaborator  
  
1. 如果BurpSuite Collaborator收到目标站点发出的请求(HTTP请求),则疑似存在SSRF漏洞  
  
1. 手动确认  
  
## 插件截图  
  
![img.png](https://mmbiz.qpic.cn/sz_mmbiz_png/icZ1W9s2Jp2UIBqamJRzd6WXRyyK0Wziaiah7C1MeMjUA90qJKnFLdolhjHOvIn0hKYxInH68eaTjcJWq3H3wNGKQ/640?wx_fmt=png&from=appmsg&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
![img_1.png](https://mmbiz.qpic.cn/sz_mmbiz_png/icZ1W9s2Jp2UIBqamJRzd6WXRyyK0WziaiaFrZ7YJCSYGlmfouibQE3tVbng56B2apB7MnAYgT02lf9bFMOSHBshvg/640?wx_fmt=png&from=appmsg&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
![img.png](https://mmbiz.qpic.cn/sz_mmbiz_png/icZ1W9s2Jp2UIBqamJRzd6WXRyyK0WziaiaSM48t8iblwOCVMzLPQfPmU4XVcicf0m6WXnjquatYGHhHT4HiaGrH08cg/640?wx_fmt=png&from=appmsg&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
## Features  
- [x] 插件的启动/关闭取决于BurpSuite的被动扫描状态  
  
- [x] 支持扫描Proxy、Repeater  
  
- [x] 可疑点使用dnslog探测  
  
- [x] 线程池大小可配置  
  
- [x] 支持JSON请求体的扫描  
  
- [x] 支持XML请求体的扫描  
  
- [x] 重复流量过滤  
  
- [x] 重复流量过滤器的缓存持久化  
  
- [x] 配置持久化  
  
- [ ] 接入SRC厂商提供的SSRF靶子  
  
- [ ] 探测127.0.0.1消除误报  
  
- [ ] 自动 Bypass  
  
  
  
  
## 工具获取  
  
  
  
https://github.com/banchengkemeng/Auto-SSRF/tree/master  
  
> **文章来源：夜组安全**  
  
  
  
黑白之道发布、转载的文章中所涉及的技术、思路和工具仅供以安全为目的的学习交流使用，任何人不得将其用于非法用途及盈利等目的，否则后果自行承担！  
  
如侵权请私聊我们删文  
  
  
**END**  
  
  
