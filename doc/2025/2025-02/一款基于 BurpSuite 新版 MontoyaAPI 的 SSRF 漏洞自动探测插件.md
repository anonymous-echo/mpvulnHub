#  一款基于 BurpSuite 新版 MontoyaAPI 的 SSRF 漏洞自动探测插件   
banchengkemeng  无影安全实验室   2025-02-14 13:16  
  
免责声明：  
本篇文章仅用于技术交流，  
请勿利用文章内的相关技术从事非法测试  
，  
由于传播、利用本公众号无影安全  
实验室所提供的信息而造成的任何直接或者间接的后果及损失，均由使用者本人负责，公众号无影安全实验室及作者不为此承担任何责任，一旦造成后果请自行承担！  
如有侵权烦请告知，我们会立即删除并致歉。谢谢！  
  
  
  
朋友们现在只对常读和星标的公众号才展示大图推送，建议大家把"**无影安全实验室**  
"设为星标，这样更新文章也能第一时间推送！  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/3GHDOauYyUGbiaHXGx1ib5UxkKzSNtpMzY5tbbGdibG7icBSxlH783x1YTF0icAv8MWrmanB4u5qjyKfmYo1dDf7YbA/640?&wx_fmt=gif&tp=webp&wxfrom=5&wx_lazy=1 "")  
  
  
安全工具  
  
  
  
## 0x01 前言  
  
Auto-SSRF是一款基于  
BurpSuite MontoyaApi的自动SSRF漏洞探测插件, 捕获BurpSuite 流经Passive Audit、Pr  
oxy、Repeater的流量进行SSRF漏洞探测分析。## 0x02 运行原理  
1. 捕获参数中存在URL链接特征的请求包  
  
1. 参数值替换为BurpSuite Collaborator的payload(类似DNSLOG)  
  
1. 重新发包, 并监听BurpSuite Collaborator  
  
1. 如果BurpSuite Collaborator收到目标站点发出的请求(HTTP请求),则疑似存在SSRF漏洞  
  
1. 手动确认  
  
## 0x03 插件截图  
  
![img.png](https://mmbiz.qpic.cn/mmbiz_png/awCdqJkJFERyEohSD3rTQF2Tl3KM2TKicchb2t8c2BVg128lO40MkAGGQL0Zvs3paPVa9QdMluN75vubcfpCR0g/640?wx_fmt=png&from=appmsg "")  
  
![img_1.png](https://mmbiz.qpic.cn/mmbiz_png/awCdqJkJFERyEohSD3rTQF2Tl3KM2TKicljnSqru2o15qYvprCYhNkdmgtfq7W24icNlq0e4zAGwfLKDTbtgGoVw/640?wx_fmt=png&from=appmsg "")  
  
![img.png](https://mmbiz.qpic.cn/mmbiz_png/awCdqJkJFERyEohSD3rTQF2Tl3KM2TKicCCUVPa8bBO16y6SD5BOAvAAHJk4Yks7ROEAzLicS07Et0KNfPA0Prcw/640?wx_fmt=png&from=appmsg "")  
## 0x03 Features  
  
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
  
## 0x04 工具下载  
  
**点****击关注**  
**下方名片****进入公众号**  
  
**回复关键字【250214****】获取**  
**下载链接**  
  
  
  
最后推荐一下小密圈，干货满满，物超所值，**内部圈子每增加100人，价格将上涨20元，越早进越优惠嗷~~**  
  
****  
