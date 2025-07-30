#  BurpSuite插件 | 告别手动测试，快速挖掘漏洞！   
 黑白之道   2025-05-29 01:50  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/3xxicXNlTXLicwgPqvK8QgwnCr09iaSllrsXJLMkThiaHibEntZKkJiaicEd4ibWQxyn3gtAWbyGqtHVb0qqsHFC9jW3oQ/640?wx_fmt=gif "")  
  
工具介绍  
  
AutoFuzz是一款针对BurpSuite的安全测试辅助插件，旨在提高测试效率。它通过自动识别请求中的参数，并根据预设的payload逐个进行发包测试，帮助安全研究人员快速发现潜在漏洞。该插件借鉴了经典的xia_sql项目，加入了参数解析优化与越权、未授权访问场景的集成，支持自动化渗透测试，特别适用于复杂的JSON参数测试。通过插件，用户可以轻松设置域名/IP、payload、Header等测试条件，进一步提升测试的精确度和效率。  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/GzdTGmQpRic0XjQK8ibPxdDI1pyrrXxJawDIYD5FOuplOqGrHn3DxMW77mQriaTjicjT8D8gmgP6oaGpHt5WQPZ6xQ/640?wx_fmt=png&from=appmsg&wxfrom=13&tp=wxpic "")  
### 主要功能  
#### 基本功能  
- #### 启用插件：顾名思义勾选后该插件启用。  
  
- **监听 Proxy：自动捕获经过 BurpSuite Proxy 符合条件的请求。**  
  
- **监听 Repeter：自动捕获 BurpSuite Repeter 中符合条件的请求。**  
  
- **清空请求记录：清空右侧表格中的记录。**  
  
**Tips：**  
- 通过监听捕获的流量相同接口只会 fuzz 一次。Method + Host + Path 均相同的请求视为同一请求。  
  
- 通过右键菜单发送到插件获取的请求，可无视域名/IP限制，无视去重限制。  
  
#### 使用介绍  
### 插件安装： Extender - Extensions - Add - Select File - Next  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/GzdTGmQpRic0XjQK8ibPxdDI1pyrrXxJawHdZEAzagBYSwPibMkHHyp0OBhIXj8ECics9DibrMIkDmqkfNM5Ot24ucw/640?wx_fmt=png&from=appmsg&tp=wxpic&wxfrom=5&wx_lazy=1 "")  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/GzdTGmQpRic0XjQK8ibPxdDI1pyrrXxJaw55XuyBVLwGr5yoeicqia6I5CE2iaub56Pdg7M3qIw2Zhe9U9WSnI4Hclg/640?wx_fmt=png&from=appmsg&tp=wxpic&wxfrom=5&wx_lazy=1 "")  
#### 项目地址  
#### https://github.com/Chave0v0/AutoFuzz  
  
  
> **文章来源：乌雲安全**  
  
  
  
黑白之道发布、转载的文章中所涉及的技术、思路和工具仅供以安全为目的的学习交流使用，任何人不得将其用于非法用途及盈利等目的，否则后果自行承担！  
  
如侵权请私聊我们删文  
  
  
**END**  
  
  
