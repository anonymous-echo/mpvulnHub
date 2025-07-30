#  deepseek本地部署工具---ollama任意文件读取漏洞复现   
原创 a1batr0ss  天翁安全   2025-03-31 18:26  
  
**免责声明：**  
本公众号所发布的全部内容，包括但不限于技术文章、POC脚本、漏洞利用工具及相关测试环境，均仅限于合法的网络安全学习、研究和教学用途。所有人在使用上述内容时，应严格遵守中华人民共和国相关法律法规以及道德伦理要求。未经明确的官方书面授权，严禁将公众号内的任何内容用于未经授权的渗透测试、漏洞利用或攻击行为。 所有人仅可在自己合法拥有或管理的系统环境中进行本地漏洞复现与安全测试，或用于具有明确授权的合法渗透测试项目。所有人不得以任何形式利用公众号内提供的内容从事非法、侵权或其他不当活动。 如因违反上述规定或不当使用本公众号提供的任何内容，造成的一切法律责任、经济损失、纠纷及其他任何形式的不利后果，均由相关成员自行承担，与本公众号无任何关联。  
## 漏洞介绍  
  
Ollama是一个专为本地机器设计的开源框架，旨在简化大型语言模型（LLM）的部署和运行过程。它提供了一套工具和命令，使用户能够轻松地下载、管理和运行各种语言模型，包括LLaMA、LLaVA等流行模型。Ollama通过优化设置和配置细节，如GPU使用情况，提高了模型运行的效率，并且其代码简洁明了，运行时占用资源少，使得在本地高效地运行大型语言模型成为可能。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/I2eHcAFia5S7XCCVSc1w20IQq0S4hhVv2YqsohX5SmZ87VMH4F5yyjgqHzmsrsvVyE4M1RxwAzZ7e3aSIIoTMFA/640?wx_fmt=png&from=appmsg "")  
  
在 **Ollama 0.1.34 之前的版本**  
 中，在获取模型路径时，**未对摘要（digest）的格式进行验证**  
（应为包含 64 个十六进制字符的 SHA256 值），因此在处理 TestGetBlobsPath  
 测试用例时会出现问题，例如：十六进制字符少于 64 个、超过 64 个、或者摘要字符串以 ../  
 开头。  
## 漏洞条件  
  
•  
Ollama < 0.1.34  
## 环境搭建  
```
docker-compose up -d
```  
  
访问   
http://your-ip:11434  
 即可  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/I2eHcAFia5S7XCCVSc1w20IQq0S4hhVv2d6dJWWefBWFukH6mke2FLNuvO7zrmCGDP91XlDnJG4zu2C04PJVwBg/640?wx_fmt=png&from=appmsg "")  
## 漏洞复现  
  
**具体脚本见文末**  
  
根据Ollama机制，/api/pull  
接口默认可以从Ollama官方registry拉取镜像，当然我们也可以选择从自己构建的私人服务器上拉取镜像。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/I2eHcAFia5S7XCCVSc1w20IQq0S4hhVv2rnIFicErurOtFNvYpicQiciaSYpt53XMC0cEicvNib41JftdLI61UcZVqo8Q/640?wx_fmt=png&from=appmsg "")  
  
首先运行事先构造好的恶意registry服务器：**evilRegServer.py**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/I2eHcAFia5S7XCCVSc1w20IQq0S4hhVv2PrOHSCTULqib5NAF15AyUicX1cEYA6icfgzPKvcaYJ0T7onKCuBibUibq3w/640?wx_fmt=png&from=appmsg "")  
  
执行pull操作  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/I2eHcAFia5S7XCCVSc1w20IQq0S4hhVv2xBSp6sK4phToVflP69agUbBzg2u2dQQIkBmWpwqLWX4IB8pyJpD0mg/640?wx_fmt=png&from=appmsg "")  
  
执行push操作  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/I2eHcAFia5S7XCCVSc1w20IQq0S4hhVv2Wn5xPSHicQKx1yzDJUXjM888ZuajzZ2UzV2s8P5kBTVmW5heMcA0uAg/640?wx_fmt=png&from=appmsg "")  
  
发现成功读取到/etc/passwd  
内容  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/I2eHcAFia5S7XCCVSc1w20IQq0S4hhVv2zGhqm3TI5lBDanfR1FKGTzvae6aaqeoXzHKPIK2XhRp2B5Ynsv8bIQ/640?wx_fmt=png&from=appmsg "")  
  
也可以直接执行漏洞利用脚本**POC-CVE-2024-37032.py**  
读取到/etc/passwd  
：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/I2eHcAFia5S7XCCVSc1w20IQq0S4hhVv2Wia2Dj6MHmhHImRL52KmFE939Iibh1rKn2n2U9uRvXsBaDpYDiboYf3IA/640?wx_fmt=png&from=appmsg "")  
## 漏洞修复  
  
•  
升级至最新版本（0.1.34及以上版本）  
## 知识星球  
  
漏洞利用POC及复现环境可在知识星球内自行领取  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/I2eHcAFia5S7XCCVSc1w20IQq0S4hhVv2mM9BMbYOOoYWXEiabDOgcCjhyegZJK3E5omn9IY9yfKwTYPxCJF7WLg/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/I2eHcAFia5S7XCCVSc1w20IQq0S4hhVv2Hrbg8YOFibBRw2zQTu20AyxrQ4nQXNpbPzeKHxuJqrGIvIibxSSNdMQg/640?wx_fmt=png&from=appmsg "")  
  
星球不定期更新市面上最新的热点漏洞及复现环境，欢迎加入交流和学习：  
  
**本月最新披露**  
漏洞：Vite任意文件读取漏洞（CVE-2025-30208）复现及漏洞环境  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/I2eHcAFia5S7XCCVSc1w20IQq0S4hhVv2NBUP9lDQ6Y3BwDaVhRicgyEyxsb5aticmLUqTZGXIhjCuibpyiauqc9z9Q/640?wx_fmt=png&from=appmsg "")  
  
**实战渗透测试技巧分享&讨论**  
：某次若依系统渗透测试带来的思考与讨论  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/I2eHcAFia5S7XCCVSc1w20IQq0S4hhVv2eE0LB0AmxL3SUAd9EJtxPODuzgYI2RjurpNkTw1LRebUju6PtmQ8Zg/640?wx_fmt=png&from=appmsg "")  
  
一些比较新奇有趣的漏洞分享：Windows**拖拽图标**  
而触发的漏洞  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/I2eHcAFia5S7XCCVSc1w20IQq0S4hhVv25xxibm1Axsbib1x8ia0L4wT6zIFP4aJZ2ibKSKwfMpCuCbuPOG441DIQWg/640?wx_fmt=png&from=appmsg "")  
  
知识星球限时新人立减券发放  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/I2eHcAFia5S7XCCVSc1w20IQq0S4hhVv2bDicHDr4VE4ughOdn2JXanCyn2yf3WZr4qEcibMRE3QG8EI5qBZGtf2Q/640?wx_fmt=png&from=appmsg "")  
  
  
