#  手把手教你构建企业级本地AI漏洞文库：基于Ollama + DeepSeek R1+ Anything LLM 完整指南   
原创 渗透测试  渗透测试   2025-02-13 07:17  
  
    ![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/x5oSJqsiavIibT7zN5Ng0riatokZjibdOsdaJUAT8KkH6RXEKlPPqz3dT7pvlWIEH0wWsOD6ic0zb3cZUvHv0ANHjBg/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
**点击上方蓝字****关注【渗透测试】不迷路**  
  
  
  
### 前言  
```
声明：文章中涉及的工具(方法)可能带有攻击性，仅供安全研究与教学使用；
读者若做其他违法犯罪用途，由用户承担全部法律及连带责任；
文章作者不承担任何法律及连带责任。
```  
  
  
****###   
### 测试环境：  
```
Windows 10  16G运行内存
Ollama       #0.5.7  AI模型运行环境必装之一
DeepSeek R1   #deepseek-r1:7b
Anything LLM  #V1.7.3-r2  几乎支持所有包含文字的文档格式:txt、word、csv、xls、Markdow、pdf等等
自备科学上网
```  
### Ollama是什么？  
  
    Ollama是一款开源的  
本地大语言模型（LLM）运行框架，  
支持Linux/macOS/Windows多平台。它通过简单的命令行工具，让用户无需复杂配置就能在本地运行Llama、  
DeepSeek、Phi等前沿AI模型。通过智能化的依赖检测、自动GPU加速支持，以及轻量级架构设计，Ollama将大模型部署门槛降到新低。  
  
安装ollama  
```
官网：https://ollama.com/download
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/z3TOtprWtZ9HE2dMF0I8ibxkmQohicXf7q4j83WGbg4fye5tYPfDgIncrB8POW7wdOibNacECGHxVkPibaArxWnRvQ/640?wx_fmt=png&from=appmsg "")  
  
我这里是Windows系统，所以选择Windows版。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/z3TOtprWtZ9HE2dMF0I8ibxkmQohicXf7qhNibNslB7G8cg39EqoiaxAGnJ24DH6jfaSHR5uJFZc03C2GyaSVGeNbw/640?wx_fmt=png&from=appmsg "")  
  
坐等下载完成......  
  
Windows:下载完成后，运行下载的安装文件（通常为OllamaSetup.exe），按照屏幕上的指示完成安装过程。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/z3TOtprWtZ9HE2dMF0I8ibxkmQohicXf7qOrTkicPt7gTftyRsDFVicMoQDp5TicwzC8WqYalGgB4FlxXaWlLkJwvYA/640?wx_fmt=png&from=appmsg "")  
  
安装完成后，您可以在应用程序菜单或搜索栏中找到Ollama，启动它。  
  
验证安装  
  
启动Ollama后，您可以在命令行中输入以下命令来验证Ollama是否成功。  
```
ollama --version
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/z3TOtprWtZ9HE2dMF0I8ibxkmQohicXf7qQqfKdynODVfgNZfWxQGp5dtcnPC2hFmibHBhAUq3e37pex1vTQfGKKg/640?wx_fmt=png&from=appmsg "")  
  
浏览器访问http://127.0.0.1:11434为ollama的api端口。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/z3TOtprWtZ9HE2dMF0I8ibxkmQohicXf7qSPAibIVby0bHdFmATvcFKp9nI1LxbM7gwJvb4LsyhmzyPH7KhuYk1Nw/640?wx_fmt=png&from=appmsg "")  
  
通过以上步骤，您应该能够  
成功安装并运行Ollama。如果在安装过程中遇到任何问题，建议查看Ollama的官方文档或寻求社区支持。  
### 部署DeepSeek-R1模型  
```
下载地址: https://ollama.com/library/deepseek-r1
```  
  
根据您的需求选择相应的模型版本，  
数字越大，代表数据量越多。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/z3TOtprWtZ9HE2dMF0I8ibxkmQohicXf7qEwn5CpvbzJU4nrL6Orh6dCsS0596W5NZt8hzU2xIApZmVsqvNZhHFg/640?wx_fmt=png&from=appmsg "")  
  
我这里选择7b  
```
ollama run deepseek-r1:7b
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/z3TOtprWtZ9HE2dMF0I8ibxkmQohicXf7qtMibwqQpJ8OKC8MMulFiclKTEsN79EmJUXAd5M1LX3AxDwngS0kOIhrA/640?wx_fmt=png&from=appmsg "")  
  
模型部署完成后查看当前系统中有哪些模型：  
```
ollama list   #可以看到我们刚刚下载的deepseek-r1:7b模型
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/z3TOtprWtZ9HE2dMF0I8ibxkmQohicXf7qJpXAtKq6JRDk1uKd8PooxS7horN7lSaQcZHOIqlBRr4HwibkKJrbzyQ/640?wx_fmt=png&from=appmsg "")  
  
启动交互式对话  
```
ollama run deepseek-r1:7b

## 当界面显示>>>标签表示会话启动成功，输入“你好，你是谁？”，看DeepSeek-R1是怎么回答的。
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/z3TOtprWtZ9HE2dMF0I8ibxkmQohicXf7qUOpdsqaBVYXve5fAhr2FY0S4ibaia9roB57IXWibufH3RUMDR7MRVicuwA/640?wx_fmt=jpeg "")  
  
至此 代表DeepSeek-R1已经完全部署好了可成功运行。  
### 安装AnythingLLM  
  
        AnythingLLM 是由 Mintplex Labs Inc. 开发的一款全栈应用程序， 全方位AI应用程序。与文档聊天，使用AI代理，高度可配置，多用户，无需繁琐的设置。  适用于桌面（  
Mac、Windows和Linux），可以将任何文档、资源（如网址链接、音频、视频）或内容片段转换为上下文，以便任何[大语言模型](（LLM）在聊天期间作为参考使用，同时支持多用户管理并设置不同权限，一个完全可定制的、私有的、多合一的 AI 应用程序，用于您的企业或组织，它基本上是一个具有许可的完整 ChatGPT，但具有任何 LLM、嵌入模型或向量数据库。  
```
官网Windows版下载：
https://docs.anythingllm.com/installation-desktop/windows#install-using-the-installation-file
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/z3TOtprWtZ9HE2dMF0I8ibxkmQohicXf7qyms78Wm0qhJdUKPB39KmmneKkZocqMz38IuZ2l1tLj1A9ibhG45lV4Q/640?wx_fmt=png&from=appmsg "")  
  
坐等下载完成......  
  
Windows:下载完成后，运行下载的安装文件（通常为AnythingLLMDesktop.exe），按照屏幕上的指示完成安装过程。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/z3TOtprWtZ9HE2dMF0I8ibxkmQohicXf7qS68QBjXeXiaaupBicujxRTzgkicO7pCHzFPShd8YEGcPfLK46FN4yTSiaw/640?wx_fmt=png&from=appmsg "")  
### 配置 AnythingLLM  
  
选择Ollama 》deepseek-r1  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/z3TOtprWtZ9HE2dMF0I8ibxkmQohicXf7q2ujibic6xdtA6WHneucibnNyvreCtouEIR0tiaFa2AeXp93ibQN22X3ezkw/640?wx_fmt=png&from=appmsg "")  
  
设置默认语言“Chinese”  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/z3TOtprWtZ9HE2dMF0I8ibxkmQohicXf7qjib8cZKl4HqicOkN8ubFR33fciaxUgWLm5I64PH91V1cZOQPfTsUAofSQ/640?wx_fmt=png&from=appmsg "")  
### LLM 首选项配置  
  
这些是您首选的LLM聊天和嵌入提供商的凭据和设置，否则AnythingLLM 将无法正常运行。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/z3TOtprWtZ9HE2dMF0I8ibxkmQohicXf7qUJyib0aKaibiaWa2qbtOVYWykrkMHQJXiao1tdYSkPHVzb9caEfqo3Qt7w/640?wx_fmt=png&from=appmsg "")  
  
基本配置完成后“新建工作区”  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/z3TOtprWtZ9HE2dMF0I8ibxkmQohicXf7q0ZlficnOWxQOUyORRyd4HCjL8XTsVxItZTiccUdjh98JggzwqIF1fpGA/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/z3TOtprWtZ9HE2dMF0I8ibxkmQohicXf7qCKk3YibcdXd4FaiaWYrdrwTicQtuh97l1PFGdTaibm3mqjooluFgFb1kOg/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/z3TOtprWtZ9HE2dMF0I8ibxkmQohicXf7qBUXBfGsajb8KgVmhrV7TWStNcwBhyvfOTebibzBtqMswIuLicTFTGxyg/640?wx_fmt=png&from=appmsg "")  
  
点击上传标志，选择“Click to upload or drag and drop”开始添加文档。  
  
知识库上传本地的文档（  
PDF、TXT、Markdown‌、DOCX‌文档）或  
第三方Web链接、GitHub、GitLab等平台的数据链接  
。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/z3TOtprWtZ9HE2dMF0I8ibxkmQohicXf7qOX6icYyo7fb62ORrjh4JFianXp8qoatkgBAu7tl0Yexkyv5rd8rJJTlA/640?wx_fmt=png&from=appmsg "")  
  
选择文档点击 “Move to Workspace”  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/z3TOtprWtZ9HE2dMF0I8ibxkmQohicXf7qzjsEIxeC2WSKibHBQnicfrl3Js6KtvIJNLvVY9xCUmCJVYOPjlVBJKBw/640?wx_fmt=png&from=appmsg "")  
  
下滑页面，然后点击 “Save and Embed”  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/z3TOtprWtZ9HE2dMF0I8ibxkmQohicXf7qFOSiayhV7LWXEuMTrPc1CBZlD9nSXA2cQvBnXTdcKNnPfZFCjREcriaA/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/z3TOtprWtZ9HE2dMF0I8ibxkmQohicXf7qRBteKLEFbZfa3a9YCWhgoSEnHf6tibj9Go3aR34XbxIaGSHwLW8LB6w/640?wx_fmt=jpeg "")  
  
等待上传。。。。。。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/z3TOtprWtZ9HE2dMF0I8ibxkmQohicXf7qibyL0bVajfwcyP8gt9tjiaRDPDNm5aLXKfxU3fzk4ZwjPmcia0iaFUgvibg/640?wx_fmt=png&from=appmsg "")  
  
出现 “Workspace updated successfully.” 就表示配置已经完成。  
### 验证效果  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/z3TOtprWtZ9HE2dMF0I8ibxkmQohicXf7qtu5Z35ibLPvpOfSlwNjgicujARpyoiaPMJicsHcsQbPib7C6pVXPsNE5ibtw/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/z3TOtprWtZ9HE2dMF0I8ibxkmQohicXf7qIJibOMSVHnWE4shQ92fGzRyP5VnynibywLeeo1hjCiar669W2BRTNTf7g/640?wx_fmt=png&from=appmsg "")  
  
查看索引文件  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/z3TOtprWtZ9HE2dMF0I8ibxkmQohicXf7qhyNibNvRpibWb730P74gK7NsTN1ymDVoibjrh10vLVg1VQBCLy1jj5FxQ/640?wx_fmt=png&from=appmsg "")  
### 在线数据源添加  
  
可以通过数据连接器直接获取解析网络内容，例如  
GitHub、Youtube、或者抓取网站内容，等待抓取网站内容结束后，添加到工作区，  
可以直接引用抓取的数据来生成回答内容。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/z3TOtprWtZ9HE2dMF0I8ibxkmQohicXf7qsmzicjHIKK6QS0ibVzR4XFDw4iboq7Dmf4q1e0w7vnUOcHvhoTxFnVZTA/640?wx_fmt=png&from=appmsg "")  
  
**文中涉及的工具及方法仅用于技术交流，请勿用于非法用途。**  
  
  
## 技术交流  
  
    扫描下方二维码，并在验证信息中说明来意，文章仅供交流学习,本公众号不承担任何有关责任!  
  
![图片](https://mmbiz.qpic.cn/mmbiz_jpg/z3TOtprWtZibxicaHzm6icoKWFPFB9gcBcv3aWA5wEMcgOXfZpDoqgYicfibMPBzx2Jle7p28TWsEGCdgwsDRwhUy2w/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
**星球介绍**  
  
**自研工具、二开工具、免杀工具、漏洞复现、教程等资源、漏洞挖掘分析、网络安全相关资料分享。**  
  
  
  
