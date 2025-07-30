#  Ollama未授权漏洞简单复现   
原创 ss  shadowsec   2025-03-02 10:25  
  
前言：**本文仅限技术研究与讨论，严禁用于非法用途，否则产生的一切后果自行承担。**  
  
最近Deepseek爆火，很多企业之类的都开始部署ai。而Ollama是运行 AI 模型的最受欢迎的开源项目之一，在Github上有13w以上star。在以后，或许AI也会成为一条新的可以渗透的路线，所以在看到ollama出现漏洞的时候复现学习一下。  
  
fofa语法：  
```
app="Ollama"
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/FnaToS7EzpmkXm0nMlp5fMPt9CxhIFXgGOJ0YpdXX969crw16zn6e7q1MoJP4xQbHlWricmfwPea00RxHGZT8Ew/640?wx_fmt=png&from=appmsg "")  
  
大概有2w左右。  
  
随机访问一个  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/FnaToS7EzpmkXm0nMlp5fMPt9CxhIFXgz78grKaKd2E968n6alib2PXUXOgUomRFRiclkUo5FlGe9sbjXD9hAkcw/640?wx_fmt=png&from=appmsg "")  
  
默认访问的话会在页面返回ollama is running。  
  
查看Ollama api文档。Ollama提供了多个API 端点，用于执行不同的操作。以下是这些端点的详细解释：  
```
/api/generate
用于生成文本或内容。通常用于基于给定的输入生成响应或输出，例如生成对话回复、文章等。
/api/chat
专门用于聊天交互。用户可以通过此端点与模型进行对话，模型会根据输入生成相应的回复。
/api/create
用于创建新的模型或资源。可能涉及初始化一个新的模型实例或配置。
/api/tags
用于管理或查看模型的标签。标签可以帮助用户对模型进行分类或标记，便于管理和查找。
/api/show
用于显示模型或资源的详细信息。用户可以获取模型的配置、状态或其他相关信息。
/api/copy
用于复制模型或资源。用户可以通过此端点创建一个现有模型的副本。
/api/delete
用于删除模型或资源。用户可以通过此端点移除不再需要的模型或数据。
/api/pull
用于从 Ollama 下载模型。用户可以通过此端点将模型从远程服务器拉取到本地环境中。
/api/push
用于将模型上传到 Ollama。用户可以通过此端点将本地模型推送到远程服务器。
/api/embeddings
用于生成文本的嵌入向量。嵌入向量是文本的数值表示，通常用于机器学习任务中的特征提取。
/api/version
用于获取 Ollama 的版本信息。用户可以通过此端点查询当前使用的 Ollama 版本。
```  
  
未授权状态下，可以通过访问/api/  
tags获取搭建的所有模型信息。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/FnaToS7EzpmkXm0nMlp5fMPt9CxhIFXgBy6CSSQ5KCic3U0yUc7Aovgc1cufQbERUVGeUtQCTJicPicI9a6XZf9JQ/640?wx_fmt=png&from=appmsg "")  
  
这里可以看到采用的是deepseek-r1模型和bge-m3。通过官网的文档，我们可以调用/api/chat来完成聊天请求，消耗资源。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/FnaToS7EzpmkXm0nMlp5fMPt9CxhIFXgnM6OeEMrJ9L30WBCpgxafAHTTx0cerhD35PahBKskw0y8r7icnoRicRA/640?wx_fmt=png&from=appmsg "")  
  
也可以将ip配置于chatbox上直接调用。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/FnaToS7EzpmkXm0nMlp5fMPt9CxhIFXgXAFNLAnjvQByalMAdsbzNUbLHiaPeTEJic0qO2JXWkabVkdjej5vhUBA/640?wx_fmt=png&from=appmsg "")  
  
这里是api配置成功的调用图。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/FnaToS7EzpmkXm0nMlp5fMPt9CxhIFXg5SCElCjPPOUREsHVAYoH01AJ2MuyNnO6jONBLH0ZZbkBshJ4SePNnQ/640?wx_fmt=png&from=appmsg "")  
  
如果是拿来做自己私有的知识库，通过引导很有可能就造成了一些信息的泄露。  
  
除了这个之外,历史ollama也爆出一个  
代码执  
行  
漏洞(cve-2024-37032)。影响版本:  
```
Ollama < 0.1.34
```  
  
首先尝试部署一下ollama，下载地址：  
```
https://registry.ollama.com/download
```  
  
这个确实是很方便的，安装之后根据网页信息即可查看是否部署成功。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/FnaToS7EzpnCTAxx7bRBBtHVj1ziaibBypePRAgjaMFTvwViabwbkKXmyHTBnRs2YNsIvWCC19I5T9BT8GqibwvqtQ/640?wx_fmt=png&from=appmsg "")  
  
然后你可以根据文档选择你的需求:  
```
https://ollama.com/library/deepseek-r1
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/FnaToS7EzpnCTAxx7bRBBtHVj1ziaibByp7CmavDHN0JzKFiaO1BHqgCDMPHANWEKhiatiadodef0iaLE2foa4Sjbtrg/640?wx_fmt=png&from=appmsg "")  
  
我这里虚拟机演示就选择了最低的。  
```
ollama run deepseek-r1:1.5b
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/FnaToS7EzpnCTAxx7bRBBtHVj1ziaibBypQkTFgWniaOmLUFzexCoDIWOOJckCgwpouCY6T5yU7VGdNcrT0TX3V9g/640?wx_fmt=png&from=appmsg "")  
  
这样就部署成功了。  
  
如果需要投喂的话可按照此文  
```
https://www.cnblogs.com/xiezhr/p/18714692
```  
  
根据文章分析该漏洞  
```
https://www.wiz.io/blog/probllama-ollama-vulnerability-cve-2024-37032
```  
  
理解为接口/api/pull可以从远程服务器下载私有模型到本地，此时攻击者构造恶意的服务器(部署恶意文件)然后植入到受害者主机从而获取权限。  
  
参考实现项目：  
```
https://github.com/Threekiii/Vulnerability-Wiki/blob/master/docs-base/docs/ai/Ollama-%E7%9B%AE%E5%BD%95%E9%81%8D%E5%8E%86%E8%87%B4%E4%BB%A3%E7%A0%81%E6%89%A7%E8%A1%8C%E6%BC%8F%E6%B4%9E-CVE-2024-37032.md
```  
```
https://github.com/Bi0x/CVE-2024-37032
```  
  
不过看github现在ollama版本已到  
v0.5.13  
，根据fofa资产普遍版本都到了0.5.x。基本解决了这个问题，但公网未授权漏洞普遍，需要做好防火墙白名单。  
  
