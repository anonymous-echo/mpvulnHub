#  【高危】AI大模型部署软件Ollama 未授权访问漏洞，警惕你部署的大模型被别人使用。   
原创 安全透视镜  网络安全透视镜   2025-02-13 23:10  
  
声明  
# 请勿利用文章内的分享的相关技术内容，从事非法活动。  
# 该文章仅供学习用途使用。由于传播、利用此文所提供的信息而造成的任何直接或者间接的后果及损失，均由使用者本人负责，所产生的一切不良后果与文章作者无关。  
#   
  
![](https://mmbiz.qpic.cn/mmbiz_png/apNprpz3YS4ibIBPcmgJMLNXWIaCPcW54mVicYJkaOO1JQicEDBGCBM1P7IiaiablZ9tEUrP27FyvB9CZWl5SiaqhicDw/640?wx_fmt=png "")  
#   
  
  
一、产品描述  
  
Ollama 是一个开源的本地大语言模型运行框架，旨在让用户能够轻松地在本地运行、管理和与大型语言模型进行交互。它支持多种预训练语言模型，如 LLaMA、DeepSeek、Mistral 等，并提供了简单的命令行工具和 RESTful API。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/apNprpz3YS5mcjPNyqSS8OibNA6NOvq0oG9WkUCAv8YRPoclkcGicWdNn2o21aAaVTOE4OaJAtTTcicVFC3ZU5kfQ/640?wx_fmt=png&from=appmsg "")  
  
背景  
  
随着DeepSeek的火爆，自媒体又开始了新一波割韭菜（比如：标题2025年普通人的最后一次机会之类的）。在各种社交软件上面，兜售教程，开直播，教别人本地化部署AI。 为了方便普通人使用，采用Ollama这种傻瓜式的软件部署。 不少公司及个人购买云服务器私有化部署AI。  
  
二、漏洞描述  
  
Ollama服务开启后，API默认开启且无访问控制权限校验，导致API接口未授权访问，攻击者可通过此接口直接调用用户部署的AI大模型。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/apNprpz3YS5mcjPNyqSS8OibNA6NOvq0os5E5yAruKd11Pga9Izamugr5twsw8QSGuP54MmGrK6ymugriaPt1ialQ/640?wx_fmt=png&from=appmsg "")  
  
  
未授权可执行的功能很多，比如:   
  
可以删除用户部署的大模型，威胁用户数据安全。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/apNprpz3YS5mcjPNyqSS8OibNA6NOvq0o92LoMhibn4JvibBu7ZxxGWfdjhq9qe8r6N7fgbBNdfcdlpTzuqy1KpMQ/640?wx_fmt=png&from=appmsg "")  
  
可调用用户部署的任意大模型，进行对话。恶意攻击者可通过此接口批量发送大量会话内容，从而形成  
针对大模型会话的Dos攻击，占用服务器大量资源，导致正常业务无法进行。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/apNprpz3YS5mcjPNyqSS8OibNA6NOvq0oaOAwPj7z7zJOUZ9gwkYopuKe18NWagVJ5rLKk2oBKLdibichL9XVADpA/640?wx_fmt=png&from=appmsg "")  
  
  
可通过API 部署其他大模型。恶意攻击者可通过此API，在服务器上部署很多其他开源的大参数大模型，从而  
占用服务器存储资源，导致用户其他数据无法正常存储。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/apNprpz3YS5mcjPNyqSS8OibNA6NOvq0objQkOg3J7tDx95yjumquaLUCsiaiaTcsxdUL1GAPBjVIN4xFRgVzkEFg/640?wx_fmt=png&from=appmsg "")  
  
  
........   
  
具体功能可自行查看官方API文档  
  
  
三、漏洞复现  
  
fofa查询  
  
![](https://mmbiz.qpic.cn/mmbiz_png/apNprpz3YS5mcjPNyqSS8OibNA6NOvq0oUlKAgnNzAibbHLztNTpa16AgJJuGXloI1JO0IpqbSXytaM2XgUTLLzg/640?wx_fmt=png&from=appmsg "")  
  
考虑到漏洞的危害性，这里不给出具体代码。仅仅调用进行对话演示。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/apNprpz3YS5mcjPNyqSS8OibNA6NOvq0od8W68aB5gSLn6IYib4FdiccTMHBcKxZgjsNeOnNtfSXoH9XFXTNoQS5w/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/apNprpz3YS5mcjPNyqSS8OibNA6NOvq0owUIHvCVZvsdkTOfotlTh9Bb1FR5C1BTEsFLkx6SO96dkKEyCWkUFIg/640?wx_fmt=png&from=appmsg "")  
  
  
四、漏洞修复  
  
Ollama是开源的，我也没找到怎么设置密钥访问，最初的目的都是给个人做本地部署使用的。本地部署，本地调用原本是没问题的，可部署到公网上，就成了API未授权访问漏洞。  
  
截至发稿，已发现有人开始利用网上私有化部署的大模型。  
  
建议使用Ollama部署大模型的，防火墙或者云服务器安全组做一些白名单访问。  
  
顺便提一下，这个好像还没有CVE  CNVD漏洞编号。关注微信公众号 网络安全透视镜 回复  
 Ollama 获取fofa查询语法  
  
从全网测试来看，几乎全是开源的大模型，有的是别人微调训练过的，有的使用RAG搭建了自己的知识库，也有用于各行各业的AI，以及一些中小公司的AI客服。还有一些统一多模态大模型，可以文生图，也可以图生文。    
  
一些实际应用的AI挺有意思的，读者可自行探索那些被调教过的AI   
（互联网并非法外之地，切勿恶意攻击）  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/apNprpz3YS5mcjPNyqSS8OibNA6NOvq0oWyxbhg0ureZe02NucMpNib8iardUoWJ4VV1KYSJIdWrjAFewz3jHcWFQ/640?wx_fmt=jpeg&from=appmsg "")  
  
  
  
请勿利用文章内的分享的相关技术内容，从事非法活动。  
# 该文章仅供学习用途使用。由于传播、利用此文所提供的信息而造成的任何直接或者间接的后果及损失，均由使用者本人负责，所产生的一切不良后果与文章作者无关。  
#   
  
![](https://mmbiz.qpic.cn/mmbiz_png/apNprpz3YS4ibIBPcmgJMLNXWIaCPcW54mVicYJkaOO1JQicEDBGCBM1P7IiaiablZ9tEUrP27FyvB9CZWl5SiaqhicDw/640?wx_fmt=png "")  
  
  
  
