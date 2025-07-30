#  AI模型可被劫持，Hugging Face转换服务存在高风险漏洞   
看雪学苑  看雪学苑   2024-02-29 18:08  
  
网络安全公司HiddenLayer上周三在一份报告中表示，他们发现Hugging Face Safetensors转换工具存在着漏洞，可能被利用来劫持AI模型并发动供应链攻击。  
  
  
Hugging Face是一家从事人工智能（AI）、自然语言处理（NLP）和机器学习（ML）的科技公司，提供一个社区协作平台，方便用户托管并共享模型、数据集以及应用程序。  
  
  
而Safetensors则是该公司专门设计的一种新型模型存储格式，旨在以安全为前提存储张量，它为此配备了一个转换服务，使用户可以通过拉取请求将PyTorch模型（即pickle，较容易被黑客武器化，以执行任意代码并部署Cobalt Strike、Mythic和Metasploit。）转换为更安全的Safetensor。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8GAU6FettiaadHxOcltAfCZKx4KN1TYfkKpnOlHoBPwaOicWmANFT4icBazG2dQEHxAvDomBBFuAQZaw/640?wx_fmt=png&from=appmsg "")  
  
  
然而，HiddenLayer的分析发现，攻击者能够冒充Hugging Face转换机器人，向该平台上的任何存储库发送恶意拉取请求，同时劫持通过转换服务提交的任何模型。一旦用户尝试转换自己的私人存储库，潜在的攻击可能会导致Hugging Face令牌被盗取，进而使得内部模型和数据集被访问并篡改。  
  
  
安全研究员对Hugging Face上托管的PyTorch和Tensorflow Keras模型进行了扫描，从中发现了上百个具有某种形式恶意功能的模型。一个例子是最近由名为“baller423”的用户上传的一个PyTorch模型（已从Hugging Face上移除），其中包含一个有效负载，使其具有建立到指定主机（210.117.212.93）的反向shell的能力。  
  
  
HiddenLayer的研究人员表示：“虽然Hugging Face生态系统在保护机器学习模型方面有着最好的意图，但转换服务已经被证明是容易受攻击的，并且有可能通过Hugging Face官方服务引发广泛的供应链攻击。”  
  
  
报告链接：https://hiddenlayer.com/research/silent-sabotage/  
  
  
  
编辑：左右里  
  
资讯来源：hiddenlayer  
  
转载请注明出处和本文链接  
  
  
**每日涨知识**  
  
MD5   
  
一种重复加密散列函数，用于进行消息验证（包含数字签名）。该函数于 1991 年由  
Rivest 开发。  
  
  
﹀  
  
﹀  
  
﹀  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/Uia4617poZXP96fGaMPXib13V1bJ52yHq9ycD9Zv3WhiaRb2rKV6wghrNa4VyFR2wibBVNfZt3M5IuUiauQGHvxhQrA/640?wx_fmt=jpeg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/1UG7KPNHN8E9S6vNnUMRCOictT4PicNGMgHmsIkOvEno4oPVWrhwQCWNRTquZGs2ZLYic8IJTJBjxhWVoCa47V9Rw/640?wx_fmt=gif "")  
  
**球分享**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/1UG7KPNHN8E9S6vNnUMRCOictT4PicNGMgHmsIkOvEno4oPVWrhwQCWNRTquZGs2ZLYic8IJTJBjxhWVoCa47V9Rw/640?wx_fmt=gif "")  
  
**球点赞**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/1UG7KPNHN8E9S6vNnUMRCOictT4PicNGMgHmsIkOvEno4oPVWrhwQCWNRTquZGs2ZLYic8IJTJBjxhWVoCa47V9Rw/640?wx_fmt=gif "")  
  
**球在看**  
  
****  
****  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/1UG7KPNHN8FxuBNT7e2ZEfQZgBuH2GkFjvK4tzErD5Q56kwaEL0N099icLfx1ZvVvqzcRG3oMtIXqUz5T9HYKicA/640?wx_fmt=gif "")  
  
戳  
“阅读原文  
”  
一起来充电吧！  
  
