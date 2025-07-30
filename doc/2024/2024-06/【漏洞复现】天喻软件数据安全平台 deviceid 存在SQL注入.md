#  【漏洞复现】天喻软件数据安全平台 deviceid 存在SQL注入   
mole5  云鸦安全   2024-06-23 16:25  
  
一、产品描述  
  
武汉天喻软件有限公司专注于为中国制造业企业提供信息化及协同管理、数字化设计、数据安全等软件解决方案和工程咨询服务。这家公司依托国家企业信息化应用支撑软件工程研究中心建立，旨在通过专业的数字化设计软件帮助制造业企业提升效率和安全性。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/AbAaoHnsh8JmCDoHr8dHGplNqOu3gGeQsHUgtWGWhuUVHGZxZ08iceca66l9nkGyckyksAsGBJ4FMAY526l13lw/640?wx_fmt=png&from=appmsg "")  
  
  
二、漏洞复现  
  
fofa  
:  
```
app="天喻软件数据安全平台"
body="数据安全" && body="天喻"
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/AbAaoHnsh8JmCDoHr8dHGplNqOu3gGeQfzS0QSd2g81dQTialo5eRxzPl2VW4yibuhIzh7XmJxB6BICgdtcaVxrw/640?wx_fmt=png&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/AbAaoHnsh8JmCDoHr8dHGplNqOu3gGeQGcwwiatv2SjYez8vILvVg4sKchR0yzdpWICKKStu7R8WibveIEysq5Jw/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/AbAaoHnsh8LwcxufKobwdrjtYW614clN9YnHnRHGFbraFWW0cxiafW1uWfKBPmO68J1fkRJbxDkgEKar306icM3w/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
关注公众号回复  
06231获取poc  
> 免责声明：文章来源互联网收集整理，请勿利用文章内的相关技术从事非法测试。读者在使用本文提供的信息时，应自行判断其适用性，并承担由此产生的一切风险和责任。本文作者对于读者基于本文内容所做出的任何行为或决定不承担任何责任。在任何情况下，由于传播、利用此文所提供的信息或者工具而造成的任何直接或者间接的后果及损失，均由使用者本人负责，所产生的一切不良后果与文章作者无关。该文章仅供学习用途使用。  
  
  
