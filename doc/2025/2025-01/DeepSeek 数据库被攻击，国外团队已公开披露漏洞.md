#  DeepSeek 数据库被攻击，国外团队已公开披露漏洞   
原创 Mstir  星悦安全   2025-01-30 07:16  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/lSQtsngIibibSOeF8DNKNAC3a6kgvhmWqvoQdibCCk028HCpd5q1pEeFjIhicyia0IcY7f2G9fpqaUm6ATDQuZZ05yw/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
点击上方  
蓝字  
关注我们 并设为  
星标  
## 0x01 漏洞研究  
  
    AI 初创公司 DeepSeek 最近因其开创性的 AI 模型，尤其是 DeepSeek-R1 推理模型而引起了媒体的广泛关注。该模型在性能上可与 OpenAI 的 o1 等领先的 AI 系统相媲美，并以其成本效益和效率而著称。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/uicic8KPZnD5cDvYfMzqZwx6ia3eWZa18Bpdp38AY4Mle42h3boPn4EDoAg0opZ2EMicTGO5dOjHuolmvdAybPviaBQ/640?wx_fmt=png&from=appmsg "")  
  
      
漏洞源于DeepSeek一个公开暴露在公网上的ClickHouse数据库，该数据库未设置任何访问权限验证  
  
```
漏洞地址：******.deepseek.com:9000***.deepseek.com:9000
```  
  
  
    该数据库内蕴藏了海量的聊天记录、后端数据以及诸多敏感信息，诸如日志流、API密钥和详尽的操作细节等。  
  
    尤为严重的是，此漏洞使得攻击者能够在DeepSeek环境中实现全面的数据库控制与权限提升，而无需突破任何外部的身份验证或防御壁垒  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/uicic8KPZnD5cDvYfMzqZwx6ia3eWZa18BpALMQEicnaVnYpSaxI98wmz7lDnAibf3RO1ITia4DXbTgictWUTKv9OJ3Cg/640?wx_fmt=other&from=appmsg "")  
  
    漏洞扫描始于DeepSeek的公开可访问领域。运用简明的侦察技巧（包括被动和主动的子域发现），这些子域大多看似无害，承载着聊天机器人界面、状态页面和API文档等内容，并不构成高风险暴露。  
  
    然而，我们偶然发现了两个异乎寻常的开放端口（8123和9000），它们与以下主机紧密相连：  
  
```
http://******.deepseek.com:8123  http://***.deepseek.com:8123  http://******.deepseek.com:9000  http://***.deepseek.com:9000 
```  
  
  
      
  
     
在深入调查之后，我们发现这些端口通向了一个无需任何身份验证即可访问的ClickHouse数据库，这一发现立即触发了安全警报。  
  
  
   ClickHouse，作为一个开源的列式数据库管理系统，由Yandex匠心独运，专为迅速分析查询庞大数据集而设计。它在实时数据处理、日志存储以及大数据分析领域内广泛应用，因此，这样一个数据库的暴露无疑是一个极具价值和敏感性的安全发现。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/uicic8KPZnD5cDvYfMzqZwx6ia3eWZa18BpiaIElJcNwbqYiaLMHwwcrL4N8aejHzjxz03GHCBE9lbvhtIDfOSIVwLQ/640?wx_fmt=other&from=appmsg "")  
  
  
通过利用 ClickHouse 的 HTTP 接口，访问了 /play 路径，该路径允许通过浏览器直接执行任意 SQL 查询  
  
运行一个简单的 SHOW TABLES;query 返回可访问数据集的完整列表。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/uicic8KPZnD5cDvYfMzqZwx6ia3eWZa18BpCcopXZsoWJPELbTJgRMF2Y7ZribN8oicBjVVHzIBbEQm797GlictUq6Gg/640?wx_fmt=png&from=appmsg "")  
  
其中，有一个表脱颖而出：log_stream，其中包含大量日志和**高度敏感的数据**。log_stream 表包含**超过 100 万个日志条目**，其中特别具有启发性的列：  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/uicic8KPZnD5cDvYfMzqZwx6ia3eWZa18BpDW7ZPA277jYvs9Xrq9icBvFGsozjesajDBf7hdib25b7oI4zRDQYic1KQ/640?wx_fmt=other&from=appmsg "")  
  
  
- timestamp – **2025 年 1 月 6 日的日志**  
   
  
- span_name – 对各种内部 **DeepSeek API 端点的引用**  
   
  
- string.values – **纯文本日志**，包括**聊天历史记录**、**API 密钥、后端详细信息和操作元数据**  
   
  
- _service – 指示**哪个 DeepSeek 服务**生成了日志  
  
- _source – 公开**日志请求的来源**，包括**聊天历史记录、API 密钥、目录结构和聊天机器人元数据日志**  
   
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/uicic8KPZnD5cDvYfMzqZwx6ia3eWZa18BpmadrwqSicyljC8J6D0ic503ufSMRX43DTeCvRicNMWx2f7DGvNAQW8Licw/640?wx_fmt=other&from=appmsg "")  
  
这种级别的访问对 DeepSeek 自身的安全及其最终用户构成了严重风险。攻击者不仅可以检索敏感日志和实际的纯文本聊天消息，而且还可能使用如下查询直接从服务器窃取纯文本密码和本地文件以及专有信息：SELECT * FROM file（'filename'），具体取决于他们的 ClickHouse 配置。  
## 0x02 公开交流群  
  
**标签:代码审计，0day，渗透测试，系统，通用，0day，闲鱼，转转**  
  
**PS:持续关注下方公众号，持续更新安全文章**  
  
  
  
  
**开了个星悦安全公开交流4群，🈲发公众号，纯粹研究技术，还会拉一些大佬，希望大家多多交流.**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/uicic8KPZnD5cDvYfMzqZwx6ia3eWZa18Bp4BdGO4YiaPrEa7h0Qxu71ZgHdRg7WDaibmHyZEL6iakoCSFZByFvtLrVw/640?wx_fmt=jpeg&from=appmsg "")  
  
**免责声明:****文章中涉及的程序(方法)可能带有攻击性，仅供安全研究与教学之用，读者将其信息做其他用途，由读者承担全部法律及连带责任，文章作者和本公众号不承担任何法律及连带责任，望周知！！!**  
  
****  
**文章翻译自:https://www.wiz.io/blog/wiz-research-uncovers-exposed-deepseek-database-leak**  
  
