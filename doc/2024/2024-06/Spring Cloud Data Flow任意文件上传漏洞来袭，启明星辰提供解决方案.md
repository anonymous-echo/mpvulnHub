#  Spring Cloud Data Flow任意文件上传漏洞来袭，启明星辰提供解决方案   
 启明星辰集团   2024-06-05 18:30  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/BwR7Xg3aXhasKjicBZsG8bShBJeuxiaYcWUwXw6vZsfodqd2y6g1SXF4NYprHyvvrmlLWeDdhlxPa3gZhwFf2euw/640?wx_fmt=gif&from=appmsg "")  
  
  
  
**Spring
Cloud Data Flow**  
**(SCDF)**  
是一个用于构建、部署和管理微服务的框架。它通过提供一组工具和服务，简化了数据处理和分析的流程，允许开发人员快速构建和部署复杂的数据处理管道。SCDF 的使用场景包括流式数据处理、批量数据处理、事件驱动处理等多种场景。  
  
  
**SCDF的核心组件包括：**  
- Spring
Cloud Data Flow Server  
：负责接收、管理和执行数据处理管道的请求。  
  
- Spring
Cloud Data Flow Shell  
：命令行工具，用于与  
   
SCDF Server交互。  
  
- Spring
Cloud Data Flow UI  
：  
Web 界面，用于管理和监控数据处理管道。  
  
- Spring
Cloud Data Flow Task  
：用于批量数据处理的任务执行引擎。  
  
- Spring
Cloud Stream  
：用于构建流式数据处理管道的框架。  
  
- Spring
Cloud Task  
：用于构建批量数据处理管道的框架。  
  
- Spring
Cloud Skipper  
：用于部署和升级   
Spring Boot 应用程序的工具。  
  
使用  
 SCDF  
，开发人员可以通过定义和组合多个数据处理组件来构建复杂的数据处理和分析管道，同时也可以方便地部署、监控和管理这些管道。此外，  
SCDF   
还提供了一组标准化的组件，使得开发人员可以更加方便地构建数据处理管道，同时也能够保证这些组件的可靠性和互操作性。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/BwR7Xg3aXhZkJWsvn4MAiaYiaJjkEHZiasrpB2atuLItNKjwjSPXMqvYfMOoiaiagtZEC9I8JaicUghJ0DKorFLqcpNw/640?wx_fmt=gif&wxfrom=5&wx_lazy=1&tp=webp "")  
  
**漏洞详情**  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/BwR7Xg3aXhZkJWsvn4MAiaYiaJjkEHZiasrpB2atuLItNKjwjSPXMqvYfMOoiaiagtZEC9I8JaicUghJ0DKorFLqcpNw/640?wx_fmt=gif&wxfrom=5&wx_lazy=1&tp=webp "")  
  
  
  
2024年6月4日，启明星辰  
**金睛安全研究团队**  
监控到Spring官方发布了  
Spring Cloud Data
Flow 中的**任意文件写入漏洞**  
CVE-2024-22263情报。  
  
  
该漏洞的原因是  
Spring Cloud
Skipper服务器接收到恶意的请求文件名及恶意的文件流数据后对恶意文件名处理不当，导致恶意文件无法正常删除，有权访问  
Spring Cloud Skipper api接口的恶意用户可以构建恶意的上传请求将任意文件写入  
Spring
Cloud Skipper文件系统上的任何位置。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwR7Xg3aXhYhpibpxWibek6E9HT1y15DwhNMAXaEpmdEuvNUKtBU6gBZdxxOAXBvz7oZnpt0IMia6bnB6Sk7eNxoA/640?wx_fmt=png&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/BwR7Xg3aXhZkJWsvn4MAiaYiaJjkEHZiasrpB2atuLItNKjwjSPXMqvYfMOoiaiagtZEC9I8JaicUghJ0DKorFLqcpNw/640?wx_fmt=gif&wxfrom=5&wx_lazy=1&tp=webp "")  
  
**漏洞复现截图**  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/BwR7Xg3aXhZkJWsvn4MAiaYiaJjkEHZiasrpB2atuLItNKjwjSPXMqvYfMOoiaiagtZEC9I8JaicUghJ0DKorFLqcpNw/640?wx_fmt=gif&wxfrom=5&wx_lazy=1&tp=webp "")  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwR7Xg3aXhYhpibpxWibek6E9HT1y15DwhldQDZ25FQGnL6ibIqdgLF9DhUVqP1wia0NxupRT7XBHUIwUqAck7E3eQ/640?wx_fmt=png&from=appmsg "")  
  
  
待上传的文件  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwR7Xg3aXhYhpibpxWibek6E9HT1y15Dwh6Eh4apYhXWGicyXTUoiccHrRZfZ0eIfOkwnYQUCQ9XANhQeS6xSwH0Og/640?wx_fmt=png&from=appmsg "")  
  
  
上传成功截图  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwR7Xg3aXhYhpibpxWibek6E9HT1y15Dwhtq5FiaRDZFecC9K2yea2wTYeWHiaP4lkiaVy4K7GXhgxtgVFfTA9CiaYoQ/640?wx_fmt=png&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/BwR7Xg3aXhZkJWsvn4MAiaYiaJjkEHZiasrpB2atuLItNKjwjSPXMqvYfMOoiaiagtZEC9I8JaicUghJ0DKorFLqcpNw/640?wx_fmt=gif&wxfrom=5&wx_lazy=1&tp=webp "")  
  
**影响版本**  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/BwR7Xg3aXhZkJWsvn4MAiaYiaJjkEHZiasrpB2atuLItNKjwjSPXMqvYfMOoiaiagtZEC9I8JaicUghJ0DKorFLqcpNw/640?wx_fmt=gif&wxfrom=5&wx_lazy=1&tp=webp "")  
  
  
- 2.11.0 - 2.11.2  
  
- 2.10.x  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/BwR7Xg3aXhZkJWsvn4MAiaYiaJjkEHZiasrpB2atuLItNKjwjSPXMqvYfMOoiaiagtZEC9I8JaicUghJ0DKorFLqcpNw/640?wx_fmt=gif&wxfrom=5&wx_lazy=1&tp=webp "")  
  
**修复建议**  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/BwR7Xg3aXhZkJWsvn4MAiaYiaJjkEHZiasrpB2atuLItNKjwjSPXMqvYfMOoiaiagtZEC9I8JaicUghJ0DKorFLqcpNw/640?wx_fmt=gif&wxfrom=5&wx_lazy=1&tp=webp "")  
  
  
  
**1、官方修复方案**  
  
受影响版本的用户应升级到相应的固定版本。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwR7Xg3aXhYhpibpxWibek6E9HT1y15DwhEBwWBJUQ5aQaClnic3nxiarroISlQLDIZF8zjDzxh6iaPNmPr2vWCIE8g/640?wx_fmt=png&from=appmsg "")  
  
  
**2、启明星辰方案**  
  
  
天阗入侵检测与管理系统、天阗超融合检测探针（  
CSP  
）、天阗威胁分析一体机（  
TAR  
）、天清入侵防御系统（  
IPS  
）、天清  
Web  
应用安全网关（  
WAF  
）升级到  
20240605  
版本即可有效检测或防护该漏洞造成的攻击风险。  
  
  
  
  
  
•  
  
END  
  
•  
  
  
  
[](https://mp.weixin.qq.com/s?__biz=MzA3NDQ0MzkzMA==&mid=2651696952&idx=1&sn=f2bb1c66eca7a93bc760079e7ed36523&chksm=8486b2cdb3f13bdb72d39215b362aa55ce57b6022207eb95cc8054eff268b5f4d330eb7c88f2&token=1376838202&lang=zh_CN&scene=21#wechat_redirect)  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/BwR7Xg3aXhZnP8uSH0r6r3GRzEZPLpW1Ticn02ZJ4dkMLZjnN6HFbzz7BROCQYZNrN0GKJvcW7dTQx0l9VzX3Qw/640?wx_fmt=gif&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/BwR7Xg3aXhaOXFAap6OpOk7J3jrs8jWroVOQDibibC40UcRxx343kDbCEuib4KsvWfFZPW1WfEe0t4V5f5caJGGqw/640?wx_fmt=gif "")  
  
  
