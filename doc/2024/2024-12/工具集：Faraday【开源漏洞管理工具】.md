#  工具集：Faraday【开源漏洞管理工具】   
wolven Chan  风铃Sec   2024-12-30 04:05  
  
### 工具介绍  
  
安全有两个艰巨的任务：设计智能的方式获取新信息，以及跟踪发现的内容以改善修复工作。有了 Faraday，您可以专注于发现漏洞，而我们将帮助您处理其余的工作。只需在终端中使用它，您就可以在操作的同时将工作组织起来。Faraday 旨在让您真正以多用户的方式利用社区中可用的工具，这对经理和分析师来说都是有价值的。  
  
Faraday 聚合并规范化您加载的数据，允许将其转化为不同的可视化形式。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qGTEdaLg0HkFJHcFCYExrG6ZTOvRWNbic3tBLzK3fSIqdm7IiaI9KOyMMZsxmERrt0Fmd4IalVkBhf7rsNC3Nyaw/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qGTEdaLg0HkFJHcFCYExrG6ZTOvRWNbicGXLmj6VaAVnlea9DRLJIU3PJ9Y3RKKC7ck2hUF7kIpmW9ZBNFibACuQ/640?wx_fmt=png&from=appmsg "")  
  
## 安装  
#### Docker-compose  
  
让faraday启动并运行的最简单方法是使用我们的docker-compose。  
```
```  
#### Docker  
  
您需要先运行一个postgres。  
```
```  
#### PyPi  
```
```  
#### Binary Packages (Debian/RPM)  
```
```  
  
将你的用户添加至   
faraday  
组后运行。  
## Faraday Cli  
  
faraday -cli是我们的命令行客户端，提供易于访问的控制台工具，直接从终端在faraday工作！  
  
这是一种自动化扫描的好方法，可以将其集成到CI/CD管道中，或者只是从工作空间中获取指标  
```
```  
  
控制台插件：它解释你执行的工具的输出。  
```
```  
  
报告插件，它允许您导入以前生成的工件，如xml、json。  
```
```  
### 项目地址  
```
```  
  
