#  一款常用的API漏洞扫描工具|渗透|简单实用   
淮橘安全  淮橘安全   2024-01-13 17:54  
  
# 声明：请勿利用文章内的相关技术从事非法测试，由于传播、利用此文所提供的信息而造成的任何直接或者间接的后果及损失，均由使用者本人负责，淮橘安全及文章作者不为此承担任何责任。  
  
  
现在只对常读和星标的公众号才展示大图推送，建议大家能把  
“  
**设为星标**  
”，  
否则可能就看不到了啦  
！公众号会经常分享一些0day，1day，工具供大家学习  
  
  
**0x01 简介**  
  
  
APIDetector 是一款功能强大且高效的工具，旨在测试各种子域中暴露的 Swagger 端点，具有检测误报的独特智能功能。它对于从事 API 测试和漏洞扫描的安全专业人员和开发人员特别有用。  
  
  
**0x02 工具使用**  
  
### 用法  
  
使用命令行运行 APIDetector。以下是一些使用示例：  
- 常见用法，使用 Chrome 用户代理扫描 30 个线程的子域列表，并将结果保存在文件中：  
```
```  
  
  
- 要扫描单个域：  
```
```  
  
  
- 要扫描一个文件中的多个域：  
```
```  
  
  
- 要指定输出文件：  
```
```  
  
  
- 要使用特定数量的线程，请执行以下操作：  
```
```  
  
  
- 要同时使用 HTTP 和 HTTPS 协议进行扫描：  
```
```  
  
  
- 要在安静模式下运行脚本（禁止详细输出），请执行以下操作：  
```
```  
  
  
- 要使用自定义用户代理运行脚本，请执行以下操作：  
```
```  
  
  
### 选项  
- -d  
、 ：要测试的单个域。--domain  
  
- -i  
， ：包含要测试的子域的输入文件。--input  
  
- -o  
， ：要将有效 URL 写入的输出文件。--output  
  
- -t  
， ：用于扫描的线程数（默认值为 10）。--threads  
  
- -m  
、 ：测试 HTTP 和 HTTPS 协议。--mixed-mode  
  
- -q  
、：禁用详细输出（默认模式为详细）。--quiet  
  
- -ua  
， ：请求的自定义 User-Agent 字符串。--user-agent  
  
  
- ### APIDETECTOR 发现的每个端点的风险详细信息  
  
- 暴露 Swagger 或 OpenAPI 文档端点可能会带来各种风险，主要与信息泄露有关。下面是基于潜在风险级别的有序列表，将相似的端点组合在一起 APIDetector 扫描：  
  
- #### 1. 高风险端点（直接 API 文档）：  
  
- 端点：  
  
- '/swagger-ui.html'  
, , , , , , , , ,'/swagger-ui/''/swagger-ui/index.html''/api/swagger-ui.html''/documentation/swagger-ui.html''/swagger/index.html''/api/docs''/docs''/api/swagger-ui''/documentation/swagger-ui'  
  
- 风险：  
  
- 这些端点通常提供 Swagger UI 界面，该界面提供所有 API 端点的完整概述，包括请求格式、查询参数，有时甚至是示例请求和响应。  
  
- 风险等级：高。暴露这些内容可让潜在攻击者详细了解您的 API 结构和潜在攻击媒介。  
  
- #### 2. 中高风险端点（API 架构/规范）：  
  
- 端点：  
  
- '/openapi.json'  
, , , , , , , , , , , ,'/swagger.json''/api/swagger.json''/swagger.yaml''/swagger.yml''/api/swagger.yaml''/api/swagger.yml''/api.json''/api.yaml''/api.yml''/documentation/swagger.json''/documentation/swagger.yaml''/documentation/swagger.yml'  
  
- 风险：  
  
- 这些端点提供原始 Swagger/OpenAPI 规范文件。它们包含有关 API 端点的详细信息，包括路径、参数，有时还包括身份验证方法。  
  
- 风险等级：中高。虽然它们比 UI 界面需要更多的解释，但它们仍然揭示了有关 API 的大量信息。  
  
- #### 3. 中等风险端点（API 文档版本）：  
  
- 端点：  
  
- '/v2/api-docs'  
, , , , , , , , , , , , , , ,'/v3/api-docs''/api/v2/swagger.json''/api/v3/swagger.json''/api/v1/documentation''/api/v2/documentation''/api/v3/documentation''/api/v1/api-docs''/api/v2/api-docs''/api/v3/api-docs''/swagger/v2/api-docs''/swagger/v3/api-docs''/swagger-ui.html/v2/api-docs''/swagger-ui.html/v3/api-docs''/api/swagger/v2/api-docs''/api/swagger/v3/api-docs'  
  
- 风险：  
  
- 这些端点通常引用特定于版本的文档或 API 说明。它们揭示了有关 API 结构和功能的信息，这可以帮助攻击者了解 API 的功能和潜在弱点。  
  
- 风险等级：中等。这些可能不如完整的文档或架构文件详细，但它们仍为攻击者提供了有用的信息。  
  
- #### 4. 低风险端点（配置和资源）：  
  
- 端点：  
  
- '/swagger-resources'  
, , , ,'/swagger-resources/configuration/ui''/swagger-resources/configuration/security''/api/swagger-resources''/api.html'  
  
- 风险：  
  
- 这些端点通常提供与 API 文档设置相关的辅助信息、配置详细信息或资源。  
  
- 风险等级：较低。它们可能不会直接透露 API 端点详细信息，但可以深入了解 API 文档的配置和设置。  
  
- ### 总结：  
  
- 最高风险：直接暴露交互式 API 文档接口。  
  
- 中高风险：公开原始 API 架构/规范文件。  
  
- 中等风险：特定于版本的 API 文档。  
  
- 降低风险：API 文档的配置和资源文件。  
  
**0x03 项目下载链接**  
  
下载链接：https://github.com/brinhosa/apidetector  
  
  
各位师傅关注下公众号，有什么需要的工具或需求可发给公众号，我看见了就会回复你们  
  
  
  
**0x04 星球介绍**  
  
  
**星球介绍**  
  
1.  
每个工作日我们都会定时推送近期高质量的  
1day  
，  
0day等  
。  
  
2.各位师傅欢迎加入，星球现在人越来越多了，后续价格也会持续上涨，各位师傅们，趁现在抓紧加入，后续有机会成为嘉宾，享受永久使用权哟！  
  
  
3.  
新年活动期间，星球价格仅仅59  
元  
，公众号回复“  
星球优惠劵  
”限时领取活动券享受更低价格。各位师傅  
后续价格将要恢复到99了，感兴趣的抓紧了哟  
  
  
  
  
  
  
