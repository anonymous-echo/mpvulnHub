#  GraphQL API 漏洞   
原创 【白】  白安全组   2025-03-28 22:55  
  
最近无所更新，很多新东西都在学习的过程中，还未整理成熟，不适合发文章误导大家，所以从库存中，准备更新一个系列。  
# 前言  
  
GraphQL API漏洞是由于设计缺陷产生，比如，自省功能处于开启状态，使攻击者可以查询API来收集架构的信息。  
# 查找GraphQL端点  
  
我们测试GraphQLAPI之前，需要找到端点，由于GraphQL对所有请求都使用相同的端点，所以找到端点很有价值。  
## 如何发现端点  
### 1、BurpSuite  
  
使用bp在扫描过程中自动测试GraphQL端点，找到会引发找到GraphQL端点问题。（需要最新版才支持）  
### 2、通用查询  
  
如果发送query{__typename}到任何 GraphQL 端点  
  
它将{"data": {"__typename": "query"}}在其响应中的某个位置包含该字符串。这称为通用查询，是探测 URL 是否对应于 GraphQL 服务的有用工具。  
### 3、通用端点名称  
  
GraphQL 服务通常使用类似的端点后缀。测试 GraphQL 端点时，您应该尝试将通用查询发送到以下位置：  
```
/graphql
/api
/api/graphql
/graphql/api
/graphql/graphql
```  
  
如果这些常见端点没有返回 GraphQL 响应，您也可以尝试附加/v1到路径。  
  
**注：GraphQL服务通常对任何非GraphQL请求做出查询不存在或者错误的响应。**  
### 4、请求方法  
  
找到GraphQL端点最好的方式，就是bp设置post请求仅接收application/json方法。  
# 利用不安全参数  
  
如果API使用参数可以直接访问对象，就可能收到访问控制漏洞的影响。用户只需要提供正确的参数，就可以访问到一些未授权信息，成为IDOR  
# 如何发现GraphQL架构信息  
  
最好的方式是使用自省查询，自省是一个内置的GraphQL函数，可以让我们查询服务器以获取相关的架构信息。  
## 如何使用自省  
  
要使用自省来发现架构信息，需要查询该__schema字段。这个字段在所有查询的类型上都可用。我们可以使用burp进行查询  
  
我们使用BURP在记录中找到  
  
/graphql  
  
/api  
  
/api/graphql  
  
/graphql/api  
  
/graphql/graphql  
  
/graphql/v1  
  
找到着一些页面，我们可以发送到重发器，最新版的bp可以在其中找到GraphQL  
  
![](https://mmbiz.qpic.cn/mmbiz_png/1AUjJ6HpTUZuUXKBmtmbo4hicAuib3KTPcpPjIPfOw86FJiaKsWVkHT1dres73VTbM0b8xAzkSlA2NSvviaAf9291A/640?wx_fmt=png&from=appmsg "")  
## 自省启动了但查询未运行  
  
如果启用了自省但上述查询未运行，尝试从查询结构中删除onOperation、onFragment和指令。许多端点不接受这些指令作为自省查询的一部分，通过删除它们，通常可以更成功地进行自省。  
  
  
  
后续还会继续更新该漏洞类型相关的学习哦！  
  
