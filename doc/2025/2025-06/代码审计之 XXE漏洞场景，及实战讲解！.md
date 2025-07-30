#  代码审计之 XXE漏洞场景，及实战讲解！  
 闪石星曜CyberSecurity   2025-06-09 08:08  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/9TyXeX23U8y1LReapictgxN75fEFrwcATlS5SSs6gVzm6m9IpA0VsV8zWFRocDx52niaibz4AhhBSYa1BUwyjib6Ew/640?wx_fmt=gif&from=appmsg "")  
  
声明：文章涉及网络安全技术仅作为学习，从事非法活动与作者无关！  
  
本篇为代码审计系列XXE漏洞理论篇第六篇，看完本篇你将掌握关于XXE漏洞的代码视角原理剖析、基础挖掘漏洞核心能力，看完如有技术错误欢迎评论区指正。  
- 基本概念  
  
- XML概念  
  
- DTD概念  
  
- DOCTYPE概念  
  
- 业务视角XML代码  
  
- 漏洞校验XML代码  
  
- 实战审计案例-JavaMelody组件  
  
  
  
**XXE漏洞**  
  
一  
  
基本概念  
  
        XML格式使用DTD用来约束其中元素的名称、属性，XML中有DOCTYPE标识。用来标记为外部加载DTD还是内部加载DTD，其中外部加载DTD可能会触发XXE漏洞，使用漏洞进行敏感信息探测。  
  
1.1XML概念  
  
XML (Extensible Markup Language)  
通俗来讲是一种特殊的数据交互的规范格式，与JSON相似。客户端可以使用使用XML格式数据提交给服务器识别、解析、做进一步业务处理，服务器也可以响应XML格式数据客户端进行响应。以下为XML示例：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/9TyXeX23U8y1LReapictgxN75fEFrwcATFDfdfnlcrSAibWXjS8cfuP5uQiaTBvbeib6GB54r6bhfxznFTH2icmnvDw/640?wx_fmt=png&from=appmsg "")  
  
  
1.2DTD概念  
  
DTD（Document Type Definition）  
是文档类型定义的缩写。它是一种用来定义XML文档结构的文本文件，用于描述XML文档中元素的名称、属性和约束关系。DTD可以帮助浏览器或其他应用程序更好地解析和处理XML文档。以下为DTD文件。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/9TyXeX23U8y1LReapictgxN75fEFrwcATAs1QKtYqzUnDrWvLp9hIqOdTdDuTEcFhm1FSyGmr4aicEVEcc0icKFNg/640?wx_fmt=png&from=appmsg "")  
  
1.3DOCTYPE概念  
  
DOCTYPE  
是 XML 文件中用于声明 DTD 的语法。它告诉解析器使用哪个 DTD 来验证 XML 文档的合法性。DOCTYPE可以引用内部 DTD 或外部 DTD，其中只有外部DTD才会引发XXE外部实体注入漏洞。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/9TyXeX23U8y1LReapictgxN75fEFrwcATUbLSDopaiab5xD4KVhIK7xg4RHVZGUq50gSF0kfo8USyqYwB1cDzFfQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/9TyXeX23U8y1LReapictgxN75fEFrwcATNricneFm0C9iajA5gg1O1nf6ic5od4PeRXgDHTYiaPOow7biaByZObjbyYA/640?wx_fmt=png&from=appmsg "")  
  
二  
  
业务视角DEMO代码  
  
DOM和SAX为原生自带的，JDOM、DOM4J和Digester需要引入第三方依赖库,常见的XML解析有以下几种方式  
- DOM解析  
  
- SAX解析  
  
- JDOM解析  
  
- DOM4J解析  
  
- Digester解析  
  
  
  
  
2.1DOM解析XML流程及Demo代码  
  
- 创建一个DocumentBuilderFactory对象  
  
- 创建一个DocumentBuilder对象  
  
- 通过DocumentBuilder的parse()方法加载XML  
  
- 遍历name和value节点  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/9TyXeX23U8y1LReapictgxN75fEFrwcATQwicNibqsY4BGjPJNbf0ia0jxfjXhD7aeP3KpNCnn8biaeNicibkjNZujxpg/640?wx_fmt=png&from=appmsg "")  
  
  
2.2SAX解析XML流程及Demo代码  
  
- 获取SAXParserFactory的实例  
  
- 获取SAXParser实例  
  
- 创建一个handler()对象  
  
- 通过parser的parse()方法来解析XML  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/9TyXeX23U8y1LReapictgxN75fEFrwcAT69HnuheCXv6vIpgudHria5K8BGoK0xfxY0LS27BdeibtVS66cf0bR8sg/640?wx_fmt=png&from=appmsg "")  
  
三  
  
 漏洞校验XML代码  
  
Java中的XXE支持sun.net.www.protocol里面的所有协议：http，https，file，ftp，mailto，jar，netdoc。核心使用关键词定位xml解析代码  
  
XMLReaderDocumentHelperXMLStreamReaderSAXParserSAXSourceTransformerFactorySAXTransformerFactorySchemaFactoryUnmarshallerXPathExpressionjavax.xml.parsers.DocumentBuilderjavax.xml.parsers.DocumentBuilderFactory  
  
    XXE漏洞限制：为了修复XXE漏洞并提高代码的安全性，可以采取以下措施：  
- 代码层面禁用外部实体解析  
  
- 使用安全的 XML 解析库  
  
- SpringBoot使用安全配置  
  
- 使用白名单限制外部实体加载内容  
  
  
  
3.1代码层面禁用外部实体解析  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/9TyXeX23U8y1LReapictgxN75fEFrwcATCqFGzFIPxgytzVSGoeOGI33oQbVYwXSPVUphpNMr9xnklkiaOOj41EA/640?wx_fmt=png&from=appmsg "")  
  
  
  
3.2使用安全的 XML 解析库  
  
OWASP ESAPI或JAXB。使用这些库可以降低 XXE 风险  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/9TyXeX23U8y1LReapictgxN75fEFrwcATgOqbRe3Ih01B3W5DribkT6K30XLtibiap8MLOlLIlzGgIxGJwAJa7BoiaA/640?wx_fmt=png&from=appmsg "")  
  
四  
  
JavaMelody实战审计案例  
  
此篇XXE为白盒审计，以JavaMelody1.74.0版本组件部署后从源代码视角到漏洞定位及抓包调试进行讲解。以下XXE审计思路：  
  
- 使用XML解析依赖  
  
- 未禁用外部实体解析  
  
4.1项目部署  
  
GitHub项目地址：https://github.com/javamelody/javamelody/wiki  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/9TyXeX23U8y1LReapictgxN75fEFrwcATEgDEI3adYnIO1y35LEAlZm8EFCd79Fp5WsYUb6zLYRg1ue3vUBX4CQ/640?wx_fmt=png&from=appmsg "")  
  
查看项目部署说明：POM.xml引入依赖，访问http://localhost:port/monitoring进入监控页面  
  
安装项目  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/9TyXeX23U8y1LReapictgxN75fEFrwcATDGUImA0ibYwgzkLCicVl404Wd09Oke7JPMby3waehoX0PxENDP3kSl9w/640?wx_fmt=png&from=appmsg "")  
  
    Idea直接按照步骤操作进行部署即可  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/9TyXeX23U8y1LReapictgxN75fEFrwcATqg56qR3xO1iapTcD4X7PTqH2D3h7wNLwxYpl6sMO4F39wG2lVR5ibibJA/640?wx_fmt=png&from=appmsg "")  
  
    成功启动项目  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/9TyXeX23U8y1LReapictgxN75fEFrwcAT48YyqfW4IjictvkMw0LcA5BAnJQngAwKH6jq9dfibB6IR9gPqXqYoUCA/640?wx_fmt=png&from=appmsg "")  
  
4.2JavaMelody组件源码分析  
  
组件中涉及两个jar包，其中以Javamelody-spring-boot-starter为配置入口其中Pom.xml引入Javamelody-core作为业务代码，优先分析Javamelody-core。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/9TyXeX23U8y1LReapictgxN75fEFrwcATonOIqs67Rgze4W5ia5rdNjd5uFNCeZRnRGzLwEhDiak3pzicueAFiaibTQw/640?wx_fmt=png&from=appmsg "")  
  
使用关键字搜索定位Xml使用方法，定位到PayloadNameRequestWrapper.java  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/9TyXeX23U8y1LReapictgxN75fEFrwcAT84IdtlXx4PCpYlz63jP8FU9cecprfRTg9Kwav7AkmIpQBmZZhxfW2g/640?wx_fmt=png&from=appmsg "")  
  
234行PayloadNameRequestWrapper类中parseSoapMethodName方法使用XMLInputFactory进行解析Xml文件，直接解析。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/9TyXeX23U8y1LReapictgxN75fEFrwcATaZpJbJjic78hHomLqsRwRM0IqCnQicJW7a8Ph0hII4SWF2pBcjsjRX9A/640?wx_fmt=png&from=appmsg "")  
  
需要找到调用接口以及查看是否之前存在XXE防护代码，查看层次结构层层查看  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/9TyXeX23U8y1LReapictgxN75fEFrwcATQYYX8R0lic7BfIXIAibXaHngicKicdZ0rKSLw2eOIpia5PoLwqiaMseCu91w/640?wx_fmt=png&from=appmsg "")  
  
104行PayloadNameRequestWrapper类的initialize方法主要是做了判断，需要HTTP请求头contentType = "application/soap+xml"或者"text/xml"并且"SOAPAction"不为空  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/9TyXeX23U8y1LReapictgxN75fEFrwcATEtSwYNveH7PsaiaKEDCD23hUjPAeGOXe4oOR2k40QscLQSicLYTxZWGA/640?wx_fmt=png&from=appmsg "")  
  
跟进getBufferedInputStream()方法，看样子是POST方式请求体Xml的内容  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/9TyXeX23U8y1LReapictgxN75fEFrwcATCAfFIpse0uGHIsQehZIJX00GIKHZwhwybuOO7mmz9t3axRh4PhSVWg/640?wx_fmt=png&from=appmsg "")  
  
继续查看调用关系MonitoringFilter.java中createRequestWrapper也是在做初始化操作  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/9TyXeX23U8y1LReapictgxN75fEFrwcATjQ3kMTUQlljF5W6KiaBdj22jDErWHz2GWiaSbPueaI5eiak8ib1IoorIqA/640?wx_fmt=png&from=appmsg "")  
  
  
继续查看调用关系还是在MonitoringFilter.java的doFilter方法，发现重写了doFilter  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/9TyXeX23U8y1LReapictgxN75fEFrwcATA9CVtfwvfwP5oW4YiaibNN9N0gJyXDlIIb8DEBHNqduOS9KSjCyXsRmA/640?wx_fmt=png&from=appmsg "")  
  
Javamelody-spring-boot-starter：定义了一个名为monitoringFilter的Spring Bean，用于注册JavaMelody的监控过滤器（MonitoringFilter），看到任意路由都会经过该Filter处理使用1.74.0版本JavaMelody组件的Web应用都可以利用XXE漏洞  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/9TyXeX23U8y1LReapictgxN75fEFrwcATsmxW0zHuprJkTXcvsqtiaibvFAfNicA9Qj6OVeKzmZibWDH8xYZetPyg8Q/640?wx_fmt=png&from=appmsg "")  
  
4.3漏洞测试  
  
4.3.1开启Web python服务  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/9TyXeX23U8y1LReapictgxN75fEFrwcATJMZBA8rSnibMuFkqFAdCbNy6O9vXIqXrSqptR0QHMsMB5ibjlPjfty0g/640?wx_fmt=png&from=appmsg "")  
  
4.3.2直接构造XXE参数进行成功HTTP加载  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/9TyXeX23U8y1LReapictgxN75fEFrwcATficUU3ibEjUSumEpXSp4qTq3kErPbsMibC1wdJwYfC6cqB069wv9SAgtw/640?wx_fmt=png&from=appmsg "")  
  
4.4漏洞修复  
  
查看javamelody修复记录  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/9TyXeX23U8y1LReapictgxN75fEFrwcATfQfdLDUuvicR5N0Wf13TjyGtdzlwotwtkb9zVhHKRygc0wRziaIkxBEQ/640?wx_fmt=png&from=appmsg "")  
  
END  
  
  
  
