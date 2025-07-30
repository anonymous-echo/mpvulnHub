#  edusrc 某中学Swagger接口泄露未授权漏洞挖掘   
 星悦安全   2024-11-29 04:52  
  
一、对目标资产进行信息收集  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/QkjvmbC1CD0zJ9hBlrElSv4ZqETGn3otgH8VHW1QuoOec3JMAbUyr0iaurJy4DPHBwUsDXiadJ3aha4CvJwyYVew/640?wx_fmt=png "")  
  
**打开目标网站发现只有一个智慧校园扫码登入、不能直接从登入界面下手，换个思路，先对其指纹和目录扫描均未发现任何有用的信息。**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/KA2c7J5ZOaou1Z9yYDXStN3uXKWFJCNvosPgp46HhUFnTXicVja7lvHzYmNibrmob2pU4PeJ7Ub36qzGjYj16lDg/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/QkjvmbC1CD0zJ9hBlrElSv4ZqETGn3otgH8VHW1QuoOec3JMAbUyr0iaurJy4DPHBwUsDXiadJ3aha4CvJwyYVew/640?wx_fmt=png "")  
  
**查看API接口，发现该目标存在其他资产**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/KA2c7J5ZOaou1Z9yYDXStN3uXKWFJCNvicxFticMs4eCyUD70ZCTmxWQUibCOXUesMlu4RhlqmibCT6rnGicUxm5F0w/640?wx_fmt=png&from=appmsg "")  
  
二、对Sping Boot框架进行漏洞利用  
  
![](https://mmbiz.qpic.cn/mmbiz_png/QkjvmbC1CD0zJ9hBlrElSv4ZqETGn3otgH8VHW1QuoOec3JMAbUyr0iaurJy4DPHBwUsDXiadJ3aha4CvJwyYVew/640?wx_fmt=png "")  
  
发现是Sping Boot框架，使用SpringBoot-Scan扫描是否存在信息泄露  
  
**Sping Boot框架识别技巧：**  
  
**1.网页标签的图标（favicon.ico）像一个绿色的树叶**  
  
**2.Whitelabel Error Page特有的报错信息**  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/KA2c7J5ZOaou1Z9yYDXStN3uXKWFJCNvcnXR1zUJ95wcNOyqfOOP7K6ZYibDmsiabBV1zxevvnwOr5gqk8duib0GA/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/KA2c7J5ZOaou1Z9yYDXStN3uXKWFJCNvcsDoVOG5K5LeKdVKjF3ogxdO3hIQZATUbrrhEGaz7VHHOVUcpOo3lw/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/QkjvmbC1CD0zJ9hBlrElSv4ZqETGn3otgH8VHW1QuoOec3JMAbUyr0iaurJy4DPHBwUsDXiadJ3aha4CvJwyYVew/640?wx_fmt=png "")  
  
**发现存在swagger接口泄露未授权访问，查看生成的API接口文档村长目标敏感信息泄露和对用户权限进行修改**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/KA2c7J5ZOaou1Z9yYDXStN3uXKWFJCNvGpaaTDxgSQmao7pCia6aBjDflM4ucw7iaibuwfVjvqU3MUE1DSSqvENSQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/KA2c7J5ZOaou1Z9yYDXStN3uXKWFJCNvZGiab5oZzBEjOVyW7FKcibBkGPkmNgc1tk2DVHoNIdj3AHOAkTwhRscg/640?wx_fmt=png&from=appmsg "")  
  
三、对本次src的总结  
  
![](https://mmbiz.qpic.cn/mmbiz_png/QkjvmbC1CD0zJ9hBlrElSv4ZqETGn3otgH8VHW1QuoOec3JMAbUyr0iaurJy4DPHBwUsDXiadJ3aha4CvJwyYVew/640?wx_fmt=png "")  
  
**SpringBoot-Scan是作用于探测Spring Boot的敏感信息泄露端点，并可以直接测试Spring的相关高危漏洞。**  
  
**工具作者：曾哥**  
  
**工具地址：https://github.com/AabyssZG/SpringBoot-Scan**  
  
**Swagger 未授权访问地址存在以下默认路径：**  
  
```
/api
/api-docs
/api-docs/swagger.json
/api.html
/api/api-docs
/api/apidocs
/api/doc
/api/swagger
/api/swagger-ui
/api/swagger-ui.html
/api/swagger-ui.html/
/api/swagger-ui.json
/api/swagger.json
/api/swagger/
/api/swagger/ui
/api/swagger/ui/
/api/swaggerui
/api/swaggerui/
/api/v1/
/api/v1/api-docs
/api/v1/apidocs
/api/v1/swagger
/api/v1/swagger-ui
/api/v1/swagger-ui.html
/api/v1/swagger-ui.json
/api/v1/swagger.json
/api/v1/swagger/
/api/v2
/api/v2/api-docs
/api/v2/apidocs
/api/v2/swagger
/api/v2/swagger-ui
/api/v2/swagger-ui.html
/api/v2/swagger-ui.json
/api/v2/swagger.json
/api/v2/swagger/
/api/v3
/apidocs
/apidocs/swagger.json
/doc.html
/docs/
/druid/index.html
/graphql
/libs/swaggerui
/libs/swaggerui/
/spring-security-oauth-resource/swagger-ui.html
/spring-security-rest/api/swagger-ui.html
/sw/swagger-ui.html
/swagger
/swagger-resources
/swagger-resources/configuration/security
/swagger-resources/configuration/security/
/swagger-resources/configuration/ui
/swagger-resources/configuration/ui/
/swagger-ui
/swagger-ui.html
/swagger-ui.html#/api-memory-controller
/swagger-ui.html/
/swagger-ui.json
/swagger-ui/swagger.json
/swagger.json
/swagger.yml
/swagger/
/swagger/index.html
/swagger/static/index.html
/swagger/swagger-ui.html
/swagger/ui/
/Swagger/ui/index
/swagger/ui/index
/swagger/v1/swagger.json
/swagger/v2/swagger.json
/template/swagger-ui.html
/user/swagger-ui.html
/user/swagger-ui.html/
/v1.x/swagger-ui.html
/v1/api-docs
/v1/swagger.json
/v2/api-docs/v3/api-docs
```  
  
  
SIMPLE STYLE  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/J94CGkoMibOg4F1Wg6KaHNfhjRU0MSZVQRJWz4aOYva2uLeB4areffHHJPLrshVVA5huh5NG9sXM2O9UU091u0g/640?from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/gwUPU4KGJTk6sV9HPom8saLlFuDwL1fItS4OJ7GCzRLXIE4icAqKHgJricj1XRcFN7k3CKQR2kYzWyrozUZRIdww/640?from=appmsg "")  
  
**免责声明:文章中涉及的程序(方法)可能带有攻击性，仅供安全研究与教学之用，读者将其信息做其他用途，由读者承担全部法律及连带责任，文章作者和本公众号不承担任何法律及连带责任，望周知！！!**  
  
‍  
  
