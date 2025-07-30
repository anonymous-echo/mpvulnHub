#  【渗透工具】Swagger API 信息泄露漏洞 工具篇   
小C学安全  小C学安全   2024-11-20 03:29  
  
### Swagger API 信息泄露漏洞 工具篇  
- 免责申明  
  
- 简介  
  
- 默认路径  
  
- Swagger-hack工具  
  
- 整改建议  
  
- 下载链接  
  
- 关注公众号  
  
免责申明  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BkyJtnXQDAskLkV8WcVk4zic789oFWIMMyL9h3OmYBhJeP7DUeeEmoTZYqrHupR0S4gvsGDWuKxlpbuZQOcIkTQ/640?wx_fmt=png&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BkyJtnXQDAskLkV8WcVk4zic789oFWIMM4QE6MQeXibzDwsouMMmibdwVqiaicAPXQY2WJMnIU99VicedkIH1Vtzc1Sg/640?wx_fmt=png&from=appmsg "")  
  
本公众号的技术文章仅供参考，此文所提供的信息只为网络安全人员对自己所负责的网站、服务器等（包括但不限于）进行检测或维护参考，未经授权请勿利用文章中的技术资料对任何计算机系统进行入侵操作。利用此文所提供的信息而造成的直接或间接后果和损失，均由使用者本人负责。本文所提供的工具仅用于学习，禁止用于其他！！！  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BkyJtnXQDAskLkV8WcVk4zic789oFWIMMomVz7gteKGAT6wJv5iaAiada6E0BkPHhnuZqbx528BZ4H7rgqaJWAFng/640?wx_fmt=png&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BkyJtnXQDAskLkV8WcVk4zic789oFWIMMG6O2wcpAcicUIXjSHCfD1oTfOygb5P2haUuPqkRtrKRzErRyFKLSb9w/640?wx_fmt=png&from=appmsg "")  
  
  
  
简介  
  
Swagger是一个规范和完整的框架，用于生成、描述、调用和可视化 RESTful 风格的 Web 服务。总体目标是使客户端和文件系统作为服务器以同样的速度来更新。  
  
相关的方法，参数和模型紧密集成到服务器端的代码，允许API来始终保持同步。Swagger-UI会根据开发人员在代码中的设置来自动生成API说明文档，若存在相关的配置缺陷，攻击者可以未授权翻查Swagger接口文档，得到系统功能API接口的详细参数，再构造参数发包，通过回显获取系统大量的敏感信息。  
  
Swagger未开启页面访问限制，Swagger未开启严格的Authorize认证。‍  
  
  
默认路径  
  
swagger未授权访问地址默认路径  
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
/v2/api-docs
/v3/api-docs

```  
  
FOFA:  
```
"swagger/index.html"
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BkyJtnXQDAskLkV8WcVk4zic789oFWIMM5oUia8ZIPBcBMKlEV9vPibkp6mibjqs6jOX4N46cnCCICDN59XZa24Icg/640?wx_fmt=png&from=appmsg "")  
  
找到一个测试地址  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BkyJtnXQDAskLkV8WcVk4zic789oFWIMMsSf0icsVxx2DwsibpmPyCqpKHInd8JgKliagqeD8H3hXnGhicxlv439euw/640?wx_fmt=png&from=appmsg "")  
  
可以安装浏览器插件Swagger-UI![](https://mmbiz.qpic.cn/sz_mmbiz_png/BkyJtnXQDAskLkV8WcVk4zic789oFWIMM03AfUIyNYb0ZMEJbyufd41VUADIeaVXHkic8fjX31xBib7WXbBMrp4gg/640?wx_fmt=png&from=appmsg "")  
  
安装完成后会在Swagger接口泄露的一个站点上显示Authorize关键字，点击按钮可以输入认证信息。![](https://mmbiz.qpic.cn/sz_mmbiz_png/BkyJtnXQDAskLkV8WcVk4zic789oFWIMMqdNz4bJrajMva5FGZuZDKhfJLNun44ibCaDHkQhaTw0ureU2Fo7UXfg/640?wx_fmt=png&from=appmsg "")  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BkyJtnXQDAskLkV8WcVk4zic789oFWIMMCyuVlHKHU0ib4tbRF7F8PYoDXxMqAvCYBMrnqtNtVZzwHSKH0rBl11Q/640?wx_fmt=png&from=appmsg "")  
  
访问swagger/v1/swagger.json文件目录存在很多接口泄露  
  
Swagger-hack工具  
# 在测试Swagger API 信息泄露漏洞时，有的泄露接口特别多，每一个都手动去试根本试不过来 找到一个Swagger-hack工具，可以自动化访问所有接口  
```
python swagger-hack2.0.py -u
 "http://X.X.X.X/swagger/v0.0.0.0/swagger.json"
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BkyJtnXQDAskLkV8WcVk4zic789oFWIMMa1k01MB9ANfKX38AIG2rgtsuKhvdvbqa24dPXOXFClwv1WDaAibPfnA/640?wx_fmt=png&from=appmsg "")  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BkyJtnXQDAskLkV8WcVk4zic789oFWIMM02iavpiclnZM2k7d8GKdG1UcxibwOUCctd2L8gAWibaLkTvEd4qz4JicFgA/640?wx_fmt=png&from=appmsg "")  
#   
  
  
整改建议  
# 在生产节点禁用Swagger2，在maven中禁用所有关于Swagger包  
  
结合SpringSecurity/shiro进行认证授权，将Swagger-UI的URLs加入到各自的认证和授权过滤链中，当用户访问Swagger对应的资源时，只有通过认证授权的用户才能进行访问。  
```
swagger:  config:    # 开启身份认证功能    login: true    username: admin    password: admin
```  
  
结合nginx/Filter对对应的接口端点进行访问控制。enable = false 关闭  
```
public Docket createRestApi() {        return new Docket(DocumentationType.SWAGGER_2)                .apiInfo(apiInfo()).enable(false)                .select()                //为当前包路径                .apis(RequestHandlerSelectors.any())                .paths(PathSelectors.any())                .build();    }    
```  
  
下载链接  
# 关注公众号回复 ：“20241120”  
  
  
关注公众号  
  
              
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BkyJtnXQDAskLkV8WcVk4zic789oFWIMMnx6IGz12gDUyeYMk0pmS260riapeJKiaD72I2nreQou25iadsvKZNIpWg/640?wx_fmt=png&from=appmsg "")  
  
  
扫码关注  
  
**小C学安全**  
  
获取更多精彩内容  
  
  
**-END-**  
  
  
  
