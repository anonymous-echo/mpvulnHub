#  swagger-api未授权访问漏洞及防治方法   
原创 EBCloud  EBCloud   2025-05-14 08:00  
  
Swagger是一款开源软件框架，专门用于设计、构建、文档化以及使用RESTful风格的Web服务。它通过提供交互式文档页面，极大地便利了开发者查看和测试API接口。然而，Swagger的这种便捷性也可能带来安全隐患，未经授权的访问可能会导致安全漏洞。本文将详细介绍如何解决Swagger API未授权访问漏洞问题。  
  
  
  
**＜01＞**  
  
**未授权访问漏洞基础概念**  
  
  
未授权访问漏洞是指未经授权的用户能够访问未受保护的资源或功能。在Swagger API的场景中，若缺乏有效的访问控制机制，攻击者可能会利用Swagger文档中展示的API接口及其参数信息，发现并利用那些未受保护的API，从而对系统造成潜在威胁。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/On3KpSicKJfBooKibia7sZsfnTexTRk9pfFmFN4DMicv8Swo0gsNxjqnoRdNSqLSGkIMh8vuRnRZLEyhJgiaEyr1XDA/640?wx_fmt=png "")  
  
为了解决Swagger API的未授权访问漏洞，可以采取以下措施：  
  
  
**1.身份验证与授权：**  
应部署合适的身份验证与授权机制，以严格限制对API的访问权限。例如，可采用API密钥、令牌或访问令牌等方式来核实用户身份，并根据身份授予相应的权限。  
  
**2.访问控制列表（ACL）：**  
创建和维护可访问API的用户列表，只允许在此列表中的用户访问API。这可以防止未经授权的用户通过Swagger API访问API端点。  
  
**3.API端点限制：**  
限制对敏感或特权API端点的访问。例如，只允许具有特定权限的用户或角色访问这些端点。  
  
**4.API文档安全：**  
确保Swagger API文档本身是受保护的，并且只有经过身份验证和授权的用户才能访问。这可以防止攻击者通过查看Swagger文档来发现未授权的API。  
  
**5.定期漏洞扫描：**  
定期对API进行漏洞扫描和安全性测试，以便及时发现和修复任何可能存在的未授权访问漏洞。  
  
  
  
**＜02＞**  
  
**常见Swagger未授权访问地址**  
  
  
下面的路径就是常见的Swagger未授权访问泄露路径，攻击者通常通过bp抓包，然后再对该接口路径进行爆破。  
  
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
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/On3KpSicKJfBooKibia7sZsfnTexTRk9pfFXvvpsjMXQxr84AWbreOp3SSibqegsu5HkTYzKkjW2dmmyMkQ3ibbFwbw/640?wx_fmt=png "")  
  
/actuator接口下面经常会有信息泄露。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/On3KpSicKJfBooKibia7sZsfnTexTRk9pfF2GYc4PNCuG3rQUZBAJ7RiatwYV0ejsjcnuTBlrWJgSwnmayr5s2dhtw/640?wx_fmt=png "")  
  
/actuator/env目录账号密码泄露.  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/On3KpSicKJfBooKibia7sZsfnTexTRk9pfF4lMfgCMXyUrm5KxW6LmwXYZTPbt7aWYJX0RsCwfmEwJSwVXIfe0Xkg/640?wx_fmt=png "")  
  
  
  
**＜03＞**  
  
**在SpringBoot项目中进行配置防止未授权访问**  
  
  
在 SpringBoot 中，进行以下配置可以解决Swagger API的未授权访问漏洞：  
  
**1、添加Swagger依赖：**  
在pom.xml文件中，添加Swagger的依赖项。  
```
<dependency>
    <groupId>io.springfox</groupId>
    <artifactId>springfox-swagger2</artifactId>
    <version>2.9.2</version></dependency><dependency>
    <groupId>io.springfox</groupId>
    <artifactId>springfox-swagger-ui</artifactId>
    <version>2.9.2</version>
</dependency>
```  
  
**2、配置Swagger API文档：**  
在Spring Boot主配置类中，添加Swagger的配置。  
```
@Configuration@EnableSwagger2
publicclassSwaggerConfig{
    @Bean
    public Docket api(){
        returnnew Docket(DocumentationType.SWAGGER_2)
            .select()
            .apis(RequestHandlerSelectors.basePackage("com.example.controller"))
            .paths(PathSelectors.any())
            .build();
    }
}
```  
  
启用Swagger文档，并配置它扫描@Controller注解的类，并生成API文档。  
  
**3、添加访问控制：**  
```
@Configuration@EnableSwagger2
publicclassSwaggerConfig{
    @Bean
    public Docket api(){
        returnnew Docket(DocumentationType.SWAGGER_2)
            .select()
            .apis(RequestHandlerSelectors.basePackage("com.example.controller"))
            .paths(PathSelectors.any())
            .build()
            .securitySchemes(Arrays.asList(apiKey()))
            .securityContexts(Arrays.asList(securityContext()));
    }

    private ApiKey apiKey(){
        returnnew ApiKey("apiKey", "api_key", "header");
    }

    private SecurityContext securityContext(){
        return SecurityContext.builder()
            .securityReferences(defaultAuth())
            .forPaths(PathSelectors.any())
            .build();
    }

    List<SecurityReference> defaultAuth(){
        AuthorizationScope authorizationScope = new AuthorizationScope("global", "accessEverything");
        AuthorizationScope[] authorizationScopes = new AuthorizationScope[1];
        authorizationScopes[0] = authorizationScope;
        return Arrays.asList(new SecurityReference("apiKey", authorizationScopes));
    }
}
```  
  
可以根据实际情况进行适当的修改，自定义访问控制的角色或权限。  
  
**4、配置Spring Security：**  
如果应用程序中使用了Spring Security，请确保其已正确配置，以合理地允许或拒绝对Swagger API的访问。例如，可以根据用户角色或权限来配置Spring Security规则，从而实现精准的访问控制。  
  
  
通过上述措施，可以有效保护Swagger API免受未授权访问漏洞的威胁，并建立起完善的访问控制机制。同时，还需要定期开展漏洞扫描和安全性测试，密切关注Swagger和Spring Boot的最新安全更新与建议，以确保系统的持续安全性。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/On3KpSicKJfBooKibia7sZsfnTexTRk9pfF99Wiaj0jpB6swic5RA8NMmxgm16KLlONSdSYPm7uicjoknXMWaz1EfvQA/640?wx_fmt=jpeg "")  
  
EBCloud  
  
**文章作者**  
丨王锐  
  
