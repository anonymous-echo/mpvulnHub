#  【漏洞预警】Spring Data MongoDB SpEL表达式注入漏洞   
 SecPulse安全脉搏   2022-06-22 16:46  
  
##   
  
1. **通告信息**  
  
  
  
##   
  
近日，  
安识科技  
A-Team团队  
监测到一则   
Spring Data MongoDB SpEL存在表达式注入漏洞  
的信息，该漏洞的  
CVSSv3评分为8.2  
，  
漏洞编号：  
CVE-2022-22980  
，漏洞威胁等级：高危。  
Spring Data MongoDB应用程序在对包含查询参数占位符的SpEL表达式使用@Query或@Aggregation注解的查询方法进行值绑定时，如果输入未被过滤，则容易受到SpEL注入攻击。  
  
  
2. **漏洞概述**  
  
  
  
##   
  
CVE  
：  
CVE-2022-22980  
  
简述：  
Spring Data for MongoDB是 Spring Data 项目的一部分，该项目旨在为新的数据存储提供熟悉和一致的基于Spring的编程模型，同时保留存储的特定特征和功能。Spring Data MongoDB应用程序在对包含查询参数占位符的SpEL表达式使用@Query或@Aggregation注解的查询方法进行值绑定时，如果输入未被过滤，则容易受到SpEL注入攻击。  
  
  
3. **漏洞危害**  
  
  
  
##    
  
Spring Data MongoDB应用程序在对包含查询参数占位符的SpEL表达式使用@Query或@Aggregation注解的查询方法进行值绑定时，如果输入未被过滤，则容易受到SpEL注入攻击。  
  
  
4. **影响版本**  
  
  
  
##   
  
目前受影响的   
Spring Data MongoDB版本：  
  
Spring Data MongoDB 3.4.0  
  
Spring Data MongoDB 3.3.0 - 3.3.4  
  
以及其它旧的、不受支持的版本。  
  
  
5. **解决方案**  
  
  
  
##   
  
目前此漏洞已经修复，受影响用户可以升级到以下版本：  
  
Spring Data MongoDB 3.4.1或更高版本；  
  
Spring Data MongoDB 3.3.5或更高版本。  
  
  
下载链接：  
  
https://github.com/spring-projects/spring-data-mongodb/tags  
  
  
缓解措施：  
  
重写  
query 或aggregation声明，在表达式中使用参数引用（"[0]"而不是"?0"）；  
  
在调用查询方法前对参数进行过滤；  
  
通过具有受限  
QueryMethodEvaluationContextProvider的BeanPostProcessor重新配置repository factory bean。  
  
  
注：当满足以下任一条件时，则不受此漏洞影响：  
  
l  
@Query或@Aggregation注解方法不包含表达式；  
  
l  
@Query或@Aggregation注解方法不使用表达式中的参数占位符语法；  
  
l  
过滤了用户提供的输入；  
  
l  
存储库配置为使用限制  
SpEL使  
用的  
QueryMethodObservationContextProvider。  
  
  
6. **时间轴**  
  
  
  
##    
  
【  
-  
】  
202  
2  
年  
0  
6  
月  
20  
日   
安识科技  
A  
-T  
eam团队监测到漏洞公布信息  
  
【  
-  
】  
2  
02  
2  
年  
0  
6  
月  
21  
日   
安识科技  
A-Team团队根据漏洞信息分析  
  
【  
-  
】  
2  
02  
2  
年  
0  
6  
月  
22  
日   
安识科技  
A-Team团队发布安全通告  
  
