#  详细剖析某erp漏洞   
Dili  白帽子左一   2024-02-03 12:01  
  
扫码领资料  
  
获网安教程  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CBJYPapLzSFbaUgVwdsriauB77CgQS8lyBNAxtx9IMqJQdhuuoITunu8A5Gp7kFjF7BvEXSaLMuDTYhnu7Nicghg/640?wx_fmt=png&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/b96CibCt70iaaJcib7FH02wTKvoHALAMw4fchVnBLMw4kTQ7B9oUy0RGfiacu34QEZgDpfia0sVmWrHcDZCV1Na5wDQ/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
# 深入学习Java代码审计技巧—详细剖析某erp漏洞  
## 简介  
  
对于Java代码审计，主要的审计步骤如下：  
- 确定项目技术框架、项目结构  
  
- 环境搭建  
  
- 配置文件的分析：如pom.xml、web.xml等，特别是pom.xml，可以从组件中寻找漏洞  
  
- Filter分析：Filter是重要的组成部分，提前分析有利于把握项目对请求的过滤，在后续漏洞利用时能够综合分析  
  
- 路由分析：部分项目请求路径与对用的controller方法不对应，提前通过抓包调试分析，了解前端请求到后端方法的对应关系，便于在后续分析中更快定位代码  
  
- 漏洞探测  
  
- 探测之前可借用工具辅助分析，如codeql、fortify、Yakit、BP等  
  
- SQL注入分析、RCE分析可先从代码入手，通过关键API及特征关键字来进行逆向数据流分析，从sink到source，判断参数是否可控  
  
- XSS、文件上传等漏洞适合正向数据流分析，由于存储型XSS数据流断裂，从代码层面不好将两条数据流联系起来，可以通过前端界面的测试，找到插入口和显示处性质一样的点，在通过后端代码分析，构造出可利用的payload  
  
- 逻辑漏洞这类也是从前端入手比较好处理，后端代码庞大难以定位  
  
个人观点，仅供参考  
## 文件结构分析  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CBJYPapLzSFORNQzTB9tr7aVg8XvxscCLCvrxZgqo37K9p6xzIK7SPiaxA6fRToIzm79UtS7pHk3Pm4T5ByE6pA/640?wx_fmt=png&from=appmsg "")  
  
在审计项目之前，先了解项目的结构  
- src/main/java：存放java核心代码，里面包含controller、service、filter、dao等，还包括主函数ErpApplication  
  
- src/main/resources：包含mybatis配置文件，properties等  
  
- erp_web：里面存放的是该网站的html、css及js文件  
  
- docs：包含数据库文件及文档文件等  
  
- test：项目的测试目录  
  
- pom.xml：项目的依赖配置  
  
## 环境搭建  
  
**数据库创建**：  
```
```  
  
**项目启动**：  
  
application.properties文件中配置数据库连接信息及server和port，启动主类ErpApplication.java即可  
## 配置文件分析  
  
在对项目开始审计之前，需要先了解其配置文件  
- application.properties：Spring的全局配置文件，里面包含server的ip及port，同时还有数据库连接信息，在环境搭建时可修改  
  
- pom.xml：项目的组件依赖，审计开始前先了解依赖的组件并判断是否存在对应组件版本的漏洞，这也可以是漏洞挖掘的第一步  
  
**依赖fastjson**  
```
```  
  
1.2.55版本存在反序列化漏洞，现在需要寻找利用点，全局搜索parseObject方法  
  
- ![](https://mmbiz.qpic.cn/sz_mmbiz_png/CBJYPapLzSFORNQzTB9tr7aVg8XvxscCVP3iaetXCPJTdR6znhWPMWib0AloEaXicezwYdzBYhTH2V4dYkPS8C9Ow/640?wx_fmt=png&from=appmsg "")  
  
猜测search可能可控，进入分析  
```
```  
  
查看getInfo函数的调用处，比较多，一个一个筛选，这里选择UserComponent.java中的getUserList方法进行分析  
```
```  
  
逐层向上调用分析，可以得知在ResourceController.java中调用select，即search参数可控  
```
```  
  
根据路由分析，这里的apiName为user，这样能够寻找到UserComponent里的select方法  
  
**测试**  
  
抓包设置payload  
```
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CBJYPapLzSFORNQzTB9tr7aVg8XvxscCeJm6dTmDngdkq6dv6zDmK9ULibRnKTXic8L02hUfXoYCjHUC7BX2vFqQ/640?wx_fmt=png&from=appmsg "")  
  
收到DNS请求，证明漏洞存在  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CBJYPapLzSFORNQzTB9tr7aVg8XvxscCykOB8FWY8B5LZpf7eqwJKFK5MzjHcu5yN9FA1icvTWhPDQ5yfDdqAHA/640?wx_fmt=png&from=appmsg "")  
  
接下来可以进行LDAP注入，但是需要确定AutoType是否开启  
  
可以通过以下代码开启  
```
```  
  
但是在实际测试的过程中，没有开启可以通过mysql服务来打  
  
payload：  
```
```  
  
**依赖log4j**  
```
```  
## Filter分析  
  
在项目中只存在一个Filter类，即LogCostFilter，观察其doFilter方法  
```
```  
  
根据对init方法的分析可知，ignoredUrls为[.css，.js，.jpg，.png，.gif，.ico]，allowUrls为[/user/login，/user/registerUser，/v2/api-docs]  
  
先看verify方法  
```
```  
  
将ignoredUrls中的逐个元素拼接成正则表达式后与当前url进行匹配，匹配成功即返回true，例如第一个元素形成的正则表达式为^.*.css.*$，即只要包含ignoredUrls中的任意一个元素即可在不登录的情况下访问  
  
在白名单过滤中，只要请求url中以/user/login、/user/registerUser、/v2/api-docs开头即不需要登陆即可访问  
## 路由分析  
  
大部分请求路径都包含在Controller文件夹中，这里有一个特殊的类，即ResourceController.java，它的请求路径中包含{apiName}，代码中使用CommonQueryManager.java类对其进行处理，以select方法为例：  
```
```  
  
configComponentMap存放的是Component类，即如图所示：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CBJYPapLzSFORNQzTB9tr7aVg8XvxscCmqTTcI0B6SB0P65q6mG8BpXDoDv3mEgQZ6dnorxoLficPzNibGWAkiamw/640?wx_fmt=png&from=appmsg "")  
  
具体可通过调试得到，这样通过apiname（首字母大写）+ Component即得到处理的对应类，从该类中选择select方法  
## SQL注入  
### 审计关键点  
- 重点关注创建查询的函数如 createQuery()、createSQLQuery()、createNativeQuery()。  
  
- 定位SQL语句上下文，查看是否有参数直接拼接，是否有对模糊查询关键字的过滤。  
  
- 是否使用预编译技术，预编译是否完整，关键函数定位setObject()、setInt()、setString()、setSQLXML()关联上下文搜索set*开头的函数。  
  
- Mybatis中搜索${}，因为对于like模糊查询、order by排序、范围查询in、动态表名/列名，没法使用预编译，只能拼接，所以还是需要手工防注入，此时可查看相关逻辑是否正确。  
  
- JPA搜索JpaSort.unsafe()，查看是否用实体之外的字段对查询结果排序，进行了SQL的拼接。以及查看EntityManager的使用，也可能存在拼接SQL的情况。  
  
### 注入点1  
#### 分析  
  
根据SQL注入代码审计经验，Mybatis框架下一般寻找mapper下的xml文件中的${}  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CBJYPapLzSFORNQzTB9tr7aVg8XvxscCDHDAUm2eoL09iaMkdppd7mjE129wgT0T1ZMArRB5y74jnDDPlH7DdtA/640?wx_fmt=png&from=appmsg "")  
  
挺多，先看这两个，对应在UserMapperEx.xml文件中，查询如下  
```
```  
  
一看like，只要这里两个参数可控，另外这里要查询的是一个数字，无其他可用的返回参数，即可能存在SQL注入，优先考虑时间盲注。找到对应的Mappper，即UserMapperEx  
```
```  
  
继续网上，找调用此方法的service，Ctrl+B找到上层UserService  
```
```  
  
继续Ctrl+B，这里有两个调用处，由于第一个UserController中调用的countUser两个参数均为null，暂时忽略，来到UserComponent  
```
```  
  
还是没有到Controller层，继续Ctrl+B，来到CommonQueryManager  
```
```  
  
继续往上，终于来到ResourceController  
```
```  
  
这里包含一个路径变量apiName，以apiName为名找对应的处理包，对应的包中存在Component类，根据上面分析，从UserComponent中来的，对应的是user包，因此apiName为user  
  
另外根据UserComponent类中的counts方法，在map中寻找userName和loginName，因此search参数包含userName和loginName  
  
正向数据链：/user/list——>ResourceController.getList——>CommonQueryManager.counts——>UserComponent.counts——>UserService.countUser——>UserMapperEx.countsByUser——>UserMapperEx.xml中id为countsByUser的查询  
  
同样的道理，在这个getList方法中，还有一个select查询，对应的数据链：  
  
/user/list——>ResourceController.getList——>CommonQueryManager.select——>UserComponent.select——>UserComponent.getUserList——>UserService.select——>UserMapperEx.selectByConditionUser——>UserMapperEx.xml中id为selectByConditionUser的查询  
```
```  
#### 测试  
  
触发界面  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CBJYPapLzSFORNQzTB9tr7aVg8XvxscCfiaAdLmHhgwXy3G1pUELgfFiaGcBJIlnbIZGaW64lZdKic5XevNiajnibRQ/640?wx_fmt=png&from=appmsg "")  
  
抓包  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CBJYPapLzSFORNQzTB9tr7aVg8XvxscCPtj80dNdnJQjIbTWHVYeOBtoCic8qBNhXm2pQk0UnspPFxfLJZpt1KQ/640?wx_fmt=png&from=appmsg "")  
  
这里的search参数包含了userName和loginName参数，后端的SQL语句如下：  
  
ID：com.jsh.erp.datasource.mappers.UserMapperEx.countsByUser  
```
```  
  
按照该SQL语句在login_name构造布尔盲注的payload：%'/**/And/**/SleeP(3)-  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CBJYPapLzSFORNQzTB9tr7aVg8XvxscCSlzEZwcxyibiaPd0JpfENMu7LSNFhEOuxyicMG2sITxrfqQp30d5d0DQA/640?wx_fmt=png&from=appmsg "")  
  
根据响应时间成功得到此处存在SQL注入  
  
对应的SQL语句：  
```
```  
  
接下来使用sqlmap跑就ok了，同样在userName参数也是一样的问题  
### 注入点2  
#### 分析  
  
关注一个没有like匹配的  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CBJYPapLzSFORNQzTB9tr7aVg8XvxscCnAH4n8rzrL9kpxQkAdT3WMtarSX2xyRGqYqOlrmIjewQvxPcKPKs8w/640?wx_fmt=png&from=appmsg "")  
  
关注红框这个，找到MsgMapperEx.xml文件，SQL查询如下  
```
```  
  
这里的status参数直接经过拼接，因此可能存在SQL注入，找对应的Mapper，MsgMapperEx.java的文件中：  
```
```  
  
Ctrl+B找被调用处，应该到Service层，即MsgService.java文件中：  
```
```  
  
继续往上到Controller层，来到MsgController.java  
```
```  
  
首先传入的status在本方法中没有进行任何过滤，同时根据前面分析，filter中也没有进行过滤，另外这里存在3种返回状态：  
- 查询语句报错，返回500，即获取数据失败  
  
- 根据SQL语句分析，查询得到的count为0，即拼接的条件为false  
  
- 查询结果count不为0，即where的条件为true，默认没有拼接条件  
  
根据分析，这里可以利用布尔盲注，前提需要在消息列表至少插入一条数据，当然时间注入也可以  
  
正向数据链：/msg/getMsgCountByStatus——>MsgController.getMsgCountByStatus——>MsgService.getMsgCountByStatus——>MsgMapperEx.getMsgCountByStatus——>MsgMapperEx.xml中id为getMsgCountByStatus  
#### 测试  
  
触发界面：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CBJYPapLzSFORNQzTB9tr7aVg8XvxscCXibJXkjAIkOeTOy83fQmEkcCBXDvq9dVLfMTicia7mbFMFxvUEk4pIJLA/640?wx_fmt=png&from=appmsg "")  
  
后台查询语句：  
```
```  
  
拼接payload：1'/**/and/**/1=1--、1'/**/and/**/1=2--  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CBJYPapLzSFORNQzTB9tr7aVg8XvxscCkFcFz9ZtMqdksCDE7zaAVLJhqzCrdsPTdu1bY0cWwVV2YQ55m9mmyg/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CBJYPapLzSFORNQzTB9tr7aVg8XvxscCmnXDfGrhVB1IztEfUJviacMP3ibDxibUNmszSefkScQHTVBNQdgWn8hqw/640?wx_fmt=png&from=appmsg "")  
  
后台SQL语句：  
```
```  
  
根据后面的条件是否成立返回的结果不一致，故存在布尔盲注，后面只需要使用sqlmap跑一遍即可  
  
还存在很多，不一一列举  
## 信息泄露  
### swagger-api文档信息泄露  
#### 关键点  
  
Swagger是一个规范和完整的框架，用于生成、描述、调用和可视化 RESTful 风格的 Web 服务。总体目标是使客户端和文件系统作为服务器以同样的速度来更新。  
  
spring项目中的配置参考：解决 Swagger API 未授权访问漏洞：完善分析与解决方案-阿里云开发者社区 (aliyun.com)  
  
相关路径，在实际测试工程中可用以下字典fuzz  
```
```  
#### 分析  
  
swagger配置类：Swagger2Config.java  
```
```  
  
在该类及配置文件中未进行任何的限制及访问控制和身份验证，另外在filter中也未进行身份判断，因此导致在未登录的情况下能够请求得到api接口  
#### 测试  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CBJYPapLzSFORNQzTB9tr7aVg8XvxscCCPxNFP9qVLIHfZxMTkfj7FZh4CiaaqUfnBicLhRHaszDN9XjobfNbyUw/640?wx_fmt=png&from=appmsg "")  
#### 修复  
1. 限制生成文档的请求处理程序：使用适当的 RequestHandlerSelectors 来选择只包含需要公开的接口，而不是使用 RequestHandlerSelectors.any()。  
  
1. 限制生成文档的路径：使用适当的 PathSelectors 来选择只包含需要公开的路径，而不是使用 PathSelectors.any()。  
  
1. 添加访问控制和身份验证：确保只有授权用户能够访问 Swagger API 文档。这可以通过配置身份验证和授权机制来实现，例如基于角色或令牌的访问控制。  
  
1. 定期审查和更新配置：定期审查 Swagger API 文档的配置，确保其与应用程序的安全需求保持一致，并经常更新以反映最新的安全要求。  
  
```
文章来源: https://xz.aliyun.com/t/13525
文章作者: Dili 
如有侵权，联系删除
```  
  
声明：⽂中所涉及的技术、思路和⼯具仅供以安全为⽬的的学习交流使⽤，任何⼈不得将其⽤于⾮法⽤途以及盈利等⽬的，否则后果⾃⾏承担。**所有渗透都需获取授权**  
！  
  
  
@  
  
**学习更多渗透技能！体验靶场实战练习**  
  
```
```  
  
  
  
  
