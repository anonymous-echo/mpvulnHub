#  【漏洞通告】Apache Linkis多个安全漏洞通告   
深瞳漏洞实验室  深信服千里目安全技术中心   2023-04-12 20:08  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/w8NHw6tcQ5xMrhHS98ib8mR6UpDDic28ILt9A6GRno8Aiamlm9NyC6VtWjW6bs9npe0K74IekL4c1hQRw2KWPDflg/640?wx_fmt=gif "")  
  
**漏洞名称：**  
  
Apache Linkis多个安全漏洞  
  
**组件名称：**  
  
Apache Linkis  
  
**安全公告链接：**  
  
https://github.com/apache/linkis/releases  
  
https://linkis.apache.org/download/release-notes-1.3.2/  
  
**官方解决方案：**  
  
已发布  
  
  
  
  
**漏洞分析**  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/w8NHw6tcQ5xMrhHS98ib8mR6UpDDic28ILRoxmZXHoicopFusXkiawaicBUtkGJpocGNfZfL8DUvMmEfQ00A9oplSFQ/640?wx_fmt=gif "")  
  
**组件介绍**  
  
Apache Linkis 是一个开源的数据处理和调度平台，旨在为数据科学家、数据工程师和数据分析师提供一个统一的数据处理和调度平台。通过使用Linkis 提供的REST/WebSocket/JDBC 等标准接口，上层应用可以方便地连接访问MySQL/Spark/Hive/Presto/Flink 等底层引擎，同时实现统一变量、脚本、用户定义函数和资源文件等用户资源的跨上层应用互通，以及通过REST标准接口提供了数据源管理和数据源对应的元数据查询服务。  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/w8NHw6tcQ5xMrhHS98ib8mR6UpDDic28ILRoxmZXHoicopFusXkiawaicBUtkGJpocGNfZfL8DUvMmEfQ00A9oplSFQ/640?wx_fmt=gif "")  
  
**漏洞描述**  
  
  
近日，深信服安全团队监测到一则Apache Linkis官方发布安全更新的通告，共修复了5个安全漏洞。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/w8NHw6tcQ5xMrhHS98ib8mR6UpDDic28ILZHeogK7mS0m3YlRnicWoVjSFYlGEQicP7qhse0JVGn4Z2Hb4pjJjTypQ/640?wx_fmt=png "")  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/w8NHw6tcQ5xMrhHS98ib8mR6UpDDic28ILRoxmZXHoicopFusXkiawaicBUtkGJpocGNfZfL8DUvMmEfQ00A9oplSFQ/640?wx_fmt=gif "")  
  
**漏洞描述**  
  
  
1. Apache Linkis DatasourceManager模块反序列化漏洞(CVE-2023-29216)  
  
由于DatasourceManager模块没有对参数进行有效过滤，攻击者可利用该漏洞使用MySQL数据源和恶意参数配置新的数据源以触发反序列化漏洞，并执行远程代码，最终可获取服务器权限。  
  
  
2. Apache Linkis JDBC EngineCon反序列化漏洞(CVE-2023-29215)  
  
由于JDBC EengineConn模块中缺乏对参数的有效过滤，攻击者可利用该漏洞在JDBC EengineConn模块中配置恶意Mysql JDBC参数触发反序列化漏洞，并执行远程代码，最终可获取服务器权限。  
  
  
3. Apache Linkis publicsercice 模块文件上传漏洞(CVE-2023-27602)  
  
由于PublicService模块中缺乏对上传文件路径和文件类型的有效过滤，攻击者可利用该漏洞在PublicService模块中上传恶意文件，最终可获取服务器权限。  
  
  
4. Apache Linkis Mangaer模块远程代码执行漏洞(CVE-2023-27603)  
  
由于Manager模块中engineConn 缺乏对zip路径的检查，攻击者可利用该漏洞在Manager模块中engineConn上传恶意zip文件，解压后可能导致任意文件覆盖，最终可获取服务器权限。  
  
  
5. Apache Linkis Gateway模块身份验证绕过漏洞(CVE-2023-27987)  
  
由于Apache Linkis Gateway部署生成的token过于简单，攻击者可利用该漏洞获取默认token并绕过身份认证机制，最终登陆系统后台或泄漏敏感信息。  
  
  
  
**影响范围**  
  
  
Linkis 自2019年开源发布以来，已累计积累了700多家试用企业和1000多位沙盒试验用户，涉及金融、电信、制造、互联网等多个行业。许多公司已经将Linkis 作为大数据平台底层计算存储引擎的统一入口，和计算请求/任务的治理管控利器，因此漏洞影响力较大。  
  
  
**解决方案**  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/w8NHw6tcQ5xMrhHS98ib8mR6UpDDic28ILRoxmZXHoicopFusXkiawaicBUtkGJpocGNfZfL8DUvMmEfQ00A9oplSFQ/640?wx_fmt=gif "")  
  
**如何检测组件版本**  
  
  
检查Apache linkis编译安装时的pom.xml文件，搜索org.apache.linkis关键词查看version版本，如果version字段值低于1.3.2，则可能受漏洞影响。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/w8NHw6tcQ5xMrhHS98ib8mR6UpDDic28ILSiakzVGrR5gXtCNdAxw0S8lxSDSm0R91QcFOX7tWE3Q3YA3EDxkLiaEw/640?wx_fmt=png "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/w8NHw6tcQ5xMrhHS98ib8mR6UpDDic28ILRoxmZXHoicopFusXkiawaicBUtkGJpocGNfZfL8DUvMmEfQ00A9oplSFQ/640?wx_fmt=gif "")  
  
**官方修复建议**  
  
当前官方已发布最新版本，建议受影响的用户及时更新升级到最新版本。下载链接如下：  
  
https://github.com/apache/linkis/releases  
  
  
**参考链接**  
  
```
```  
  
  
  
**时间轴**  
  
  
  
**2023/4/12**  
  
深信服监测到Apache linkis官方发布安全补丁。  
  
  
**2023/4/12**  
  
深信服千里目安全技术中心发布漏洞通告。  
  
  
  
点击**阅读原文**，及时关注并登录深信服**智安全平台**，可轻松查询漏洞相关解决方案。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/w8NHw6tcQ5xMrhHS98ib8mR6UpDDic28ILEOBJa3HRibeWmIhFXucbasNXqFjLxCl5Dr6R8XVC9Be8MicxysdXJ4hw/640?wx_fmt=png "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/w8NHw6tcQ5xMrhHS98ib8mR6UpDDic28ILL5doHSU6IQqC9XMTOXcb8ibFic74yW7NbnXeicKVAEBSAoS0WdeiaIlTaA/640?wx_fmt=jpeg "")  
  
  
