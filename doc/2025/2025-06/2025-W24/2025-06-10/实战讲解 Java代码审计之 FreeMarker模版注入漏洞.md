#  实战讲解 Java代码审计之 FreeMarker模版注入漏洞  
 闪石星曜CyberSecurity   2025-06-10 08:38  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/9TyXeX23U8yoiaO8icQIR2sAJ64f376bhhTFXxssRKRibPrUny0o7hxaM7fec9hgzxk5uFSAKGyAQDCbNHFfnECww/640?wx_fmt=gif&from=appmsg "")  
  
本篇为代码审计系列SSTI服务器端模板注入漏洞理论篇-FreeMarker第八篇，看完本篇你将掌握关于FreeMarker模版注入漏洞的代码视角原理剖析、基础挖掘漏洞核心能力，看完如有技术错误欢迎评论区指正。  
  
文章引用了FreeMarker官方介绍：http://freemarker.foofun.cn/index.html  
- FreeMarker概念  
  
- FreeMarker引擎  
  
- FreeMarker模版  
  
- 业务视角FreeMarker流程  
  
- 漏洞视角FreeMarker漏洞原理及防范  
  
- OFCMS 实战审计案例  
  
  
  
**FreeMarker模版注入漏洞**  
  
一  
  
FreeMarker  
  
    FreeMarker由引擎+模版构成完整的业务流程，FreeMarker引擎加载Template+Javaobjects，Template模版为HTML模版。如下图所示：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/9TyXeX23U8yoiaO8icQIR2sAJ64f376bhhvzkiaszuEVxgxX5P0ncZxsHmSXXuGvmoHp7XyNtN8YyBtkpSaLYtEww/640?wx_fmt=png&from=appmsg "")  
  
  
1.1FreeMarker引擎  
  
    FreeMarker 是一款模板引擎:引擎用于加载FreeMarker模版与模版中的数据通过将模板文件与数据模型结合，生成最终的输出HTML内容。  
  
  
1.2FreeMarker模版  
  
    模板编写为FreeMarker Template Language (FTL)。后端业务代码准备数据在填充在已经固定的HTML模版中，比如数据库查询和业务运算，之后模板显示数据库查询的结果或运算的结果数据。模版中包含如下内容：  
  
文本：文本会照着原样来输出。  
  
插值：这部分的输出会被计算的值来替换。插值由${and}所分隔的(或者#{and}  
  
FTL标签：FTL标签和HTML标签很相似，但是它们却是给FreeMarker的指示， 而且不会打印在输出内容中。  
  
注释：注释和HTML的注释也很相似，但它们是由<#--和-->来分隔的。注释会被FreeMarker直接忽略， 更不会在输出内容中显示。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/9TyXeX23U8yoiaO8icQIR2sAJ64f376bhh8RGdbbd12lrDhdDicr9N9rHA4dlNmAE6v5gQzF7VeGVoibmAiboCTHpKQ/640?wx_fmt=png&from=appmsg "")  
  
二  
  
业务视角FreeMarker场景与流程  
  
FreeMarker使用场景如下  
- Web 开发  
：与 Spring MVC、Struts 等框架集成，生成动态 HTML 页面  
  
- 电子邮件模板  
：生成动态邮件内容  
  
- 配置文件生成  
：根据环境或需求生成配置文件  
  
- 代码生成工具  
：在开发工具中生成代码文件  
  
  
  
  
2.1FreeMarker使用流程  
  
- 引入FreeMarker模版  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/9TyXeX23U8yoiaO8icQIR2sAJ64f376bhhibRrC0V9cTmD1eMfuBcdlqOyicWicTHhbHjqJsiaJX3u7Gc261vMGgQw8Q/640?wx_fmt=png&from=appmsg "")  
  
- 引入FreeMarker配置  
:在SpringBoot中配置FreeMarkersrc/main/resources/application.properties  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/9TyXeX23U8yoiaO8icQIR2sAJ64f376bhhAn572BbpicK6QjFR5GkOTrIHnJWViaStA2PPvfAZ2sAkK6y82m0Wq4wA/640?wx_fmt=png&from=appmsg "")  
  
- 引入FreeMarker配置  
:如为Spring MVC使用中applicationContext.xml编写即可  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/9TyXeX23U8yoiaO8icQIR2sAJ64f376bhhXrCjlWVfpyIuFZlfkZPr6B1nfY8Ddpib784QS8okt9iaCoEZS1V3ibKww/640?wx_fmt=png&from=appmsg "")  
  
- 引入FreeMarker配置  
：如为其他Web框架初始化模版配置,创建Configuration实例进行配置  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/9TyXeX23U8yoiaO8icQIR2sAJ64f376bhhic8ibLlyuRGQXNuF2OPB6k6YcEbR09LjDNjKyblpriaIlVQubeLR2nyKg/640?wx_fmt=png&from=appmsg "")  
  
- FreeMarker模版文件  
：编写模版.ftl文件：(不一定非得是.ftl也可能是.html)  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/9TyXeX23U8yoiaO8icQIR2sAJ64f376bhhiccjh3pPtJaYAvb50oB5Z92oKZYvnmg4jb6S0F4vgqz1ph5icZ9NTEDg/640?wx_fmt=png&from=appmsg "")  
  
编写业务层代码：  
- 创建数据模型  
：可以使用 java.lang 和 java.util 包中的类，还有用户自定义的Java Bean来构建数据对象  
  
- 获取模版:  
freemarker.template.Template实例。典型的做法是从 Configuration 实例中获取一个Template 实例  
  
- 合并模版和数据模型  
：数据模型+模板=输出  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/9TyXeX23U8yoiaO8icQIR2sAJ64f376bhhyMhiaw9mp2psH0Nng6Y6uCzBZ2vpjemsG5ChIUyAduCMRhspbYzDiaVQ/640?wx_fmt=png&from=appmsg "")  
  
  
三  
  
 漏洞视角Freemarker模版原理及防范  
  
3.1漏洞原理  
  
    Freemarker模版注入漏洞属于SSTI类漏洞，对于模板注入漏洞成因是在模板引擎渲染模板  
  
文件时，由于模板文件中存在内建危险函数且可执行，模版引擎进行解析后造成的攻击  
  
  
  
3.2漏洞触发场景  
  
    触发Freemarker的漏洞的场景大致为：  
- 文件上传  
：用户的使用上传包含危险内建函数的FreeMarker模版，并且可访问渲染后的文件  
  
- 文件编辑  
：用户可以修改为包含内建函数的模版文件，访问该模版后造成的攻击  
  
  
  
  
  
3.3漏洞触发条件  
  
3.3.1上传or修改.ftl模版文件  
  
      添加模版、更新模版内容等功能可进行修改,其中FreeMarker已经内置的方法StringTemplateLoader下的putTemplate()方法  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/9TyXeX23U8yoiaO8icQIR2sAJ64f376bhhZbd1hfGeANdU9fIQyC2lwOtJXH62IlUu7L2HH3Y5GQZcmyWkPCfA9A/640?wx_fmt=png&from=appmsg "")  
  
 以下图片来源为FreeMarker官方文档(http://freemarker.foofun.cn/ref_builtins_expert.html#ref_builtin_new)  
  
api函数  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/9TyXeX23U8yoiaO8icQIR2sAJ64f376bhhuU9uvyqIPNrpAcOjKv3QW3C8Pcz3YysEMyuezfuoWRdkVlDoawl6GQ/640?wx_fmt=png&from=appmsg "")  
  
new 函数可以创建一个继承自 freemarker.template.TemplateModel 类的变量  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/9TyXeX23U8yoiaO8icQIR2sAJ64f376bhhib8WmficOPchFCsgBZJ68rIfxqBQFwTJUpWZPKt3uMiaamteZKCbibjdOg/640?wx_fmt=png&from=appmsg "")  
  
freemarker.template.utility包中存在三个符合条件的类，分别为Execute类、ObjectConstructor类、JythonRuntime类最终实现了TemplateModel类。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/9TyXeX23U8yoiaO8icQIR2sAJ64f376bhhnvyEnVPkNC82v0RoLetqSyAYepVK4o86FO3ib0SkN4O4FCib1anUMGaw/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/9TyXeX23U8yoiaO8icQIR2sAJ64f376bhh666ZK3644CFCod2cicsxm9hKkDBo1iawuBHria1N5USN6URiabsk6YN88g/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/9TyXeX23U8yoiaO8icQIR2sAJ64f376bhhC6iaVILHLBQx6c4ZFz6I89bkSt71On0icFuCvalu7Mj7BMGHb7pC2bVg/640?wx_fmt=png&from=appmsg "")  
  
3.3.2Freemarker模版漏洞定位关键词  
  
freemarker、<#assign>、<#include>、<#if>、<#list>、<#macro>  
  
四  
  
OfCms实战审计案例  
  
此篇OfCms为分析FreeMarker漏洞进行白盒与黑盒结合方式审计，通常模版文件上传、编辑等功能可能会存在模版注入漏洞。部署后从系统功能视角到源代码定位及抓包调试进行讲解。  
  
抓包使用内建函数测试即  
  
白盒审计流程  
：  
- 项目组件分析  
：Pom.xml引入模版引擎依赖  
  
- 框架分析  
：Spring、Spring Boot、其他框架渲染模版引擎配置对应关键词定位  
  
- 渲染模版  
：定位渲染文件是否可控  
  
- Poc测试  
：抓包使用内建函数测试即可  
  
黑盒审计流程  
：  
- 上传/编辑功能  
：是否可编辑前端模版文件  
  
- 接口定位源代码  
：查看模版文件是否存在过滤或转义等处理  
  
- Poc测试  
：定位渲染文件是否可控  
  
  
  
4.1OfCms漏洞项目部署  
  
Gitee:https://gitee.com/oufu/ofcms/repository/archive/V1.1.2.zip  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/9TyXeX23U8yoiaO8icQIR2sAJ64f376bhh2CCQwNpttOnu2BDfzdZtAOMlx4UgsVeojH5SZ6bbwbJOrndwFEN2Hg/640?wx_fmt=png&from=appmsg "")  
  
直接打开Pom.xml引入依赖即可，查看Web框架使用的jfinal而非Spring或SpringBoot  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/9TyXeX23U8yoiaO8icQIR2sAJ64f376bhhE6HHryBbgj5XpCIT9P7icPGZeicPQ3hicRNdHibqxxz2tGTjb7Cd3XY1SA/640?wx_fmt=png&from=appmsg "")  
  
FreeMarker显示2.3.21版本  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/9TyXeX23U8yoiaO8icQIR2sAJ64f376bhheNTCMdicBgpBHC894VB89yKGQwSLaaqn58XMTGo6hpf8fVLA7LjM4tQ/640?wx_fmt=png&from=appmsg "")  
  
导入数据库文件，并修改数据库账号密码，成功启动项目  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/9TyXeX23U8yoiaO8icQIR2sAJ64f376bhhTYEwictzfMc50lKqSpGnGk07exT3e4cRdy7A3lTDstl0b3vX5PcSmXw/640?wx_fmt=png&from=appmsg "")  
  
4.2白盒源代码漏洞分析  
  
jfinal白盒定位关键词  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/9TyXeX23U8yoiaO8icQIR2sAJ64f376bhhKncbJUVUR5uTaszDiaL3VoBK5ohmR9JIzbnE6NH5ibaVic2j8gb7wgxicA/640?wx_fmt=png&from=appmsg "")  
  
- TempleteUtile.java中用来初始化模版引擎，查看源代码后发现该process方法会进行模版引擎渲染  
  
process(String templatefile, Map<?, ?> param) 方法使用模板文件名和参数 map 生成字符串输出。处理模板后，去除 HTML/XML 中标签之间的空白字符。  
  
process(String templatefile, Map<String, Object> param, File file) 方法  
  
将模板处理结果写入指定的文件中，使用 UTF-8 编码保存  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/9TyXeX23U8yoiaO8icQIR2sAJ64f376bhhJCnDX8S4MsCMiac06NmObpVWL6oGgwOvabRDPcAzXxrTb9ianHbKlrxg/640?wx_fmt=png&from=appmsg "")  
  
templatefile注释来看为传入的模版文件并直接渲染，查看是否模版文件可控  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/9TyXeX23U8yoiaO8icQIR2sAJ64f376bhhdibsjesMmo5xldDum8WgPJfhkMgZr8LReF9t9Pl8Tml9NKd2T292yyQ/640?wx_fmt=png&from=appmsg "")  
  
向上查找参数均发现不可控，转换思路进行黑盒挖掘尝试  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/9TyXeX23U8yoiaO8icQIR2sAJ64f376bhhJV7uyBiatoNPuIU1oWKbpKU05opzzicra0bthgtxhmXMv3oPSPzeRPNA/640?wx_fmt=png&from=appmsg "")  
  
4.3黑盒项目功能触发漏洞分析  
  
往往很多漏洞黑盒要比白盒方便很多，因为功能非常明显找到模版文件保存功能  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/9TyXeX23U8yoiaO8icQIR2sAJ64f376bhhib6dHV6Pp7WibkGn4ByaJ1CLIiavAxIkQuRicpyIR2oQfOSKnsIDk71M8Q/640?wx_fmt=png&from=appmsg "")  
  
    抓包定位接口  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/9TyXeX23U8yoiaO8icQIR2sAJ64f376bhh1L3q4wiapnNRiaWaWxVl09xboabAZwYtcCK0zXBR29Cruiaib40AX1q1ww/640?wx_fmt=png&from=appmsg "")  
  
 功能定位分析：发现只有一个特殊符号转义但对保存为恶意模版文件并没起到作用  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/9TyXeX23U8yoiaO8icQIR2sAJ64f376bhhg2ZsyOIJtiakp6GtKfLArNsrSsB90IV889awuBXVjQVDIp06yLC305A/640?wx_fmt=png&from=appmsg "")  
  
确定模版文件参数：file_content_  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/9TyXeX23U8yoiaO8icQIR2sAJ64f376bhhkjqSsI0Z9d89WicNoSyRhzkcMsp3SCOBlD0HE7GPmibU3QjMbtRtprUg/640?wx_fmt=png&from=appmsg "")  
  
Payload插入，修改为恶意模版文件  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/9TyXeX23U8yoiaO8icQIR2sAJ64f376bhhQadvyxiaYpBZbD2jeM3v9rJTGzVibQXh1jjBPW0hiaiabrSbSlXLJc1jNg/640?wx_fmt=png&from=appmsg "")  
  
保存模版文件中，毫无过滤  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/9TyXeX23U8yoiaO8icQIR2sAJ64f376bhhKBLHflOIJlia7nHybjcculqWB1svdgWHe2UdYOfh4fNALiaMEXoOpoPw/640?wx_fmt=png&from=appmsg "")  
  
访问404页面，执行成功  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/9TyXeX23U8yoiaO8icQIR2sAJ64f376bhhnsSVY0GAibXrPzV9IlPMLtmBrmRaTDdVst8zoPmZanHnbmfjWqib3iaHA/640?wx_fmt=png&from=appmsg "")  
  
分析如何404模版文件解析流程  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/9TyXeX23U8yoiaO8icQIR2sAJ64f376bhhguNPeupordtV8MBjCpgkXcQHuhULAI1siawnSd7xm1VkPhJvYK4o4gQ/640?wx_fmt=png&from=appmsg "")  
  
向上追踪定位到FreeMarkerRender类：  
  
`FreeMarkerRender是一个基于 JFinal 框架的 FreeMarker 模板渲染器，主要功能如下：  
  
封装 FreeMarker 配置：通过静态变量 config初始化 FreeMarker 的配置；  
  
提供配置方法:setProperty()、setSharedVariable()、setProperties()用于设置模板参数和共享变量；  
  
模板路径设置:setTemplateLoadingPath()` 设置模板加载路径；  
  
初始化配置:init()方法完成模板引擎的各项基础设置（编码、异常处理、日期格式等）；  
  
渲染视图:render() 方法将数据模型与模板合并输出 HTML 到响应；  
  
内容类型控制:getContentType()返回默认文本类型为 HTML + 编码。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/9TyXeX23U8yoiaO8icQIR2sAJ64f376bhhnEBial2AujU4rp9CN04l61fcCFx0IftGTlibefk41LDaE7hibv1yaFib6g/640?wx_fmt=png&from=appmsg "")  
  
  
END  
  
  
  
