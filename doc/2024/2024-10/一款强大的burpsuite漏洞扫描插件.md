#  一款强大的burpsuite漏洞扫描插件   
 黑白之道   2024-10-19 09:20  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/3xxicXNlTXLicwgPqvK8QgwnCr09iaSllrsXJLMkThiaHibEntZKkJiaicEd4ibWQxyn3gtAWbyGqtHVb0qqsHFC9jW3oQ/640?wx_fmt=gif "")  
  
### 目前功能  
1. 1. fastjson扫描  
  
1. 2. 权限绕过扫描  
  
1. 3. 未授权检测扫描  
  
1. 4. sql注入检测  
  
1. 5. 多层级路由扫描  
  
1. 6. 工具调用  
  
1. 7. log4j检测  
  
1. 8. 复杂数据提交  
  
1. 9. 一键生成nuclei模板  
  
1. 10. 生成指定kb大小的随机字符串  
  
1. 11. 代理池功能  
  
1. 12. 子域名收集(复刻https://github.com/Acmesec/Sylas)  
  
### 使用说明  
  
请使用mvn clean package  
进行编译打包,生成的jar包在target/目录下  
  
请使用mvn clean package  
进行编译打包,生成的jar包在target/目录下  
  
请使用mvn clean package  
进行编译打包,生成的jar包在target/目录下  
  
皆可通过使用鼠标右键菜单,进行调用  
  
### 功能说明  
## fastjson扫描  
  
![](https://mmbiz.qpic.cn/mmbiz_png/bMyibjv83iavzJKyxAJ1F8vOibRhugxJsvw9g1wRG7THoibJicE5WxoBWjvzlGnQaUZzZx3lZdIZhpzo7iaVNSibPTzjg/640?wx_fmt=png&from=appmsg&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
> 使用前请先在配置面板配置dns,ip并点击保存  
  
1. 1. 通过鼠标右键菜单,扫描dns,jndi,回显,报错等  
  
1. 2. dns扫描可以在数据库配置,type为dns,需要在替换dns域名的地方填写FUZZ,并在FUZZ前填写一个字符,如a.FUZZ,主要是为了区别  
  
1. 3. jndi扫描可以在数据库配置,type为jndi,需要在替换jndi的地方填写FUZZ,jndi扫描会让你选择是使用dns还是ip  
  
1. 4. 回显扫描可以在数据库配置,type为echo,需要你填写执行的命令,默认是在请求头加Accept-Cache字段,响应是在响应头Content-auth字段  
  
1. 5. 回显支持tomcat,spring等回显,  
  
1. 6. dns探测使用的f0ng师傅的测试payload,感谢f0ng师傅  
  
## 权限绕过  
1. 1. 通过给uri中加入特殊字符绕过权限  
  
1. 2. 通过给header中加入字段绕过权限  
  
1. 3. 添加accept头进行绕过  
  
## 未授权检测  
> 使用前请先在面板设置相关参数值  
  
1. 1. 通过替换低权限用户的cookie,来判断是否存在未授权  
  
1. 2. 通过删除用户的cookie,来判断是否存在未授权  
  
1. 3. 支持被动扫描  
  
## sql注入检测  
> 使用前请先在面板设置相关参数值  
  
1. 1. 通过添加特殊字符,来判断是否存在sql注入  
  
1. 2. sql注入支持get,post,cookie,json等多种方式  
  
1. 3. json注入支持多层级json注入,一次性替换所有参数  
  
## 工具调用  
  
> 使用前请先在面板设置相关参数值,并点击保存  
  
1. 1. 通过添加常用功能,来调用工具  
  
1. 2. {host} 会被替换为当前请求的host  
  
1. 3. {url} 会被替换为当前请求的url  
  
1. 4. {request} 会保存当前数据包到用户名目录的./gather/目录下,进行调用  
  
1. 5. 此处生成文件有bug,每次右击的时候都会生成一个文件,请使用配置面板的删除req缓存文件进行删除  
  
## log4j检测  
  
1. 1. 支持原始payload或者通用payload,原始payload需要自己填写,通用payload会自动替换dnslog-url  
  
1. 2. 可通过勾选dns选择是dnslog地址,否则为ip,替换参数为dnslog-url  
  
1. 3. 支持get,post,json,header等多种方式  
  
1. 4. 支持被动扫描  
  
## 复杂数据提交  
1. 1. 此功能主要是为了解决burp提交如序列化数据时,编码转义的问题  
  
1. 2. 请将数据进行base64后,放在<datab64></datab64>  
中,然后点击提交即可  
  
## 一键生成nuclei模板  
1. 1. 在request面板使用右击填写相关数据即可生成nuclei模板  
  
## 路由扫描  
1. 1. 此功能主要是为了解决多层级路由扫描问题  
  
1. 2. 支持解析表达式如下,等于或者不等于,小括号内的优先级最高,层级只支持2层 ``` code=200 body="hello" title="druid" headers="Content-Type: application/json"  
  
code=200 && body="hello" code!=200 && (body="hello" || title="druid")  
  
**项目地址：**  
  
https://github.com/kN6jq/gatherBurp  
  
> **文章来源：乌雲安全**  
  
  
  
黑白之道发布、转载的文章中所涉及的技术、思路和工具仅供以安全为目的的学习交流使用，任何人不得将其用于非法用途及盈利等目的，否则后果自行承担！  
  
如侵权请私聊我们删文  
  
  
**END**  
  
  
