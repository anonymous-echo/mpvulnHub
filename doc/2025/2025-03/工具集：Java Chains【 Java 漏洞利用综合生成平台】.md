#  工具集：Java Chains【 Java 漏洞利用综合生成平台】   
wolven  风铃Sec   2025-03-01 01:20  
  
#### 工具介绍  
  
Java-Chains  
 是一个 Java Payload 生成与漏洞利用 Web 平台，便于广大安全研究员快速生成 Java Payload，以及对 JNDI 注入、MySQL JDBC 反序列化、JRMP 反序列化等漏洞进行方便快速测试，能够在一定程度上提高测试效率。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qGTEdaLg0HnJRW5aSuWdMUtHFickvEv0tD2QEr2t4ITTBrGT0Iribpzl6GxeLdibibyeJnv4blWFkzgUNicNwj5CYHw/640?wx_fmt=png&from=appmsg "")  
#### 模块介绍  
  
Java-Chains  
 含有以下六大模块  
#### 生成模块(Generate)  
  
JavaNativePayload  
: Java 反序列化原生 Payload 生成  
  
HessianPayload  
: Hessian1 反序列化 Payload 生成，并支持 HessianServlet 格式反序列化数据  
  
Hessian2Payload  
: Hessian2 反序列化 Payload 生成  
  
ShiroPayload  
: Shiro Payload 生成，在某些特殊环境下方便手动进行生成与测试  
- 支持自定义 AES KEY  
  
- 支持 AES GCM 模式  
  
- 支持插入 Base64 混淆字符  
  
OtherPayload  
：  
- CharsetJarConvet  
: 生成 charsets.jar 包，适用于 SpringBoot 下文件上传 RCE 场景  
  
- GroovyJarConvert  
: 生成 fastjson-groovy.jar 包，适用于 Fastjson 高版本下通过 Groovy 链加载特定格式 Jar 包实现 RCE）  
  
- SnakeyamlJarConvert  
: 生成 snakeyaml.jar 包，适用于 SnakeYaml 通过 SPI 加载特定格式 Jar 包实现 RCE  
  
- JDBCPayload  
: JDBC Payload 生成  
  
- H2 JDBC  
  
- PostgresSQL  
  
ExpressionPayload  
: 表达式 Payload 生成，本质上是将表达式加载字节码模板中的字节码部分进行替换，推荐手动实现  
- BcelConvert  
: BCEL 格式字节码生成  
  
- JsConvert  
: Oracle Nashorn JS 表达式加载字节码  
  
- VelocityConvert  
: Velocity 通过 bcel 来加载字节码  
  
BytecodePayload  
: 字节码生成  
- 例如可生成执行命令字节码、Sleep字节码、DNSLog字节码，注入内存马字节码，回显字节码、中间件探测字节码、写文件字节码、下载文件字节码  
  
- 支持自定义字节码版本  
  
- 支持自定义字节码类名  
  
- 支持生成 TemplatesImpl 字节码格式 - 实现 AbstractTranslet 接口  
  
- 支持使用 Class-Obf 进行字节码混淆  
  
XStreamPayload  
: XStream 数据生成，暂未全面测试，部分Payload无法使用  
  
本平台生成的 Payload 支持的一些混淆情况如下：  
  
<table><thead><tr style="box-sizing: border-box;break-inside: avoid;break-after: auto;border: 1px solid rgb(223, 226, 229);margin: 0px;padding: 0px;"><th style="box-sizing: border-box;padding: 6px 13px;font-weight: bold;border-width: 1px 1px 0px;border-top-style: solid;border-right-style: solid;border-left-style: solid;border-top-color: rgb(223, 226, 229);border-right-color: rgb(223, 226, 229);border-left-color: rgb(223, 226, 229);border-image: initial;border-bottom-style: initial;border-bottom-color: initial;margin: 0px;"><span cid="n2194" mdtype="table_cell" style="box-sizing: border-box;display: inline-block;min-width: 1ch;width: 215.896px;min-height: 10px;"></span></th><th style="box-sizing: border-box;padding: 6px 13px;font-weight: bold;border-width: 1px 1px 0px;border-top-style: solid;border-right-style: solid;border-left-style: solid;border-top-color: rgb(223, 226, 229);border-right-color: rgb(223, 226, 229);border-left-color: rgb(223, 226, 229);border-image: initial;border-bottom-style: initial;border-bottom-color: initial;margin: 0px;"><span cid="n2195" mdtype="table_cell" style="box-sizing: border-box;display: inline-block;min-width: 1ch;width: 173.083px;min-height: 10px;"><span md-inline="plain" style="box-sizing: border-box;"><span leaf="">JavaNativePayload</span></span></span></th><th style="box-sizing: border-box;padding: 6px 13px;font-weight: bold;border-width: 1px 1px 0px;border-top-style: solid;border-right-style: solid;border-left-style: solid;border-top-color: rgb(223, 226, 229);border-right-color: rgb(223, 226, 229);border-left-color: rgb(223, 226, 229);border-image: initial;border-bottom-style: initial;border-bottom-color: initial;margin: 0px;"><span cid="n2196" mdtype="table_cell" style="box-sizing: border-box;display: inline-block;min-width: 1ch;width: 145.844px;min-height: 10px;"><span md-inline="plain" style="box-sizing: border-box;"><span leaf="">HessianPayload</span></span></span></th><th style="box-sizing: border-box;padding: 6px 13px;font-weight: bold;border-width: 1px 1px 0px;border-top-style: solid;border-right-style: solid;border-left-style: solid;border-top-color: rgb(223, 226, 229);border-right-color: rgb(223, 226, 229);border-left-color: rgb(223, 226, 229);border-image: initial;border-bottom-style: initial;border-bottom-color: initial;margin: 0px;"><span cid="n2197" mdtype="table_cell" style="box-sizing: border-box;display: inline-block;min-width: 1ch;width: 156.177px;min-height: 10px;"><span md-inline="plain" style="box-sizing: border-box;"><span leaf="">Hessian2Payload</span></span></span></th></tr></thead><tbody><tr style="box-sizing: border-box;break-inside: avoid;break-after: auto;border: 1px solid rgb(223, 226, 229);margin: 0px;padding: 0px;"><td style="box-sizing: border-box;padding: 6px 13px;border: 1px solid rgb(223, 226, 229);margin: 0px;min-width: 32px;"><span cid="n2199" mdtype="table_cell" style="box-sizing: border-box;display: inline-block;min-width: 1ch;width: 215.896px;min-height: 10px;"><span md-inline="plain" style="box-sizing: border-box;"><span leaf="">随机集合脏数据填充</span></span></span></td><td style="box-sizing: border-box;padding: 6px 13px;border: 1px solid rgb(223, 226, 229);margin: 0px;min-width: 32px;"><span cid="n2200" mdtype="table_cell" style="box-sizing: border-box;display: inline-block;min-width: 1ch;width: 173.083px;min-height: 10px;"><span md-inline="plain" style="box-sizing: border-box;"><span leaf="">✅</span></span></span></td><td style="box-sizing: border-box;padding: 6px 13px;border: 1px solid rgb(223, 226, 229);margin: 0px;min-width: 32px;"><span cid="n2201" mdtype="table_cell" style="box-sizing: border-box;display: inline-block;min-width: 1ch;width: 145.844px;min-height: 10px;"><span md-inline="plain" style="box-sizing: border-box;"><span leaf="">✅</span></span></span></td><td style="box-sizing: border-box;padding: 6px 13px;border: 1px solid rgb(223, 226, 229);margin: 0px;min-width: 32px;"><span cid="n2202" mdtype="table_cell" style="box-sizing: border-box;display: inline-block;min-width: 1ch;width: 156.177px;min-height: 10px;"><span md-inline="plain" style="box-sizing: border-box;"><span leaf="">✅</span></span></span></td></tr><tr style="box-sizing: border-box;break-inside: avoid;break-after: auto;border: 1px solid rgb(223, 226, 229);margin: 0px;padding: 0px;background-color: rgb(248, 248, 248);"><td style="box-sizing: border-box;padding: 6px 13px;border: 1px solid rgb(223, 226, 229);margin: 0px;min-width: 32px;"><span cid="n2204" mdtype="table_cell" style="box-sizing: border-box;display: inline-block;min-width: 1ch;width: 215.896px;min-height: 10px;"><span md-inline="plain" style="box-sizing: border-box;"><span leaf="">垃圾类填充</span></span></span></td><td style="box-sizing: border-box;padding: 6px 13px;border: 1px solid rgb(223, 226, 229);margin: 0px;min-width: 32px;"><span cid="n2205" mdtype="table_cell" style="box-sizing: border-box;display: inline-block;min-width: 1ch;width: 173.083px;min-height: 10px;"><span md-inline="plain" style="box-sizing: border-box;"><span leaf="">✅</span></span></span></td><td style="box-sizing: border-box;padding: 6px 13px;border: 1px solid rgb(223, 226, 229);margin: 0px;min-width: 32px;"><span cid="n2206" mdtype="table_cell" style="box-sizing: border-box;display: inline-block;min-width: 1ch;width: 145.844px;min-height: 10px;"><span md-inline="plain" style="box-sizing: border-box;"><span leaf="">✅</span></span></span></td><td style="box-sizing: border-box;padding: 6px 13px;border: 1px solid rgb(223, 226, 229);margin: 0px;min-width: 32px;"><span cid="n2207" mdtype="table_cell" style="box-sizing: border-box;display: inline-block;min-width: 1ch;width: 156.177px;min-height: 10px;"><span md-inline="plain" style="box-sizing: border-box;"><span leaf="">✅</span></span></span></td></tr><tr style="box-sizing: border-box;break-inside: avoid;break-after: auto;border: 1px solid rgb(223, 226, 229);margin: 0px;padding: 0px;"><td style="box-sizing: border-box;padding: 6px 13px;border: 1px solid rgb(223, 226, 229);margin: 0px;min-width: 32px;"><span cid="n2209" mdtype="table_cell" style="box-sizing: border-box;display: inline-block;min-width: 1ch;width: 215.896px;min-height: 10px;"><span md-inline="plain" style="box-sizing: border-box;"><span leaf="">UTF-8 Overlong Encoding</span></span></span></td><td style="box-sizing: border-box;padding: 6px 13px;border: 1px solid rgb(223, 226, 229);margin: 0px;min-width: 32px;"><span cid="n2210" mdtype="table_cell" style="box-sizing: border-box;display: inline-block;min-width: 1ch;width: 173.083px;min-height: 10px;"><span md-inline="plain" style="box-sizing: border-box;"><span leaf="">✅</span></span></span></td><td style="box-sizing: border-box;padding: 6px 13px;border: 1px solid rgb(223, 226, 229);margin: 0px;min-width: 32px;"><span cid="n2211" mdtype="table_cell" style="box-sizing: border-box;display: inline-block;min-width: 1ch;width: 145.844px;min-height: 10px;"><span md-inline="plain" style="box-sizing: border-box;"><span leaf="">✅</span></span></span></td><td style="box-sizing: border-box;padding: 6px 13px;border: 1px solid rgb(223, 226, 229);margin: 0px;min-width: 32px;"><span cid="n2212" mdtype="table_cell" style="box-sizing: border-box;display: inline-block;min-width: 1ch;width: 156.177px;min-height: 10px;"><span md-inline="plain" style="box-sizing: border-box;"><span leaf="">✅</span></span></span></td></tr><tr style="box-sizing: border-box;break-inside: avoid;break-after: auto;border: 1px solid rgb(223, 226, 229);margin: 0px;padding: 0px;background-color: rgb(248, 248, 248);"><td style="box-sizing: border-box;padding: 6px 13px;border: 1px solid rgb(223, 226, 229);margin: 0px;min-width: 32px;"><span cid="n2214" mdtype="table_cell" style="box-sizing: border-box;display: inline-block;min-width: 1ch;width: 215.896px;min-height: 10px;"><span md-inline="plain" style="box-sizing: border-box;"><span leaf="">TC_RESET 填充</span></span></span></td><td style="box-sizing: border-box;padding: 6px 13px;border: 1px solid rgb(223, 226, 229);margin: 0px;min-width: 32px;"><span cid="n2215" mdtype="table_cell" style="box-sizing: border-box;display: inline-block;min-width: 1ch;width: 173.083px;min-height: 10px;"><span md-inline="plain" style="box-sizing: border-box;"><span leaf="">✅</span></span></span></td><td style="box-sizing: border-box;padding: 6px 13px;border: 1px solid rgb(223, 226, 229);margin: 0px;min-width: 32px;"><span cid="n2216" mdtype="table_cell" style="box-sizing: border-box;display: inline-block;min-width: 1ch;width: 145.844px;min-height: 10px;"><span md-inline="plain" style="box-sizing: border-box;"><span leaf="">❌</span></span></span></td><td style="box-sizing: border-box;padding: 6px 13px;border: 1px solid rgb(223, 226, 229);margin: 0px;min-width: 32px;"><span cid="n2217" mdtype="table_cell" style="box-sizing: border-box;display: inline-block;min-width: 1ch;width: 156.177px;min-height: 10px;"><span md-inline="plain" style="box-sizing: border-box;"><span leaf="">❌</span></span></span></td></tr></tbody></table>  
注：若想通过 UserCustomByteArrayFromXXX 提供自定义的Java序列化字节流数据来进行混淆，那么目前暂不支持使用随机集合与垃圾类插入混淆，这与混淆的实现有关，具体支持情况如下：  
  
<table><thead><tr style="box-sizing: border-box;break-inside: avoid;break-after: auto;border: 1px solid rgb(223, 226, 229);margin: 0px;padding: 0px;"><th style="box-sizing: border-box;padding: 6px 13px;font-weight: bold;border-width: 1px 1px 0px;border-top-style: solid;border-right-style: solid;border-left-style: solid;border-top-color: rgb(223, 226, 229);border-right-color: rgb(223, 226, 229);border-left-color: rgb(223, 226, 229);border-image: initial;border-bottom-style: initial;border-bottom-color: initial;margin: 0px;"><span cid="n2225" mdtype="table_cell" style="box-sizing: border-box;display: inline-block;min-width: 1ch;width: 296.583px;min-height: 10px;"></span></th><th style="box-sizing: border-box;padding: 6px 13px;font-weight: bold;border-width: 1px 1px 0px;border-top-style: solid;border-right-style: solid;border-left-style: solid;border-top-color: rgb(223, 226, 229);border-right-color: rgb(223, 226, 229);border-left-color: rgb(223, 226, 229);border-image: initial;border-bottom-style: initial;border-bottom-color: initial;margin: 0px;"><span cid="n2226" mdtype="table_cell" style="box-sizing: border-box;display: inline-block;min-width: 1ch;width: 448.417px;min-height: 10px;"><span md-inline="plain" style="box-sizing: border-box;"><span leaf="">JavaNativePayload(自定义序列化场景)</span></span></span></th></tr></thead><tbody><tr style="box-sizing: border-box;break-inside: avoid;break-after: auto;border: 1px solid rgb(223, 226, 229);margin: 0px;padding: 0px;"><td style="box-sizing: border-box;padding: 6px 13px;border: 1px solid rgb(223, 226, 229);margin: 0px;min-width: 32px;"><span cid="n2228" mdtype="table_cell" style="box-sizing: border-box;display: inline-block;min-width: 1ch;width: 296.583px;min-height: 10px;"><span md-inline="plain" style="box-sizing: border-box;"><span leaf="">随机集合混淆</span></span></span></td><td style="box-sizing: border-box;padding: 6px 13px;border: 1px solid rgb(223, 226, 229);margin: 0px;min-width: 32px;"><span cid="n2229" mdtype="table_cell" style="box-sizing: border-box;display: inline-block;min-width: 1ch;width: 448.417px;min-height: 10px;"><span md-inline="plain" style="box-sizing: border-box;"><span leaf="">❌</span></span></span></td></tr><tr style="box-sizing: border-box;break-inside: avoid;break-after: auto;border: 1px solid rgb(223, 226, 229);margin: 0px;padding: 0px;background-color: rgb(248, 248, 248);"><td style="box-sizing: border-box;padding: 6px 13px;border: 1px solid rgb(223, 226, 229);margin: 0px;min-width: 32px;"><span cid="n2231" mdtype="table_cell" style="box-sizing: border-box;display: inline-block;min-width: 1ch;width: 296.583px;min-height: 10px;"><span md-inline="plain" style="box-sizing: border-box;"><span leaf="">垃圾类插入</span></span></span></td><td style="box-sizing: border-box;padding: 6px 13px;border: 1px solid rgb(223, 226, 229);margin: 0px;min-width: 32px;"><span cid="n2232" mdtype="table_cell" style="box-sizing: border-box;display: inline-block;min-width: 1ch;width: 448.417px;min-height: 10px;"><span md-inline="plain" style="box-sizing: border-box;"><span leaf="">❌</span></span></span></td></tr><tr style="box-sizing: border-box;break-inside: avoid;break-after: auto;border: 1px solid rgb(223, 226, 229);margin: 0px;padding: 0px;"><td style="box-sizing: border-box;padding: 6px 13px;border: 1px solid rgb(223, 226, 229);margin: 0px;min-width: 32px;"><span cid="n2234" mdtype="table_cell" style="box-sizing: border-box;display: inline-block;min-width: 1ch;width: 296.583px;min-height: 10px;"><span md-inline="plain" style="box-sizing: border-box;"><span leaf="">UTF-8 Overlong Encoding</span></span></span></td><td style="box-sizing: border-box;padding: 6px 13px;border: 1px solid rgb(223, 226, 229);margin: 0px;min-width: 32px;"><span cid="n2235" mdtype="table_cell" style="box-sizing: border-box;display: inline-block;min-width: 1ch;width: 448.417px;min-height: 10px;"><span md-inline="plain" style="box-sizing: border-box;"><span leaf="">✅</span></span></span></td></tr><tr style="box-sizing: border-box;break-inside: avoid;break-after: auto;border: 1px solid rgb(223, 226, 229);margin: 0px;padding: 0px;background-color: rgb(248, 248, 248);"><td style="box-sizing: border-box;padding: 6px 13px;border: 1px solid rgb(223, 226, 229);margin: 0px;min-width: 32px;"><span cid="n2237" mdtype="table_cell" style="box-sizing: border-box;display: inline-block;min-width: 1ch;width: 296.583px;min-height: 10px;"><span md-inline="plain" style="box-sizing: border-box;"><span leaf="">TC_RESET 填充</span></span></span></td><td style="box-sizing: border-box;padding: 6px 13px;border: 1px solid rgb(223, 226, 229);margin: 0px;min-width: 32px;"><span cid="n2238" mdtype="table_cell" style="box-sizing: border-box;display: inline-block;min-width: 1ch;width: 448.417px;min-height: 10px;"><span md-inline="plain" style="box-sizing: border-box;"><span leaf="">✅</span></span></span></td></tr></tbody></table>#### JNDI 注入利用模块 (JNDI)  
  
支持六种利用姿势，外加一个便于一键测试常见链的 ShowHand 链  
  
JndiBasicPayload  
: LDAP 远程加载字节码  
  
JndiDeserializationPayload  
: LDAP 中基于 javaSerializedData 字段实现的反序列化  
  
JndiResourceRefPayload  
: LDAP 基于 BeanFactory 的 Tomcat EL、Groovy等利用  
  
JndiReferencePayload  
: LDAP 基于其他 ObjectFactory 的Reference利用，例如各种DataSource JDBC利用  
  
JndiRMIDeserializePayload  
: LDAP 高版本 JDK 绕过之RMI反序列化  
  
JndiRefBypassPayload  
: LDAP 高版本 JDK 绕过之ReferenceBypass  
  
JndiShowHandPayload  
: JNDI梭哈链，一键测试常规利用链，提高测试效率  
#### Mysql JDBC 反序列化利用模块 (Fake MySQL)  
  
FakeMySQLPayload  
: MySQL JDBC 反序列化利用姿势  
  
FakeMySQLReadPayload  
: MySQL JDBC 客户端文件读取利用姿势  
  
FakeMySQLSHPayload  
: FakeMySQL 反序列化梭哈链，一键测试常规反序列化链，提高测试效率  
#### JRMP 反序列化利用模块 (JRMPListener)  
  
可配合 JRMPClient 反序列化链实现RMI低版本的绕过  
#### TCP Server  
  
一个简易的 TCP Server，可以将生成的Payload文件挂载到TCP端口服务上，访问该端口即可返回指定内容  
  
适用于 Derby 反序列化 RCE 场景，可直接通过tcp端口获取反序列化数据  
#### HTTP Server  
  
一个简易的HTTP服务器，将生成的Payload文件挂载到HTTP端口服务上，访问指定端口即可返回指定内容  
  
适用于 postgresql 远程加载 SpringBeanXML 文件等场景  
#### 小工具(Tools)  
  
底层调用了 SerializationDumper，能够解析序列化数据，并能实现手动更改类的 serialVersionUID 字段  
  
![SerializationDumper.png](https://mmbiz.qpic.cn/mmbiz_png/qGTEdaLg0HnJRW5aSuWdMUtHFickvEv0tADXlJ3Uh62hOibXcprK5icKKE08YxgMT27IGoI0jcMoJlicwt44ltLK6w/640?wx_fmt=png&from=appmsg "")  
## 快速开始  
  
**特别注意：我们默认只对 8011 端口进行了随机密码的登录保护。其他端口可能存在被反制的风险，使用完相关功能后记得及时关闭相应端口**  
#### 方式一：Docker  
  
你可以通过   
docker  
 一条命令启动   
java-chains  
 项目（这也是推荐做法）  
```
```  
  
可通过环境变量配置鉴权或密码；  
  
**CHAINS_AUTH**  
: true为开启鉴权，false为关闭鉴权，默认开启鉴权  
  
**CHAINS_PASS**  
: 指定web密码，若该变量为空则随机生成密码，默认随机生成密码  
  
备注：生成功能仅使用   
8011  
 端口即可，其他端口为   
exploit  
 模块使用  
  
使用以下命令从docker中获取随机生成的强密码  
```
```  
  
输出示例  
```
```  
  
登录页面：  
http://your-ip:8011  
#### 方式二：Jar包启动  
  
⚠️仅支持 JDK8，推荐使用 Temurin8/Zulu8 JDK  
  
使用   
java -jar web-chains.jar  
 即可启动，每次启动后会打印出随机生成的密码  
  
默认监听 0.0.0.0 ，登录页面：  
http://your-ip:8011  
 （使用这里的用户名密码登录）  
  
可通过环境变量设置web登录密码，例如：  
##### Linux：  
```
```  
##### Windows：  
```
```  
## 详细使用  
  
Github Wiki:   
https://github.com/vulhub/java-chains/wiki  
```
```  
#### 项目地址  
```
```  
#### 直接下载  
> 我用夸克网盘分享了「web-chains-1.3.1-all.tar.gz」，点击链接即可保存。打开「夸克APP」，无需下载在线播放视频，畅享原画5倍速，支持电视投屏。  
  
链接：  
https://pan.quark.cn/s/15babac9d77d  
  
  
  
