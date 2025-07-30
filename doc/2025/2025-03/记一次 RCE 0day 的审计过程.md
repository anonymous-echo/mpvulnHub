#  记一次 RCE 0day 的审计过程   
原创 Sukali  信安之路   2025-03-19 09:43  
  
大家好，我是 **Sukali**  
，首次在信安之路上投稿，并获得免费加入信安之路知识星球的机会，同时解锁了信安之路成长平台、文库以及 POC 管理系统的使用权限，今天来为大家分享一下自己挖掘的一个 RCE 0day 的审计过程。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/sGfPWsuKAfc1ibbG6mEdqV5Xpw0yu9UxtIoLlhiazxU4NakInEiam1mOnHHYw4pVq3nrrCc8tpnn5ictdhmNLUaHuA/640?wx_fmt=png&from=appmsg "")  
  
RCE 是远程代码执行或者远程命令执行的缩写，在案例讲解之前，先来聊聊 java 代码审计的一些基础知识：  
### 1、在 Java 代码审计过程中，我们的目标是：  
- 识别 常见的安全漏洞  
  
- 理解代码逻辑，寻找不安全的输入处理  
  
- 分析漏洞可利用性，判断是否能造成实际攻击  
  
- 提出 合理的修复方案  
  
### 2、代码审计的基本方法  
#### 手工审计  
- 查找 用户输入点  
  
- 跟踪 变量的传递路径  
  
- 分析 是否进入危险函数  
  
#### 自动化工具  
- FindSecBugs（Java 代码安全分析插件）  
  
- SonarQube（静态代码扫描）  
  
- CodeQL（代码查询分析）  
  
#### 黑盒测试  
- Fuzzing（模糊测试），通过随机输入探测漏洞  
  
- 渗透测试，模拟真实攻击场景  
  
### 3、Java 常见的命令执行函数  
  
Java 提供多个执行系统命令的方法，如果使用不当，会造成**远程命令执行漏洞（RCE）**  
。以下是 Java 常见的**高危命令执行 API**  
：  
  
<table><thead><tr style="box-sizing: border-box;break-inside: avoid;break-after: auto;"><th style="box-sizing: border-box;font-weight: bold;border-bottom-width: 0px;border-bottom-style: none;border-bottom-color: currentcolor;padding-bottom: 0.5em;"><strong style="box-sizing: border-box;"><span style="box-sizing: border-box;"><span leaf="">危险 API</span></span></strong></th><th style="box-sizing: border-box;font-weight: bold;border-bottom-width: 0px;border-bottom-style: none;border-bottom-color: currentcolor;padding-bottom: 0.5em;"><strong style="box-sizing: border-box;"><span style="box-sizing: border-box;"><span leaf="">描述</span></span></strong></th><th style="box-sizing: border-box;font-weight: bold;border-bottom-width: 0px;border-bottom-style: none;border-bottom-color: currentcolor;padding-bottom: 0.5em;"><strong style="box-sizing: border-box;"><span style="box-sizing: border-box;"><span leaf="">漏洞等级</span></span></strong></th></tr></thead><tbody><tr style="box-sizing: border-box;break-inside: avoid;break-after: auto;"><td style="box-sizing: border-box;border-bottom-width: 1px;border-bottom-style: solid;border-bottom-color: rgb(221, 221, 221);padding: 10px 0px;"><span style="box-sizing: border-box;"><span leaf="">Runtime.getRuntime().exec(cmd)</span></span></td><td style="box-sizing: border-box;border-bottom-width: 1px;border-bottom-style: solid;border-bottom-color: rgb(221, 221, 221);padding: 10px 0px;"><span style="box-sizing: border-box;"><span leaf="">直接执行 cmd，如果 cmd 由用户输入控制，可能导致 RCE。</span></span></td><td style="box-sizing: border-box;border-bottom-width: 1px;border-bottom-style: solid;border-bottom-color: rgb(221, 221, 221);padding: 10px 0px;"><span style="box-sizing: border-box;"><span leaf="">高</span></span></td></tr><tr style="box-sizing: border-box;break-inside: avoid;break-after: auto;"><td style="box-sizing: border-box;border-bottom-width: 1px;border-bottom-style: solid;border-bottom-color: rgb(221, 221, 221);padding: 10px 0px;"><span style="box-sizing: border-box;"><span leaf="">ProcessBuilder.start()</span></span></td><td style="box-sizing: border-box;border-bottom-width: 1px;border-bottom-style: solid;border-bottom-color: rgb(221, 221, 221);padding: 10px 0px;"><span style="box-sizing: border-box;"><span leaf="">启动进程并执行命令，如果参数未严格过滤，可能被利用。</span></span></td><td style="box-sizing: border-box;border-bottom-width: 1px;border-bottom-style: solid;border-bottom-color: rgb(221, 221, 221);padding: 10px 0px;"><span style="box-sizing: border-box;"><span leaf="">高</span></span></td></tr><tr style="box-sizing: border-box;break-inside: avoid;break-after: auto;"><td style="box-sizing: border-box;border-bottom-width: 1px;border-bottom-style: solid;border-bottom-color: rgb(221, 221, 221);padding: 10px 0px;"><span style="box-sizing: border-box;"><span leaf="">ScriptEngine.eval(script)</span></span></td><td style="box-sizing: border-box;border-bottom-width: 1px;border-bottom-style: solid;border-bottom-color: rgb(221, 221, 221);padding: 10px 0px;"><span style="box-sizing: border-box;"><span leaf="">执行 JavaScript 代码，可能导致</span></span><strong style="box-sizing: border-box;"><span style="box-sizing: border-box;"><span leaf="">远程代码执行</span></span></strong><span style="box-sizing: border-box;"><span leaf="">。</span></span></td><td style="box-sizing: border-box;border-bottom-width: 1px;border-bottom-style: solid;border-bottom-color: rgb(221, 221, 221);padding: 10px 0px;"><span style="box-sizing: border-box;"><span leaf="">高</span></span></td></tr><tr style="box-sizing: border-box;break-inside: avoid;break-after: auto;"><td style="box-sizing: border-box;border-bottom-width: 1px;border-bottom-style: solid;border-bottom-color: rgb(221, 221, 221);padding: 10px 0px;"><span style="box-sizing: border-box;"><span leaf="">GroovyShell.evaluate(script)</span></span></td><td style="box-sizing: border-box;border-bottom-width: 1px;border-bottom-style: solid;border-bottom-color: rgb(221, 221, 221);padding: 10px 0px;"><span style="box-sizing: border-box;"><span leaf="">执行 Groovy 代码，如果 script 可控，则可能被攻击者利用。</span></span></td><td style="box-sizing: border-box;border-bottom-width: 1px;border-bottom-style: solid;border-bottom-color: rgb(221, 221, 221);padding: 10px 0px;"><span style="box-sizing: border-box;"><span leaf="">高</span></span></td></tr></tbody></table>### RCE 0day 审计案例  
  
**在通过对其手工代码审计发现在dbBackUp方法中存在命令执行的功能。并将sb数组作为参数传入执行。Sb数组中在没有过滤的情况下添加了pathSql变量，该变量由backPath+backName组成。**  
  
![img](https://mmbiz.qpic.cn/mmbiz_jpg/sGfPWsuKAfcBOVMkJYmWk3hbaX4QCYdSFwoRZT38xloItdxiawiaZpiaNxcX9ve0OwXRMXMkiaskgz5iaS1ZpDzmezw/640?wx_fmt=jpeg&from=appmsg "")  
#### 详细解释  
  
**从图片中的代码可以看到**  
##### 1、pathSql 变量可控  
  
```
String pathSql = backPath + backName;
```  
  
##### backPath 和 backName 由外部参数传入，如果 backPath 可控，攻击者可以拼接恶意命令。  
##### 2、未经安全处理  
```
sb.append(" " + pathSql);
```  
##### sb.append() 直接拼接了 pathSql ，如果 pathSql 由攻击者控制，就可以执行任意命令。  
##### runtime.exec() 直接执行命令   
```
Process process = runtime.exec("cmd /c " + sb.toString());
Process process = runtime.exec("/home/mysql/mysql/bin/" + sb.toString());
```  
##### runtime.exec() 不会自动过滤 Shell 特殊字符，攻击者可以注入 &&、;、|| 等符号进行命令拼接，最终实现远程命令执行（RCE）  
  
**通过查找 dbBackUp 函数的调用链可以发现在 process 方法中调用了 dbBackUp 方法并给其提供了fileUrl 以及 backName 参数，backName 参数是直接生成了一个以时间命名的 .sql 文件，我们关注 fileUrl 参数即可，fileUrl 是由 MappingCache.getValue 获取 FILE_LOCATION 得到**  
：  
  
![img](https://mmbiz.qpic.cn/mmbiz_jpg/sGfPWsuKAfcBOVMkJYmWk3hbaX4QCYdSauNrPz2f2vC3IM8yItVdxMgRfTYwmc1IGwUJKiaYxAmSetXmfxQPQnA/640?wx_fmt=jpeg&from=appmsg "")  
#### 详细解释  
##### fileUrl 变量  
```
String fileUrl = MappingCache.getValue(DOMAIN_COMMON, FILE_LOCATION);
```  
##### fileUrl 由 MappingCache.getValue() 方法获取FILE_LOCATION变量的值。  
  
**问题：如果**  
**FILE_LOCATION**  
**变量的值可被攻击者控制，攻击者可以构造恶意路径或命令，导致远程命令执行（RCE）。**  
##### val.split("&")  
```
String[] split = val.split("&");
```  
##### val 是从 MappingCache.getValue(DOMAIN_COMMON, BACKUP_DATABASE) 获取的配置项，包含数据库连接信息。  
  
split("&") 解析用户输入，可能导致**未受控的数据流**  
，如果 val 由攻击者控制，也可能影响执行的 SQL 备份命令。  
##### dbBackUp 方法调用  
```
BackupDatabaseTemplate.dbBackUp(userName, password, databaseName, fileUrl, backName, port);
```  
##### dbBackUp 方法的 fileUrl 直接来源于 FILE_LOCATION，如果 FILE_LOCATION 可控，fileUrl 也将被攻击者操控。  
  
**追踪 getValue 发现内容都是从 redis 中获取，现在只需要寻找在哪里写入 redis 中的即可**  
  
![img](https://mmbiz.qpic.cn/mmbiz_jpg/sGfPWsuKAfcBOVMkJYmWk3hbaX4QCYdSPxZ6WNdZkj8WUgIwsgdicqMpVSUnKXUFbHtibcR2VJiaNWlErbantHkoQ/640?wx_fmt=jpeg&from=appmsg "")  
#### 代码解析  
##### getValue 方法主要做了什么？  
  
**连接 Redis**  
```
redis = getJedis();
```  
  
**getJedis() 方法用于获取 Redis 连接。**  
  
这意味着**数据存储在 Redis**  
，getValue 只是读取 Redis 里的数据。  
  
**拼接 Redis Key**  
```
redis.get((domain + key + _SUFFIX_MAPPING).getBytes());
```  
  
domain + key + _SUFFIX_MAPPING 组成 Redis**键名**  
。  
  
通过 get() 方法**从 Redis 获取数据**  
。  
  
**反序列化数据**  
```
Object object = SerializeUtil.unserialize(redis.get(...));
```  
  
**代码使用 SerializeUtil.unserialize() 反序列化数据。**  
  
如果 Redis 存储的是**序列化对象**  
，那么这里会将其**还原为 Java 对象**  
。  
  
**返回数据**  
```
Mapping mapping = (Mapping) object;
return mapping.getValue();
```  
  
**反序列化的数据被转换为 Mapping 类型，并返回 getValue()。**  
#### 利用链跟踪  
  
**在前端寻找 FILE_LOCATION 发现在通用配置中可以配置 FILE_LOCATION 内容。**  
  
![img](https://mmbiz.qpic.cn/mmbiz_jpg/sGfPWsuKAfcBOVMkJYmWk3hbaX4QCYdSboTslBicqQ1X8dEGQoyMQW59OhfpeFicyFOib6rHVhmzHJZ9iaZPF4QwyA/640?wx_fmt=jpeg&from=appmsg "")  
  
**回到 process 方法我们查看调用链发现 startTask 中引用了 process，继续跟进**  
  
![img](https://mmbiz.qpic.cn/mmbiz_jpg/sGfPWsuKAfcBOVMkJYmWk3hbaX4QCYdSUa4BqEZkW3b0xNwllib2kNM5N4ibAem63zlMiarEiczEQdwqdOFQnbXKOQ/640?wx_fmt=jpeg&from=appmsg "")  
  
**发现在 job.runJob 服务中的 doCmd 引用了 startTask 方法**  
  
![img](https://mmbiz.qpic.cn/mmbiz_jpg/sGfPWsuKAfcBOVMkJYmWk3hbaX4QCYdSeDJXYaVTmauYHR63hn4WBLiaSJcTR1KxF60JDAlFtXeoH7DMLksNJcA/640?wx_fmt=jpeg&from=appmsg "")  
  
**继续查找调用可以找到 invokeListener 方法中引用 doCmd 方法**  
  
![img](https://mmbiz.qpic.cn/mmbiz_jpg/sGfPWsuKAfcBOVMkJYmWk3hbaX4QCYdSIp2p5ib2Aq3AKwTy78A8kibq67xvuUQTGZ3EibbicayrAU85b27N69eFxg/640?wx_fmt=jpeg&from=appmsg "")  
  
**继续跟进上一个调用函数则是 multicastEvent 方法**  
  
![img](https://mmbiz.qpic.cn/mmbiz_jpg/sGfPWsuKAfcBOVMkJYmWk3hbaX4QCYdS8ibDlk4egxw7nYPEOtf01mpjXxB4pdC0T1mxDU9rXPoaod6tTrv3SVg/640?wx_fmt=jpeg&from=appmsg "")  
  
**省略其他冗余的调用方法追踪，最后是在 Service 的 post 请求方法下调用含有漏洞的**  
  
**方法链**  
  
![img](https://mmbiz.qpic.cn/mmbiz_jpg/sGfPWsuKAfcBOVMkJYmWk3hbaX4QCYdSicEuNJMkBZEQwgsAyMaDNNxE9Jt7elIP6IBaadWSRicOibrwE0jS1VxSA/640?wx_fmt=jpeg&from=appmsg "")  
  
**完整调用链**  
  
![img](https://mmbiz.qpic.cn/mmbiz_jpg/sGfPWsuKAfcBOVMkJYmWk3hbaX4QCYdSPqLgGpqCoLm3P7neDW67NMgfSR0BbWNt33C49FwR7Qric1LbgRj5vIg/640?wx_fmt=jpeg&from=appmsg "")  
### 漏洞复现  
  
**tmp/ || calc.exe || 保存到**  
  
![img](https://mmbiz.qpic.cn/mmbiz_jpg/sGfPWsuKAfcBOVMkJYmWk3hbaX4QCYdSmwiaFqsgrggrw4ttTzOkia8vKw4YSABEb9rfUibguj2udG8BOoIribJErA/640?wx_fmt=jpeg&from=appmsg "")  
  
**调用 job.runJob 服务成功命令执行**  
  
![img](https://mmbiz.qpic.cn/mmbiz_jpg/sGfPWsuKAfcBOVMkJYmWk3hbaX4QCYdSUliaEwUzIpdj26YctX2icPDom5w0eKcyT5kurY02oLyj03R6iczyfgcRw/640?wx_fmt=jpeg&from=appmsg "")  
  
**成功执行**  
  
![img](https://mmbiz.qpic.cn/mmbiz_jpg/sGfPWsuKAfcBOVMkJYmWk3hbaX4QCYdSe2iarVLwalgl01kmFaAf3V2XGX4Lk8MlK08OTRpcL7icOc2BcenLo7PA/640?wx_fmt=jpeg&from=appmsg "")  
### 修复方案  
#### 1. 使用 ProcessBuilder 替代 Runtime.exec()  
```
ProcessBuilder pb = new ProcessBuilder(
  "mysqldump",
  "-h", "3306",
  "-u", "root",
  "-p", "password",
  "-r", "/safe/path/backup.sql"
);
pb.start();
```  
#### ProcessBuilder 能够隔离参数，防止命令拼接漏洞。  
#### 2. 限制 backPath 只能在安全目录  
```
if (!backPath.startsWith("/var/backups/")) {
  throw new SecurityException("非法备份路径！");
}
```  
#### 3. 过滤 backName 防止命令拼接  
```
if (!backName.matches("[a-zA-Z0-9_-]+\\.sql")) {
  throw new IllegalArgumentException("非法文件名！");
}
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/sGfPWsuKAfc1ibbG6mEdqV5Xpw0yu9UxtIoLlhiazxU4NakInEiam1mOnHHYw4pVq3nrrCc8tpnn5ictdhmNLUaHuA/640?wx_fmt=png&from=appmsg "")  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
