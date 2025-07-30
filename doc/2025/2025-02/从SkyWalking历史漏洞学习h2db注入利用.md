#  从SkyWalking历史漏洞学习h2db注入利用   
NEURON  SAINTSEC   2025-02-04 02:00  
  
> 摘要：从skywalking的cve带入，通过skywalking的漏洞场景来了解h2数据库的注入利用方式。  
  
  
Apache SkyWalking 是一款应用性能监控（APM）工具，对微服务、云原生和容器化应用提供自动化、高性能的监控方案。其官方网站显示，大量的国内互联网、银行及民航等领域的公司在使用此工具。  
  
https://github.com/apache/skywalking  
  
https://archive.apache.org/dist/skywalking/6.6.0/apache-skywalking-apm-6.6.0-src.tgz  
  
https://archive.apache.org/dist/skywalking/6.6.0/apache-skywalking-apm-6.6.0.tar.gz  
  
几个洞都是关于graphql注入造成的漏洞，在skywalking部署起来后访问  
http://127.0.0.1:8080/graphql  
会发现提供了一个graphql接口，允许使用graphql查询数据。  
  
  
1  
## 远程调试  
  
  
在下载的apache-skywalking-apm-8.3.0-src.tgz的bin下找到startup.sh，能够看出skywalking由：  
```
```  
  
oap和webapp两个service组成，我们的几个漏洞都位于oap中，在oapservice.sh中，在启动语句中加入调试命令即可：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Gw8FuwXLJnRBKxSgNWFGsATKfjSEhKRRAUj7lic1Ro4Lia1nSAwqjTTY6xNXofrIsGgBn28atMgW0Yn5icEB6Kgtw/640?wx_fmt=png "")  
```
```  
  
Ide：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Gw8FuwXLJnRBKxSgNWFGsATKfjSEhKRRTyhUWrCXOc5ZwicP99ibOvVljQrzgT0xW0Bqyeyd5bUjtovh5CAhBEog/640?wx_fmt=png "")  
  
  
  
2  
## skywalking中的graphql  
  
  
skywalking中关于graphql的接口声明写在：  
  
org.apache.skywalking.oap.query.graphql.GraphQLQueryProvider#prepare  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Gw8FuwXLJnRBKxSgNWFGsATKfjSEhKRR0CnCS6QCXPsyzblIY0ib8IQhjozYBywBgL83CnaLEFTpsT3RS0jfIsw/640?wx_fmt=png "")  
  
  
根据这些文件就能找到对应的接口。  
  
随意抓个包就能拿到其格式：  
```
```  
  
  
3  
## CVE-2020-9483  
> 当SkyWalking使用H2、MySQL或者TiDB作为存储方案时，攻击者可通过默认未授权的GraphQL接口构造恶意请求，从而获取敏感数据。  
  
  
https://github.com/apache/skywalking/pull/4639  
  
Version:6.0-6.6\7.0  
  
commit位于：  
https://github.com/apache/skywalking/pull/4639/commits/2b6aae3b733f9dbeae1d6eff4f1975c723e1e7d1  
  
没什么好说的，主要是拼接导致的注入，漏洞点位于：  
  
oap-server/server-storage-plugin/storage-jdbc-hikaricp-plugin/src/main/java/org/apache/skywalking/oap/server/storage/plugin/jdbc/h2/dao/H2MetricsQueryDAO.java#getLinearIntValues  
:  
```
```  
  
idValues可控，对应的查询位于：  
  
https://github.com/apache/skywalking-query-protocol/tree/e47462fd6af92d42d1c161cf1cec975661148ab0  
  
其中定义了使用方式：  
```
```  
  
断点调试后能发现：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Gw8FuwXLJnRBKxSgNWFGsATKfjSEhKRRkthdIf5tRLgH2EwDhvAicejFJnnfYZoGPTW56ggHRKfBJS3kvGKRGZw/640?wx_fmt=png "")  
  
where后拼接然后直接拼接union即可完成注入：  
```
```  
  
简化一下：  
```
```  
  
比较可惜的是此处使用的是executeQuery，往里深入会发现是调用的prepareStatement，无法执行堆叠注入。  
  
ps.堆叠注入通常用的是addBatch 和 executeBatch 这两个函数。  
  
  
4  
## CVE-2020-13921  
## 及最新的注入  
  
  
https://github.com/apache/skywalking/pull/4970  
  
ver:6.5.0, 6.6.0, 7.0.0, 8.0.0, 8.0.1  
  
涉及到的类比较多，还是拼接导致的注入：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Gw8FuwXLJnRBKxSgNWFGsATKfjSEhKRRRTLEsznZrFajoRoVicN8DQzUy5xW7iafZOcibn3o0Aol9zZTNCiaN6WA7A/640?wx_fmt=png "")  
  
以org.apache.skywalking.oap.server.storage.plugin.jdbc.h2.dao.H2MetadataQueryDAO#searchServices为例，其graphqls如下：  
```
```  
  
以此构造出poc如下：  
```
```  
  
注入点位于keyword，sql语句变为：  
```
```  
  
不过处于like字段不太方便注入，在此处尝试注入总是Column   
"  
%  
"  
 not found。  
  
然而官方对于上面注入的修复不完善，还存在着一处queryLog注入，漏洞点位于org.apache.skywalking.oap.server.storage.plugin.jdbc.h2.dao.H2LogQueryDAO#queryLogs：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Gw8FuwXLJnRBKxSgNWFGsATKfjSEhKRRBSBeic0N3x8FargPDia9ahBvoRQOcMAWKjlLfsY3x9EE8xJs8FzXHozQ/640?wx_fmt=png "")  
  
对于metricName做了拼接，而关于querylog的用法在log.graphqls中有:  
```
```  
  
以此构造poc，需要注意的是后面使用预编译，而在注入时需要注释掉后续拼接上的占位符，因此需要手动加上俩占位符：  
```
```  
##   
  
5  
## h2注入的进一步利用  
  
  
h2注入的利用思路比较多，因为skywalking是以sa权限启动的h2，所以各种需要权限的函数都可以使用。  
  
读文件的函数FILE_READ：  
  
SELECT FILE_READ('/etc/passwd', NULL)  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Gw8FuwXLJnRBKxSgNWFGsATKfjSEhKRR6m37v9ldTQKVD8iaQahUavGLeXtG1HHzdUT9cmicX2oiaCRsicVgYlLo8g/640?wx_fmt=png "")  
  
能读就能写，文件写入函数为FILE_WRITE：  
```
```  
  
ps.此处需要写入的是16进制的文件内容。  
  
getshell的方式也有，除了常规的利用写文件到定时任务或者其他我不了解的姿势之外，还有利用h2内置的函数link_schema。  
  
首先，通过写文件我们可以写入恶意类，但还需要对该恶意类进行加载才能达成执行代码的效果，而link_schema函数的第二个参数在底层有加载类的效果。![](https://mmbiz.qpic.cn/mmbiz_png/Gw8FuwXLJnRBKxSgNWFGsATKfjSEhKRRJOvwMMV9QgxfISvau13tJEG3La3VdbmNV42LOiaLTfEWZsBVT4gKFyQ/640?wx_fmt=png "")  
  
  
从这里跟入后能看到具体代码，具体在：org.h2.util.JdbcUtils#loadUserClass，没啥好说的，就是最后调用了Class.forName。![](https://mmbiz.qpic.cn/mmbiz_png/Gw8FuwXLJnRBKxSgNWFGsATKfjSEhKRRgnK2q2aTZ0pN3mqM9x1fngU0aeq1os5EiauPkyAEWbz7PKwsm4Ic3Vg/640?wx_fmt=png "")  
  
  
那么这里就可以将我们写入的恶意类进行加载了。  
```
```  
  
需要注意的是写入的路径根据实际可写路径变化，不一定是config。  
  
加载：  
```
```  
  
由于类加载机制（双亲委派机制）导致加载过的类无法再次加载，因此每次都需要创建一个不同的类名进行加载，同时将写入evi类和加载放一起，简单地写了一个生成脚本：  
```
```  
  
往sw一丢就触发calc了。  
  
在尝试成功加载完恶意类后再看回到前面的link_schema底层代码，会发现有意思的东西（lookup）：  
![](https://mmbiz.qpic.cn/mmbiz_png/Gw8FuwXLJnRBKxSgNWFGsATKfjSEhKRRhHx6nkgNAZ1m1SRmee5HaeY6VOeYqU5moKDFdwhialpTJruibkheibkMg/640?wx_fmt=png "")  
  
  
很熟悉的东西，一看见lookup就立马会联想到jndi，是否可以直接利用jndi注入？答案是可以的。  
  
var1实际上是link_schema的第三个参数，也就是数据库的连接串，第二个参数放入  
javax.naming.InitialContext  
，此时可以用lookup来发起连接。  
```
```  
  
在CVE-2020-9483时有提到过堆叠注入，sw的几处注入最后都是用executeQuery->prepareStatement，不满足堆叠的条件，既然提到了那么就顺带看一下在允许堆叠注入的情况下h2db的getshell方式。  
  
CREATE ALIAS创建函数$$内为函数定义:  
```
```  
  
最后用call去调用函数达成命令执行。  
  
  
  
