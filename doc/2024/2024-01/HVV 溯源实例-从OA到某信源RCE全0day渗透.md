#  HVV 溯源实例-从OA到某信源RCE全0day渗透   
Alivin  黑客白帽子   2024-01-27 08:00  
  
![](https://mmbiz.qpic.cn/mmbiz_png/PJG3jJlPv0w6V8YUTyNSuV2udfyY3rWyR6V1UeHWuiab6T80I5ldZicZswCnrbicD4ibpaDMqCZ6UvFmhWLyTzptSA/640?wx_fmt=png&random=0.6636094571400317&random=0.6219011309810436&random=0.21191420540585404 "")  
  
**感谢师傅 · 关注我们**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/PJG3jJlPv0w6V8YUTyNSuV2udfyY3rWyR6V1UeHWuiab6T80I5ldZicZswCnrbicD4ibpaDMqCZ6UvFmhWLyTzptSA/640?wx_fmt=png&random=0.9829534454876507&random=0.2787622380037358&random=0.29583791053286834 "")  
  
  
由于，微信公众号推送机制改变，现在需要设置为星标才能收到推送消息。大家就动动发财小手设置一下呗！啾咪~~~  
  
![](https://mmbiz.qpic.cn/mmbiz_png/PJG3jJlPv0y50hQk1TiaBIAnSjzqkmZcPS4TWvohHfHPTVUBWM2mFxcqwhiaZKaQM6S7t11fuiajZ2zZqXD5hJJmA/640?wx_fmt=png "")  
  
  
  
来源于奇安信社区（Alivin ）  
  
原文链接：  
https://forum.butian.net/share/1765  
  
2021年国Hvv真实溯源过程，在流量设备告警能力弱的情况下，重人工介入分析整个过程总结，回顾当时整个溯源过程和0day的捕获过程，尝试把当时的心境和技术上的思考点梳理出来，给大家参考。  
# 0x02 溯源过程  
  
事件起源于4月9日午后的一则来自EDR的webshell告警，如下：![](https://mmbiz.qpic.cn/mmbiz_png/CBJYPapLzSFqcLttTLqDkBibnPEtxNicxlucUwpiblolbhSgOluTWWTMAHt9VS7EoEHIrNaViacLxIro40UqGNSVEQ/640?wx_fmt=png&wxfrom=13&wx_lazy=1&wx_co=1&tp=wxpic "")  
  
  
马上展开对该服务器的排查，该服务器为某信源VRV，纯内网环境。说明攻击者已经进入内网环境，分两条线分别对攻击入口和内网影响面进行排查。  
## 2.1 向内溯源，确定影响面  
### 2.1.1 某信源VRV溯源  
#### 2.1.1.1 从日志分析  
  
因为某信源VRV的管理后台使用SSL协议，在协调厂商提供证书的同时，对access.log日志进行分析，尝试找出其中的攻击入口。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/CBJYPapLzSFqcLttTLqDkBibnPEtxNicxlgtKcM6LEr6GiaA7Y6Y7EmswzHhbMzpd499LFHQ8f5z0D6EnibbzhiaB8w/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1&tp=wxpic "")  
  
  
从日志寻找入口的思路：  
  
（1）定位webshell访问接口，确认攻击跳板的IP  
  
（2）对webshell访问前后日志进行分析，确定漏洞URL  
  
（3）将可疑URL在其他时段日志中进行搜索，找出在其他时段没出现过的URL重点分析  
  
（4）对POST请求的日志重点分析。  
  
通过对日志分析，发现10.*.*.*2在对VRV服务器尝试扫描，扫描日志符合fscan等类型内网扫描工具的流量，如下：![](https://mmbiz.qpic.cn/mmbiz_png/CBJYPapLzSFqcLttTLqDkBibnPEtxNicxl0mADZsO7pMic7A9mhAtXB4YsXdQkDbInlwyNfodibZIbBYlorbmucnGQ/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1&tp=wxpic "")  
  
  
此时已经定位了攻击某信源VRV的主机为10.*.*.*2，同时安排其他同事对该IP进行溯源分析。  
  
该部分扫描无影响，然后继续分析，发现攻击队成功登陆了audit账号：![](https://mmbiz.qpic.cn/mmbiz_png/CBJYPapLzSFqcLttTLqDkBibnPEtxNicxl624NQkGWLGGSyyPquMyQjeCrjibUfvH0VO2lhhrrTswKPJXrU70wxnA/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1&tp=wxpic "")  
  
  
结合测试，发现audit账户为弱口令123456，同时在audit审计账户的后台中发现system也被登录过，同样为弱口令。（PS：此时猜测admin用户也是弱口令，经过测试并不是。）![](https://mmbiz.qpic.cn/mmbiz_png/CBJYPapLzSFqcLttTLqDkBibnPEtxNicxl9I5RjkASSww9508s1uFcYGSAicdMJd6Rvavq6lnmst9PvD9SmvbhX9g/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1&tp=wxpic "")  
  
  
时间和IP都和攻击者路径对得上。但audit和system账户权限有限，并不会直接控制终端。  
  
此外，在审计用户的后台还发现，admin账户的密码被修改过,操作者时admin本人，登录IP为攻击队控制的跳板机，修改后密码后，admin账户成功登录。![](https://mmbiz.qpic.cn/mmbiz_png/CBJYPapLzSFqcLttTLqDkBibnPEtxNicxl0YNsGcw74ECckeNnT0fkejkNSmaPnWcCP3jEfUicniaoyPNxT5M32bHw/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1&tp=wxpic "")  
![](https://mmbiz.qpic.cn/mmbiz_png/CBJYPapLzSFqcLttTLqDkBibnPEtxNicxlcibdGbt33aCXbd0J3UkFicicIfZn3ELiaoqbFnnDiahNnRU5R15eojbP0KQ/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1&tp=wxpic "")  
  
  
到这得到的信息，总觉得是因为admin账户密码被重置导致的整台服务器实现（如果是admin弱口令的话，就不会存在admin修改自己密码的操作了。）继续分析日志，发现在logo.aspx文件被访问前，还曾访问过logo.txt。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/CBJYPapLzSFqcLttTLqDkBibnPEtxNicxlfdjpnc5YbnGwxmAqsO4yXgeSwob0O4RUJ89d4B8aVq1c3b78K4WEdA/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1&tp=wxpic "")  
  
  
而且logo.txt的访问中存在一次404的访问，说明马没写成功。那么比对两次logo.txt访问前被访问的接口，大概率可以定位到漏洞存在点。![](https://mmbiz.qpic.cn/mmbiz_png/CBJYPapLzSFqcLttTLqDkBibnPEtxNicxlYic1KuicQm1yjsDH5DwS3kqrQ2wObiaoVnTCmQPiaT8Fib1zF4yYcRD3bsg/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1&tp=wxpic "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/CBJYPapLzSFqcLttTLqDkBibnPEtxNicxlJmib294X0wV0RgyjwTk0cf2Mmc6qjbBQDM0fP0buib1A8zVahM4tc80Q/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1&tp=wxpic "")  
  
成功定位/VRVEIS/SystemMan/GetNavUserByNavGuid.aspx就是漏洞文件，而该文件能写入shell，且从日志看，该路径应该需要admin权限才能访问。  
  
那么问题来了，admin账号权限咋来的？带着疑问，先分析GetNavUserByNavGuid.aspx被访问的日志：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/CBJYPapLzSFqcLttTLqDkBibnPEtxNicxlmWfdmQaicerC6Oicqh1cNGzRC97R3WTMgpSJxuicIb8m5UL5CrdL68Oiag/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1&tp=wxpic "")  
  
在admin用户登录前，已经出现了大量的接口调用和访问，里面奇迹般的记录了一个POST的body，把思路引向了注入（后话：最后证明pczq参数与漏洞利用无关）。  
  
恰好如果是注入的话，也解释的通admin账号的来源和写文件的操作。mssql支持堆叠注入，update操作可以改密码，xp_cmdshell可以用于写shell。  
  
而在登录admin之前，登录audit、sys  
tem账号的行为，原因大概是因为admin用户的密码复杂，cmd不可解。所以先解开audit和system的密码登录的。  
#### 2.1.1.2 从流量分析  
  
从流量分析已经是几个小时以后的事情了，某信源厂家并不愿意提供证书对流量进行解密。但是在不经意间看到VRV根目录下有一个cert目录，在其中找到证书。![](https://mmbiz.qpic.cn/mmbiz_png/CBJYPapLzSFqcLttTLqDkBibnPEtxNicxlHcGQjxwAvj8IOmr76J9gxQFV1u3wRUAc0OKeehicEN2lSSGKsS3PcSA/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1&tp=wxpic "")  
  
  
证书有加密，尝试以后发现证书密码是123。  
  
此时终于有了明文流量了，直接搜索接口，验证上面从日志中溯源的结论，如下：![](https://mmbiz.qpic.cn/mmbiz_png/CBJYPapLzSFqcLttTLqDkBibnPEtxNicxlfJzUYgP95sMrMLY2OOWsp6O2h2hwpwCzOKiaWSXAvS1icOoXJwW9IjVA/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1&tp=wxpic "")  
  
  
与日志分析结论一致，且在流量中有发现修改admin的密码。（时间久远，找不到数据包截图了，payload截图如下）![](https://mmbiz.qpic.cn/mmbiz_png/CBJYPapLzSFqcLttTLqDkBibnPEtxNicxlg2KZmGfJ251wB53nZV4hpqMMGmCBh0QelOf0T6bTKMsMUku10mn00Q/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1&tp=wxpic "")  
  
#### 2.1.1.3 杂记  
  
某信源这个漏洞是0day，后来因为客户要求，将细节给了某信源，某信源还特地发了公告：![](https://mmbiz.qpic.cn/mmbiz_png/CBJYPapLzSFqcLttTLqDkBibnPEtxNicxlRQeN9Q7PE007NPtLzjicYZJOLlewtvdJMePAo4BPXOqc6PVt5avzadg/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1&tp=wxpic "")  
  
  
具体漏洞分析过程见3.1  
### 2.1.2 某信源后台失陷的影响面  
  
shell在上传后，我们马上进行了处置，从某信源服务器进行拓展是来不及的，所以我们重点从某信源后台失陷后，攻击者都干了些什么来确定影响面。众所周知，某信源是终端管控系统，其最常用的攻击方法就是通过后台对管控的终端进行下发文件/执行命令等方式操作进行利用。于是在日志中找到相应的接口进行分析：![](https://mmbiz.qpic.cn/mmbiz_png/CBJYPapLzSFqcLttTLqDkBibnPEtxNicxlXlQPib9rYBgRGhTBawubMPWh5RM84k5szxu1OiaOyWEgmb8vDtg1M0nA/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1&tp=wxpic "")  
  
  
根据DeviceID可以确定出被攻击的机器具体是哪台，最终梳理出一个表，最后使用时间都在被攻击之前，如下：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/CBJYPapLzSFqcLttTLqDkBibnPEtxNicxl6eoCf6pYI9z12vwSOtph0Ja20CBounWIV12LSibnDGs8AKgNC8KdAvA/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1&tp=wxpic "")  
  
也不敢大意，在流量侧重点监控了几个IP的流量，没有明显异常行为，对PC都进行了查杀、进程、启动项、注册表分析，确认未被攻击者控制。此时已经凌晨3点多。  
  
第二天与客户沟通后发现，该VRV是用于VPN接入时进行管控的，而VPN在4月8日晚上已经关闭。  
### 2.1.3 10.*.*.*2失陷后的影响面  
  
该失陷主机在DMZ区，且开放对互联网的访问，所以大概率这就是首台被攻破的机器了。  
  
凌晨3点多，我同事还没有完整的梳理出该机器的影响面，于是我参与其中一起梳理。（PS：客户第二天一早要看到影响面，不敢怠慢）。  
  
分析思路：  
（1）以10.*.*.*2作为源IP，分析其对内网的整个访问流程中的异常流量。（2）分析10.*.*.*2上的木马文件、攻击者工具等文件，在分析影响面的同时也寻找被攻击的点。（3）关联服务器分析  
  
整个分析展开时，由于流量设备告警能力弱（可以说连SQL注入都不怎么告警），分析依靠蛮力介入的比较大。整体看下来就是扫描流量非常多，但分析是否成功实在工作量太大了。  
  
在扫描文件的时候，发现服务器上仍存在攻击队未删除的fscan扫描结果，如下：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/CBJYPapLzSFqcLttTLqDkBibnPEtxNicxl35bicwIBxtFp6q3O5Fk1yXU63AZic0BgXiaslEUnPPc99gdlg4FP0n5HQ/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1&tp=wxpic "")  
  
整理后，结合流量进行分析，发现攻击队共计探测到28台内网机器（含10.*.*.*2本身），其中存在漏洞的情况如下：  
- 10.*.*.*2 存在MS17-010漏洞（本机），DMZ区域做了策略优化，禁止了该区域内的445访问，所以其只能访问自己的445。  
  
- 10.*.*.*7 存在Druid未授权访问漏洞，未发现流量中有利用行为。  
  
- 10.*.*.*1 存在MySQL弱口令，未在流量中发现进一步漏洞利用。  
  
- 10.*.*.*5 存在某信源SQL注入0day  
  
- 10.*.*.*3 被成功登录了数据库  
  
其本身情况就是这样了，然后对其关联的服务器进行分析，因为该应用站库分离，用的是mssql，使用的是sa用户，IP为10.*.*.*3，在流量中也证实该机器被成功登录了mssql。那极有可能通过xp_cmdshell已经获取到了数据库服务器的权限。  
  
通过上机排查10.*.*.*3，发现xp_cmdshell已经被激活，但未从数据库日志里面找到xp_cmdshell被调用的记录，无法得知攻击队用xp_cmdshell做了什么。  
  
在流量侧对10.*.*.*3进行分析，仅发现其与10.*.*.*2（应用）有流量交互，不存在向内网扩散的行为。  
## 2.2 向外溯源，查找入口点  
  
之所以把对DMZ区域的攻击过程溯源放的比较靠后，是因为该机器出现问题后一直处于断网状态，所以不急着分析。  
### 2.2.1 寻找线索，发现端倪  
  
对于10.*.*.*2的被攻击的路径是一点线索也没有，所以上去先对进程、文件、定时任务、启动项、网络连接进行检查，状况如下：  
  
（1）定时任务、进程、启动项里面没有驻留的后门  
  
（2）网络连接只有外网访问该应用的，并没有由内向外的C2回连（因为不出  
网）  
  
（3）文件方面只发现了fscan，竟然没有发现webshell。  
  
此时可以说是一头雾水，又整理了一下手里的信息：  
  
（1）服务器处于DMZ区，向外提供服务  
  
（2）服务是e-mobile，当时未暴出0day（ps：溯源到的第二天细节公开了）  
  
（3）无文件落地，可能是用了内存马（ps：不排除攻击过程中有文件落地）  
  
于是，使用cop对内存马进行检测，如下：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/CBJYPapLzSFqcLttTLqDkBibnPEtxNicxl4sSfwOX0xaHLYC9UgTwwoIg8HyrqEuYTLjhbpuJXa6OGqZPXbn0Qibw/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1&tp=wxpic "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/CBJYPapLzSFqcLttTLqDkBibnPEtxNicxlniaMrUnk1DTcKNtPnRb1lREPIyQQa6Hdy5QzXaqg62icQUmre409E2MQ/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1&tp=wxpic "")  
  
果然发现了内存马，然后找到内存马对应的java文件，如下：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/CBJYPapLzSFqcLttTLqDkBibnPEtxNicxlYiaK9OnI1RpaiaLeAon56iaXtf2OjaiclnpQpMZ8myJLZlj0uLzicRe5LrQ/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1&tp=wxpic "")  
  
根据对样本进行分析，发现该内存马的特征流量为返回包的set-cookie中包含eagleeye-traceid字段，对流量中包含该特征的流量进行检索，如下：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/CBJYPapLzSFqcLttTLqDkBibnPEtxNicxlW1YRAgbzkNGZZfJLGLOv2ncSpDybd4s5A06KL7ghMEuIJ0MVJBdwzg/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1&tp=wxpic "")  
  
发现两个IP有过webshell连接的请求，随后对两个IP的的流量进行分析，发现两个IP的交互都很有目标,直接就连接了webshell，未发现其进行其他攻击操作。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/CBJYPapLzSFqcLttTLqDkBibnPEtxNicxlPakDDRMiawg82pMUCCnnKLceic5b2q8AJFdYiaPw8ZE5NfmJSZksIfz6Q/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1&tp=wxpic "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/CBJYPapLzSFqcLttTLqDkBibnPEtxNicxliaachqFsQYACcRtrnOUU4ic4O0P5EQibaffqcm7qtp3ciaMWicfNDWRbO6w/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1&tp=wxpic "")  
  
然后又开始了苦逼的分析。  
### 2.2.2 深入分析，找到过程  
  
通过对内存马访问前后流量的排查，未发现直接上传webshell的操作（服务没shell文件，不排除内存马植入后删除了木马，所以排查了webshell上传行为）。  
  
想到可能是直接执行代码将内存马加载到内存中的，搜索关键字loadClass，截图如下：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/CBJYPapLzSFqcLttTLqDkBibnPEtxNicxlNKzSC310KdC3rIibPmNw0DgrZM8nRFOY3FhOIpNDUcFBZx38icSovsdQ/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1&tp=wxpic "")  
  
从而定位到攻击IP和加载内存马的过程。根据攻击IP筛选，还原整个漏洞利用过程。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/CBJYPapLzSFqcLttTLqDkBibnPEtxNicxlhc0VdlqI8DByVtCUL7SKNxlzsS7cXOH5lKIknaknbiaU4TtwDr3IXXw/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1&tp=wxpic "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/CBJYPapLzSFqcLttTLqDkBibnPEtxNicxluqoRD4z01ZN0y4cCKXFDDIzvDeUH8so0JFucBz5erkfHW5dg7LTE3Q/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1&tp=wxpic "")  
  
漏洞为SQL注入，通过创建别名的方式执行java代码，将内存马的字节码文件写入到tmp目录下的tmpD591.tmp中，字节码文件较长，所以进行了多次追加写入，然后在最后调用java.net.URLClassLoader类将tmpD591  
.tmp字节码文件加载到内存中。  
  
随后上机排查，在tmp目录下发现tmpD591.tmp,截图如下：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/CBJYPapLzSFqcLttTLqDkBibnPEtxNicxlq1jL3DN6tZyicVGxbZd3icWlibgYBAHM7ickKNako5ibUWkOvKIibQ8KbOEw/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1&tp=wxpic "")  
  
通过对字节码文件进行分析，发现其中包含了一个名为resin.class的字节码文件。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/CBJYPapLzSFqcLttTLqDkBibnPEtxNicxl2ApZQKIjcI8a0VAZPLiaHyS7TT9vHbX6H52Ub9R9288UUzNO5piaKVwQ/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1&tp=wxpic "")  
  
通过分析代码，证实该文件是Resion的内存马。至此，整个溯源过程结束，跨时2天。  
# 0x03 漏洞分析  
## 3.1 E-moblie注入分析  
  
当我们在为发现两枚0day而窃喜的时候，第二天E-moblie这个漏洞就被公开了。下面是分析过程，看官们直接跳转，不赘述了。  
https://forum.butian.net/share/84  
## 3.2 某信源SQL注入分析  
  
找到漏洞文件，代码如下：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/CBJYPapLzSFqcLttTLqDkBibnPEtxNicxl3yQGLVicic1ITwR1ITBGxTsKsp2TYnGXWLESpp7PicbFmHNJNFHIjGdTg/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1&tp=wxpic "")  
  
通过反编译VRV的dll文件，找到该方法的实现：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/CBJYPapLzSFqcLttTLqDkBibnPEtxNicxlmTKhPAXDZ7TcOBPwPG46TXk1ffUxhGMU3YCcicIYIv3IspxwGBtE3HA/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1&tp=wxpic "")  
  
直接从request中拿到了navGuid参数，然后带入了GetListByNavGuid方法，跟踪该方法：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/CBJYPapLzSFqcLttTLqDkBibnPEtxNicxl9nd5ewZicJRg3uGLfDGSghDO8CjibBdspJL3FVjdcNDhMRxyYmMxSuoQ/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1&tp=wxpic "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/CBJYPapLzSFqcLttTLqDkBibnPEtxNicxlfN0DN80hFs2NK0kQBs4VfgW8PSraGkWfNUkWpUOicicpNb6Qmy0icl6iaQ/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1&tp=wxpic "")  
  
直接将参数拼接到SQL语句中产生的注入。  
# 0x04 总结  
  
时隔1年多，整理手中的材料时想拿出来做分享，部分过程没有找到相对应的截图。各位看官将就一下。站在上帝视角，回顾整个过程，颇有收获：  
  
（1）DMZ区的被攻破应用的数据库就在核心区域，而且核心区域访问关系不清晰，没有做严格的分级分域，里面全部互通。如果攻击队通过10.*.*.*3  
进行资产扫描，我们早就退场了。这也给了我以后打红队的启发。  
  
（2）在分析过程中，对于漏洞攻击过程的追求远大于对事件影响的排查，也庆幸在甲方的督促下，我注意到了其中的重要性。  
  
（3）关于项目开发，某信源对0day的解释是某项目的定制需求，定制需求还放在标准产品中，显然是审计工作不够充分。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/CBJYPapLzSFqcLttTLqDkBibnPEtxNicxlxgvYNb5101yJ6c624BjuHPuE6J1BQnicmn0xicYGbvAtiaardWJGTXnWA/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1&tp=wxpic "")  
  
  
（4）某信源系统多个不被人关注到的账号，都是123456这个弱密码。这类问题不止体现在某信源，其他产品也是，所以作为防守方应该注意这些问题。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/CBJYPapLzSFqcLttTLqDkBibnPEtxNicxlKkgMRiaIicKnqMdKPLPxTXVwkFnXZCbewlPcOicGjibhFrewibnSoNonySg/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1&tp=wxpic "")  
  
  

								  

									  

										  

											  
往期推荐  

										  

									  

									  

								[ 【推荐收藏】Linux&Windows应急响应+案例分析 (2024HW必备) ](http://mp.weixin.qq.com/s?__biz=MzA5MzYzMzkzNg==&mid=2650940887&idx=1&sn=f87f09a8d0cd12cd1a0244a1d7d8b0ef&chksm=8bac6928bcdbe03eb2bc4b090d94db8207e83cde383c515b997c9f395264adefc456da5bf1c9&scene=21#wechat_redirect)  

							  
  

								[ 一款用于生成各类免杀webshell工具 ](http://mp.weixin.qq.com/s?__biz=MzA5MzYzMzkzNg==&mid=2650940724&idx=1&sn=5fd180f6a914df79a5ea5ae913d9d4f5&chksm=8bac69cbbcdbe0dd615328ae59b9e549e53f30f496aa008add6ac7b06e15ad17a30029810045&scene=21#wechat_redirect)  

							  
  

								[ 十个查杀引擎免杀的PHP Webshell ](http://mp.weixin.qq.com/s?__biz=MzA5MzYzMzkzNg==&mid=2650940621&idx=1&sn=68378a60f817c34944f81ff4c1ddca25&chksm=8bac6832bcdbe1247ce18fc131285697665e1966b25a2a953145dc84329d8b8cc26cd05c027f&scene=21#wechat_redirect)  

							  
  

								[ 【Linux】常用提权总结-上篇 ](http://mp.weixin.qq.com/s?__biz=MzA5MzYzMzkzNg==&mid=2650940533&idx=1&sn=c66cd9975daa6f95b67306658a2a3bf1&chksm=8bac688abcdbe19c106a36d3a1826c628324e25beca67e88f497b822466771300dacfd803d2a&scene=21#wechat_redirect)  

							  
  

								[ 实战｜一次相当曲折又精彩的渗透 ](http://mp.weixin.qq.com/s?__biz=MzA5MzYzMzkzNg==&mid=2650940442&idx=1&sn=fce3be8143fb230545967bd5f69eec9a&chksm=8bac68e5bcdbe1f3143d29fd65fe3ddbb7d9a066f72186361084b64a3cb399aff81b0ed609e6&scene=21#wechat_redirect)  

							  
  

								[ 内网打靶-春秋云镜双靶场第二篇 ](http://mp.weixin.qq.com/s?__biz=MzA5MzYzMzkzNg==&mid=2650940279&idx=1&sn=8b1bbabe4434bad0d7440ca0d9e70ac0&chksm=8bac6f88bcdbe69e6f19f5c938edd97b0bef4e6db5a708afdd5eb09b45f804827524359bb11c&scene=21#wechat_redirect)  

							  
  

								[ 比Hydra快五十倍的暴力破解工具 ](http://mp.weixin.qq.com/s?__biz=MzA5MzYzMzkzNg==&mid=2650940174&idx=1&sn=7298896121b8a5ee9795522a10d99ef1&chksm=8bac6ff1bcdbe6e787e6837a52b82a35db03bb5a0b5a847a17b39648658d7d0593b14ecc17f2&scene=21#wechat_redirect)  

							  
  

								[ 渗透测试|记一次报错页面搞定zfb钓鱼网站 ](http://mp.weixin.qq.com/s?__biz=MzA5MzYzMzkzNg==&mid=2650940093&idx=1&sn=f2d86203bbd15ff84cbbe09fec7beb80&chksm=8bac6e42bcdbe7547c075f762b7433a4b58e633d0c1a5477c050623a859517b175a18df90f49&scene=21#wechat_redirect)  

							  
  

								[ 【Web实战】某头部直辖市攻防演练纪实-如何不用0day打下n个点 ](http://mp.weixin.qq.com/s?__biz=MzA5MzYzMzkzNg==&mid=2650940016&idx=1&sn=8b1053819125c3a860d7074c922ab003&chksm=8bac6e8fbcdbe799fa4a2c3c2b974886f7149bca209c483c74d6c9795b9f8004906e95b1fcc1&scene=21#wechat_redirect)  

							  
  

								[ 一款集成了JS接口提取漏洞扫描及内网渗透的工具-漏洞探测 ](http://mp.weixin.qq.com/s?__biz=MzA5MzYzMzkzNg==&mid=2650939863&idx=1&sn=8339d8ce24b178c7b1a0c5f2040bc8cc&chksm=8bac6d28bcdbe43e7f8b1f347194e3aea362e625075cdbe785598620a096accfdcde719bb486&scene=21#wechat_redirect)  

							  
  
  
  
声明：本公众号所分享内容仅用于网安爱好者之间的技术讨论，禁止用于违法途径，**所有渗透都需获取授权**  
！否则需自行承担，本公众号及原作者不承担相应的后果  
```
```  
  
