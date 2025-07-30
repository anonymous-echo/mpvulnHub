#  春秋云镜靶场Initial_WP   
原创 t3  ZeroPointZero安全团队   2025-02-08 06:34  
  
![](https://mmbiz.qpic.cn/mmbiz_png/vTLDcxb9m5Hq09lO4ZRiapmzBstkjCxicffoScBIJvAPdhOn9z87EpSX0QV7ymiceCcfKcAH48JAsBawTJpvJOtFw/640?wx_fmt=png&from=appmsg "")  
  
此靶机只需要交一个  
flag  
，而把这个  
flag  
分成  
3  
段，分别位于每个靶机的用户下.  
  
###   
  
![](https://mmbiz.qpic.cn/mmbiz_gif/vTLDcxb9m5Hq09lO4ZRiapmzBstkjCxicfO4ZDe6wnFLOSARgnPhwnWrJoNugCs5zAWNAqHERwq9GG9koOlIZgbg/640?wx_fmt=gif&from=appmsg "")  
  
**FLAG1：**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/vTLDcxb9m5Hq09lO4ZRiapmzBstkjCxicfukUBemUtvnOuFjMMDgkdhC6ZnEV7LcOuSA4v2sKvRag1tsh4f6N67A/640?wx_fmt=png&from=appmsg "")  
  
  
访问服务可以看见映入眼帘的ThinkPhP框架  
  
![](https://mmbiz.qpic.cn/mmbiz_png/vTLDcxb9m5Hq09lO4ZRiapmzBstkjCxicfjWQO2pjZ7EAhnQicPiaQ6ib4jzwv8uboyShvdefrlLF8SMKcHy6nIegZA/640?wx_fmt=png&from=appmsg "")  
  
直接掏出我们的Thinkphp一把梭工具，造！  
  
![](https://mmbiz.qpic.cn/mmbiz_png/vTLDcxb9m5Hq09lO4ZRiapmzBstkjCxicficAia6lys5Imgw26AMviaJ8FMvpP9zlBrNVff7WsV8XtpMzpACMJH0hsQ/640?wx_fmt=png&from=appmsg "")  
![](https://mmbiz.qpic.cn/mmbiz_png/vTLDcxb9m5Hq09lO4ZRiapmzBstkjCxicfLKkA8h4keERTaNWYr0s6mBhmb1vLunohULyNSoficXTBAWPH3NndNOQ/640?wx_fmt=png&from=appmsg "")  
  
成功连上webshell后进行简单信息收集，发现mysql数据库root是无需密码登录  
  
![](https://mmbiz.qpic.cn/mmbiz_png/vTLDcxb9m5Hq09lO4ZRiapmzBstkjCxicfiaSGJFuWDP4ERZNrJ7c6J7OnaJWe52nCOycMYcIKAOpytB4zHqDwQxA/640?wx_fmt=png&from=appmsg "")  
  
但是连接上去发现无法进行任何操作但是就是成功连接（很奇怪没搞懂）  
```
#查询suid
Find / -perm -u=s
-type=f 2>/dev/null
 
#查询sudo
Sudo -l
```  
  
  
然后呢搜了一下suid和sudo发现了一个可以将当前www-data提取到root的点：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/vTLDcxb9m5Hq09lO4ZRiapmzBstkjCxicfguibZv5icz3c6l1tVoqDQKxLKlarWwvRib9avDCYEjSaYJOIHKZibDwiaag/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/vTLDcxb9m5Hq09lO4ZRiapmzBstkjCxicfK2fEt9YibyadicibM4icVuxjYiaD1Md8NXnHknbRJrHbqy4iaaMuXAHkiciaicw/640?wx_fmt=png&from=appmsg "")  
  
并结合https://gtfobins.github.io/  
  
![](https://mmbiz.qpic.cn/mmbiz_png/vTLDcxb9m5Hq09lO4ZRiapmzBstkjCxicfhJ1KU7IUTkRXWt5v5eRYpkCOL5wW6jx9CiacFbm6FLWvbgCcZfqH5jQ/640?wx_fmt=png&from=appmsg "")  
  
成功提权，并反弹root权限到公网主机  
  
![](https://mmbiz.qpic.cn/mmbiz_png/vTLDcxb9m5Hq09lO4ZRiapmzBstkjCxicfHfoc58w4POGWkGpW1bicIP6awicPYtgWGja2dCnS7QkAVOjFCQ4eCYvQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/vTLDcxb9m5Hq09lO4ZRiapmzBstkjCxicf6ncp1mBXS3yKOcRj7Ff2YY3awZLmghQcylFgVB9Lm8dphE8Jcl1xpw/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/vTLDcxb9m5Hq09lO4ZRiapmzBstkjCxicfwumBCkesMDv1ZiaRPw3QibvlgHlaibzjQEJGh3aIFqmicibNa3XSOlthUgw/640?wx_fmt=png&from=appmsg "")  
  
获取第一部分flag： flag{60b53231-，题目又提示下一部分在网络中，那说明内网存在其他机器  
  
开始扫描内网准备，通过python3进行一波shell的加固让他ctrl+c时不会掉线  
```
$ python3 -c 'import pty; pty.spawn("/bin/bash")'  
//启用python交互式
# 把它丢到后台挂起
$ ctrl + z   
# 重置stty，也就意味着你看不到输入的内容
$ stty raw -echo  
# 把后台挂起的程序调回前台
$ fg   
# 接下来设置环境变量，根据第一步得到的环境变量来设置
$ export SHELL=bash   
$ export TERM=xterm-256color
```  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/vTLDcxb9m5Hq09lO4ZRiapmzBstkjCxicfeBAIk8rpTgicTyNPDoSIB8icKgF1icw2mqEm4nU4ibSWgiadaybdkSM1v3w/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/vTLDcxb9m5Hq09lO4ZRiapmzBstkjCxicf40GM9CPib2wL0Sok7KKOO23Bg8j6CZPB2uMKPduv6gvb6SicEBzPUzWw/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/vTLDcxb9m5Hq09lO4ZRiapmzBstkjCxicfQ6jG535S9KpciaO7bpoCib3ibY9dzicJ6kOLyWos5ibs3vlgEka03UDhRfw/640?wx_fmt=png&from=appmsg "")  
  
开始想通过编写了一些sh脚本探测内网，结果发现无法探测，后面老实了fscan一把唆：  
  
先通过python3启动http进行fscan的上传（原本想直接github拉取，多简单）  
  
![](https://mmbiz.qpic.cn/mmbiz_png/vTLDcxb9m5Hq09lO4ZRiapmzBstkjCxicfFRQ2arice7mmH5HpNGOgJ32bpM0BQd00dqUkAGttkb7kXIzcvAqRl3Q/640?wx_fmt=png&from=appmsg "")  
  
成功上传赋予权限一把梭开始：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/vTLDcxb9m5Hq09lO4ZRiapmzBstkjCxicfNYATibFQntomqlGIfUmjeGibcIPhe8sjMArDtKHN9xegBmMzwpdKt7PA/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/vTLDcxb9m5Hq09lO4ZRiapmzBstkjCxicfRBGOicN5Vsmw3IADW71uXmfS9hvrYM4ZX3yymy9fEPLbzaHE8PmUu5g/640?wx_fmt=png&from=appmsg "")  
  
还得是fscan舒服。  
  
###   
  
![](https://mmbiz.qpic.cn/mmbiz_gif/vTLDcxb9m5Hq09lO4ZRiapmzBstkjCxicfO4ZDe6wnFLOSARgnPhwnWrJoNugCs5zAWNAqHERwq9GG9koOlIZgbg/640?wx_fmt=gif&from=appmsg "")  
  
**Flag2：**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/vTLDcxb9m5Hq09lO4ZRiapmzBstkjCxicfukUBemUtvnOuFjMMDgkdhC6ZnEV7LcOuSA4v2sKvRag1tsh4f6N67A/640?wx_fmt=png&from=appmsg "")  
  
###   
  
已经确定内网的机器  
  
2是DC域控  
  
21  
是域下机器，存在  
ms17-010  
  
18是oa  
  
15是当前跳板  
  
开始搭建frp隧道将攻击机带入内网漫游  
  
客户端配置：  
```
serverAddr ="**********"
serverPort = 7000
 
[[proxies]]
name =
"socks5"
type =
"tcp"
remotePort =
30333
[proxies.plugin]
type =
"socks5"
```  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/vTLDcxb9m5Hq09lO4ZRiapmzBstkjCxicfez24X5XsUnsXsFSd51XInLjy3N5XiahZ5jWg6apLQc6RH4L8YDYsjXA/640?wx_fmt=png&from=appmsg "")  
  
直接连接socks  
  
访问18oa，发现是信呼oa且存在弱口令：admin/admin123  
  
![](https://mmbiz.qpic.cn/mmbiz_png/vTLDcxb9m5Hq09lO4ZRiapmzBstkjCxicfZBpapgtGa9WGJKP30ZiaoHCSOKoEDmp1jLSsNapJaPKgUeSKFmBPO2w/640?wx_fmt=png&from=appmsg "")  
  
百度发现getshell，然后尝试利用  
  
![](https://mmbiz.qpic.cn/mmbiz_png/vTLDcxb9m5Hq09lO4ZRiapmzBstkjCxicfvQZw9ljFhVBsvX2Fvl6icibLyQYLP3JAZmOweWfmatBTYgFJ8KUGBuQA/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/vTLDcxb9m5Hq09lO4ZRiapmzBstkjCxicfxHBZ4CTfmPdQ0LpWiafI2BRsictBoSzfgZBS3dNgFicvnmJxoEx474eBg/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/vTLDcxb9m5Hq09lO4ZRiapmzBstkjCxicfabFe8DdYIrocd5PhKxGh6SFYSBVbAhjpOHL9Qdic1sFENdqibuu8fZBQ/640?wx_fmt=png&from=appmsg "")  
  
大概原理就是你上传的php不在白名单，就会重命名后缀为.uptemp，但是如果访问task并带入上传文件的id，就会将源文件后缀还原 从而上传成功。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/vTLDcxb9m5Hq09lO4ZRiapmzBstkjCxicfqZRW4YztCrBCN6ibczHqfCwa7CY3vTS2pr3h9jQHWT0kbnBlS2SRtsA/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/vTLDcxb9m5Hq09lO4ZRiapmzBstkjCxicf22BCYw7kthomnjDwwgTREia3z3MNBUXcZmZPK6omibYr9BN43BhH62BA/640?wx_fmt=png&from=appmsg "")  
  
读取到第二部分flag：2ce3-4813-87d4-  
  
然后提示又叫我们去打打域控，然后回头看看发现就很有可能是ms17-010那个机器是打域控的跳板  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/vTLDcxb9m5Hq09lO4ZRiapmzBstkjCxicfO4ZDe6wnFLOSARgnPhwnWrJoNugCs5zAWNAqHERwq9GG9koOlIZgbg/640?wx_fmt=gif&from=appmsg "")  
  
**Flag3：**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/vTLDcxb9m5Hq09lO4ZRiapmzBstkjCxicfukUBemUtvnOuFjMMDgkdhC6ZnEV7LcOuSA4v2sKvRag1tsh4f6N67A/640?wx_fmt=png&from=appmsg "")  
  
  
直接msfconse一把梭ms17-010  
  
![](https://mmbiz.qpic.cn/mmbiz_png/vTLDcxb9m5Hq09lO4ZRiapmzBstkjCxicfpuXcK3EKGY04CW71SOdNXHSUNAVkJSNZJRa0rxeqSTTMDIbSWU9DRw/640?wx_fmt=png&from=appmsg "")  
  
通过DCSync（其实就是当前服务器账户拥有活动目录的复制和读取权限，并通向域控发送同步活动目录让域控认为你也是域控机器 ，从而向你同步数据）进行dumphash，成功获取域管hash，探测时也发现DC是开启445端口和139端口的，直接 psexec后着smbexec横向到DC上  
  
![](https://mmbiz.qpic.cn/mmbiz_png/vTLDcxb9m5Hq09lO4ZRiapmzBstkjCxicfhlnSUzGbrSGDiaLVIRWk84Fh8zqYKL58icQhJwEK6B0icfOsXFx9hF2Ug/640?wx_fmt=png&from=appmsg "")  
  
拿到最后一个flag：-e8f88d0d43d6}  
  
![](https://mmbiz.qpic.cn/mmbiz_png/vTLDcxb9m5Hq09lO4ZRiapmzBstkjCxicfK9ia3jWDqUENGSCXpF6ypibFWHcYl1NtoArxA8bcAsmbChUCQqhLcejw/640?wx_fmt=png&from=appmsg "")  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/vTLDcxb9m5Hq09lO4ZRiapmzBstkjCxicfO4ZDe6wnFLOSARgnPhwnWrJoNugCs5zAWNAqHERwq9GG9koOlIZgbg/640?wx_fmt=gif&from=appmsg "")  
  
**总结：**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/vTLDcxb9m5Hq09lO4ZRiapmzBstkjCxicfukUBemUtvnOuFjMMDgkdhC6ZnEV7LcOuSA4v2sKvRag1tsh4f6N67A/640?wx_fmt=png&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/vTLDcxb9m5Hq09lO4ZRiapmzBstkjCxicft4ambia3LgsxqrxmibculJAjJEZyaeiczzJwWvniaOH3M1kozoS4hJIzgA/640?wx_fmt=gif&from=appmsg "")  
  
靶机基本上都是一把梭，唯一可能花时间的就是加固shell和frp流量的设置，算是比较简单的靶机。  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/vTLDcxb9m5Hq09lO4ZRiapmzBstkjCxicfy9CuboYvZ5pfvqMlhSDZfoFcxq7wLCJqXsn7r1mFXyZAW9atUj7BkA/640?wx_fmt=gif&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/vTLDcxb9m5Hq09lO4ZRiapmzBstkjCxicfZrJnicUSmauHzZicalTZvJicIBJbL222kOOV8PSNwZRoWLEypJYvJicxvw/640?wx_fmt=jpeg&from=appmsg "")  
  
注：ZeroPointZero安全团队有对此文章的修改和解释权。如欲转载或传播此文章，必须保证此文章的完整性，包括版权声明等全部内容。未经允许，不得任意修改或者增减此文章内容，不得以任何方式将其用于商业目的  
  
  
