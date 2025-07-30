> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzU4OTg4Nzc4MQ==&mid=2247506254&idx=1&sn=8945ac3b22b0e0ec85487c07f59e79bd

#  应急响应之linux 排查  
原创 Flag  网络安全实验室   2025-06-25 00:56  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/BSCWGKoGibicQqQMTyjnicFjCia9YMkHJRIC1ibOD4PfiahM3MiaKn8StibHq0furcHluYNFBYAqrUarmB9ZysgAoIM8JQ/640?wx_fmt=gif "")  
  
   
   
  
![](https://mmbiz.qpic.cn/mmbiz_gif/dleU3icGE4HiaFHOiaDmlLaNBpiadM7SUM0g0alQpGS1Hw30Ws9vWHhrgPhEZv8TH0jIJH2uB0J8qeGicNCgBN8hKLg/640?wx_fmt=gif "")  
  
  
后台回复“应急”，获取windows、linux应急响应资料、应急工具集  
  
最近发现一个不错的在线靶场，给大家推荐一下。       
  
玄机靶场地址：https://xj.edisec.net/  
  
**第一章 应急响应- Linux入侵排查**  

```
1.web目录存在木马，请找到木马的密码提交
2.服务器疑似存在不死马，请找到不死马的密码提交
3.不死马是通过哪个文件生成的，请提交文件名
4.黑客留下了木马文件，请找出黑客的服务器ip提交
5.黑客留下了木马文件，请找出黑客服务器开启的监端口提交
```

  
题目是linux的入侵排查，5个问题，提交格式为flag{***}。  
  
首先开启靶场环境，用xshell链接靶场。  

```
1.web目录存在木马，请找到木马的密码提交
```

  
题目1是web目录存在木马，这种情况我们先切换到web目录下，  
网站目录/var/www/html，通过ls -l可以看到许多.php文件，一般来说木木都会放在index.php或者一些特殊名字的php文件下面。打开1.php，发现里面有一段代码，<?php eval($ PoST[11);?>  熟悉的人都知道，这是标准的一句话木马。POST里面的就是木马连接密码。提交flag{1}就可以了。  
  
除了这种方法外，还可以通过find+grep命令查找木马常用函数eval()，或者assert（）。我们可以在网站目录下查找包含这个函数的php文件。  
  
find./ -name "*.php" | xargs grep "eval("  
  
![](https://mmbiz.qpic.cn/mmbiz_png/myXZGtxSCgDIApfltTHDOOTOERibTVLAuTRwS0ND72dibzyCPysC8Jd4r92toibsHsgiaLySIj8ruyibV6BkMLLQjDQ/640?wx_fmt=other&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
可以发现3个文件里都有eval函数。  
第一个题的答案就在1.php里面  
## 2.服务器疑似存在不死马，请找到不死马的密码提交  
  
第二个题是存在不死马，找到不死马密码。刚才我们看了1.php，还有index.php和shell.php，打开shell  
.php可以发现里面存在一些MD5字段，通过MD5在线工具解密后得到flag，提交得到正确答案。  
## 3.不死马是通过哪个文件生成的，请提交文件名  
  
查看index.php发现其每隔usleep(3000)就会生成一个.shell.php文件，从而使其达到不死马的条件，题目是哪个文件生成的，提交文件名即可。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/myXZGtxSCgDIApfltTHDOOTOERibTVLAuhEMFP9t1zgUljMCUaYj0Ricgibn9iagppNHcfYhwPNzeVXGR1M1xUO66A/640?wx_fmt=other&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
## 4.黑客留下了木马文件，请找出黑客的服务器ip提交  
  
一般来说木马文件是以.elf结尾，我们可以在网站目录下看到一个明显的  
'shell(1).elf'文件，打开看一下里面没找到IP地址。这种情况我们有2个方法，一是把文件通过xftp考下来，放到沙箱里跑一下，可以得到服务器IP地址，或者我们在虚拟机里运行一下，然后查看netstat -antlp，也可以得到回连的IP地址。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/myXZGtxSCgDIApfltTHDOOTOERibTVLAu45UxH12XF2hymp2hicaeXNj8dIIfv6T9fuRO6As4Mo0VepiamhFDPUJA/640?wx_fmt=other&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/myXZGtxSCgDIApfltTHDOOTOERibTVLAuqw2Tf3jzgA2yBicf8TPRlmtxUxQ75UJVRXTUFq6ytHO2b7F8wNw8OXQ/640?wx_fmt=other&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
**5.黑客留下了木马文件，请找出黑客服务器开启的监端口提交**  
  
上题查看IP的时候就能看到端口号了，直接提交即可。  
  
**总  结**  
  
这个题目用到的命令总结如下：  
  
cd  切换目录  
  
1．语法:cd 目录名  
  
2．功能：改变工作目录。将当前工作目录改变到指定的目录下。  
  
举例：cd … : 返回上级目录 cd /home/litao/linux/ : 绝对路径  
  
cd …/day02/ : 相对路径  
  
cd ~：进入用户家目  
  
cd -：返回最近访问目录  
  
补充知识：  
  
从根目录中去找某一个文件称为绝对目录  
  
以当前路径为参照物，找文件成为相对路径  
  
find**语法**  
  
find [路径] [匹配条件] [动作]  
  
**参数说明**  
 :  
  
**路径**  
 是要查找的目录路径，可以是一个目录或文件名，也可以是多个路径，多个路径之间用空格分隔，如果未指定路径，则默认为当前目录。  
  
·  
-name pattern  
：按文件名查找，支持使用通配符  
 * 和 ?  
。  
  
·  
-type type  
：按文件类型查找，可以是  
 f  
（普通文件）、  
d  
（目录）、  
l  
（符号链接）等。  
  
·  
-size [+-]size[cwbkMG]  
：按文件大小查找，支持使用  
 + 或 - 表示大于或小于指定大小，单位可以是 c  
（字节）、  
w  
（字数）、  
b  
（块数）、  
k  
（  
KB）、M  
（  
MB）或 G  
（  
GB）。  
  
·  
-mtime days  
：按修改时间查找，支持使用  
 + 或 - 表示在指定天数前或后，days 是一个整数表示天数。  
  
·  
-user username  
：按文件所有者查找。  
  
·  
-group groupname  
：按文件所属组查找。  
  
**动作:**  
可选的，用于对匹配到的文件执行操作，比如删除、复制等。  
  
find 命令中用于时间的参数如下：  
  
·  
-amin n  
：查找在  
 n 分钟内被访问过的文件。  
  
·  
-atime n  
：查找在  
 n*24 小时内被访问过的文件。  
  
·  
-cmin n  
：查找在  
 n 分钟内状态发生变化的文件（例如权限）。  
  
·  
-ctime n  
：查找在  
 n*24 小时内状态发生变化的文件（例如权限）。  
  
·  
-mmin n  
：查找在  
 n 分钟内被修改过的文件。  
  
·  
-mtime n  
：查找在  
 n*24 小时内被修改过的文件。  
  
在这些参数中，  
n 可以是一个正数、负数或零。正数表示在指定的时间内修改或访问过的文件，负数表示在指定的时间之前修改或访问过的文件，零表示在当前时间点上修改或访问过的文件。  
  
**正数应该表示时间之前，负数表示时间之内。**  
### 实例  
  
查找当前目录下名为  
 file.txt 的文件：  
  
find . -name file.txt  
  
将当前目录及其子目录下所有文件后缀为**.c**  
 的文件列出来:  
  
# find . -name "*.c"  
  
将当前目录及其子目录中的所有文件列出：  
  
# find . -type f  
  
查找  
 /home 目录下大于 1MB 的文件：  
  
find /home -size +  
1M  
  
查找  
 /var/log 目录下在 7 天前修改过的文件：  
  
find /  
var  
/log -mtime +  
7  
  
查找过去  
 7 天内被访问的文件:  
  
find /path/to/search -atime -  
7  
  
在当前目录下查找最近  
 20 天内状态发生改变的文件和目录:  
  
# find . -ctime 20  
  
将当前目录及其子目录下所有  
 20 天前及更早更新过的文件列出:  
  
# find . -ctime +20  
  
查找  
 /var/log 目录中更改时间在 7 日以前的普通文件，并在删除之前询问它们：  
  
# find /var/log -type f -mtime +7 -ok rm {} \;  
  
查找当前目录中文件属主具有读、写权限，并且文件所属组的用户和其他用户具有读权限的文件：  
  
# find . -type f -perm 644 -exec ls -l {} \;  
  
查找系统中所有文件长度为  
 0 的普通文件，并列出它们的完整路径：  
  
# find / -type f -size 0 -exec ls -l {} \;  
  
找并执行操作（例如删除）：  
  
find /path/to/search -name   
"pattern"  
 -  
exec  
 rm {} \;  
  
这个例子中，**-exec**  
 选项允许你执行一个命令，**{}**  
 将会被匹配到的文件名替代，**\;**  
 表示命令结束。  
  
  
  
  
**网络安全攻防实验室**  
  
《网络安全攻防实验室》专注于网络安全领域，包括安全岗位招聘、网络攻防对抗、红蓝队建设、CTF比赛、安全运营规划、安全技术分享等，目前帮会笔记数量近6000，全是干货笔记。  
  
**1**  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/HaJr68L1tTTyCC8O1Oa7QCNiaQwscfJqPCZib6GkcFrg9UiazicTe9PZdDEwZ111UTxdTXXrgeUzibuo6AQiaMuKTpNg/640?wx_fmt=gif&from=appmsg "")  
  
**参与项目即可回本**  
  
**现在加入帮会，就能参与兼职项目，即刻回本，每月稳定赚吃饭钱！**  
不仅是这一个项目，后面帮会陆续接手更多兼职项目，**赚钱路径只多不少**  
。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/HaJr68L1tTTyCC8O1Oa7QCNiaQwscfJqPLxib1noMpr7Oiba9oiar12G182OrtVEyhBKOF5JRfQribefYrcibFwtTPnQ/640?wx_fmt=png&from=appmsg "")  
  
**2**  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/HaJr68L1tTTyCC8O1Oa7QCNiaQwscfJqPCZib6GkcFrg9UiazicTe9PZdDEwZ111UTxdTXXrgeUzibuo6AQiaMuKTpNg/640?wx_fmt=gif&from=appmsg "")  
  
**帮会内容框架**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/HaJr68L1tTTyCC8O1Oa7QCNiaQwscfJqPc633wShEAvkeYvSgS6XcynVWqNNuwLnnkN8hek3BYogkhCMtQicjsXg/640?wx_fmt=png&from=appmsg "")  
  
**3**  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/HaJr68L1tTTyCC8O1Oa7QCNiaQwscfJqPCZib6GkcFrg9UiazicTe9PZdDEwZ111UTxdTXXrgeUzibuo6AQiaMuKTpNg/640?wx_fmt=gif&from=appmsg "")  
  
**帮会已有内容**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/HaJr68L1tTTyCC8O1Oa7QCNiaQwscfJqPcJhNQbsmxAqW2J1Vz23y9Q9Ria5dUHT07IjVxEYeIPvaLSGhEbW2c9Q/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/HaJr68L1tTTyCC8O1Oa7QCNiaQwscfJqPKibXI3AuY5iaMe1351iaXo0wCsicpus841x4rcLia6beuNSVX5CRqLPs99g/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/HaJr68L1tTTyCC8O1Oa7QCNiaQwscfJqPCHRHeTg97DMpdYdFXCHStIFAicXfv8waFYYZHTqojX6jGjOxQyXZe9w/640?wx_fmt=png&from=appmsg "")  
  
**4**  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/HaJr68L1tTTyCC8O1Oa7QCNiaQwscfJqPCZib6GkcFrg9UiazicTe9PZdDEwZ111UTxdTXXrgeUzibuo6AQiaMuKTpNg/640?wx_fmt=gif&from=appmsg "")  
  
**目前已更新2000+干货笔记**  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/myXZGtxSCgAD68mr5vZ95bDtXggmkJrWSVicxpsnkGxjia1PVhCAUssBEsrRRJOO2p6bhkB9RgkBs7ElUVtRiaicQg/640?wx_fmt=jpeg&from=appmsg "")  
  
**5**  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/HaJr68L1tTTyCC8O1Oa7QCNiaQwscfJqPCZib6GkcFrg9UiazicTe9PZdDEwZ111UTxdTXXrgeUzibuo6AQiaMuKTpNg/640?wx_fmt=gif&from=appmsg "")  
  
**加入帮会，你可获得：**  
  
1. 各类网络安全攻防、CTF比赛信息、解题工具、技巧、书籍、靶场等资源；  
  
1. 攻防思维导图，0基础开启网络安全学习之路；  
  
1. 参与FreeBuf知识大陆官方专属兼职项目，开启兼职赚钱之旅；  
  
1. 遇到任何技术题都快速提问与讨论交流的思路；  
  
1. 组织队伍参与各类CTF比赛；  
  
1. 面试大厂心得及内推资格；  
  
1. 学习规划、人生规划也可以探讨哦！  
  
  
  
  
  
**（三）部分内容资源展示**  
  
**01**  
  
**HW/攻防对抗**  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/HaJr68L1tTTyCC8O1Oa7QCNiaQwscfJqPQ8PZFCOON9dZhwiaRuN3Y8NAGwWQRwY4KJbuyUbB5bgRvv2an2rVzyw/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/HaJr68L1tTTyCC8O1Oa7QCNiaQwscfJqPGr4HKrjlHRBSeAIAJKs1yL1ibiaNCDagL5QAjagsxGLiaGlk3JwXMVClw/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/HaJr68L1tTTyCC8O1Oa7QCNiaQwscfJqPfBaUCuxF9TJEUMs6Gy6ibr2REMibS1Y4c24hC40XxvcLDPNG0eLR0fNg/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/HaJr68L1tTTyCC8O1Oa7QCNiaQwscfJqPY2lIXljXickB5zJ5z3sreE9RngmN54L7XtpbE2Fosg8ddpMB7hTSQXw/640?wx_fmt=png&from=appmsg "")  
  
**02**  
  
**分析研判**  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/HaJr68L1tTTyCC8O1Oa7QCNiaQwscfJqPBDdUSm49JDKmPGQjVadZUeqXb0wz9iaOoN1xHmLbnPYOgUBwVJvcOwg/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/HaJr68L1tTTyCC8O1Oa7QCNiaQwscfJqPlhoEPIoOL644iciaVQdpFaQW5SrXic7d40j8ibU0ViaLslo0znoXyIgkQwg/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/HaJr68L1tTTyCC8O1Oa7QCNiaQwscfJqPOJZYMvGLzobTymHWCc62uv7wsgmYIRC5nlJ9TficNmMROthkcHqIicbA/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/HaJr68L1tTTyCC8O1Oa7QCNiaQwscfJqPEIJOEGEnmia37rUOLnN5wqjibADoiarv0ubO5VnVOwicdLpcQdacooQiaXA/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/HaJr68L1tTTyCC8O1Oa7QCNiaQwscfJqPtUXW4yQicEKH2Zro2r79hZTCYoefZVMcQqjbH0ds38bpCtVBJZVsSMQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/HaJr68L1tTTyCC8O1Oa7QCNiaQwscfJqPXic1A0Q5M7V072B5VJHibylT8lTpo5dMWWdt0BjVicchYc81RGxNoia8hw/640?wx_fmt=png&from=appmsg "")  
  
**03**  
  
**APP渗透**  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/HaJr68L1tTTyCC8O1Oa7QCNiaQwscfJqPodPPms90IV3ZGY50xH9UBLLdy6CibXIuH3K1hcZDvOPMz5Zf0dpNTKQ/640?wx_fmt=png&from=appmsg "")  
  
**04**  
  
**POC/EXP合集**  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/HaJr68L1tTTyCC8O1Oa7QCNiaQwscfJqPMtzuPCrqAia08t8LUjSeQSfS9XiccicO0oNrO06uPiczxmN1pBeLkLhcXg/640?wx_fmt=png&from=appmsg "")  
  
**05**  
  
**网络安全报告**  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/HaJr68L1tTTyCC8O1Oa7QCNiaQwscfJqPOnWnHDQmibQqMGw1N2x5gbian9icAXKRSjdXbrX6rqPaUWiciaoFxNDGK9w/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/HaJr68L1tTTyCC8O1Oa7QCNiaQwscfJqPzloPvFHp9IibLCFKZzhNZWZfsS2W3stibib2zWQVuMrCjeAcaUGhg7cUQ/640?wx_fmt=png&from=appmsg "")  
  
**06**  
  
**CTF学习资料**  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/HaJr68L1tTTyCC8O1Oa7QCNiaQwscfJqPhlo1pkE12GjjVbLicicV9jmhibCWF9R7gPibxyoSgxY7DIWzzSfTqShGXg/640?wx_fmt=png&from=appmsg "")  
  
**07**  
  
**红蓝队、CTF工具包**  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/HaJr68L1tTTyCC8O1Oa7QCNiaQwscfJqPLzibPfWmibwDf1uZicvXW1e8oaHbdtcerYSzuKvhNBdTNw2WOPLdw4zicg/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/HaJr68L1tTTyCC8O1Oa7QCNiaQwscfJqPKrfQoibcRS1xmWlzogWazU6ibKRiamOXM7ITUvnzq5P1x4sCvOZDZTl9g/640?wx_fmt=png&from=appmsg "")  
  
**08**  
  
**网络安全学习笔记**  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/HaJr68L1tTTyCC8O1Oa7QCNiaQwscfJqPbSQLgpwibFn2GlAgXQ8d23ZCRgJvfJV201ThsFWPOkdibNvWFeTbsRKQ/640?wx_fmt=png&from=appmsg "")  
  
  
  
  
**（四）帮会资源与服务**  
  
**1**  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/HaJr68L1tTTyCC8O1Oa7QCNiaQwscfJqPCZib6GkcFrg9UiazicTe9PZdDEwZ111UTxdTXXrgeUzibuo6AQiaMuKTpNg/640?wx_fmt=gif&from=appmsg "")  
  
**帮会网盘**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/HaJr68L1tTTyCC8O1Oa7QCNiaQwscfJqPSWj0LEcs4sUGMnVrwI1E8FxIEgxffvABK1fgQODzyTXMClKPWGiaUMw/640?wx_fmt=png&from=appmsg "")  
  
**2**  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/HaJr68L1tTTyCC8O1Oa7QCNiaQwscfJqPCZib6GkcFrg9UiazicTe9PZdDEwZ111UTxdTXXrgeUzibuo6AQiaMuKTpNg/640?wx_fmt=gif&from=appmsg "")  
  
**帮会专属兼职项目**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/HaJr68L1tTTyCC8O1Oa7QCNiaQwscfJqPLxib1noMpr7Oiba9oiar12G182OrtVEyhBKOF5JRfQribefYrcibFwtTPnQ/640?wx_fmt=png&from=appmsg "")  
  
**3**  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/HaJr68L1tTTyCC8O1Oa7QCNiaQwscfJqPCZib6GkcFrg9UiazicTe9PZdDEwZ111UTxdTXXrgeUzibuo6AQiaMuKTpNg/640?wx_fmt=gif&from=appmsg "")  
  
**内部社群技术交流**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/HaJr68L1tTTyCC8O1Oa7QCNiaQwscfJqPR9TktRDFO4nO0iaqUxFicdCydwTx0N4nQQa6C4tGCM1UdOhibjKHje54w/640?wx_fmt=png&from=appmsg "")  
  
**4**  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/HaJr68L1tTTyCC8O1Oa7QCNiaQwscfJqPCZib6GkcFrg9UiazicTe9PZdDEwZ111UTxdTXXrgeUzibuo6AQiaMuKTpNg/640?wx_fmt=gif&from=appmsg "")  
  
**帮会技术力量保证**  
  
帮主：网络安全攻防实验室  
- 「网络安全攻防实验室」的帮主；  
  
- 公众号“网络安全实验室”的作者；  
  
- 资深安全专家，16年网安经验；  
  
- 拥有丰富的HW、重大保障、应急响应、安全运营、网络交换等方面经验/独特见解。  
  
  
  
  
**（五）加入方式**  
  
**目前秉持着打造**  
**人多热闹****的帮会理念，**  
  
**永久会员只需119元，**  
  
**之后随人数增长，将涨价至149元。**  
  
如何加入帮会？  
  
- PC端可进入链接：  
  
https://wiki.freebuf.com/societyDetail?society_id=168  
  
- 也可直接微信扫码支付↓↓  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/myXZGtxSCgDAOibXuKD4fnP2A0Y5mAicyK59BZ8XAThzEYEYeU1v6x1Im8ClPPG91K06rHYSl9Qg9ibv0EGmcoEMQ/640?wx_fmt=jpeg&from=appmsg "")  
  
  
**加入帮会的师傅们，可以看帮会置顶加入兼职项目赚钱哦**  
  
  
