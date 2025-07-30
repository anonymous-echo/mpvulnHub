#  windows&linux中 命令执行的各种绕过方式   
原创 仙草里没有草噜丶  泷羽Sec   2024-10-26 10:26  
  
##### ~ 凡是过往，皆为序章 ~  
  
## 简介  
  
[星河飞雪网络安全人才培养计划，绝对零区，公益免费教学！](http://mp.weixin.qq.com/s?__biz=Mzg2Nzk0NjA4Mg==&mid=2247492422&idx=1&sn=b6e828a36ff9ae331f58cf466d130100&chksm=ceb1784bf9c6f15db2b5c51ced6640058054ad69ccda576f6a9dfb6a47267fe84f3d8e6a3b9a&scene=21#wechat_redirect)  
  
  
[【渗透测试】16个实用谷歌浏览器插件分享](http://mp.weixin.qq.com/s?__biz=Mzg2Nzk0NjA4Mg==&mid=2247491227&idx=1&sn=85391faa88bbcadf023c4eeec9dc957a&chksm=ceb28596f9c50c80f1090e7665b5ebd6d786539721a28b20c3bc39c8784c4084b8e3d62b2265&scene=21#wechat_redirect)  
  
  
学网安，来飞雪计划，欢迎关注b站【泷羽Sec】，免费渗透教学，社群答疑。  
  
本文将为介绍有关**windows和linux命令执行的时候各种绕过方式**，仅供参考，如果还有其他的绕过方式，还请师傅们留言，让更多想要学习网安的朋友们学习，感谢。  
## Windows  
  
我们在windows命令行中执行命令的时候，是不区分**大小写**的  
```
C:\>WHOAMI
yv\administrator

```  
  
在命令行中可以有无数个"  
```
C:\>wh""""oami
yv\administrator

C:\>wh""""""""""""""""""""""""""""""oami
yv\administrator

```  
  
不能有两个连续的^  
```
C:\>whoa^mi
yv\administrator

C:\>whoam^^i
'whoam^i' 不是内部或外部命令，也不是可运行的程序
或批处理文件。

C:\>who^a^m^i
yv\administrator

```  
  
在命令中如果 " 在^之前，此时"的**数量**必须为偶数  
```
C:\>who""a^mi
yv\administrator

C:\>who"a^mi
'who"a^mi' 不是内部或外部命令，也不是可运行的程序
或批处理文件。

```  
  
在命令中"在^之后，且带有参数，则”也需要带有偶数  
```
C:\>n^et" user
'net" user' 不是内部或外部命令，也不是可运行的程序
或批处理文件。

C:\>n^et"" user

\\YV 的用户帐户

-------------------------------------------------------------------------------
Administrator            DefaultAccount           Guest
mysql                    WDAGUtilityAccount       www
命令成功完成。

```  
  
也可以使用()对命令进行包裹  
```
C:\>(whoami)
yv\administrator

C:\>(n^et"" user)

\\YV 的用户帐户

-------------------------------------------------------------------------------
Administrator            DefaultAccount           Guest
mysql                    WDAGUtilityAccount       www
命令成功完成。

```  
  
()的数量不设上限  
```
C:\>(((whoami)))
yv\administrator

```  
### 使用变量  
  
简单拼接  
  
%%局部分开每个变量  
```
C:\>set cmd1=who

C:\>set cmd2=am

C:\>set cmd3=i

C:\>%cmd1%%cmd2%%cmd3%
yv\administrator

```  
  
变量拼接方式二  
```
C:\>set cmd1=who

C:\>set cmd3=i

C:\>%cmd1%am%cmd3%
yv\administrator

```  
  
变量拼接方式三  
```
C:\>set cmd1=wh"""o

C:\>set cmd3=i"""

C:\>%cmd1%am%cmd3%
yv\administrator

```  
  
变量拼接方式四 ^  
```
C:\>set cmd1=wh""""o    # 这里需要偶数，因为在变量拼接结果中有 ^ 

C:\>set cmd3=i"""    # 后面正常多少个 " 都行  

C:\>%cmd1%a^m%cmd3%
yv\administrator

```  
  
含有参数的命令，net user  
```
C:\>set cmd1=s""er

C:\>set cmd2=t u

C:\>set cmd3=n^e

C:\>%cmd3%%cmd2%%cmd1%

\\YV 的用户帐户

-------------------------------------------------------------------------------
Administrator            DefaultAccount           Guest
mysql                    WDAGUtilityAccount       www
命令成功完成。


```  
  
一次性执行多条命令  
```
C:\>cmd /C "set cmd1=s""ser && set cmd2=t u && set cmd3=n^e && %cmd3%%cmd2%%cmd1%"

\\YV 的用户帐户

-------------------------------------------------------------------------------
Administrator            DefaultAccount           Guest
mysql                    WDAGUtilityAccount       www
命令成功完成。

```  
### Windows环境变量切分  
  
先设置一个变量  
```
C:\>set cmd=whoami   

C:\>%cmd%    
yv\administrator

```  
  
这个0,1表示的**数组切片**，代表前后切片的索引  
```
C:\>set cmd=whoami

C:\>echo %cmd:~0,1%
w

C:\>echo %cmd:~0,4%
whoa

```  
  
也可以为负数，负数表示从右边开始数第几个  
```
C:\>set cmd=whoami

C:\>echo %cmd:~-4,4%
oami

C:\>echo %cmd:~-6,4%
whoa

```  
  
当然也能直接向外部写一个php一句话木马  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5975bXHXfWEW6rMtxXicvmdQdUiazgMsw9f01YqtDdDSsNkYOIPvuOuagINXkuW7cSiarDpLs97jV8aFHjPleohzw/640?wx_fmt=png&from=appmsg "")  
  
image-20240812113353901  
  
检查是否存在  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5975bXHXfWEW6rMtxXicvmdQdUiazgMsw95ET1hibhPYy3wvECVUtNj6HO8lm4VrEaaGSnZTCUCBnFb6UhfiaZibPtA/640?wx_fmt=png&from=appmsg "")  
  
image-20240812113248382  
  
for循环执行命令  
```
C:\>cmd /V:ON /C "set kpx=awlh2im,xiaoyu&& for %G in (1,3,-3,0,6,5) do set lq=!lq!!kpx:~%G,1!&& if %G==5 !lq:~4!"

C:\>set lq=!lq!!kpx:~1,1!  && if 1 == 5 !lq:~4!

C:\>set lq=!lq!!kpx:~3,1!  && if 3 == 5 !lq:~4!

C:\>set lq=!lq!!kpx:~-3,1!  && if -3 == 5 !lq:~4!

C:\>set lq=!lq!!kpx:~0,1!  && if 0 == 5 !lq:~4!

C:\>set lq=!lq!!kpx:~6,1!  && if 6 == 5 !lq:~4!

C:\>set lq=!lq!!kpx:~5,1!  && if 5 == 5 !lq:~4!
yv\administrator

```  
## Linux  
  
linux中是区分大小写的  
```
┌──(root㉿251ebe86465a)-[/]
└─# LS
LS: command not found

┌──(root㉿251ebe86465a)-[/]
└─# Ls
Ls: command not found

```  
  
运算符;表示连续指令，即使前面那条命令报错，后面也会接着执行  
```
┌──(root㉿251ebe86465a)-[/]
└─# LS;whoami
LS: command not found
root

```  
  
& 用于后台执行命令，这个可能看不出来  
```
┌──(root㉿251ebe86465a)-[/]
└─# ls&wHoami
[1] 59
archive-key.asc  boot  etc   lib    lib64  mnt  proc  run   srv  tmp  var
bin              dev   home  lib32  media  opt  root  sbin  sys  usr
Command 'Whoami' not found, did you mean:
  command 'whoami' from deb coreutils
Try: apt install <deb name>
[1]+  Done                    ls --color=auto

```  
  
我们使用ping 127.0.0.1 & whoami，这条命令会将ping放在后台执行，这个时候你没有设置ping的次数，就会一直执行下去，停止不了，而whoami已经执行完毕了。  
```
┌──(root㉿kali)-[/usr/local]
└─# ping 127.0.0.1& whoami
[1] 4508
root

PING 127.0.0.1 (127.0.0.1) 56(84) bytes of data.
64 bytes from 127.0.0.1: icmp_seq=1 ttl=64 time=5.80 ms
┌──(root㉿kali)-[/usr/local]
└─# 64 bytes from 127.0.0.1: icmp_seq=2 ttl=64 time=0.593 ms
64 bytes from 127.0.0.1: icmp_seq=3 ttl=64 time=0.049 ms
64 bytes from 127.0.0.1: icmp_seq=4 ttl=64 time=0.044 ms
64 bytes from 127.0.0.1: icmp_seq=5 ttl=64 time=0.058 ms
64 bytes from 127.0.0.1: icmp_seq=6 ttl=64 time=0.045 ms
--------之后将会一直运行下去，也停止不了。。。。

```  
  
&&连接两个指令的时候，要保证命令两个命令都能正常执行，否则一个错，就执行不了了  
```
┌──(root㉿251ebe86465a)-[/]
└─# ls&&whoami
archive-key.asc  boot  etc   lib    lib64  mnt  proc  run   srv  tmp  var
bin              dev   home  lib32  media  opt  root  sbin  sys  usr
root

┌──(root㉿251ebe86465a)-[/]
└─# LS&&whoami
LS: command not found

```  
  
|管道符：用于将一个命令的**输出**作为另一个命令的输入。它允许两个或多个命令之间传递数据。  
  
例如，我获取这个/data路径的下的所有包含boo的文件  
```
┌──(root㉿251ebe86465a)-[/]
└─# ls | grep '*boo*'
boot

```  
  
||逻辑运算符：如果||左边的命令执行失败（返回非零退出状态），那么||右边的命令将会被执行。执行成功一个命令后，后面的苏哦有命令都不会执行。  
```
┌──(root㉿251ebe86465a)-[/]
└─# ip addr || wHoami || ls
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host
       valid_lft forever preferred_lft forever
5: eth0@if6: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP group default
    link/ether 02:42:ac:11:00:02 brd ff:ff:ff:ff:ff:ff link-netnsid 0
    inet 172.17.0.2/16 brd 172.17.255.255 scope global eth0
       valid_lft forever preferred_lft forever

```  
  
转义字符\  
```
┌──(root㉿251ebe86465a)-[/]
└─# who\ami
root

```  
  
''，()，$，``  
```
┌──(root㉿251ebe86465a)-[/]
└─# who''ami
root

┌──(root㉿251ebe86465a)-[/]
└─# (whoami)
root

┌──(root㉿251ebe86465a)-[/]
└─# (who''ami)
root

┌──(root㉿251ebe86465a)-[/]
└─# `(echo whoami)`
root

┌──(root㉿251ebe86465a)-[/]
└─# $(echo whoami)
root

```  
  
命令引用  
```
┌──(root㉿kali)-[/data]
└─# t=l;j=s;$t$j             #相当于执行了 ls 
谷歌插件  GitHack  miku

```  
### linux特有变量  
  
$1，$*，$@，$n这个n表示除0以外的任意数字，都可以作为系统命令绕过的方式  
```
┌──(root㉿kali)-[/data]
└─# who$2ami
root

┌──(root㉿kali)-[/data]
└─# who$4ami
root

┌──(root㉿kali)-[/data]
└─# who$*ami
root

┌──(root㉿kali)-[/data]
└─# who$@ami
root

┌──(root㉿kali)-[/data]
└─# who$0ami
who-zshami：未找到命令

```  
### linux通配符  
  
我们以执行whoami这个命令来进行测试  
```
┌──(root㉿kali)-[/etc/docker]
└─# whereis whoami
whoami: /usr/bin/whoami /usr/share/man/man1/whoami.1.gz

┌──(root㉿kali)-[/etc/docker]
└─# /usr/bin/whoam*
root

┌──(root㉿kali)-[/etc/docker]
└─# /usr/bin/whoam?
root

┌──(root㉿kali)-[/etc/docker]
└─# /usr/bin/wh?am?
root

┌──(root㉿kali)-[/etc/docker]
└─# /usr/bin/????mi
root

┌──(root㉿kali)-[/etc/docker]
└─# /u?r/b?n/????mi
root

┌──(root㉿kali)-[/etc/docker]
└─# /*/b?n/????mi
root

```  
### Linux中命令中的命令  
  
虽然会报错，但是命令也会正常执行  
```
┌──(root㉿kali)-[/etc/docker]
└─# `666666`
666666：未找到命令

┌──(root㉿kali)-[/etc/docker]
└─# 666666`whoami`6666
666666root6666：未找到命令

┌──(root㉿kali)-[/etc/docker]
└─# `6666`whoami`6666`
6666：未找到命令
6666：未找到命令
root

┌──(root㉿kali)-[/etc/docker]
└─# 6666`whoami`6666
6666root6666：未找到命令

┌──(root㉿kali)-[/etc/docker]
└─# w`sfdawfewa`ho`sajfdkljas`am`sdjflk123`i
sfdawfewa：未找到命令
sajfdkljas：未找到命令
sdjflk123：未找到命令
root

┌──(root㉿kali)-[/etc/docker]
└─# wh${sdf}oam${ddkjdld}i
root

┌──(root㉿kali)-[/etc/docker]
└─# wh${sdf242341}oam${ddkjdld234232}i
root

```  
  
已上仅供参考，更多的还请自行百度了解  
#### 往期推荐  
  
[【RCE剖析】从0-1讲解RCE漏洞绕过，Windows与Linux/RCE漏洞绕过方式总结](http://mp.weixin.qq.com/s?__biz=Mzg2Nzk0NjA4Mg==&mid=2247488816&idx=1&sn=0664a58fa94b84e8bf8f7974169263ab&chksm=ceb28e3df9c5072b335bfcabcd62d67fd922935d3a32444bf7795302a499549b30369d203a3d&scene=21#wechat_redirect)  
  
  
[飞雪-网络安全见闻](http://mp.weixin.qq.com/s?__biz=Mzg2Nzk0NjA4Mg==&mid=2247492458&idx=1&sn=de3c51c29c6960c687befda0f8513c5c&chksm=ceb17867f9c6f171879edddad3749d5fba10e1a8323cd90671952dad3fd84b6b0d5d9314de2a&scene=21#wechat_redirect)  
  
  
[【内网渗透】免工具，内网、域内信息收集的40种方式总结](http://mp.weixin.qq.com/s?__biz=Mzg2Nzk0NjA4Mg==&mid=2247491058&idx=1&sn=ecf020c69fc944cd680c261140a3d202&chksm=ceb286fff9c50fe974e65956578fb0deabaf55fd0d362febf5bf1d19c8edf497989b15ad2532&scene=21#wechat_redirect)  
  
  
[PHP反序列化漏洞从入门到深入8k图文介绍，以及phar伪协议的利用](http://mp.weixin.qq.com/s?__biz=Mzg2Nzk0NjA4Mg==&mid=2247487816&idx=1&sn=6c20255c10d7fece96f504cd4bdf989f&chksm=ceb28a45f9c50353b765d305304ac74f1f7df5e70cdda8b6abc1ff9212101f466258560ed414&scene=21#wechat_redirect)  
  
  
[我是如何利用Typora写网络安全技术文章的，公众号格子背景又是如何做到的？](http://mp.weixin.qq.com/s?__biz=Mzg2Nzk0NjA4Mg==&mid=2247492406&idx=1&sn=b28a85786af68d5b3d67612b0594d7b8&chksm=ceb1783bf9c6f12d4cad8146d59a7fbe5a7ee149f4f36849c9173e9a94d0d6be83feebc4a9d2&scene=21#wechat_redirect)  
  
  
  
  
