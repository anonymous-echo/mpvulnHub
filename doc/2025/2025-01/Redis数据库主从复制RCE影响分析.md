#  Redis数据库主从复制RCE影响分析   
NEURON  SAINTSEC   2025-01-30 10:00  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Gw8FuwXLJnTUBMAW5xdbMBnhCV0yI0NkzHa9Jic36LYNZibRA8icZqmukw5IonETEl1QpAL2ibFiacbrYLmq4aZAWVA/640?wx_fmt=png "")  
  
  
Reids 未授权的常见攻击方式有绝对路径写Webshell、写ssh公钥、利用计划任务反弹shell、主从复制RCE。  
  
利用主从复制RCE，可以避免了通过写文件getshell时由于文件内含有其他字符导致的影响，也可以不需要借助crontab、php这种第三方的程序直接getshell，有明显的优势。但是，很多实战过的师傅就会发现，在有些情况下，不管攻击成功与否，数据库会出现一下异常情况，这里就尝试分析下。  
  
redis 4.x/5.x RCE是由  
LC/BC  
战队队员  
Pavel Toporkov  
在  
zeronights 2018  
上提出的基于主从复制的redis rce，其利用条件是Redis未授权或弱口令。  
### 恶意模块加载  
  
自从Redis4.x之后redis新增了一个模块功能，Redis模块可以使用外部模块扩展Redis功能，以一定的速度实现新的Redis命令，并具有类似于核心内部可以完成的功能。  
  
Redis模块是动态库，可以在启动时或使用  
MODULE LOAD  
命令加载到Redis中。  
> 恶意so文件下载  
，下载完成后直接 make 即可  
  
1. 搭建环境  
```
```  
  
1. 复制恶意so到容器中  
```
```  
  
1. 加载恶意模块  
```
```  
  
那么在真实环境中，我们如何将恶意so文件传输到服务器中呢？这里就需要用到Redis的主从复制了。  
### 主从复制  
  
主从复制，是指将一台Redis服务器的数据，复制到其他的Redis服务器。前者称为主节点(master)，后者称为从节点(slave)；数据的复制是单向的，只能由主节点到从节点。  
  
Redis的持久化使得机器即使重启数据也不会丢失，因为redis服务器重启后会把硬盘上的文件重新恢复到内存中。但是要保证硬盘文件不被删除，而主从复制则能解决这个问题，主redis的数据和从redis上的数据保持实时同步，当主redis写入数据是就会通过主从复制复制到其它从redis。  
  
当slave向master发送  
PSYNC  
命令之后，一般会得到三种回复：  
> +FULLRESYNC：进行全量复制。+CONTINUE：进行增量同步。-ERR：当前master还不支持PSYNC。  
  
  
进行全量复制是，会将master上的  
RDB  
文件同步到slave上。而进行增量复制时，slave向master要求数据同步，会发送master的runid和offest，如果runid和slave上的不对应则会进行全量复制，如果相同则进行数据同步，但是  
**不会传输RDB文件**  
。  
  
为了能让恶意so传输到目标服务器上，这里则必须采用全量复制。  
  
在进行全量复制之前，如果从服务器存在和主服务一样的变量，则其值会被覆盖，同时，如果存在主服务器不存在的变量，则会被删除。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Gw8FuwXLJnTUBMAW5xdbMBnhCV0yI0NkbickNYDue0NmMkh8tcPKZdGvXFDCun2YicnGcytV0P0FNpiacmCoCfBMA/640?wx_fmt=png "")  
  
攻击过程中相关命令  
```
```  
### 痕迹清除  
  
为了减少对服务器的影响，攻击完成后，应该尽量清除痕迹，需要恢复目录和数据库文件，卸载同时删除模块，而数据原本的配置信息，需要在攻击之前进行备份。  
```
```  
```
```  
  
漏洞利用的版本是redis 4.x/5.x ，如果是先前版本的Redis，则无法加载模块，自然也就无法利用。在网上开了几个开源的利用脚本，都没有进行版本的判断，如果直接使用exp，除了攻击失败外，可能会修改了 dir 和dbfilename ，这些都可以通过redis未授权修改回原来的配置（前提是有提前备份），而目录下会多生成一个 exp.so文件。  
### 利用脚本  
  
这里的脚本是在   
https://github.com/vulhub/redis-rogue-getshell  
 的基础上进行修改的，主要增加了版本检测，防止误打其他版本的Redis服务器。此外，还增加了配置信息备份，当痕迹清除时，如果目标Redis服务器的的dir、dbfilename、主从关系等不是默认配置时，需要手动修改脚本中的参数。  
```
```  
  
  
  
