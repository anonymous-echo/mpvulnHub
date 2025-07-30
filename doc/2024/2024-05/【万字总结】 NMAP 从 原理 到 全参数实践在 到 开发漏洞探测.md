#  【万字总结】 NMAP 从 原理 到 全参数实践在 到 开发漏洞探测   
原创 lsaisai  W啥都学   2024-05-19 23:04  
  
这个分享的内容比较长慢慢看，大概有一万字左右！！  
  
这个笔记已经写的有一些年头了大概是20年写的，主要看的书是《诸神之眼NMAP》进行的总结，基本上是**“整个《诸神之眼NMAP》书的全部总结笔记“**还有一些自己的总结**“估计应该是全网最全的“**  
  
因为前两天在做线上的渗透测试的时候，由于内网不能上网无法传任何东西，但是主机上有一个nmap，就想到可以通过nmap编写poc进行内网大批量扫描，然后就回过来翻了翻之前看了下nmap的笔记，现在看我之前写的**“笔记多多少少还是干货还是挺多的“，拿出来分享分享**  
  
**这个工具就不多介绍了很有名的曾在《黑客帝国1-2》电影里面出现过**  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/b76VA5DEYFCiaFsTqv9xdrLthbcH4mXXC35szoIgqhj9iaczkuCDdpTqMxn6SLWhI30ma76uKicIgxx23icS5BbtRw/640?wx_fmt=jpeg "")  
# nmap范围扫描  
```
192.168.0.1-255  //指定范围
192.168.0.1/24     //对整个子网进行扫描
192.168.0.1，192.168.0.50，192.168.0.30 //对多个主机进行扫描
nmap [目标]  --exclude  [指定不扫描的主机]  //排除主机扫描
-iL a.txt  //指定a.txt 文件内容进行扫描
-iR  [数量]   //要指定的随机ip扫面
```  
# 探测存活主机  
  
nmap发送的那些数据包可以用--packet-trace来查看  
## ARP扫描探测存活主机  
> 交换机里面中每个接口都有寻址寄存器，里面存放这物理地址表 ARP扫描原理就是，向内网送ARP包如果主机给我相应了，就说明主机存活 注意：这个ARP扫描很难防御，在内网扫描ARP扫描是最佳的扫描 列  
  
```
nmap -PR [目标]
```  
  
例如：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/b76VA5DEYFBgHEHvll1ia3R0N4Zc1nuI0SCI12hL0eRarDYtReiaPcGRnicsV83FVj82n3MWG4UOchVsDeiaWcmjPw/640?wx_fmt=png&from=appmsg "null")  
## ICMP探测探测存活主机  
  
![](https://mmbiz.qpic.cn/mmbiz_png/b76VA5DEYFBgHEHvll1ia3R0N4Zc1nuI0nhHbkib4aDxIxRXX3Zr0icyUibRGq69uqdXKWH78NibZg8WpDiaOjhtIOaw/640?wx_fmt=png&from=appmsg "null")  
  
在这里插入图片描述  
### 请求和响应应答探测存活主机  
  
发送ICMP响应请求，如果得到目标主机发回的ICMP响应，则说明该主机处于活跃状态，就和ping命令一样  
```
nmap -PE [目标地址]
```  
  
例如：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/b76VA5DEYFBgHEHvll1ia3R0N4Zc1nuI0ibwcialhhViaicGibXbtD5pYG0ZFk7NYFymdMAq8tFTrkZ22AB1Y7Z3Zh7A/640?wx_fmt=png&from=appmsg "null")  
  
image-20240519212144108  
## 时间戳请求和响应探测存活主机  
```
nmap   -sn  -PP [目标]
```  
## 地址俺码请求和响应探测存活主机  
```
nmap  -sn   -PM  [端口，或多个端口] [目标]
```  
## TCP探测存活主机  
### SYN探测存活主机  
  
原理是客户端发送SYN目标会返回SYN ACK创建连接，如果端口没有开放就断开连接回RST数据包，如何有一个返回就说明目标存活 格式  
```
nmap  -sn  -PS [端口，或多个端口] [目标]
```  
### ACK探测存活主机  
  
这个被防火墙过滤 原理客户端发送一个ACK数据包给服务器，如果服务器存活就发送RST数据包，如果没有存活就没有都不响应 格式  
```
nmap  -sn -PA [端口，或多个端口] [目标]
```  
### UDP探测存活主机  
  
当目标收到UDP数据包如果这个端口是关闭的，就返回ICMP端口不可达数据包， 这个扫描不太准 格式  
```
nmap -sn PU  [端口，或多个端口] [目标]
```  
### SCTP探测存活主机  
  
SCTP用的比较少 流控制传输协议（SCTP，Stream Control Transmission Protocol）是一种在网络连接两端之间同时传输多个数据流的协议。SCTP提供的服务于UDP和TCP类似 SCTP是可以确保数据传输的，和TCP类似，也是通过确认机制来实现的。和TCP不同的是：  
  
TCP是以字节为单位传输的，SCTP是以数据块为单位传输的  
  
TCP接收端确认的是收到的字节数，SCTP接收端确认的是接收到的数据块。SCTP的这种数据块（被称为DATA CHUNK）通常会携带应用的一个数据包，或者说是应用要发送的一个消息。  
  
在实际的应用中，TCP发送方的可以将应用程序需要发送的多个消息打包到一个TCP包里面发出去。比如，应用程序连续调用两次send()向对端发送两条消息，TCP协议可能把这两条消息都打包放在同一个TCP包中。接收端在收到这个TCP包时，回给对端的ACK只是表明自己接收到了多少个字节，TCP协议本身并不会把收到的数据重新拆散分成两条应用层消息并通知应用程序去接收。事实上，应用程序可能只需要调用一次receive()，就会把两条消息都收上来，然后应用需要根据应用程序自己定义的格式去拆成两条消息。  
  
与TCP不同，SCTP是将应用程序的每次调用sendmsg()发送的数据当作一个整体，放到一个被称为DATA CHUNK的数据块里面，接收端也是以DATA CHUNK为单位接收数据，并重新组包，通知应用程序接收。通常，应用程序每次调用recvmesg()都会收到一条完整的消息。  
  
在SCTP的发送端，多条短的应用层消息可以被SCTP协议打包放在同一个SCTP包中，此时在SCTP包中可以看到多个DATA CHUNK。另一方面，一条太长（比如，超过了路径MTU）的应用层消息也可能被SCTP协议拆分成多个片段，分别放在多个DATA CHUNK并通过不同的SCTP包发送给对端。这两种情况下，SCTP的接收端都能重新组包，并通知应用程序去接收。 格式  
```
nmap -sn  -PY [端口,多个端口]   [目标]
```  
## 使用IP进行主机发现  
  
ICMP为1 IGMP为2 TCP为6 UDP为7 GRE4为7 ESP为50  
  
格式  
```
nmap -sn PO 号  [目标]
```  
  
如果不指定号默认是1 这个方法容易被被目标检查出来 可以加上--data-length添加随机数据包  
### DNS活跃主机发现和DNS相关选项  
  
在对一台主机扫描的时候，如果它有域名的话，nmap会向域名服务器提出请求，显示ip对映的域名，扫描的时候可以指定范围  
  
无论是活跃的主机和不活跃的主机都叫域名给列出来 -R 列  
```
 nmap -R  192.168.1.1-20
```  
  
这个扫描可能会消耗大量的时间  
# 端口扫描技术  
## 1. nmap对端口的状态的定义  
1. 1. open：如果目标端口的状态为open，这表明在该端口有应用程序接收TCP连接或者UDP报文。  
  
1. 2. closed：如果目标端口的状态为closed，这里要注意closed并不意味着没有任何反应，状态为closed的端口是可访问的，这种端口可以接收Nmap探测报文并做出响应。相比较而言，没有应用程序在open上监听。  
  
1. 3. filtered：产生这种结果的原因主要是存在目标网络数据包过滤，由于这些设备过滤了探测数据包，导致Nmap无法确定该端口是否开放。这种设备可能是路由器、防火墙甚至专门的安全软件。  
  
1. 4. unfiltered：这种结果很少见，它表明目标端口是可以访问的，但是Nmap却无法判断它到底是open还是closed的。通常只有在进行ACK扫描时才会出现这种状态。  
  
1. 5. open | filtered：无法确定端口是开放的还是被过滤了，开放的端口不响应就是一个例子。  
  
1. 6. closed|filtered：无法确定端口是关闭的还是被过滤了。只有在使用idle扫描时才会发生这种情况。  
  
## 端口扫描  
## SYN扫描  
  
nmap默认就是SYN扫描，扫描速度快 nmap会像主机发送一个SYN数据包，目标会返回SYN加ACK进行应答。然后nmap会返回给服务器RST数据包断开连接，没有建立三次握手，目标主机是不记录的 **响应状态**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/b76VA5DEYFBgHEHvll1ia3R0N4Zc1nuI0vIpb8Gf4Rdve0qOdauuOjq5ibqnrkUU9P1MRJeiahnV3ZW3tPH02wmbw/640?wx_fmt=png&from=appmsg "null")  
  
在这里插入图片描述  
  
扫描语法  
```
nmap -sS [目标]
```  
### Connect扫描  
  
和SYN扫描方式一样，只是完成三次握手了 格式  
```
nmap -sT [目标]
```  
## UDP扫描  
  
**响应状态**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/b76VA5DEYFBgHEHvll1ia3R0N4Zc1nuI0o2FneCbuBpicic4HXAPVKCVhgUYvtMFJ3rVSEvVf9mnQqj8QcF8yqhug/640?wx_fmt=png&from=appmsg "null")  
  
在这里插入图片描述  
  
格式  
```
nmap -sU [目标]
```  
## TCP FIN扫描  
  
发一个FIN数据包目标端口返回RST就说明端口是关闭的 格式  
```
nmap -sF [目标]
```  
## NULL扫描  
  
NULL扫描发送一个没有包含任何数据的数据包，目标端口返回RST就说明端口是关闭的 格式  
```
nmap -sN [目标]
```  
## Xmas Tree 扫描  
  
是向目标端发送一个含有FIN,URG和PUSH标志的数据包，目标端口返回RST就说明端口是关闭的 格式  
```
nmap -sX [目标]
```  
## idle扫描  
  
**僵尸机扫描端口开发** 1.攻击端给僵尸机发一个SYN/ACK僵尸机回RST/包里面有IPID=x 2.攻击端发服务器端口SYN是伪造僵尸机ip服务器发给僵尸 机SYN/ACK，应为没有建立连接僵尸机就回RST/IPID=x+1 3.攻击端在给僵尸机发一个SYN/ACK僵尸机回RST/IPIF=x+2 **僵尸机扫描端口开发** 1.攻击端给僵尸机发一个SYN/ACK僵尸机回RST/IPID=x 2.攻击端发服务器端口SYN是伪造僵尸机ip服务器发给僵尸机没有建立连接服务器回发僵尸机RST 3.攻击端在给僵尸机发一个SYN/ACK僵尸机回RST/IPIF=x+1  
  
**判断是否是僵尸机--script是使用脚本**  
```
nmap -p端口 要判断是僵尸机的ip  --script=ipidseq.nse  
```  
  
使用僵尸机扫描目标端口 -sI是僵尸扫描  
```
nmap 目标ip -sI 僵尸机ip -Pn -p 0-100  
```  
## 指定扫描的端口  
  
![](https://mmbiz.qpic.cn/mmbiz_png/b76VA5DEYFBgHEHvll1ia3R0N4Zc1nuI0OkFvXp2y8FstzIEWGB34dMpw13RYIQ00SuD4TW7pj2eEj652gGDnag/640?wx_fmt=png&from=appmsg "null")  
  
在这里插入图片描述  
  
1、指定常见的100个端口 格式  
```
nmap -F [目标]
```  
  
2、指定一个端口扫描 格式  
```
nmap -p [端口]  [目标]
```  
  
3、使用名字指定扫描端口 格式 nmap -p U:53 [目标]  
  
4、扫描所有的端口 格式  
```
nmap -p *  [目标]
```  
  
5、常用的端口扫描 格式  
```
nmap  --top-ports [目标]
```  
# 远程系统与服务探测  
## 主机探测  
  
查看返回的ttl值查看主机的系统 ttl值Windows 是128(65——128) Linux 和 Unix = 64 (1-64) Unix = 255  
```
nmap -O [目标]
```  
## 版本探测  
  
发送探针报文，得到返回确认值，得到服务的版本  
> 探测服务器版本参数-sV  
  
```
nmap  -sV [目标]
```  
  
1.如果想对全端口扫描可以加上--allport 2.设置版本扫描的强度加上--version-intensity   [1到9] 3.如果轻量级模式扫描可以加上--version-light 4.尝试每个探测相当于--version-intensity  9 加上--version-all 6.--version-trace这个参数将会打印出关于正在进行的扫描的详细调试信息 7.**-sR(RPC扫描)** 这个方法和许多端口扫描方法联合使用。它对所有的被发现的开发的TCP/UDP端口执行SunRPC程序NULL命令试图确定他们是否RPC端口，如果是，可以确定是什么程序和版本号 nmap -sP [目标]  
  
例如 --script-args 是用来指定参数的  
```
nmap --script smtp-brute --script-args brute.mode=指定的用户名  192.168.30.39 
```  
  
**2.2密码模式 这种模式先取一个密码，然后使用所有的用户名与其配对，当所有组合都结束后，再开始下一个密码** 例如  
```
nmap --script smtp-brute --script-args brute.mode=指定的密码  192.168.30.39 
```  
  
2.3文件格式取用户密码 这种模式与前两种不同，creds中所有的用户名和密码都写在同一个文件中，格式类似于admin/123456这种形式，Nmap会读取其中的每一行，然后访问服务器进行匹配 例如  
```
Nmap --script smtp-brute --script-args brute.mode=creds,brute.credfile=文件名   192.168.30.39 
```  
### 漏洞扫描类脚本  
#### 脚本http-slowloris.NSE  
  
http-slowloris.NSE脚本查看目标是否存在预防slowloris的 DoS攻击 Slowloris是在2009年Web安全专家RSnake提出的一种攻击方法，其原理是以极低的速度向服务器发送HTTP请求。由于Web Server对于并发的连接数都有一定的上限，导致拒绝服务 例如  --max-parallelism这些选项控制用于主机组的探测报文数量  
```
nmap -p 80 --script http-slowloris  --max-parallelism 300 192.168.30.39 
```  
  
这个方法是直接去打目标系统  
#### http-slowloris.NSE脚本扩展http-slowloris.send_interval参数  
  
http-slowloris.send_interval参数可以指定发送http header datas的间隔，默认值为100 --script-args 是用来指定参数的  --max-parallelism这些选项控制用于主机组的探测报文数量 例如  
```
Nmap -p 80 --script http-slowloris --script-args http-slowloris.send_interval=200 --max-parallelism 300   192.168.30.39 
```  
#### http-slowloris.NSE脚本扩展http-slowloris.timelimit参数  
  
攻击时间，默认是30分钟 --script-args 是用来指定参数的  
  
15m就是15分钟  
```
nmap -p 80 --script http-slowloris --script-args http-slowloris.timelimit=15m  192.168.30.39 
```  
#### http-slowloris.NSE脚本扩展http-slowloris.runforever参数  
  
这个参数是对目标系统进行一直DoS攻击 --script-args 是用来指定参数的  
```
Nmap -p 80 --script http-slowloris --script-args http-slowloris.runforever 192.168.30.39 
```  
  
还有一个名为http-slowloris-check.NSE的脚本也是用来发送slowloris的，都是他只会发送2个请求 例如  
```
nmap -p 80 --script http-slowloris-check 192.168.30.39 
```  
### POODLE漏洞扫描ssl-poodle脚本  
  
POODLE漏洞（亦即CVE-2014-3566）最早是由谷歌团队发现的，可以攻击者可以盗取，已经使用了的SSL3.0数据进行解密 需要攻击者完全控制网络的流量，比如ARP欺骗，钓鱼wifi等等 名为ssl-poodle的脚本来检查POODLE漏洞 --version-all相当于--version-intensity  9 扫描强度  
```
nmap -sV --version-all --script ssl-poodle -p 443 192.168.30.39 
```  
# Lua语言基础语法  
  
我们要学习NSE开发我们必须要了解Lua语言下面就简单介绍一下Lua语言的基础语法  
  
输出print("Hello")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/b76VA5DEYFBgHEHvll1ia3R0N4Zc1nuI0SpT5je7N0EPZt2J5ibOZ9xevXFRhLnISLWaicq0CHf0NicoLgu5lUCicwg/640?wx_fmt=png&from=appmsg "null")  
## 1.if  
  
Lua认为false和nil为假，true和非nil为真。 和其他语言有点不同 为真才会执行then里面的，如果是假会跳过then里面的  
```
if (真)
then
print("会执行这个")
end
```  
  
1、true例如： 代码  
```
#!/usr/bin/lua
if  true
then
   print("Hello")
end
```  
  
执行结果  
  
![](https://mmbiz.qpic.cn/mmbiz_png/b76VA5DEYFBgHEHvll1ia3R0N4Zc1nuI0PWFD0M7driaUaXgxEg49LEdyIUvUSftxlW1zgQHtlTbz3mplnDoWiaMQ/640?wx_fmt=png&from=appmsg "null")  
  
2、falsee例如 代码  
```
#!/usr/bin/lua
if false
then
   print("Hello")
end
   print("Hello1111")
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/b76VA5DEYFBgHEHvll1ia3R0N4Zc1nuI0ykcb1ydNwxnZCZd71PDKNs0F2maF9B5Jiajpa3sq7yY5ErCuIOXgYbQ/640?wx_fmt=png&from=appmsg "null")  
  
实咧 代码  
```
#!/usr/bin/lua
a="abc"
if (a=="abc")
then
   print("a变量是abc")
end
   print("##########")
```  
  
结果  
  
![](https://mmbiz.qpic.cn/mmbiz_png/b76VA5DEYFBgHEHvll1ia3R0N4Zc1nuI0Wo2ev8bDIutfLicUvfAIOOUiciaF2a4gqZpakfDBq563TosWNC5I0eRqA/640?wx_fmt=png&from=appmsg "null")  
## 1.2 if …else  
  
咧 代码  
```
#!/usr/bin/lua
a="qwe"
if (a=="abc")
then
print("a变量是abc")
elseif(a=="qwe")
then
print("a变量啥qwe")
end 
print("##########")

```  
  
结果  
  
![](https://mmbiz.qpic.cn/mmbiz_png/b76VA5DEYFBgHEHvll1ia3R0N4Zc1nuI0YeOP9qRNEuW1eGt0zAfRP25iaEcSP1EteqZJwsa1nqnW1LXuWdBbFDg/640?wx_fmt=png&from=appmsg "null")  
## while循环  
  
为真就循环do里面的  
```
while(真)
do
print("a")
end
```  
  
咧 代码  
```
#!/usr/bin/lua
a=1
while(a<10)
do
print(a)
a=a+1
end
print("结束")
```  
  
结果  
  
![](https://mmbiz.qpic.cn/mmbiz_png/b76VA5DEYFBgHEHvll1ia3R0N4Zc1nuI0Tf2E5UIL7OdDfXSibFiajC4Ee2mXzXt23lrMY50BgNJiaGoxibLvnvSqXA/640?wx_fmt=png&from=appmsg "null")  
## for循环语句  
  
与while不同的是，for语句可以直接控制循环重复执行的次数 咧  
```
#!/usr/bin/lua
for a=1,10
do 
print(a)
end 
print("结束")
```  
  
结果  
  
![](https://mmbiz.qpic.cn/mmbiz_png/b76VA5DEYFBgHEHvll1ia3R0N4Zc1nuI0cU3L6EaNeot1PcDhibHQQpWxiazFrIvWk9ibeeaxy2extvyW6PcjFuprQ/640?wx_fmt=png&from=appmsg "null")  
## repeat循环  
  
repeat…until结构也是Lua的一种循环结构，这个结构不断地重复执行循环，直到指定的条件为真时为止 如果一直为假就一直执行print("a")  
```
repeat
print("a")
until(假)
```  
  
咧  
```
#!/usr/bin/lua
a=1
repeat
print(a)
a=a+1
until(a>10)
```  
  
结果  
  
![](https://mmbiz.qpic.cn/mmbiz_png/b76VA5DEYFBgHEHvll1ia3R0N4Zc1nuI0Yvj9TxYrCDW99ibghkofWWSxpScxGO2zv34ICb2GJQcibZCgibUL6btvQ/640?wx_fmt=png&from=appmsg "null")  
## break循环语句  
  
break语句是一种循环控制语句，可以实现退出当前循环或语句  
## Lua数据类型  
  
![](https://mmbiz.qpic.cn/mmbiz_png/b76VA5DEYFBgHEHvll1ia3R0N4Zc1nuI07pbYicqTyYf8NKQGk7cdCVuApgs5p4Tpdriaq2icx0zEia4U4EyvWlB4JA/640?wx_fmt=png&from=appmsg "null")  
  
在这里插入图片描述  
  
咧 函数type是用来查看类型的  
```
#!/usr/bin/lua
a=1
print(type(a))
```  
  
结果  
  
![](https://mmbiz.qpic.cn/mmbiz_png/b76VA5DEYFBgHEHvll1ia3R0N4Zc1nuI0xhgHUnnsrNHt2yV5Xg69QuibAZAnIPml0omhmImgY4uL0FXWNp58laA/640?wx_fmt=png&from=appmsg "null")  
## string库  
  
**1、全部转为大写字母**  
 string.upper() upper函数将字符串中的字符全部转为大写字母  
  
![](https://mmbiz.qpic.cn/mmbiz_png/b76VA5DEYFBgHEHvll1ia3R0N4Zc1nuI0PQQIQqkgdvMZWUK864icUoK17xCF1QiaV96hSHSiahAtCnwtfSQ6m8p8w/640?wx_fmt=png&from=appmsg "null")  
  
在这里插入图片描述  
  
**2、全部转为小写字母**  
  
string.lower() lower函数将字符串中的字符全部转为小写字母  
  
![](https://mmbiz.qpic.cn/mmbiz_png/b76VA5DEYFBgHEHvll1ia3R0N4Zc1nuI0icEY9GNcdia8Cu7P4kHCDBrpnNMW0PK0RtWBayP8gnKaQpz7wIO0R7HQ/640?wx_fmt=png&from=appmsg "null")  
  
在这里插入图片描述  
  
**3、替换**  
  
咧  
```
string.gsub("adadadadadad","a","4",2)
```  
  
adadadadadad里面的a替换2个替换成4 结果  
  
![](https://mmbiz.qpic.cn/mmbiz_png/b76VA5DEYFBgHEHvll1ia3R0N4Zc1nuI0fGUGPicyHibpJQ28XLnX4lNALRQVJyv7MYSzOrhAgvB1lSVK8TvpK7IA/640?wx_fmt=png&from=appmsg "null")  
  
在这里插入图片描述  
  
**4、查询字符在的位置** 函数find() 咧 代码  
```
print(string.find("abcdefg","f",2))
```  
  
上面的意思就是在abcdefg字符里面的第2的位置查看是否有f这个字符 如果没有找到就返回nil 结果  
  
![](https://mmbiz.qpic.cn/mmbiz_png/b76VA5DEYFBgHEHvll1ia3R0N4Zc1nuI0FXuGH8O78O4tEo90YRGicM1BDnTYMVJyOTPWnk4ybtvbyGTgqib6I1xg/640?wx_fmt=png&from=appmsg "null")  
  
在这里插入图片描述  
  
**5、数字转换成字符** string.char(xxx,xxx,xxx,xxx) char函数将整型数字转成字符并连接， 就是对应的ASCII码值 咧 代码  
```
print(string.char(65,66,67,68))
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/b76VA5DEYFBgHEHvll1ia3R0N4Zc1nuI0kicibTNpnsTxhMggtAnYXgp3iccn7cuYRnvaIHCAw11KW4siaS7lyxnZMg/640?wx_fmt=png&from=appmsg "null")  
  
在这里插入图片描述  
  
**6、字符转换成数字** string.byte(xx,xx,xx) byte函数转换字符为整数值 他好像只能转换一个字符 可以指定字符 1.咧  
```
print(string.byte("B"))
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/b76VA5DEYFBgHEHvll1ia3R0N4Zc1nuI0JSVUdn0wulCsggHrqFFToN6hcKwWYvK8Wn1VfRYtGuoMibnMHMvLmjA/640?wx_fmt=png&from=appmsg "null")  
  
在这里插入图片描述  
  
**7、计算字符串的长度** string.len() len函数计算字符串长度 代码  
```
a="ABCD"
print(string.len(a))
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/b76VA5DEYFBgHEHvll1ia3R0N4Zc1nuI0fKYnc8KibEPJ0LOEMIjdfpaFwrnlibLUQe0erw5f6dXYibX5gZ4iarpjXA/640?wx_fmt=png&from=appmsg "null")  
  
在这里插入图片描述  
  
**8、重复显示字符串和连接** string.rep() **1.rep函数返回字符串string的n个拷贝** 咧  
```
print(string.rep("ACBD:",3))
```  
  
结果  
  
![](https://mmbiz.qpic.cn/mmbiz_png/b76VA5DEYFBgHEHvll1ia3R0N4Zc1nuI0jNibWhH9SqyMkUAKpEdv2M6KZWbNb5ovtCZJgIBEse6lD9ictLCGnKFA/640?wx_fmt=png&from=appmsg "null")  
  
在这里插入图片描述  
  
上面的意思就是重复3次  
## Lua文件I/O操作  
  
![](https://mmbiz.qpic.cn/mmbiz_png/b76VA5DEYFBgHEHvll1ia3R0N4Zc1nuI0fnDibksiaamngPZ4WJKjDACc26AsZfGWFVuZ9K1SgIm2dL86WBbYtGRQ/640?wx_fmt=png&from=appmsg "null")  
  
在这里插入图片描述  
  
打开文件，读一行和关闭文件 代码 函数io.open("文件名","打开方式")打开文件 函数read()读取文件第一行 函数close()关闭文件还可以格式io.close(a)  
  
例如：  
```
#!/usr/bin/lua
--读的方式打开文件
a=io.open("a.txt","r")

--输出文件第一行
print(a:read())

--关闭打开的文件
a:close()
```  
  
a.txt文件内容  
  
![](https://mmbiz.qpic.cn/mmbiz_png/b76VA5DEYFBgHEHvll1ia3R0N4Zc1nuI06Yh5AhfObP5pAxjnsyicm5C911OCEMLMBk2B5CkECAxqJPWgSQ5p8KA/640?wx_fmt=png&from=appmsg "null")  
  
在这里插入图片描述  
  
执行结果  
  
![](https://mmbiz.qpic.cn/mmbiz_png/b76VA5DEYFBgHEHvll1ia3R0N4Zc1nuI0UVp11nkdqvkxG343qNwEMu0AS41bnPzhloUVL1oH8RicibyzEhZxtXIw/640?wx_fmt=png&from=appmsg "null")  
  
在这里插入图片描述  
## Lua协同程序  
1. 1. 协同程序和线程类似拥有独立的堆栈、独立的局部变量、独立的指令指针，同时又与其他协同程序共享全局变量和其他大部分东西  
  
1. 2. 线程与协同程序的主要区别在于，一个具有多个线程的程序可以同时运行几个线程，而协同程序却需要彼此协作运行。在任一指定时刻只有一个协同程序在运行，并且这个正在运行的协同程序只有在明确要求挂起的时候才会被挂起。协同程序有点类似同步的多线程，在等待同一个线程锁的几个线程有点类似协同。  
  
### Lua协同程序语法  
1. 1. coroutine.create() 这个方法用来创建一个coroutine，将要进行多线程的函数作为参数，返回值是一个coroutine。  
  
1. 2. coroutine.resume() 这个方法用来完成coroutine重启操作，与create配合使用。  
  
1. 3. coroutine.yield() 这个方法用来实现coroutine的挂起操作，将coroutine设置为挂起状态。  
  
1. 4. coroutine.status() 这个方法用来查看coroutine的状态。这里coroutine的状态一共有dead、suspend、running三种。  
  
1. 5. coroutine.wrap() 这个方法创建一个coroutine，用于返回一个函数，一旦调用这个函数，就进入协同程序，与create功能相同。  
  
1. 6. coroutine.running()这个方法返回正在运行的coroutine。一个coroutine就是一个线程，当使用running时，返回的是当前正在运行的协同程序的线程号。  
  
# NSE库文件编写  
## nmap NSE中的API  
  
Nmap中的引擎会向脚本传递两个类型的参数**host**和**port** host 的table(表)存放这目标主机信息 port 的table(表)存放这目标端口信息 他和port和host详细程度取决，扫描过程中选项选项的设定，例如，如果在扫描时没有指定要对主机的操作系统进行扫描的话，那么host.os的内容就是空的  
## host table  
### host.os字段  
  
里面存放这目标主机的类型 这个字段中包括了一个我们常见的操作系统信息的数组，涉及操作系统的供应商、所属系列、具体型号、设备类型、CPE等。如果某个字段没有被定义的话，这个字段可以为nil  
  
例如： 代码 我保存到了名为wode.nse  
```
local shortport = require "shortport"

description = [[]]

author = "kali"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"default"}


portrule = function( host, port )
    return true
end


action = function(host, port)


     return host.os

end
```  
  
**上面的代码的意思是return true(真)执行return host.os返回host.os** 叫wode.nse移动到/usr/share/nmap/scripts/文件下面 复制进去要更新一下nmap脚本的数据库 命令  
```
nmap --script-updatedb
```  
  
结果 用上面的脚本  
  
命令  
```
sudo nmap --script wode 192.168.43.244 -O -p 3389
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/b76VA5DEYFBgHEHvll1ia3R0N4Zc1nuI0VQ0p19ANtZx5F1Df4qEx4Ml4sFLtePMfH3Yv8ACGrJJde0Tc3fRSuA/640?wx_fmt=png&from=appmsg "null")  
### host.ip字段  
  
里面包含了的IP地址 咧 代码 我保存到了名为wode.nse  
```
local shortport = require "shortport"

description = [[]]

author = "root"

license = "Same as Nmap--See http://nmap.org/book/man-legal.html"

categories = {"default"}





portrule = function(host, port)
    return true
end

action = function(host, port)

    return host.ip

end
```  
  
叫wode.nse移动到/usr/share/nmap/scripts/文件下面 复制进去要更新一下nmap脚本的数据库 命令  
```
nmap --script-updatedb
```  
  
结果 用上面的脚本命令  
```
sudo nmap --script wode www.baidu.com -p 80
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/b76VA5DEYFBgHEHvll1ia3R0N4Zc1nuI0maJ7830Z6EW8kh48clQ8pgjxbaPxfIloMPzZuW8nicU1ZwicpLzwXv4A/640?wx_fmt=png&from=appmsg "null")  
  
在这里插入图片描述  
### host.name字段  
  
里面包含了目标的反向DNS域名 咧 代码 我保存到了名为wode.nse  
```
local shortport = require "shortport"

description = [[]]

author = "root"

license = "Same as Nmap--See http://nmap.org/book/man-legal.html"

categories = {"default"}





portrule = function(host, port)
    return true
end

action = function(host, port)

    return host.name

end
```  
  
叫wode.nse移动到/usr/share/nmap/scripts/文件下面 复制进去要更新一下nmap脚本的数据库 命令  
```
nmap --script-updatedb
```  
  
结果 不知道怎么回事好像不能检查到  
### host.targetname字段  
  
里面包含了主机的在命令中的命令  
### host.directly_connected字段‘  
  
字段是一个布尔值true和false，表示目标计算机是否与我们同在一个子网 咧 代码 我保存到了名为wode.nse  
```
local shortport = require "shortport"

description = [[]]

author = "root"

license = "Same as Nmap--See http://nmap.org/book/man-legal.html"

categories = {"default"}





portrule = function(host, port)
    return true
end

action = function(host, port)

    return host.directly_connected

end
```  
  
叫wode.nse移动到/usr/share/nmap/scripts/文件下面 复制进去要更新一下nmap脚本的数据库 命令  
```
nmap --script-updatedb
```  
  
结果1是true,这个我扫描的是我内网 命令  
```
sudo nmap --script wode 192.168.43.221 -p 80
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/b76VA5DEYFBgHEHvll1ia3R0N4Zc1nuI0PMibNsWchvrSwcz08aUU6qSCjPLUN7xHS9tKEhhNv3UlIV9XohdTIMw/640?wx_fmt=png&from=appmsg "null")  
  
结果2是false我扫描的是百度，不是在我内网的 命令  
```
sudo nmap --script wode www.baidu.com -p 80
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/b76VA5DEYFBgHEHvll1ia3R0N4Zc1nuI076PZk0cCwU9aaybR80jXZiaXgoULDQ8qoQC3Q8wecibSHmJ1a5RIlwYw/640?wx_fmt=png&from=appmsg "null")  
### host.mac_addr字段  
  
这个字段是目标的MAC地址，注意：要是扫描的不是同一个网段的话可能就没有效果，应为扫描外网是通用IP寻址的 咧 代码 我保存到了名为wode.nse  
```
local shortport = require "shortport"

description = [[]]

author = "root"

license = "Same as Nmap--See http://nmap.org/book/man-legal.html"

categories = {"default"}





portrule = function(host, port)
    return true
end

action = function(host, port)

    return host.mac_addr

end
```  
  
叫wode.nse移动到/usr/share/nmap/scripts/文件下面 复制进去要更新一下nmap脚本的数据库 命令  
```
nmap --script-updatedb
```  
  
结果 命令  
```
sudo nmap --script wode 192.168.43.221 -p 80
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/b76VA5DEYFBgHEHvll1ia3R0N4Zc1nuI0Z02a05xCGkq1kJZ9u6us6z1kQbxjf8cHnVxqGGx4N33JiaAlvBmf2GA/640?wx_fmt=png&from=appmsg "null")  
### host.mac_addr_src  
  
段中是使用的计算机的MAC地址 咧 代码 我保存到了名为wode.nse  
```
local shortport = require "shortport"

description = [[]]

author = "root"

license = "Same as Nmap--See http://nmap.org/book/man-legal.html"

categories = {"default"}





portrule = function(host, port)
    return true
end

action = function(host, port)

    return host.mac_addr_src

end
```  
  
叫wode.nse移动到/usr/share/nmap/scripts/文件下面 复制进去要更新一下nmap脚本的数据库 命令  
```
nmap --script-updatedb
```  
  
结果 命令  
```
sudo nmap --script wode 192.168.43.1
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/b76VA5DEYFBgHEHvll1ia3R0N4Zc1nuI0VauKk8JkPVfcuzVJVhicEAw6KV9QABpntMH7buKnzTexYT6C2oFjvhg/640?wx_fmt=png&from=appmsg "null")  
### host.interface_mtu  
  
字段中是网络中的MTU值 咧 代码 我保存到了名为wode.nse  
```
local shortport = require "shortport"

description = [[]]

author = "root"

license = "Same as Nmap--See http://nmap.org/book/man-legal.html"

categories = {"default"}





portrule = function(host, port)
    return true
end

action = function(host, port)

    return host.interface_mtu

end
```  
  
叫wode.nse移动到/usr/share/nmap/scripts/文件下面 复制进去要更新一下nmap脚本的数据库 命令  
```
nmap --script-updatedb
```  
  
结果 命令  
```
sudo nmap --script wode 192.168.43.1
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/b76VA5DEYFBgHEHvll1ia3R0N4Zc1nuI0ibLxjejNFZ2TJvMoZz0ovts4X8ZIkQooyyfF0j8pcXcuhX3ObuiciaMUQ/640?wx_fmt=png&from=appmsg "null")  
### host.bin_ip字段  
  
字段中的内容是使用4字节字符串表示的IPv4目标地址以及使用16字节字符串来表示IPv6目标地址 咧 代码 我保存到了名为wode.nse  
```
local shortport = require "shortport"

description = [[]]

author = "root"

license = "Same as Nmap--See http://nmap.org/book/man-legal.html"

categories = {"default"}





portrule = function(host, port)
    return true
end

action = function(host, port)

    return host.bin_ip

end
```  
  
叫wode.nse移动到/usr/share/nmap/scripts/文件下面 复制进去要更新一下nmap脚本的数据库 命令  
```
nmap --script-updatedb
```  
  
结果 命令  
```
sudo nmap --script wode 192.168.31.22 -p 3389
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/b76VA5DEYFBgHEHvll1ia3R0N4Zc1nuI0hUeOSPVy7TUzQ9LeOeVmjBHw5jp8mKPkgEE1qicic0ukW8fG68qEJuSQ/640?wx_fmt=png&from=appmsg "null")  
1. 1. host.bin_ip_src  
  
里面字段中包含两个地址，一个是使用IPv4格式表示所使用的计算机地址，另一个是用IPv6格式表示所使用的计算机地址 咧 代码 我保存到了名为wode.nse  
```
local shortport = require "shortport"

description = [[]]

author = "root"

license = "Same as Nmap--See http://nmap.org/book/man-legal.html"

categories = {"default"}





portrule = function(host, port)
    return true
end

action = function(host, port)

    return host.bin_ip_src
end
```  
  
叫wode.nse移动到/usr/share/nmap/scripts/文件下面 复制进去要更新一下nmap脚本的数据库 命令  
```
nmap --script-updatedb
```  
  
结果  
  
![](https://mmbiz.qpic.cn/mmbiz_png/b76VA5DEYFBgHEHvll1ia3R0N4Zc1nuI0OhSBgbe5GOBcgqTZaVkrCgad6yweDGxjDSLPHwKQITCTSJiaiaFz5kgg/640?wx_fmt=png&from=appmsg "null")  
### host.times  
  
里面字段中的内容是目标的时序数据 咧 代码 我保存到了名为wode.nse  
```
local shortport = require "shortport"

description = [[]]

author = "root"

license = "Same as Nmap--See http://nmap.org/book/man-legal.html"

categories = {"default"}





portrule = function(host, port)
    return true
end

action = function(host, port)

    return host.times

end
```  
  
叫wode.nse移动到/usr/share/nmap/scripts/文件下面 复制进去要更新一下nmap脚本的数据库 命令  
```
nmap --script-updatedb
```  
  
结果  
  
![](https://mmbiz.qpic.cn/mmbiz_png/b76VA5DEYFBgHEHvll1ia3R0N4Zc1nuI0nox3OytrGCTh5kKtRicgM2W9sgK4tBWChQBKZ1mNSpA9V6ArQm4Pkyw/640?wx_fmt=png&from=appmsg "null")  
### host.traceroute  
  
字段中的数据只有指定--traceroute才会出现， --traceroute参数是跟踪路由用于检测您的计算机数据包从路由器到ISP的路由到互联网直至其特定目的地 咧 代码 我保存到了名为wode.nse  
```
local shortport = require "shortport"

description = [[]]

author = "root"

license = "Same as Nmap--See http://nmap.org/book/man-legal.html"

categories = {"default"}





portrule = function(host, port)
    return true
end

action = function(host, port)

    return host.traceroute

end
```  
  
叫wode.nse移动到/usr/share/nmap/scripts/文件下面 复制进去要更新一下nmap脚本的数据库 命令  
```
nmap --script-updatedb
```  
  
结果  
  
![](https://mmbiz.qpic.cn/mmbiz_png/b76VA5DEYFBgHEHvll1ia3R0N4Zc1nuI0Wbp2v0ckJDeOaT1kRlSrxcVdtC59mUibGicOyEy1MmHC8Cj4McvP22fA/640?wx_fmt=png&from=appmsg "null")  
## port table(表)  
### port.number字段  
  
这个字段标识了目标端口 咧 代码 我保存到了名为wode.nse  
```
local shortport = require "shortport"

description = [[]]

author = "root"

license = "Same as Nmap--See http://nmap.org/book/man-legal.html"

categories = {"default"}




portrule = function(host, port)
    return true
end

action = function(host, port)

    return port.number

end
```  
  
叫wode.nse移动到/usr/share/nmap/scripts/文件下面 复制进去要更新一下nmap脚本的数据库 命令  
```
nmap --script-updatedb
```  
  
结果 命令  
```
sudo nmap --script wode 192.168.31.21
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/b76VA5DEYFBgHEHvll1ia3R0N4Zc1nuI00ybwXhhnqeLEI2r1ib1x9bJlicsWnjjxwo6Y7mwM36DlBqHwPYaicNAxg/640?wx_fmt=png&from=appmsg "null")  
  
image-20240519214219924  
### port.protocol  
  
这个字段是识别TCP和UDP的端口的类型 咧 代码 我保存到了名为wode.nse  
```
local shortport = require "shortport"

description = [[]]

author = "root"

license = "Same as Nmap--See http://nmap.org/book/man-legal.html"

categories = {"default"}



portrule = function(host, port)
    return true
end

action = function(host, port)

    return port.protocol
end
```  
  
叫wode.nse移动到/usr/share/nmap/scripts/文件下面 复制进去要更新一下nmap脚本的数据库 命令  
```
nmap --script-updatedb
```  
  
结果 命令  
```
sudo nmap --script wode 192.168.31.21
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/b76VA5DEYFBgHEHvll1ia3R0N4Zc1nuI0Ts52EIu1oLmAf10sGON5XSq2sNforUYfMEK3H1X37JYbyVyjRLzxEA/640?wx_fmt=png&from=appmsg "null")  
### port.service字段  
  
字段是目标的端口的运行的服务 咧 代码 我保存到了名为wode.nse  
```
local shortport = require "shortport"

description = [[]]

author = "root"

license = "Same as Nmap--See http://nmap.org/book/man-legal.html"

categories = {"default"}



portrule = function(host, port)
    return true
end

action = function(host, port)

    return port.service
end
```  
  
叫wode.nse移动到/usr/share/nmap/scripts/文件下面 复制进去要更新一下nmap脚本的数据库 命令  
```
nmap --script-updatedb
```  
  
结果 命令  
```
sudo nmap --script wode 192.168.31.21 
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/b76VA5DEYFBgHEHvll1ia3R0N4Zc1nuI0kX2RDydtnSlxkohYuVxLhmz8uBD6uGiakauGVv3z2rPq5abc5hW8G9g/640?wx_fmt=png&from=appmsg "null")  
### port.version字段  
  
字段中保存了通过服务扫描发现的版本信息，包括name、name_confidence、product、version、extrainfo、hostname、ostype、devicetype、service_tunnel、service_ftp以及cpe_code等字段。注意这个字段需要使用参数-sV 咧 代码  
```
local shortport = require "shortport"

description = [[]]

author = "root"

license = "Same as Nmap--See http://nmap.org/book/man-legal.html"

categories = {"default"}



portrule = function(host, port)
    return true
end

action = function(host, port)

    return port.version
end
```  
  
叫wode.nse移动到/usr/share/nmap/scripts/文件下面 复制进去要更新一下nmap脚本的数据库 命令  
```
nmap --script-updatedb
```  
  
结果 命令  
```
sudo nmap --script wode 192.168.31.21 -sV
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/b76VA5DEYFBgHEHvll1ia3R0N4Zc1nuI0JWZkVaLgWfg4bEsrib55m05uEiczPDJicSBzhMmcWeciby6bd5GxgXyVAA/640?wx_fmt=png&from=appmsg "null")  
### port.state字段  
  
存放端口的状态 咧 代码  
```
local shortport = require "shortport"

description = [[]]

author = "root"

license = "Same as Nmap--See http://nmap.org/book/man-legal.html"

categories = {"default"}



portrule = function(host, port)
    return true
end

action = function(host, port)

    return port.state
end
```  
  
叫wode.nse移动到/usr/share/nmap/scripts/文件下面 复制进去要更新一下nmap脚本的数据库 命令  
```
nmap --script-updatedb
```  
  
结果 命令  
```
sudo nmap --script wode 192.168.31.21
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/b76VA5DEYFBgHEHvll1ia3R0N4Zc1nuI081maxujAjiaEmNA2AiaJUUtYcaU77bm2jIMVqwhflGQPic12A1tibKBQJg/640?wx_fmt=png&from=appmsg "null")  
## NSE中的异常处理  
  
代码  
```
local nmap = require "nmap"
local comm = require "comm"
local shortport = require "shortport"

description = [[]]

author = "root"

license = "Same as Nmap--See http://nmap.org/book/man-legal.html"

categories = {"default,discovery,safe"}



portrule = shortport.port_or_service(79, "ﬁnger")

action = function(host, port)
try = nmap.new_try()
return try(comm.exchange(host, port, "\r\n", 
{lines=100, timeout=5000}))
end
```  
  
上面代码说明 nmap提供了nmap库，叫nmap 监控异常的代码放置在Nmap.new_try()函数的括号中即可，这个函数的第一个返回值就表明了状态。如果返回值为false或者nil，第二个返回值就是一个错误相关的字符串 如果comm.exchange正常执行的话，就可以返回原本的值，如果出现异常，就可以返回这个异常  
## NSE中的注册表  
  
NSE注册表也是一个Lua tablc 类型的数据文件，他主要用来保持住一次扫描中各个脚本之间共享的变量，这个注册表保持住一个名为nmap.refistry的变量中。举个例子，在使用脚本对目标的口令进行爆破的时候，就可以使用这个注册表把已经破解的用户密码保持起来，已提供其他脚本的使用。例如，爆破得到目标的用户admin，密码123456,就会执行一个插入操作  
```
table.iNSErt(Nmap.registry.credentials.http, 
{ username = admin, password =123456 } )
```  
## NSE中的库文件  
### 库文件的位置  
  
库文件在/usr/share/nmap/nselib  
  
![](https://mmbiz.qpic.cn/mmbiz_png/b76VA5DEYFBgHEHvll1ia3R0N4Zc1nuI0eXk4nyr0Rbf7Ktg81Iu0AdVaJm16TjJf2VgdwD5zQdyM48KWeh4NUg/640?wx_fmt=png&from=appmsg "null")  
  
halcyon编辑器会自动按照nmap的路径进行找到库  
  
![](https://mmbiz.qpic.cn/mmbiz_png/b76VA5DEYFBgHEHvll1ia3R0N4Zc1nuI0At9sUqw9TBWzbP7xx6rUUpeoQwDHHdHCW5KcicUCmbv382fxgoVib7iag/640?wx_fmt=png&from=appmsg "null")  
  
在这里插入图片描述  
  
这些库文件涵盖了几乎当前所有的流行协议、常见的字符串处理操作，甚至包含了用来实现对用户名和密码进行破解的brute库文件。当在编写NSE脚本的时候，你可能会考虑到代码重构的问题。最好的解决方法还是将核心的代码创建为NSE的库文件。事实上，NSE库文件的创建是非常简单的。NSE中的库文件大都是使用Lua语言编写的，但是如果你使用C或者C++语言也是可行的  
### NSE库文件编写和调用  
#### NSE库文件编写  
  
咧 代码  
  
保存的文件名a.lua保持到/usr/share/nmap/nselib目录里面  
```
function b(port)         
        return string.format("The port '%s' is open",port)      
end
```  
  
代码说明 function 定义函数的，定义了一个a函数传参是port string.format函数是一个类似printf的格式化字符串我看到了一个写的很详细的在这个地址https://blog.csdn.net/hello_crayon/article/details/50667927  
#### 调用  
  
NSE脚本调用 编写一个NSE脚本 代码 保持的文件名为wode.nse  
```
local shortport = require "shortport"
local a = require "a"


description = [[]]

author = "root"

license = "Same as Nmap--See http://nmap.org/book/man-legal.html"

categories = {"default"}





portrule = function(host, port)
        return true
end

action = function(host, port)

        return b(port.number)

end
```  
  
代码调用说明 **上面的代码local a = require "a"就是调用上面编写的a.lua的脚本文件 上面的代码 return b(port.number)代码就是b就是a.lua的脚本文件里面的函数，port.number传参给a.lua的脚本文件文件里面的port**  
  
叫wode.nse移动到/usr/share/nmap/scripts/文件下面 复制进去要更新一下nmap脚本的数据库 命令  
```
nmap --script-updatedb
```  
  
结果 命令  
```
sudo nmap --script wode 192.168.31.21
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/b76VA5DEYFBgHEHvll1ia3R0N4Zc1nuI0LvIsCYmqvjbQXRuibM3kYC6N8aibDn7VKK4bRCrJCN4cZicggEUUKQ9Ug/640?wx_fmt=png&from=appmsg "null")  
  
  
免责声明：请勿利用文章内的相关技术从事非法测试，由于传播、利用此文所提供的信息或者工具而造成的任何直接或者间接的后果及损失，均由使用者本人负责，所产生的一切不良后果与文章作者无关。该文章仅供学习用途使用！！！  
  
