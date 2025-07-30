#  通达OA OfficeTask前台RCE、SQL注入漏洞分析   
原创 烽火台实验室  Beacon Tower Lab   2025-05-28 02:55  
  
一、漏洞概述  
  
  
**注:本文仅以安全研究为目的,分享对该漏洞的挖掘过程,文中涉及的所有漏洞均已报送给国家单位,请勿用做非法用途。**  
  
通达OA是国内常用的智能办公系统，为各行业不同规模的众多用户提供信息化管理能力，包括流程审批、行政办公、日常事务、数据统计分析、即时通讯、移动办公等，帮助广大用户降低沟通和管理成本，提升生产和决策效率。  
  
  
其组件定时任务服务OfficeTask开放udp端口2397，未授权接收数据，并根据数据中的命令控制字符串，执行指定任务。导致存在未授权任意php文件执行、SQL注入漏洞。  
  
  
**二、影响范围**  
  
  
  
最新版通达OA 13.2（更新时间2025-02-14 13:39）  
  
  
三、漏洞分析  
  
  
  
使用的版本为官网最新版，通达OA（V13版）13.2。下载地址：  
```
https://www.tongda2000.com/download/p2024.php
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/8E5sfrfkeAOgtejEInvRIZbCQXBT77Nm151tpyMzp8uNJ5U6kTzsaNslKYdDoJADoa8lgu3ia2nwibVKc7zSc4kw/640?wx_fmt=png&from=appmsg "")  
  
安装好后，将创建通达定时任务服务Office_Task，并开机自启动。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/8E5sfrfkeAOgtejEInvRIZbCQXBT77Nm4ETjXz00IcqiawutY3gR4xEaZCNIITmSddNicaMawGtH2r7U2rEpHAYQ/640?wx_fmt=png&from=appmsg "")  
  
  
通达定时任务服务OfficeTask.exe在0.0.0.0地址开放UDP端口2397，可以被外部直接访问。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/8E5sfrfkeAOgtejEInvRIZbCQXBT77NmTQ1ZiabEYXyZgRa9F9u21YgcZguric5RRuACFpTENTjrYrzZmibuI4S5Q/640?wx_fmt=png&from=appmsg "")  
  
  
OfficeTask.exe从2397端口接收到数据后，根据数据中的命令控制字符串，执行指定任务。命令控制字符串与命令参数以空格分隔，任务包括执行php文件，更新、备份数据库等。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/8E5sfrfkeAOgtejEInvRIZbCQXBT77NmKuXZibyC3bj1glyfiacwFlnLoNLf28ziarLOvJYCOxTVDibF5Mp8RibCslQ/640?wx_fmt=png&from=appmsg "")  
  
  
**四、前台RCE漏洞**  
  
  
  
其中命令字符串EXEC_HTTP_TASK_0表示执行指定php文件，命令参数为：php文件名和路径，可控。命令格式为：EXEC_HTTP_TASK_0  \..\poc.php。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/8E5sfrfkeAOgtejEInvRIZbCQXBT77NmB64EicIEaFjF6PblPj2xmvlaFna9lMw08rE4rtSYYwoOCiaSz7icmaM0w/640?wx_fmt=png&from=appmsg "")  
  
  
最终将创建php.exe进程，将需要执行的php文件拼接上通达OA默认安装路径C:\MYOA\webroot\，一同作为参数传递给php.exe进程执行。具体执行的命令，还会保存到默认目录下的C:\MYOA\logs\Office_Task.log日志文件中。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/8E5sfrfkeAOgtejEInvRIZbCQXBT77NmpFVJpGdcGibSFc7pictvKFZnAbMuJnvHNmnSgt2SjdjzaW0lHSr8GdGw/640?wx_fmt=png&from=appmsg "")  
  
  
由于是调用php.exe程序来执行，并不能像日志中看到的那样直接闭合双引号来实现任意命令执行，只能通过执行恶意的php脚本文件来RCE。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/8E5sfrfkeAOgtejEInvRIZbCQXBT77Nm4sy3Pzl2dktZspUFkjAjxAib8rdCOBne6xF4L3exgV4zqNIibiaqfakQQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/8E5sfrfkeAOgtejEInvRIZbCQXBT77NmiakhHbetOPOs9ib7oljs2W6ky2IIB5WLIhDpIJ77oU4khDgMJcW6tHGw/640?wx_fmt=png&from=appmsg "")  
  
  
php.exe命令执行时通过-f参数传递待执行的php文件，但是这里并不限制文件后缀必须为php。所以可以通过下面的方式分成两步来达到RCE效果。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/8E5sfrfkeAOgtejEInvRIZbCQXBT77Nmy3pr0OQwGQW6LArNXmlzd20O3BKibvKlibkRxibfb8Sicr3NEmXzjIAhUg/640?wx_fmt=png&from=appmsg "")  
  
  
命令执行成功之后会在网站根目录生成一句话木马，文件路径为webshell /logon.php。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/8E5sfrfkeAOgtejEInvRIZbCQXBT77NmFKKqA7UUicbNoviaicZ7yGZ5LFExslJ7TCGFgS3ia5bIibnicBVxBrsEk32w/640?wx_fmt=png&from=appmsg "")  
  
  
对于旧版本（V12.9及以前的版本）的通达OA需要把EXEC_HTTP_TASK_0替换为EXEC_HTTP_TASK。  
  
  
**五、前台SQL注入漏洞**  
  
  
  
其中FILE_SORT_UPD_3命令字符串将执行SQL语句update更新数据库表FILE_SORT的内容。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/8E5sfrfkeAOgtejEInvRIZbCQXBT77NmZUDJ5EcDk3KVT4YAUePFiavDib6ib5Kvmsk7oUC43DObRbibNFJbwuibAOA/640?wx_fmt=png&from=appmsg "")  
  
  
SQL语句中的SORT_ID值和更新的内容可控，未做任何过滤，存在SQL注入漏洞。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/8E5sfrfkeAOgtejEInvRIZbCQXBT77NmcGOqBhzIGcOjKZPzpekIos0BRW7Bicnmy7ib9Mnw1FBFqPXJCG7WKkxg/640?wx_fmt=png&from=appmsg "")  
  
  
SQL注入命令格式为：FILE_SORT_UPD_3  set_value@^@SORT_ID。其中“@^@”字符串为固定格式，用于分割set_value和SORT_ID。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/8E5sfrfkeAOgtejEInvRIZbCQXBT77NmNO9mcgxF5ykoaBicQfEKoHdd52wyfywQfwu7Iwow5hwIRNQy9gKqozA/640?wx_fmt=png&from=appmsg "")  
  
比如执行如下FILE_SORT_UPD_3命令：  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/8E5sfrfkeAOgtejEInvRIZbCQXBT77NmIgQGIrjTjQzFV7mhWbsKgniaXHHm4kiczXVtS6RcHAiag5SkdJYJnEfqw/640?wx_fmt=png&from=appmsg "")  
  
  
再查看file_sort表，其中sort_id=1的SORT_NAME数据修改为2，这表明SQL注入已经成功。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/8E5sfrfkeAOgtejEInvRIZbCQXBT77Nm7pDUkxVC7ziax5gEd3XUKQXX2KWE7IjWjw9L3NdNA9lymkssZn27Jfg/640?wx_fmt=png&from=appmsg "")  
  
  
通过上面的分析可以看出此漏洞属于update类型的SQL注入漏洞，只能进行盲注，并且不支持多语句。为了更好的利用此漏洞，作者直接给出可以利用此漏洞通过bool盲注获取数据库中管理员用户密码的exp脚本。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/8E5sfrfkeAOgtejEInvRIZbCQXBT77Nm77ial188wjeSibsIqxJNDEhf8UZq711wEdnRK47a9c0CE68DNice53oUQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/8E5sfrfkeAOgtejEInvRIZbCQXBT77NmsoF4iaBGgRtl8MAG2306j3u1mUCiaMwbI5AficrxpayB1f3WwDdhjOMibg/640?wx_fmt=png&from=appmsg "")  
  
  
对于旧版本（V12.9及以前的版本）的通达OA需要把FILE_SORT_UPD_3替换为FILE_SORT_UPD。  
  
  
  
**六、参考链接**  
  
  
```
https://www.ddpoc.com/DVB-2025-8979.html
https://www.ddpoc.com/DVB-2025-8971.html
```  
  
  
