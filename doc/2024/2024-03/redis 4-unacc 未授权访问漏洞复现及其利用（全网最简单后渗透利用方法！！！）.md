#  redis 4-unacc 未授权访问漏洞复现及其利用（全网最简单后渗透利用方法！！！）   
admin  猎洞时刻   2024-03-10 20:03  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/bL2iaicTYdZn6qjhZor18QnWUIA5nd7ictrUejhVibxjCbhm8PMfAXibLWJqGRv9nyqWOicQeKazDoeRscOKWUibr7DKA/640?wx_fmt=gif&from=appmsg "")  
  
点击上方蓝字关注我们  
  
  
redis 4-unacc 未授权访问漏洞复现及其利用（全网最简单后渗透利用方法！！！）  
  
一、漏洞详情  
  
Redis默认情况下，会绑定在0.0.0.0:6379(在redis3.2之后，redis增加了protected-mode，在这个模式下，非绑定IP或者没有配置密码访问时都会报错)，如果没有进行采用相关的策略，比如添加防火墙规则避免其他非信任来源ip访问等等，这样将会将Redis服务暴露在公网上，如果在没有设置密码认证(默认为空)的情况下，会导致任意用户在可以访问目标服务器的情况下未授权访问Redis以及读取Redis的数据。  
  
攻击者在未授权访问Redis的情况下，利用Redis自身的提供的config命令，可以进行写文件操作，攻击者还可以成功将自己的ssh公钥写入目标服务器的/root/.ssh文件的authotrized_keys 文件中，进而可以使用对应私钥直接使用ssh服务器登录目标服务器。  
  
漏洞的产生条件有以下两点:  
  
(1) Redis绑定在0.0.0.0:6379,且没有进行添加防火墙规则避免其他非信任来源ip访问等相关安全策略  
  
(2) 没有设置密码认证(默认为空)或者弱密码，可以免密登录  
  
二、复现过程  
  
使用的是vulhub复现的该漏洞，使用docker直接使用即可。  
  
启动漏洞环境  
  
扫描端口开放状态  
  
使用工具连接  
  
后渗透(最简单!!!)  
  
1.启动  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/bL2iaicTYdZn6qjhZor18QnWUIA5nd7ictrcBzrXxNX1Yg30sHicwibtSr8AmdSdJZ80jTOPkzkczWsn5L6MCsrlQbg/640?wx_fmt=gif&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/8GQz4qbEzVafXPFNS6tUhTZ1LFRCjsfcTINEbFd6uLgpasuMTVxAg6Dpbic2hibarr4Do9p8zOKuy2oHXwoc7GpQ/640?wx_fmt=png&from=appmsg "")  
  
2.扫描  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/bL2iaicTYdZn6qjhZor18QnWUIA5nd7ictrcBzrXxNX1Yg30sHicwibtSr8AmdSdJZ80jTOPkzkczWsn5L6MCsrlQbg/640?wx_fmt=gif&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/8GQz4qbEzVafXPFNS6tUhTZ1LFRCjsfcMuvVkYK6hAWJicKlN9yALUsduPmG43eibOVmef1HgENmQPcfbdf9jpxQ/640?wx_fmt=png&from=appmsg "")  
  
3.工具(redis-cli远程连接工具)  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/bL2iaicTYdZn6qjhZor18QnWUIA5nd7ictrUejhVibxjCbhm8PMfAXibLWJqGRv9nyqWOicQeKazDoeRscOKWUibr7DKA/640?wx_fmt=gif&from=appmsg "")  
  
PART.1  
  
**无密码登录**  
  
redis-cli -h 目标主机IP  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/bL2iaicTYdZn6qjhZor18QnWUIA5nd7ictrUejhVibxjCbhm8PMfAXibLWJqGRv9nyqWOicQeKazDoeRscOKWUibr7DKA/640?wx_fmt=gif&from=appmsg "")  
  
PART.1  
  
**有密码登录**  
  
redis-cli -h 目标主机IP -p 端口6379 -a 登录密码  
  
4.后渗透  
  
使用py脚本执行远程命令  
  
1.git clone   
https://github.com/vulhub/redis-rogue-getshell.git  
  
2.cd redis-rogue-getshell/RedisModulesSDK/exp  
  
3.make  
  
4.回到redis-rogue-getshell目录下  
  
5.(第一个ip是靶机，第二个ip是攻击机)  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/bL2iaicTYdZn6qjhZor18QnWUIA5nd7ictrcBzrXxNX1Yg30sHicwibtSr8AmdSdJZ80jTOPkzkczWsn5L6MCsrlQbg/640?wx_fmt=gif&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/8GQz4qbEzVafXPFNS6tUhTZ1LFRCjsfcgJYVBib0QuFGZIVzkqicUv9H07J1SW0SLzoLPn5XJ0VibrGXQMrCIRyPQ/640?wx_fmt=png&from=appmsg "")  
  
6.可以直接执行命令，比如写webshell/crontab-计划任务getshell等  
  
感谢观看  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/bL2iaicTYdZn6qjhZor18QnWUIA5nd7ictrUejhVibxjCbhm8PMfAXibLWJqGRv9nyqWOicQeKazDoeRscOKWUibr7DKA/640?wx_fmt=gif&from=appmsg "")  
  
  
  
  
