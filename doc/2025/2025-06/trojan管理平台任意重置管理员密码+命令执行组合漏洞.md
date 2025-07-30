#  trojan管理平台任意重置管理员密码+命令执行组合漏洞  
原创 zangcc  Eureka安全   2025-06-09 08:51  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/BictawU0A1NPmibPmwrMnlL4Gadw4ibwrvtRsBy8K8ZfSqK9jlcOcY8YNwpuiaLTR7fKcXWl7iauRhoo5HfKH0buFYA/640?wx_fmt=jpeg&from=appmsg "")  
  
  
  
      
需要明确的是，此次研究和分享基于技术研究和提升安全意识的目的。我们旨在通过对此漏洞的  
分析，帮助广大安全从业者更好地了解漏洞的成因、存在的风险，以及如何有效进行防范。  
  
    我们在  
此郑重声明，本文的读者应当是出于合法、合规的目的来阅读和使用这些信息。任何未经授权使用  
本文内容对其他系统进行攻击的行为，都与本公众号及作者本人无关。我们强烈谴责任何非法利用  
安全研究的行为，并呼吁所有安全从业者秉持道德和法律准则，共同维护网络安全环境的健康发  
展。  
  
## 0x01 前言  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BictawU0A1NOK3HDK4feqOgubSAxrlY6uOWgj0f2WVXialFIYTvqxNHXUiaU0DbjLbPAXDpd28024ISAJ4DmTCUCQ/640?wx_fmt=png&from=appmsg "")  
  
受影响的系统源码：  
  
https://github.com/Jrohy/trojan  
  
受影响的版本：v2.0.0 - v2.15.3  
  
用户数量非常多，是一个国产的管理平台。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BictawU0A1NOK3HDK4feqOgubSAxrlY6uxicDbclK2TU5FJ6KC3DNwiaCCAwECf6aLvP3ibKuWiaGCL8gX0lVIDo9jQ/640?wx_fmt=png&from=appmsg "")  
  
fofa语法：  
title=="trojan 管理平台"  
  
  
  
## 0x02 环境搭建  
  
我们不建议用fofa或者其他网络检测平台在互联网上直接用poc对网站进行复现，建议采用docker的方式本地搭建环境，会快捷方便一点。  
  
1、安装数据库：  
  
因为mariadb内存使用比mysql至少减少一半, 所以推荐使用mariadb数据库  
```
docker run --name trojan-mariadb --restart=always -p 3306:3306 -v /home/mariadb:/var/lib/mysql -e MYSQL_ROOT_PASSWORD=trojan -e MYSQL_ROOT_HOST=% -e MYSQL_DATABASE=trojan -d mariadb:10.2
```  
  
2、安装trojan：  
```
docker run -it -d --name trojan --net=host --restart=always --privileged jrohy/trojan init
```  
  
3、运行完后进入容器   
```
docker exec -it trojan bash
```  
  
然后输入'trojan'即可进行初始化安装  
  
启动web服务:   
```
systemctl start trojan-web
```  
  
设置自启动:   
```
systemctl enable trojan-web
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BictawU0A1NOK3HDK4feqOgubSAxrlY6uNkI662j9OTibJ2zLck6tS5cWnUZ4GPibJknlEGvb6KlVKQtqUXBlDicEw/640?wx_fmt=png&from=appmsg "")  
  
直接访问服务器的ip就能访问：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BictawU0A1NOK3HDK4feqOgubSAxrlY6uAJxFS145FYOmE2A32sk35U1LLZYfRCwe4safZbBx5hdFkbyHqibHr9g/640?wx_fmt=png&from=appmsg "")  
  
  
## 0x03 漏洞poc（任意修改管理员密码+命令执行）  
  
在初次登陆，访问后会让你设置admin密码。但是这个接口并没有做任何登陆态的限制，这也就导致，只要用户拿到这个接口，伪造一个请求包就能直接重置管理员的密码。这只是Jrohy-rotjan其中一个漏洞，我们先来分析这个任意修改管理密码漏洞，最新的命令执行漏洞需要配合这个漏洞一起来打。漏洞点在：  
  
https://github.com/Jrohy/trojan/blob/v2.15.3/web/auth.go#L155  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BictawU0A1NOK3HDK4feqOgubSAxrlY6upaGfAqxU7gShkuxkCISdHh0oMribOhgRs0ejurjLGEHYEfNrNq8gsQw/640?wx_fmt=png&from=appmsg "")  
```
```  
  
这将导致 admin 用户的密码被直接更新为 new_admin_password。任何未经授权的用户都可以通过访问 /auth/register 接口来重置 admin 用户的密码。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BictawU0A1NOK3HDK4feqOgubSAxrlY6uC2Vqr1DibzpvLqahmNvuka5PHO5CDaWkePZeRxuYjH1kzjkRVfgH4Ng/640?wx_fmt=png&from=appmsg "")  
  
直接用BurpSuite复现一下：  
  
