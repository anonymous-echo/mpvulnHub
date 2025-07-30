#  Jenkins未授权访问-命令执行漏洞复现及修复方案   
徐志洋  玄武盾网络技术实验室   2025-06-05 07:49  
  
作者：徐志洋  
  
声明：  
技术仅用于学术交流，请遵守《网络安全法》，严禁将此文中工具和技术用于非法攻击测试。  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/UM0M1icqlo0n06C84WhlPT7RcIzsJBCljgsWSFP97S3t936WS2gZg5mWiajPuzwAVltB9JfjAibopIxvEtKp8PzDA/640?wx_fmt=png&tp=webp&wxfrom=5&wx_lazy=1 "")  
  
一、背景  
  
Jenkins 是一款功能强大的应用工具，支持跨平台实现项目的持续集成与持续交付。作为开源代码工具，其能够胜任各类构建任务或持续集成工作。通过集成 Jenkins，可将其应用于多种测试及部署场景。从本质上来说，Jenkins 是一种支撑持续集成的软件解决方案。  
  
形成漏洞的原因：jenkins 未设置帐号口令，或者使用了弱帐号口令  
## 二、搭建环境  
  
测试环境：  
  
靶机：Ubuntu16.04 IP: 192.168.3.210  
  
攻击机  
：kali IP: 192.168.3.211  
## 2.1 Jenkins的安装  
  
wget http://mirrors.jenkins.io/debian/jenkins_1.621_all.deb #下载源码  
  
![](https://mmbiz.qpic.cn/mmbiz_png/UM0M1icqlo0l1URJy9OtSjVBSeGmP3SWrOceuyte4QU3iaYXG3rps0tZpQ8vYNWjdLGUSQ2qJELe7Vl8CuaBqAnw/640?wx_fmt=png&from=appmsg "")  
  
dpkg -i jenkins_1.621_all.deb # 安装  
  
![](https://mmbiz.qpic.cn/mmbiz_png/UM0M1icqlo0l1URJy9OtSjVBSeGmP3SWrBOI6PDPSpicgJkf9Fuo2bkgjRZDERibkicBwEDOrgndlmxFviaMLfvagKg/640?wx_fmt=png&from=appmsg "")  
  
sudo apt-get  
 -f --fix-missing install # 如若出现报依赖项的错误时执行（解决上图报错的问题）  
  
![](https://mmbiz.qpic.cn/mmbiz_png/UM0M1icqlo0l1URJy9OtSjVBSeGmP3SWrqXtlZsJ6WyXAeg6vKV212DsYOUtdIMzib2ZwdSpgRJvMBQdL3kaehCg/640?wx_fmt=png&from=appmsg "")  
  
重新安装Jenkins  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/UM0M1icqlo0l1URJy9OtSjVBSeGmP3SWrJLKpaNsDqqvoic5A3CpJ8hVy29R8nKPN2aXeacDmdS4VmSdwZBniciaeQ/640?wx_fmt=jpeg&from=appmsg "")  
  
2.2 Jenkins 访问  
  
由于没有设置口令。可以直接访问，导致存在未授权访问漏洞。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/UM0M1icqlo0l1URJy9OtSjVBSeGmP3SWr1BBXLtWTdg5FqWjSoicXVXjhKATh2nG28WsNd7JOBC0S2NPUk1bHjOw/640?wx_fmt=png&from=appmsg "")  
## 三、漏洞复现  
## 3.1 命令执行  
  
点击>系统管理>脚本命令执行  
  
![](https://mmbiz.qpic.cn/mmbiz_png/UM0M1icqlo0l1URJy9OtSjVBSeGmP3SWrQvOykExo6oDKO9nfLPv0qtW9rB1pV2nNy0Yopnwx9236xM7ewjT1Hw/640?wx_fmt=png&from=appmsg "")  
  
查看ip信息  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/UM0M1icqlo0l1URJy9OtSjVBSeGmP3SWrmX1MRDqpk42HteDBo9Cjw5ImlIibYSqiaD3bLxplTNHMwItRujNRWPHg/640?wx_fmt=jpeg&from=appmsg "")  
  
查看账号信息  
  
![](https://mmbiz.qpic.cn/mmbiz_png/UM0M1icqlo0l1URJy9OtSjVBSeGmP3SWrTXqNpwgOIHwJCzC0icGd8tlFrwR4ppnf5NbKiahrpVrEfzb5PRic7pTLg/640?wx_fmt=png&from=appmsg "")  
  
命令  
成功被  
执行  
## 3.2 反弹shell  
  
1、在攻击机上监听 8888端口  
  
nc -lvp 8888  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/UM0M1icqlo0l1URJy9OtSjVBSeGmP3SWrPHpic0K81MKLIuP1Oo06ZLtWjY1NibHib2LcserH844z68pBoRiajc6iaYg/640?wx_fmt=jpeg&from=appmsg "")  
  
2、在Jenkins主机上通过  
执行  
命令漏洞进行反弹shell  
  
![](https://mmbiz.qpic.cn/mmbiz_png/UM0M1icqlo0l1URJy9OtSjVBSeGmP3SWr9mM4oGkd84iaEC02lx37remN5RNKsiabL2J9aaH4H8AKA5IicEcup1fcA/640?wx_fmt=png&from=appmsg "")  
  
  
3、成功获取shell  
  
![](https://mmbiz.qpic.cn/mmbiz_png/UM0M1icqlo0l1URJy9OtSjVBSeGmP3SWrPCRJuHmykSEYId4oAf8ibwpIugG8ou3XgZwFlGKRgJmJe7lohMvOQMQ/640?wx_fmt=png&from=appmsg "")  
  
## 四、漏洞修复  
  
1、仔细研判业务需求后Jenkins  
禁止  
直接暴露在互联网  
  
2、  
添加访问控制认证，设置强密码复杂度如口令设置为  
8位以上，包含大小写字母，特殊符号等及账号登录失败锁定。  
  
  
