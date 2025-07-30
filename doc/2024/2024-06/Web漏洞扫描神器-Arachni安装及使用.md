#  Web漏洞扫描神器-Arachni安装及使用   
原创 大表哥吆  kali笔记   2024-06-01 15:54  
  
> arachni是一款开源的非常好用的漏洞扫描工具。它是一个包含很多特性、模块化的、高性能的Ruby框架，目的是帮助渗透测试人员和管理者评估现代web应用程序的安全。Arachni是免费、开源的，它支持所有主流操作系统，如：Windows、Mac OS X 、Linux，通过便携式可移植包的形式进行分发，使其满足即时部署的要求。  
  
# 安装  
  
访问Arachni项目地址https://github.com/Arachni/arachni/releases，根据你的环境，选择你需要的版本，如下图：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Xb3L3wnAiatghI1VySsokRJqV0A6RZMVuicz3DbGK677FhQ7v20XDKMloWc7bTnAYXnONV6Sibym968bqsrh1YaXg/640?wx_fmt=png&from=appmsg "")  
```
tar -zxvf arachni-1.6.1.3-0.6.1.1-linux-x86_64.tar.gz
cd arachni-1.6.1.3-0.6.1.1
cd bin 

```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Xb3L3wnAiatghI1VySsokRJqV0A6RZMVulw4rEz1ThibRJiaFQC1bRqBcHSlQahYh9DK2TIOyVUJoTZcvV8hHhgFg/640?wx_fmt=png&from=appmsg "")  
arachni有两种运行模式，一种是web模式，一种是命令行模式  
  
**命令模式：**  
  
在bin目录下运行：./arachni_console**Web模式：**  
  
在bin目录下运行：./arachni_web  
# 使用  
  
使用浏览器访问 http://localhost:9292/  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Xb3L3wnAiatghI1VySsokRJqV0A6RZMVuSGrjuOxJNErGHUicXpMWeuvnV6NHsFzJIS6T2XQZ5vX6eW7XvgSNt3w/640?wx_fmt=png&from=appmsg "")  
**管理员账户和密码**  
```
#管理员账号密码
E-mail: admin@admin.admin
Password: administrator

#普通账号密码
E-mail: user@user.user
Password: regular_user

```  
### 01配置扫描测量  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Xb3L3wnAiatghI1VySsokRJqV0A6RZMVuqzhPeUH6BQtuOU28STV4lR9b4EAXNv8kyumdduXG9uib234bznCeLog/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Xb3L3wnAiatghI1VySsokRJqV0A6RZMVuic4QrJypvDetjoh38d49s7J8GW9sNL5qRmqyswBpXsH7tM0aOFLGCfQ/640?wx_fmt=png&from=appmsg "")  
  
基本信息  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Xb3L3wnAiatghI1VySsokRJqV0A6RZMVu3V6IVYuJTeCuDJtF8Pg5ZZsEzcV7Kx3hBQZA1Fe0CIWuFG2sDADe9A/640?wx_fmt=png&from=appmsg "")  
  
HTTP设置  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Xb3L3wnAiatghI1VySsokRJqV0A6RZMVu5rrG3lnAg2qiaibyO35tMxGOPF8Gxppc5qR5gwtZJia8GnicWjCqPCmLrw/640?wx_fmt=png&from=appmsg "")  
  
指纹识别  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Xb3L3wnAiatghI1VySsokRJqV0A6RZMVuOw4TORzly3ZJHNElOIXISiay8ZHphLslozkjicd1yc2oc6pXdxmkxiavw/640?wx_fmt=png&from=appmsg "")  
  
主动扫描  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Xb3L3wnAiatghI1VySsokRJqV0A6RZMVu7J804HOKMnslxibJkrFqBKfbjtOSAeUpKicJIqKWziak193l7HhYdygUA/640?wx_fmt=png&from=appmsg "")  
  
选择插件  
  
最后创建配置。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Xb3L3wnAiatghI1VySsokRJqV0A6RZMVu3x6k9aG4icH5zHdZ6nNTkklQW7hUDC1Idl3I7icWoricBx10f1q69QafQ/640?wx_fmt=png&from=appmsg "")  
### 02开始扫描  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Xb3L3wnAiatghI1VySsokRJqV0A6RZMVutaGYgHjUBeRgpcOILX5LQCGW5fJ4KWt23fNUrGroMSJBBia5Dib4qhSQ/640?wx_fmt=png&from=appmsg "")  
输入目标域名，开始扫描。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Xb3L3wnAiatghI1VySsokRJqV0A6RZMVuaeiaIndoibgNtOXiafZicpA56GI25BwqEH3MlfYEC5q5HvMj8ibrgxYl3bQ/640?wx_fmt=png&from=appmsg "")  
  
最终，扫描结果可以查看扫描报告。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Xb3L3wnAiatghI1VySsokRJqV0A6RZMVua92RUgSGU1e5hPXtLTN7ickAHoVs2YJRMPRHtsWnaS86yM25qBqQ25Q/640?wx_fmt=png&from=appmsg "")  
  
  
**更多精彩文章 欢迎关注我们**  
  
  
