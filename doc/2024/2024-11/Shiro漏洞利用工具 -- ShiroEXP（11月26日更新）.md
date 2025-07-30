#  Shiro漏洞利用工具 -- ShiroEXP（11月26日更新）   
Y5neKO  Web安全工具库   2024-11-29 16:01  
  
===================================  
免责声明请勿利用文章内的相关技术从事非法测试，由于传播、利用此文所提供的信息而造成的任何直接或者间接的后果及损失，均由使用者本人负责，作者不为此承担任何责任。工具来自网络，安全性自测，如有侵权请联系删除。个人微信：ivu123ivu  
0x01 工具介绍- 爆破key及加密方式(已完成)  
  
- 漏洞探测(已完成Shiro550 URLDNS探测)  
  
- 探测回显链(已完成CB1+TomcatEcho、Spring、AllEcho回显链)  
  
- 漏洞利用(已完成命令执行、Shell模式)  
  
- 注入内存马(支持蚁剑、冰蝎、哥斯拉等filter、servlet类型)  
  
- 全局代理(已完成)  
  
  
0x02 安装与使用```
➜  ShiroEXP_jar git:(main) ✗ java -jar ShiroEXP.jar -h

   _____    __      _                    ______   _  __    ____ 
  / ___/   / /_    (_)   _____  ____    / ____/  | |/ /   / __ \
  \__ \   / __ \  / /   / ___/ / __ \  / __/     |   /   / /_/ /
 ___/ /  / / / / / /   / /    / /_/ / / /___    /   |   / ____/ 
/____/  /_/ /_/ /_/   /_/     \____/ /_____/   /_/|_|  /_/      
                                                       v0.2 by Y5neKO :)
                                                       GitHub: https://github.com/Y5neKO

usage: java ShiroEXP.jar [-be] [-bk] [-c <arg>] [--cookie <arg>] [--gadget
       <arg>] [--gadget-echo <arg>] [-h] [-k <arg>] [--mem-pass <arg>]
       [--mem-path <arg>] [--mem-type <arg>] [--proxy <arg>] [-rf <arg>]
       [-s] [--shell] [-u <arg>]
 -be,--brute-echo              爆破回显链
 -bk,--brute-key               爆破key
 -c,--cmd <arg>                执行命令
    --cookie <arg>             携带Cookie
    --gadget <arg>             指定利用链
    --gadget-echo <arg>        指定回显链
 -h,--help                     打印帮助
 -k,--key <arg>                指定key
    --mem-pass <arg>           内存马密码
    --mem-path <arg>           内存马路径
    --mem-type <arg>           打入内存马类型(输入ls查看可用类型)
    --proxy <arg>              设置代理(ip:port)
 -rf,--rememberme-flag <arg>   自定义rememberMe字段名
 -s,--scan                     扫描漏洞
    --shell                    进入Shell模式
 -u,--url <arg>                目标地址
```  
  
爆破key及加密方式  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/8H1dCzib3UibvuwvyopfSGbibfbY2XGl3qLKjI9XvKFr8tFMuekXrfnwe56nLKmiabydPYwDwk6ubTu3c7o5TVxAjQ/640?wx_fmt=png&from=appmsg "")  
  
漏洞验证  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/8H1dCzib3UibvuwvyopfSGbibfbY2XGl3qLhtuWJWlVfoeroDBsMxjl6W5VhSxmwUwEHFYjic3XxbYcxjnySDZK3rQ/640?wx_fmt=png&from=appmsg "")  
  
爆破回显链  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/8H1dCzib3UibvuwvyopfSGbibfbY2XGl3qLTOm4HzUY6X09keONvvAIGR9Q1dIdjAMFchVG1VicSnyU2KIt9vJgfYA/640?wx_fmt=png&from=appmsg "")  
  
命令执行  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/8H1dCzib3UibvuwvyopfSGbibfbY2XGl3qLiaZZ3znwdxicIKibISgwPls8vyvbvHlvRtqJeTqd55fMe2kb9J8FiazJyA/640?wx_fmt=png&from=appmsg "")  
  
Shell模式  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/8H1dCzib3UibvuwvyopfSGbibfbY2XGl3qLzaol3er9zMO3Qzj4VuGZCrua8QRTMBl5Pce2UKicVyklc0kB87gNicJg/640?wx_fmt=png&from=appmsg "")  
  
注入内存马  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/8H1dCzib3UibvuwvyopfSGbibfbY2XGl3qLzxicTibUrHGV4yDWLInGncoImWN0tnGluiaHXwaTqTbIPGYMc1bPQFvGA/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/8H1dCzib3UibvuwvyopfSGbibfbY2XGl3qLMIQ9zQSPECHynj71TLiauomf2sP6BHRGy39jh4efD6lfnlYKLE7kicdw/640?wx_fmt=png&from=appmsg "")  
  
全局代理  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/8H1dCzib3UibvuwvyopfSGbibfbY2XGl3qLXVW7jHxicX7XvvT3UYfJicNzUpo2sNibKYhmafr4u2PVyfurXvwbKJliaQ/640?wx_fmt=png&from=appmsg "")  
  
**0x03 项目链接下载**  
  
1、点击阅读原文，从原项目地址下载。  
  
2、网盘下载链接：  
https://pan.quark.cn/s/93bbb1b39700  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/8H1dCzib3UibvuwvyopfSGbibfbY2XGl3qLVn1PCbSgx4icY3wbtLazWxIabyOeBicWsP7bibxGITue2xI5H5Jy3Qf3w/640?wx_fmt=png&from=appmsg "")  
  
  
  
  
**·****今 日 推 荐**  
**·**  
  
> 《C++编程之禅:从理论到实践》从C++的基础设计原则出发，详细地探讨了封装、继承、模板等核心概念，并介绍了C++20和C++23引入的一些现代特性。书中不仅讲解了C++的基本语法和结构，还探讨了类型系统、内存模型、并发编程、设计模式、架构策略以及性能分析等高级主题，并展示了诸多**实践供开发者参考。  
  
  
  
  
