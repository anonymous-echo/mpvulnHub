#  Tenda AC9 SetSystime 命令注入漏洞分析   
原创 F0und  ChaMd5安全团队   2022-07-17 08:06  
  
## 0x10 前言  
  
这个漏洞很有趣，其实在 18 年就已经报过了（后面一直没修）  
  
![](https://mmbiz.qpic.cn/mmbiz_png/PUubqXlrzBQ8XhicldUsGqwyGmiaicIMxFJpPNAVruiaQr5NwwT9mAqhT5fr7z04KZbFtelEchgmUHGLkITF7qM4rg/640?wx_fmt=png "")  
  
可以看到报了四个漏洞，但这些漏洞报的都是栈溢出。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/PUubqXlrzBQ8XhicldUsGqwyGmiaicIMxFJSYsCyZRbibpjwS3ZV37ic8iatnzzEficMZqiauKRf1TNsZShhY7jQxL9zlw/640?wx_fmt=png "")  
  
但当我偶然接触到这个设备的时候（Tenda AC9） 使用 Telnet 拿到 shell 后查看 PS 的时候发现  
  
![](https://mmbiz.qpic.cn/mmbiz_png/PUubqXlrzBQ8XhicldUsGqwyGmiaicIMxFJqCcBE2Sqz7PQr6ycJLf1ofJB1JP9UdvXScG0RSKXicuN6aDH6Jc8zfg/640?wx_fmt=png "")  
  
而我尝试了一下发现，这里是可控的  
  
![](https://mmbiz.qpic.cn/mmbiz_png/PUubqXlrzBQ8XhicldUsGqwyGmiaicIMxFJtL6Y2oEjuUH3FicvB8XBMiakVqdJgRtPVqP19yC8NwJhK0r6BVibSZ3IA/640?wx_fmt=png "")  
  
并且这个命令确实执行了  
  
![](https://mmbiz.qpic.cn/mmbiz_png/PUubqXlrzBQ8XhicldUsGqwyGmiaicIMxFJmeNYz0FT7B6Ak6v0qALGy3OeRnAWFhweLIKP2icp5lNxT6lPEMYP3zA/640?wx_fmt=png "")  
  
于是我们就开始疑惑，因为在分析 httpd 的时候并没有发现能够执行命令的地方，没有在 httpd 这个文件里发现doSystem这种函数来执行这个命令，但这个命令又一直存在于进程中。因此觉得这个漏洞或许很有趣，才有了下面的分析，这也帮助了挖到了 AX18 系列的命令注入漏洞。  
## 0x20 漏洞分析  
  
首先我们要知道，这个参数一定是从 web 端传入进来的。因此我们首先就要去分析 httpd，我们仔细观察这段代码  
  
![](https://mmbiz.qpic.cn/mmbiz_png/PUubqXlrzBQ8XhicldUsGqwyGmiaicIMxFJiauvHT6jZCgRbMac92kGNfkyen2CicGwEYSjJI3TauQth2sz7ntzeVjQ/640?wx_fmt=png "")  
  
我们发现他使用了 Cfm， 而根据我们挖掘 Tenda 设备的经验来看，这个程序类似一个中间件，像 NVRAM 这种管理环境变量用的  
  
![](https://mmbiz.qpic.cn/mmbiz_png/PUubqXlrzBQ8XhicldUsGqwyGmiaicIMxFJC4EPNLfAJ2tKQtLm2GVX45FfJJxmM4wVwGOO9sO49tpbwPtG7QKoPg/640?wx_fmt=png "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/PUubqXlrzBQ8XhicldUsGqwyGmiaicIMxFJxwoNOHBI2ibMHibKGb6gc1IIyOHkoCRIsNXIt2nPhagdbudjXcBcILQA/640?wx_fmt=png "")  
  
而我们搜索全局字符串，发现sntp这个字符串同样出现在了netctrl 这个文件里面 而在这个文件里面我们发现set_sntp_cfg 这个函数，在这个函数中我们又发现他连接了 Cfm 这个中间件。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/PUubqXlrzBQ8XhicldUsGqwyGmiaicIMxFJiaVy14zC3KqDZzbiaMbtqVWsciaUsM1If8JiclOYWExDR2vKQ2hGAegiasA/640?wx_fmt=png "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/PUubqXlrzBQ8XhicldUsGqwyGmiaicIMxFJ7PU5EoyZfDH0rxdbOpfqR3dfibAAzxLPnzxIYZqicID8r3bYExPrWkLQ/640?wx_fmt=png "")  
  
通过对这个函数的分析我们发现他又调用了tp_sntp_handle 这个函数，而这个函数的实现是在libtpi.so 中实现的，我们跟过去分析发现  
  
![](https://mmbiz.qpic.cn/mmbiz_png/PUubqXlrzBQ8XhicldUsGqwyGmiaicIMxFJocFV9sichOX0RJQ9QeWY3mibot7CqqlZthTaHGFHtdpabbSXyPKcam0A/640?wx_fmt=png "")  
  
我们的命令是在这个函数里执行的。至此我们就找到了漏洞最终执行的地方了。我们整合调用链条就可以理清这个漏洞的逻辑  
```
httpd send env -> cfm (cfm连接netctrl) -> netctrl 取 env 调用函数set_sntp_cfg -> tpi_sntp_handle -> doSystemCmd
```  
  
而在这个漏洞中 netctrl 是通过 cfm 与 httpd 连接起来的  
```
httpd -> cfm <- netctrl

```  
## 0x30 总结  
  
这个漏洞涉及了多个文件，挖掘以及使用污点分析匹配起来是很困难的（但也可以匹配），对于本漏洞数据传递过程为  
```
httpd: 参数 netserver
cfm: 中间件，环境变量 sntp_cfg
netctrl: 连接cfm程序，set_sntp_cfg 获取cfm中的环境变量并执行
libtpi.so: tp_sntp_handle 执行doSystem

```  
  
而这个漏洞以及CVE-2022-28572这个漏洞有一个共同点，就是漏洞执行最终在 so 文件里面，而我们一般分析一个设备，大多数时间只关注他的主程序（大哥都挖烂了）而忽略了最容易出问题的地方。  
  
因此我们想要挖出更多的漏洞或者想要自己的工具匹配到更多的漏洞，我们需要更多的去关注动态链接库文件。  
  
end  
  
  
招新小广告  
  
ChaMd5 Venom 招收大佬入圈  
  
新成立组IOT+工控+样本分析   
长期招新  
  
欢迎联系  
admin@chamd5.org  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/PUubqXlrzBR8nk7RR7HefBINILy4PClwoEMzGCJovye9KIsEjCKwxlqcSFsGJSv3OtYIjmKpXzVyfzlqSicWwxQ/640?wx_fmt=jpeg "")  
