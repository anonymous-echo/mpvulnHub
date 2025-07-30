#  BlueKeep远程桌面代码执行漏洞   
原创 小智  智检安全   2025-02-19 08:31  
  
CVE-2019-0708(BlueKeep)  
  
远程桌面代码执行漏洞与靶机复现  
## 1.漏洞介绍  
  
2019年5月14日微软官方发布安全补丁，修复了Windows远程桌面服务的远程代码执行漏洞，该漏洞影响了某些旧版本的Windows系统。此漏洞是预身份验证，无需用户交互，这就意味着这个漏洞可以通过网络蠕虫的方式被利用，与2017年WannaCry勒索病毒的传播方式类似。  
## 2.漏洞原理      
  
存在漏洞的远程桌面服务器，在接收到特殊数据包时会释放一个内部信道MS_T120的控制结构体，但并未将指向该结构体的指针删除，而且在远程桌面连接结束之后还会调用 MS_T120结构体内的一个函数指针，若攻击者可通过远程发送数据重新占据被释放的MS_T120，并为结构体内的函数指针赋恰当的值，即可实现远程命令执行。  
## 3.影响版本  
  
目前已知受影响的 Windows 版本包括但不限于：  
  
Windows 7  
  
Windows Server 2008  
  
Windows Server 2008 R2  
  
Windows Server 2003  
  
Windows XP  
  
Windows 8和windows 10以及之后的版本不受此漏洞影响  
## 4.靶机环境搭建      
  
本次复现的靶机环境为Windows 7 SP1的旗舰版  
  
靶机下载链接:  
  
https://pan.baidu.com/s/14aSIZgOebdLmeI2l9lGx_w  
  
提取码:bw7m  
## 5.靶机配置      
  
导入ISO文件光盘镜像文件  
  
![](https://mmbiz.qpic.cn/mmbiz_png/UHKCrPQZGh7pVe6lObZoJdSOgpl4RLIic9uUIgASoKyBeQPSIy1JR7tt3N9ia5KbhUfTn7xE7A2ia75fhqXMUtia9Q/640?wx_fmt=png "")  
  
升级一下系统版本  
  
![](https://mmbiz.qpic.cn/mmbiz_png/UHKCrPQZGh7pVe6lObZoJdSOgpl4RLIic2MOofcuS1aEpal4dePABYCGMzTuUGOd3ibxr0pbRSQe9icQ08jkR0icvw/640?wx_fmt=png "")  
  
输入序列号：  
  
6K2KY-BFH24-PJW6W-9GK29-TMPWP  
  
开启远程桌面服务  
  
![](https://mmbiz.qpic.cn/mmbiz_png/UHKCrPQZGh7pVe6lObZoJdSOgpl4RLIicA0t2aFfSXb54M531e9UO3VvpAfKe9cOYRT1WO6bExEk2qdjUJA1uSw/640?wx_fmt=png "")  
  
      
  
查看靶机IP。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/UHKCrPQZGh7pVe6lObZoJdSOgpl4RLIicyg63Nk2BcICupiaQWTKicegd49RUvW8ZRNTXvibWt7oUPkPTRVMicOu0dg/640?wx_fmt=png "")  
  
## 6.攻击机Kali漏洞利用  
  
![](https://mmbiz.qpic.cn/mmbiz_png/UHKCrPQZGh7pVe6lObZoJdSOgpl4RLIicpD3BJLrrVic9HthGXNsN77hg3lLadibNQ7riaVlVLLbklsLJFQG24icMQQ/640?wx_fmt=png "")  
  
启动msf，使用reload_all重新加载0708的利用模块。  
      
  
![](https://mmbiz.qpic.cn/mmbiz_png/UHKCrPQZGh7pVe6lObZoJdSOgpl4RLIicKVMl729GHvQ39jUldVib97ibQT4DkY1hYe18tpicIfxVROgsYaVxVF45Q/640?wx_fmt=png "")  
  
搜寻bluekeep利用模块  
  
![](https://mmbiz.qpic.cn/mmbiz_png/UHKCrPQZGh7pVe6lObZoJdSOgpl4RLIicIq2TPkLwCbkjkMKSibNb7Nuiarj0No0Zf1GibJXG2K9M70zKVv5EI7uug/640?wx_fmt=png "")  
  
查看options  
  
![](https://mmbiz.qpic.cn/mmbiz_png/UHKCrPQZGh7pVe6lObZoJdSOgpl4RLIicPypfJ5zClqxAz6MFZ99ticNia3TibOaQBxFZvJict6z2chtVK7NSSwqFicQ/640?wx_fmt=png "")  
  
配置靶机IP：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/UHKCrPQZGh7pVe6lObZoJdSOgpl4RLIicALfu2sI1KCVaf4OVBnd6IJiaexjngMy4C2WyHpD2kdia55gT5sA1HNqw/640?wx_fmt=png "")  
  
查看target，设置target为我们的靶机所对应的版本：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/UHKCrPQZGh7pVe6lObZoJdSOgpl4RLIic4jrYXWH1gXDibzliaJAcVebZbKpB1PWZ559vxMmL5DFGP49ibRo1gvSQw/640?wx_fmt=png "")  
  
      
  
![](https://mmbiz.qpic.cn/mmbiz_png/UHKCrPQZGh7pVe6lObZoJdSOgpl4RLIicjasoh0BkEUt1awX6bqFeZXDJJjm7hKgKdXj0MBVmPNkhCKxn6oYrHg/640?wx_fmt=png "")  
  
开始攻击：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/UHKCrPQZGh7pVe6lObZoJdSOgpl4RLIicG9DLAr93SDfGyxbOFtpJdhfXa0yoyfed2uiapDpBCPKiby9ibkxOemseA/640?wx_fmt=png "")  
  
拿到shell：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/UHKCrPQZGh7pVe6lObZoJdSOgpl4RLIicQrw6xSI0o4FetSiaPYSfTnfg7ibonUJ8GTtBZsUVEopggcglbn65ibn0A/640?wx_fmt=png "")  
  
  
在复现过程中可能会出现导致靶机蓝屏重启：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/UHKCrPQZGh7pVe6lObZoJdSOgpl4RLIicXVrGgyXwUQRY0jGzhB4D1FyO2iaSw6go60lXvp8rIW8769IiagkTw2qQ/640?wx_fmt=png "")  
  
      
  
此时需要退出msf，重复之前的步骤即可成功复现。  
      
  
