#  TP-Link WR740 后门漏洞复现   
伯爵的信仰  看雪学苑   2023-07-18 17:59  
  
```
```  
  
  
◆binwalk  
  
◆firmwalker  
  
◆IDA  
  
◆FirmAE  
  
  
```
```  
  
#### 2.1 获取固件文件系统-binwalk  
  
  
binwalk用于固件解包获取文件系统。常用解包命令为：  
  
  
```
```  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8GsmuJcwcRUibv5zslumgEicRAYZ4xSfw0ibO9x6mTPpQTNOEkotDkrrv1CpsoWw2vjd3gnOLrSp5rDA/640?wx_fmt=png "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8GsmuJcwcRUibv5zslumgEicRicYF5sOXb6nyTQPechia1qq7EticOvjF1xRIb66gtw4EVKHHLNag9XicOg/640?wx_fmt=png "")  
  
#### 2.2 扫描敏感信息-firmwalker  
  
  
firmwalker用于查看文件系统中的敏感信息。扫描命令为：  
  
  
```
```  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8GsmuJcwcRUibv5zslumgEicRGQVJmd6NBvjpj9mLu2swibjedVMhx66pHhCteHc4TlQqSpzibRjPMvSw/640?wx_fmt=png "")  
  
  
由上面的信息可知：  
  
◆路由器Web相关URL的格式为：/web/userRpm/xxxxx.htm，这可能是web服务相关的命令规范。  
  
◆含有passwd和pwd相关的文件中，可以看到嵌入式web服务httpd，部分htm文件以及其他配置文件。  
  
  
查看启动项中是否存在后门服务，如telnet服务。嵌入式Linux常用启动项文件位于：etc/rc.d文件夹中。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8GsmuJcwcRUibv5zslumgEicRWGaWqy3tW5xaCfoBgEGNanBoHBNHnIvLeUkhNNibVCiaU7BKqJ3WCIDQ/640?wx_fmt=png "")  
  
  
启动项中未见异常行为，httpd文件在firmwalker扫描的敏感信息和启动项中都有涉，因此需要用IDA分析一下该文件。  
  
#### 2.3 分析可疑文件-IDA  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8GsmuJcwcRUibv5zslumgEicRiapxK8lVibAYjRuWGGcWbC4mnq2tQWmoGF10zH5W6ibqottgeEJEnF9zw/640?wx_fmt=png "")  
  
  
由file信息可知用IDA32分析，根据firmwalker扫出的敏感信息可知httpd文件中含passwd、password、root、admin、upgrade等字符串。  
  
  
通过IDA中字符串搜索发现疑似后门的敏感字符。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8GsmuJcwcRUibv5zslumgEicRKBSicGL90NrvKE21RGq29Vnmgklt9696ibWYiaRicMkGGZ243Oc5iadSPgA/640?wx_fmt=png "")  
  
  
通过查看该字符串的引用发现如下代码：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8GsmuJcwcRUibv5zslumgEicRSicpNDC5xOz9LcFonnItz9CH2vv8S2RmAicuqywMcCaQrHPBaYUFhLBw/640?wx_fmt=png "")  
  
  
根据伪代码可知其的功能是：判断命令是否为exit，若不是则验证用户名和密码，验证的用户名：osteam 密码：5up。  
  
  
通过write(pty,cmd,strlen(cmd))来模拟执行命令。（知识扩充：伪终端(pseudo terminal也称为 pty)是指伪终端 master 和伪终端 slave 这一对字符设备。其中的 slave 对应 /dev/pts/ 目录下的一个文件，而 master 则在内存中标识为一个文件描述符(fd)。伪终端由终端模拟器提供，终端模拟器是一个运行在用户态的应用程序。）  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8GsmuJcwcRUibv5zslumgEicRrPy5KAVH7xqbr0PjJjic6Kz9eNZhia1EzicT2YS0DpvU7MSjZQqXXkNdQ/640?wx_fmt=png "")  
  
  
通过查看引用找到了DebugResultRpmHtm函数的调用位置。根据此处的伪代码可推断出函数httpRpmConfAdd的功能是绑定URL和执行的函数。由函数名httpDebugInit可推断出这是一个调试后门。  
  
  
```
```  
  
  
使用FirmAE来对固件进行模拟以验证上述内容。  
  
  
FirmAE是一款完全自动化的固件模拟和漏洞分析的工具，其固件模拟成功率与Firmadyne工具相比大大提升，且与Qemu相比仅一条命令就可实现固件模拟，简单方便。FirmAE的工作模式分为5种：  
  
◆-c 检查是否能模拟  
  
◆-a 漏洞分析  
  
◆-r 固件模拟的运行  
  
◆-d 用户级的调试  
  
◆-b 内核级的调试  
  
  
```
```  
  
  
  
使用FirmAE模拟固件命令如下：  
  
  
```
```  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8GsmuJcwcRUibv5zslumgEicRoHNMyCrSos8eGaVMzX3YHcH1It49JbHUOO9eibAgFbCKygn4ZoGQ2FA/640?wx_fmt=png "")  
  
  
通过浏览器访问URL：  
http://192.168.1.1  
出现上图信息，说明模拟成功。开始运行固件模拟并验证后门漏洞。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8GsmuJcwcRUibv5zslumgEicRmlVJvcOZuqBDunX2byDBMNEzGKonAib7KE4u5hrUmd61EqUJfTt1MUg/640?wx_fmt=png "")  
  
  
固件开始运行，此时访问URL要求输入账号密码。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8GsmuJcwcRUibv5zslumgEicRQ7js1PQ5nV0pekPztmyZQNzLiaE2QozdlFumib7O9sbz7sibuyTudBEUQ/640?wx_fmt=png "")  
  
  
根据提示输入默认的账号密码admin。并访问URL：  
http://192.168.1.1/userRpmNatDebugRpm26525557/linux_cmdline.html  
出现以下界面：  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8GsmuJcwcRUibv5zslumgEicRFC3mSicqHBs1EyibjrPDIiaFge7VMVC8IBaTmH9HZibe8cN6dTYBT45ghA/640?wx_fmt=png "")  
  
  
尝试直接输入命令执行：  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8GsmuJcwcRUibv5zslumgEicRlcJ48ExD6EIp5xM9GwqD8EiagDqQndSvVfiaRYd3GhXUiaLKpXljoDWJw/640?wx_fmt=png "")  
  
  
根据返回结果可知是需要输入账号密码的。输入固件分析时找到的用户名：osteam和密码：5up并执行命令。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8GsmuJcwcRUibv5zslumgEicRiatCTgZkOvpvjL1BzA88RGia4E6J93Kc7KuqMlahqSZd8adpDyzApYtQ/640?wx_fmt=png "")  
  
  
由上可知命令被执行并返回。并且在右侧还预设了一些命令，点击按钮即可执行，这个后门很优雅。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8GsmuJcwcRUibv5zslumgEicRn0XliaxoA61hyuY9L3fDyrzm8kCPywHLCzj3kd2de5r7nhSlXwRWGjQ/640?wx_fmt=png "")  
  
  
```
```  
  
  
熟悉工具的使用和有一些分析常识很重要，通过信息收集到的敏感信息可以快速定位漏洞可能出现的位置并针对性分析，是一个由粗到细的过程。这是复现的第一个路由器漏洞，希望自己能坚持下去，用心复现，仔细记录。“靡不有初，鲜克有终！”  
  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8GsmuJcwcRUibv5zslumgEicRjJY8pq9Va1jcJRtOTvyvOibA7bqG1m9QLFnnd10E4ibE8NObibw5Tpu6Q/640?wx_fmt=png "")  
  
  
**看雪ID：伯爵的信仰**  
  
https://bbs.kanxue.com/user-home-882513.htm  
  
*本文为看雪论坛优秀文章，由 伯爵的信仰 原创，转载请注明来自看雪社区  
  
  
[](http://mp.weixin.qq.com/s?__biz=MjM5NTc2MDYxMw==&mid=2458499288&idx=1&sn=b2b9cd6ff7388a8658d254e13c72f9ad&chksm=b18e885286f9014436a590f2531fda167be67e1e227ea395812968e828932bd44eade34b0dbf&scene=21#wechat_redirect)  
  
  
**#****往期推荐**  
  
1、[在 Windows下搭建LLVM 使用环境](http://mp.weixin.qq.com/s?__biz=MjM5NTc2MDYxMw==&mid=2458500602&idx=1&sn=4bcc2af3c62e79403737ce6eb197effc&chksm=b18e8d7086f9046631a74245c89d5029c542976f21a98982b34dd59c0bda4624d49d1d0d246b&scene=21#wechat_redirect)  
  
  
2、[深入学习smali语法](http://mp.weixin.qq.com/s?__biz=MjM5NTc2MDYxMw==&mid=2458500599&idx=1&sn=8afbdf12634cbf147b7ca67986002161&chksm=b18e8d7d86f9046b55ff3f6868bd6e1133092b7b4ec7a0d5e115e1ad0a4bd0cb5004a6bb06d1&scene=21#wechat_redirect)  
  
  
3、[安卓加固脱壳分享](http://mp.weixin.qq.com/s?__biz=MjM5NTc2MDYxMw==&mid=2458500598&idx=1&sn=d783cb03dc6a3c1a9f9465c5053bbbee&chksm=b18e8d7c86f9046a67659f598242acb74c822aaf04529433c5ec2ccff14adeafa4f45abc2b33&scene=21#wechat_redirect)  
  
  
4、[Flutter 逆向初探](http://mp.weixin.qq.com/s?__biz=MjM5NTc2MDYxMw==&mid=2458500574&idx=1&sn=06344a7d18a72530077fbc8f93a40d8f&chksm=b18e8d5486f904424874d7308e840523ebfb2db20811d99e4b0249d42fa8e38c4e80c3f622c6&scene=21#wechat_redirect)  
  
  
5、[一个简单实践理解栈空间转移](http://mp.weixin.qq.com/s?__biz=MjM5NTc2MDYxMw==&mid=2458500315&idx=1&sn=19b12ab150dd49325f93ae9d73aef0c4&chksm=b18e8c5186f90547f3b615b160d803a320c103d9d892c7253253db41124ac6993d83d13c5789&scene=21#wechat_redirect)  
  
  
6、[记一次某盾手游加固的脱壳与修复](http://mp.weixin.qq.com/s?__biz=MjM5NTc2MDYxMw==&mid=2458500165&idx=1&sn=b16710232d3c2799c4177710f0ea6d41&chksm=b18e8ccf86f905d9a0b6c2c40997e9b859241a4d7f798c4aeab21352b0a72b6135afce349262&scene=21#wechat_redirect)  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/Uia4617poZXP96fGaMPXib13V1bJ52yHq9ycD9Zv3WhiaRb2rKV6wghrNa4VyFR2wibBVNfZt3M5IuUiauQGHvxhQrA/640?wx_fmt=jpeg&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/1UG7KPNHN8FHJ5XNqGmzLUOYeEJc9zylullBt3UKTEQsoxy2icCZlrib0kGSnnibUmPhrtv1ic2HR4SZvjH2PiaQASw/640?wx_fmt=gif "")  
  
**球分享**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/1UG7KPNHN8FHJ5XNqGmzLUOYeEJc9zylullBt3UKTEQsoxy2icCZlrib0kGSnnibUmPhrtv1ic2HR4SZvjH2PiaQASw/640?wx_fmt=gif "")  
  
**球点赞**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/1UG7KPNHN8FHJ5XNqGmzLUOYeEJc9zylullBt3UKTEQsoxy2icCZlrib0kGSnnibUmPhrtv1ic2HR4SZvjH2PiaQASw/640?wx_fmt=gif "")  
  
**球在看**  
  
