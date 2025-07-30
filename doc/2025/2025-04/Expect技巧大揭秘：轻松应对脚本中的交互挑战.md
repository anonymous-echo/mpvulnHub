#  Expect技巧大揭秘：轻松应对脚本中的交互挑战   
原创 didiplus  攻城狮成长日记   2025-04-29 13:30  
  
## 什么是Expect  
  
Expect  
 是一个很实用的工具，能帮我们自动完成那些需要手动交互的任务。简单来说，它就是用来让这些交互过程自动化的。它是用TCL  
这种脚本语言写的，既容易学又功能强大。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/OsuOF7sibMYtmeLvC46SqO3gEEJESp8MnZKzRTqEZyBqZygfe3mVZ8bwy4YZAO9rYOiaIUK3XXR4ghWbS4jETgyQ/640?wx_fmt=png&from=appmsg "")  
## 为什么要使用Expect  
  
现在的企业运维里，自动化运维越来越流行了。但有时候，系统在执行某些命令或程序时，还是会要求运维人员手动输入一些信息才能继续。比如，给用户设置密码的时候，通常需要手动输入两次密码。如下所示：  
```
[root@didiplus ~]# passwd rootChanging password for user oldboy.New password:          #<需要手工输入密码。Retype new password:   #<需要再次手工输入密码。passwd: all authentication tokens updated successfully.
```  
  
比如说，当你第一次用SSH远程连接到服务器时，你需要进行两次输入操作，如下所示：  
```
[root@didiplus ~]# ssh root@192.168.33.130The authenticity of host'192.168.33.130 (192.168.33.130)' can't be established.RSA key fingerprint is fd:2c:0b:81:b0:95:c3:33:c1:45:6a:1c:16:2f:b3:9a.Are you sure you want to continue connecting (yes/no) yes  #<需要手工输入yes。Warning: Permanently added '192.168.33.130' (RSA) to the list of known hosts.root@192.168.33.130's password:                         #<需要手工输入密码。Last login: Tue Oct 11 00:06:35 2016 from 192.168.33.128[root@node ~]#
```  
  
通过上面的例子，大家应该都清楚为什么需要用Expect程序了。简单来说，Expect程序用于自动处理通常需要人工操作的交互式任务，比如在使用SSH或FTP时自动输入指令，从而实现更自动化的运维工作。  
## 安装Expect软件  
  
首先，确保你的机器能正常上网，并设置好yum的安装源。接着，运行yum install expect -y  
命令来安装Expect软件。如下所示：  
```
[root@didiplus ~]# rpm -qa expect         #<检查是否安装。[root@didiplus ~]# yum install expect -y  #<执行安装命令。[root@didiplus ~]# rpm -qa expect         #<==再次检查是否安装。expect-5.44.1.15-5.el6_4.x86_64
```  
## 案例演示  
  
首先，请准备好两台虚拟机或真实服务器。具体的IP地址和主机名信息如下：  
<table><thead><tr style="border: 0;"><th style="border: 0;border-bottom: 1px solid var(--weui-FG-3);font-size: 16px;padding: 10px;text-align: left;color: var(--weui-FG-0);background-color: #fafafa;font-weight: bold;min-width: 85px;"><section><span leaf="">IP地址</span></section></th><th style="border: 0;border-bottom: 1px solid var(--weui-FG-3);font-size: 16px;padding: 10px;text-align: left;color: var(--weui-FG-0);background-color: #fafafa;font-weight: bold;min-width: 85px;"><section><span leaf="">主机名</span></section></th></tr></thead><tbody><tr style="border: 0;"><td style="border: 0;border-bottom: 1px solid var(--weui-FG-3);font-size: 16px;padding: 10px;text-align: left;min-width: 85px;"><section><span leaf="">192.168.33.128</span></section></td><td style="border: 0;border-bottom: 1px solid var(--weui-FG-3);font-size: 16px;padding: 10px;text-align: left;min-width: 85px;"><section><span leaf="">didiplus</span></section></td></tr><tr style="border: 0;"><td style="border: 0;border-bottom: 1px solid var(--weui-FG-3);font-size: 16px;padding: 10px;text-align: left;min-width: 85px;"><section><span leaf="">192.168.33.130</span></section></td><td style="border: 0;border-bottom: 1px solid var(--weui-FG-3);font-size: 16px;padding: 10px;text-align: left;min-width: 85px;"><section><span leaf="">node1</span></section></td></tr></tbody></table>  
在运行下面的例子前，先手动在128这台服务器上执行以下命令：  
```
ssh  root@192.168.33.130 uptime#<==连接到130上查看负载值。
```  
  
执行结果如下：  
```
[root@didiplus ~]# ssh  root@192.168.33.130 uptimeThe authenticity of host'192.168.33.130 (192.168.33.130)' can't be established.RSA key fingerprint is fd:2c:0b:81:b0:95:c3:33:c1:45:6a:1c:16:2f:b3:9a.Are you sure you want to continue connecting (yes/no) yes #<根据提示手工输入yes。Warning: Permanently added '192.168.33.130' (RSA) to the list of known hosts.root@192.168.33.130's password    #<手工输入密码。21:20:35 up 1 day,  9:08,  1 user,  load average: 0.08, 0.02, 0.01
```  
  
每次执行ssh命令时，都得手动输入密码，不然就用不了。接下来，咱们试试用Expect这个工具来自动处理这个过程，让它自动填入密码并运行ssh命令。  
```
[root@didiplus ~]# cat didiplus.exp      #<扩展名使用exp代表是Expect脚本。#!/usr/bin/expect      #<脚本开头解析器，和Shell类似，表示程序使用Expect解析。spawn ssh root@192.168.33.130 uptime#<执行ssh命令（注意开头必须要有spawn，                                            否则无法实现交互）。expect"*password"#<利用Expect获取执行上述ssh命令输出的字符串是否为期待的                               字符串*password，这里的*是通配符。send "123456\n"#<当获取到期待的字符串*password时，则发送123456密码给系统，\n为换行。expect eof     #<处理完毕后结束Expect。
```  
  
执行脚本：  
```
[root@didiplus ~]# which expect/usr/bin/expect[root@didiplus ~]# expect didiplus.exp   #<使用Expect执行脚本是个好习惯。spawn ssh root@192.168.33.130 uptimeroot@192.168.33.130's password       #<这里再也不需要手工输入密码了。 21:24:05 up 1 day,  9:12,  1 user,  load average: 0.00, 0.00, 0.00[root@oldboy ~]# expect oldboy.expspawn ssh root@192.168.33.130 uptimeroot@192.168.33.130's password       #<==这里再也不需要手工输入密码了。21:24:08 up 1 day,  9:12,  1 user,  load average: 0.00, 0.00, 0.00
```  
  
我们现在还没手动输入密码，就已经自动连接到远程机器执行ssh命令了，是不是很神奇？  
## 常用命令  
### spawn命令  
  
在使用Expect编写自动交互程序时，你需要先用spawn  
命令启动程序或执行命令。随后的自动交互操作都将基于这个已启动的程序或命令进行。简而言之，没有spawn  
命令，你的Expect程序就无法完成自动交互。  
- spawn命令的语法为：  
  
```
spawn [选项][需要自动交互的命令或程序]
```  
  
例如：  
```
spawn ssh root@192.168.33.130 uptime
```  
  
当你使用spawn命令时，可以直接在后面加上你想要运行的命令或程序，比如这里的ssh命令。此外，spawn还提供了几个额外的选项：  
- 使用 -open  
 可以启动一个文件进程。  
  
- 使用 -ignore  
 可以让程序忽略特定的信号。  
  
### expect命令  
  
在编写自动交互脚本时，首先使用spawn  
命令启动程序或执行命令。如果该命令输出需要响应的信息，则使用expect  
命令来等待并匹配这些输出。一旦匹配成功，就执行预设的动作。此外，通过使用如-re  
这样的选项，可以利用正则表达式进行更灵活的匹配。  
- expect命令的语法为：  
  
```
expect  表达式  [动作]
```  
  
示例如下：  
```
spawn ssh root@192.168.33.130 uptimeexpect"*password"{send  "123456\r"}
```  
> 不能直接在Linux的命令行里输入这个命令，得把它放到一个Expect脚本里面去运行。  
  
- 执行ssh  
命令远程获取服务器负载值，并自动输入yes  
及用户密码。  
  
```
[root@didiplus ~]# cat test.exp#!/usr/bin/expectspawn ssh root@192.168.33.130 uptimeexpect{#<起始大括号前要有空格。"yes/no"{exp_send "yes\r";exp_continue}#<exp_send和send类似。"*password"{exp_send "123456\r"}}expect eof 
```  
  
执行如下输出：  
```
[root@didiplus ~]# expect test.expspawn ssh root@192.168.33.130 uptimeThe authenticity of host'192.168.33.130 (192.168.33.130)' can't be established.RSA key fingerprint is fd:2c:0b:81:b0:95:c3:33:c1:45:6a:1c:16:2f:b3:9a.Are you sure you want to continue connecting (yes/no) yes  #<expect自动输入yes。Warning: Permanently added '192.168.33.130' (RSA) to the list of known hosts.root@192.168.33.130's password:  #<expect自动给密码。22:03:13 up 1 day,  9:51,  1 user,  load average: 0.00, 0.00, 0.00#<==轻松打印出负载值。
```  
### send命令  
  
在上述例子中，我们介绍了exp_send  
和send  
命令的使用方法。这两个Expect中的命令功能相似，都是用来在匹配到特定字符串后向系统发送指定内容。它们支持如\r  
（回车）、\n  
（换行）和\t  
（制表符）等转义字符，这些与TCL中的用法一致。  
- Send命令的使用示例如下：  
  
```
#!/usr/bin/expectspawn /bin/sh 18_3_1.shexpect{"username"{exp_send "oldboy\r";exp_continue}"*pass*"{send "123456\r";exp_continue}"*mail*"{exp_send "31333741@qq.com\r"}}expect eof
```  
  
send  
命令有几个可以使用的参数：  
- -i：用来指定进程ID（spawn_id），这样你就可以向不同的进程发送命令了。这个参数对于同时控制多个程序很有用。  
  
- -s：这里的s  
指的是“慢速”（slowly）。使用这个参数可以控制发送命令的速度。记得要和expect  
里的send_slow  
变量一起使用。  
  
### send_user命令  
  
send_user  
命令可以用来在Expect脚本中显示信息，就像你在Shell里使用echo  
一样。而send  
和exp_send  
命令则是把字符串发送给程序本身。下面是一个关于如何使用send_user  
命令的例子。  
```
[root@didiplus ~]# cat 18_4_1.exp#!/usr/bin/expectsend_user "hello world\n"#<\n表示换行。send_user "I like linux,\t hello world"#<\t表示Tab键。
```  
  
执行结果如下：  
```
[root@didiplus ~]# expect send_user.exphello wordI like linux,  hello world
```  
  
  
推荐文章  
  
- [一键部署Kubernetes?Kubeasz 让复杂变简单](https://mp.weixin.qq.com/s?__biz=MjM5OTc5MjM4Nw==&mid=2457388780&idx=1&sn=02273879b31ad25f4f84b918365d9740&scene=21#wechat_redirect)  
  
  
- [避坑指南！NAS存储池RAID设置，这样选才不翻车](https://mp.weixin.qq.com/s?__biz=MjM5OTc5MjM4Nw==&mid=2457388768&idx=1&sn=f050651e778ffc611bf869b0310081a5&scene=21#wechat_redirect)  
  
  
- [哇塞！Markdown用户必看！MD2CARD强势来袭，堪称 “神器”！](https://mp.weixin.qq.com/s?__biz=MjM5OTc5MjM4Nw==&mid=2457388672&idx=1&sn=315d59a64d22bdeacdf81b1bf9eb2c08&scene=21#wechat_redirect)  
  
  
- [哇塞！电脑必装的10款超良心免费神器，生产力直接拉满！](https://mp.weixin.qq.com/s?__biz=MjM5OTc5MjM4Nw==&mid=2457388647&idx=1&sn=01992485ad351415feb287d6ebf1a0ed&scene=21#wechat_redirect)  
  
  
- [惊叹！sort 命令里那些不为人知的隐秘用法大揭秘](https://mp.weixin.qq.com/s?__biz=MjM5OTc5MjM4Nw==&mid=2457388587&idx=1&sn=ba84156bbf965beef1cac95f61dc21e5&scene=21#wechat_redirect)  
  
  
- [告别平淡无奇：用 Markdown 让你的公众号文章瞬间吸粉无数！](https://mp.weixin.qq.com/s?__biz=MjM5OTc5MjM4Nw==&mid=2457387388&idx=1&sn=c0d8f7bfbe34f5a76d76a455ecb5381d&scene=21#wechat_redirect)  
  
  
- [想找免费强大的消息推送?MoePush是你的答案吗?](https://mp.weixin.qq.com/s?__biz=MjM5OTc5MjM4Nw==&mid=2457388562&idx=1&sn=231b5045dc95a57c099d1279be3770fa&scene=21#wechat_redirect)  
  
  
- [震惊！同为硬件信息查看“神器”，lshw 和 dmidecode 竟有这么多不同](https://mp.weixin.qq.com/s?__biz=MjM5OTc5MjM4Nw==&mid=2457388518&idx=1&sn=3183a8846e9f42ef30928cbc5b8154ca&scene=21#wechat_redirect)  
  
  
  
  
![微信公众号二维码](https://mmbiz.qpic.cn/sz_mmbiz_jpg/OsuOF7sibMYtmeLvC46SqO3gEEJESp8MnjMWRfjBVKZkMonicP0RtTibUqsSlImfAXyMYXiasNDic0D38DpGZILrR9Q/640?wx_fmt=jpeg&from=appmsg "")  
  
扫码关注公众号  
  
关注我的博客  
didiplus.kwpmp.cn  
  
