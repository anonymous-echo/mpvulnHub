> **原文链接**: https://mp.weixin.qq.com/s?__biz=MjM5OTc5MjM4Nw==&mid=2457389196&idx=1&sn=ccc62b0aa6ac8ca2ad1cfbe3cf5b568c

#  密码过期卡登录？看我用Expect实现无人值守批量修改  
原创 didiplus  攻城狮成长日记   2025-07-11 07:12  
  
为了确保安全并符合规范，我们通常会在生产环境中设定用户密码每90天更新一次，这样做有助于减少密码被泄露或遭受暴力破解的风险。如果您希望在密码到期前就进行更改，可以利用Ansible中的user模块来批量处理这一任务。而当密码真的过期了，在您尝试登录服务器时，系统会友好地提示您先修改密码，之后才能继续使用系统哦。如下所示：  

```
WARNING: Your password has expired.
You must change your password now and login again!
Changing password for didiplus.
Current password: 

```

  
那么，遇到这种情况时，我们该如何进行批量处理呢？有一种工具叫做Expect，它能够帮助我们解决这个问题。不过，可能有些人还不太了解Expect具体是什么，接下来就让我为您简单介绍一下吧。  
## 什么Expect命令  
  

```
Expect
```

  
是一个基于
```
Tcl
```

  
的自动化交互工具，由
```
Don Libes
```

  
在1990年创建，专门用于处理需要用户交互的命令行程序自动化。它的核心功能是模拟用户输入和响应程序输出，特别适合处理
```
SSH
```

  
登录、
```
FTP
```

  
传输、密码修改等需要人工交互的场景。  
## Expect核心命令  
### 基础命令结构  

```
#!/usr/bin/expect -f

# 设置超时时间(秒)
settimeout30

# 启动交互程序
spawn 要监控的程序

# 交互控制
expect{
&#34;模式1&#34;{ 动作1 }
&#34;模式2&#34;{ 动作2 }
timeout{ 超时处理 }
}

# 发送指令
send &#34;指令\r&#34;

# 结束交互
expect eof

```

### 关键命令详解  
- spawn：启动新的交互进程  
  
- expect：等待特定模式出现  
  
- send：向进程发送字符串  
  
- interact：将控制权交还给用户  
  
- exp_continue：继续匹配后续模式  
  
- set timeout：设置等待超时时间  
  
## 实战案例  
  
管理200台Linux服务器，密码策略设置为90天强制修改，并且密码彻底过期了。要求强制修改后才能成功登录系统。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/OsuOF7sibMYtqnlKMCUY4n9aq3Ay5qaqPIDic563fYe1N1dGYfVEPMFibwKV8xEEiaIiaRs0W8TAhLbaEnWia9SsfVEQ/640?wx_fmt=png&from=appmsg "")  
  
使用该脚本现在要在脚本同级目录创建一个名为
```
hosts.list
```

  
文件，内容如下：  

```
192.168.31.101
192.168.31.102
192.168.31.103

```

  
先为脚本赋予执行的权限，执行如下命令  

```
chmod +x batch_password_change.exp

```

  
然后，修改脚本里的用户名、旧密码和新密码，如下：  

```
....
set username &#34;didiplus&#34;
set old_password &#34;password&#34;
set new_password &#34;password&#34;

```

  
修改完之后，执行如下命令进行批量修改密码  

```
./batch_password_change.exp 

```

  
执行完成后，会输出如下结果：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/OsuOF7sibMYtqnlKMCUY4n9aq3Ay5qaqP055UfzDBYDib0BJZeQMzZ5eqSkQibzQ22SibOs1VIotCDtGAqEwshka2w/640?wx_fmt=png&from=appmsg "")  
  
重点  
  
对脚本感兴趣的小伙伴们可以关注公众号，私下回复**脚本链接**  
即可获取。  
  
  
推荐文章  
  
- [密码策略不设防？等保2.0下，这些Linux加固配置你必须知道！](https://mp.weixin.qq.com/s?__biz=MjM5OTc5MjM4Nw==&mid=2457389157&idx=1&sn=88250db9b5ef6f33d6d2b0975b546a8a&scene=21#wechat_redirect)  
  
  
- [深入解析：用lsof揪出“幽灵文件”释放磁盘空间](https://mp.weixin.qq.com/s?__biz=MjM5OTc5MjM4Nw==&mid=2457389141&idx=1&sn=edbced0413cc2a1f92cd02a19853d3a0&scene=21#wechat_redirect)  
  
  
- [等保2.0硬核要求：SSH七项加固缺一不可](https://mp.weixin.qq.com/s?__biz=MjM5OTc5MjM4Nw==&mid=2457389133&idx=1&sn=74db6f4f82687f19d4dafdb932a2b45a&scene=21#wechat_redirect)  
  
  
- [一键收集服务器日志！用Ansible剧本解放你的双手！](https://mp.weixin.qq.com/s?__biz=MjM5OTc5MjM4Nw==&mid=2457389125&idx=1&sn=699185c3232b9f2258143416a7406eaf&scene=21#wechat_redirect)  
  
  
- [惊喜来袭！1panel迎来v2时代，一键升级畅享新功能](https://mp.weixin.qq.com/s?__biz=MjM5OTc5MjM4Nw==&mid=2457389111&idx=1&sn=e7c7dc4f5846a2fffe9286bc3e356ad4&scene=21#wechat_redirect)  
  
  
  
  
![微信公众号二维码](https://mmbiz.qpic.cn/sz_mmbiz_jpg/OsuOF7sibMYtqnlKMCUY4n9aq3Ay5qaqPpUOFPqYwTt4HoF5CBx0CSknqSqyXe1aKoeCd1jxxksYN9sZGiaP4Sow/640?wx_fmt=jpeg&from=appmsg "")  
  
扫码关注公众号  
  
关注我的博客  
  
didiplus.kwpmp.cn  
  
  
