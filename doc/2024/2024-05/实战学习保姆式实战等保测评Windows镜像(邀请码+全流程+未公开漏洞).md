#  实战学习|保姆式实战等保测评Windows镜像(邀请码+全流程+未公开漏洞)   
原创 爱州  州弟学安全   2024-05-07 19:00  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/icdGEWOnYLpNJUTyXhK4Iic6TJFLAAboGBK3V3tSviaWr4PZG8a6IYoiaMTg23QFLvasNxpQL1Ed9qLsPUmGPH1mPw/640?wx_fmt=gif&wxfrom=5&wx_lazy=1&tp=webp "")  
  
**0x01 前言**  
  
  
  
   **‍思路想法不易、麻烦点个关注赞，只更高质量干货文章**  
  
    在写这篇文章之前，我在玄机官方群做了一个调研，有很多不知道等保测评是什么的师傅，也有不少师傅表示，现在等保测评都是脚本自动化了，这里我想以我自己的想法表达一下  
```
等保测评是什么
等保测试是我国按照有关管理规范和技术标准对信息系统安全等级保护状况进行检测评估的活动
等保测评的目的是验证网络系统或应用是否满足相应的安全保护等级要求
有脚本为什么还要学？
这么说：脚本是万能的吗？当环境出现问题时，需要人工排查你怎么办
       最后出报告的时候，脚本百分百正确吗?
       面试相关岗位时，你说你只会用脚本?
```  
  
    什么？上面说的太官方了？通俗来讲：如果应急响应是被攻击后进行的排查溯源，那么等保测评可以理解为在项目上线前对本机进行主机测评，中间件及数据库测评和WEB渗透测试等测评项，降低被攻击拿下的概率，保证"最小权限原则、最小安装原则、最新版本"  
  
    以北京地区 等保测评工程师为例，薪资在 10-20K之间，也有突破20K以上的企业  
  
![](https://mmbiz.qpic.cn/mmbiz_png/icdGEWOnYLpMyeQddor3PsaPxut7ibUeGPL6RtM0BCFbSUickYgtnZQjVTibR1YQdG9EqHAL8f4NibDURVp0l5ZjKxw/640?wx_fmt=png&from=appmsg "")  
  
    等保测评是硬性要求，是安全基础保障，是理论基础，有些师傅看到文字多，或者写的操作简单，没有那种梦寐以求的帅酷黑客范，就直接不学了，但是"攻防不分家"，任何技术起步都必须从基础小白做到大佬的，包括说安服岗位，在面试的时候不可能只问单方面知识  
  
**本次环境：我们实操从主机项测评、代码审计模拟、渗透测试模拟、主机漏洞模拟测评，附镜像，结尾取玄机邀请码，环境已上传到玄机应急响应平台，无需下载，直接云端开启主机即可，平台适用于网络安全爱好者，蓝队学习者，赛前训练学习，目前平台准备下一步拓展其它板块，欢迎各位同行跨界师傅参与学习！**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/icdGEWOnYLpOegDFqOo6TwgB2NR70licia522MPbq9K1awS8ByPB5An4JTGR5hqveG9KcicsMRZOH6eEKXwmjmA7HQ/640?wx_fmt=png&from=appmsg "")  
```
主机：Windows server 2019  (Linux版过后会出)
数据库: mysql 5.7
WEB:  DedeBIZ未公开漏洞(模拟渗透测试)
漏洞扫描：提供或自用工具进行扫描探测
```  
  
    关于理论篇，可以查看我以前总结的文章参考，点击以下链接直达  
  
[学习干货|等保测评2.0技术自查阶段(上)](http://mp.weixin.qq.com/s?__biz=MzkzMDE5OTQyNQ==&mid=2247484662&idx=1&sn=c5086fe24bd5e302a0cf32cc6c180f1a&chksm=c27ca618f50b2f0e02c226d32875e49afd7a0f639ae226d0a7e8589368bfc8e31e05d297d23d&scene=21#wechat_redirect)  
  
  
[学习干货|等保测评2.0技术自查阶段(中)](http://mp.weixin.qq.com/s?__biz=MzkzMDE5OTQyNQ==&mid=2247484756&idx=1&sn=cd4436a0f114fee55edee95c812936af&chksm=c27ca7baf50b2eacb4e16a292be7e1833c94a5011d1e07f4f9856aa983bfa36ba1433a489b79&scene=21#wechat_redirect)  
  
  
[学习干货|等保测评2.0技术自查阶段(下)](http://mp.weixin.qq.com/s?__biz=MzkzMDE5OTQyNQ==&mid=2247484811&idx=1&sn=94a6970b95fe7335a3ce84abb945e8e2&chksm=c27ca765f50b2e73cfe3e0b916fe37645ecd4c0049a07df9101540f3bce51aabeb9d7dc3cfa1&scene=21#wechat_redirect)  
  
  
    不同Windows系统版本所需流程差不多，命令基本一样，但是如果手动寻找页面，可能会存在差别，具体以实际情况为准****  
```
镜像下载链接
天翼云盘(不限速): https://cloud.189.cn/t/ZJrUFfVZ3UVr （访问码：s7pu）
夸克: https://pan.quark.cn/s/8c0f3f47810a
```  
  
*** 镜像内提供的源码、扫描工具仅供当前环境学习，请勿非法操作，违者后果自负**  
  
****  
**0x02 测评过程**  
```
主机账号: administrator
主机密码: 1Q2W3E4r
题目:
1. 为了进行身份鉴别，登录安全，哪个扩展名称直达强制用户输入账号密码
   需完成：将要使用本计算机，用户必须输入用户名和密码 勾选
2. 哪个扩展名称可以查看到系统中存在的所有用户及用户组页面
   需完成: 创建一个名为 security用户，并设置为密码永不过期
3. 哪个扩展名称用于直达安全策略页面来配置密码复杂度和其它复杂度
   需完成: 设置阈值为5，超过锁定30分钟，并自行测试security用户
4. 如何快速配置远程桌面安全策略，请输入此命令完成以下配置
   需完成: 将远程桌面安全层配置为RDP，将连接超时时间配置为20分钟
5. 需要你对C:\sec\hahah.txt文件读取其中flag
   需知: 目前没有权限读取，请使用当前用户修改操作此目录权限并读取flag
6. 哪个扩展名称打开管理用户页面并执行以下操作
   需完成: 执行命令后删除你刚才创建的security用户
7. 找到本地策略中其中不合理权限策略，其策略中不合理用户名提交
   需知: 在某条策略中，被写入了一个用户可控，这是十分危险的行为
8. 哪个快捷名称可快速打开安全策略页面
   需完成: 设置账户登录事件和系统事件进行设置为成功
9. 通过Windows日志，查询hacker$用户创建时的事件ID进行提交
10. 需要对Windows日志进行配置，它的日志文件名是?
   需完成: 将日志最大大小改为204800kb
11. 查看“管理审核和安全日志”策略项是否包含了与审计无关的用户组
   需完成: 找到相关用户组进行提交
12. 应最小安装原则，哪个快捷名称打开组件查看页面，查看是否存在多余组件
13. 查看多余服务及卸载相关服务应用的快捷名称是
14. 哪个快捷名称查看系统开启的所有服务并进行启停
   需完成: 模拟对phone service进行启动
15. 在Windows中开启了共享服务，请关闭名为php$的共享服务，提交关闭命令
16. 使用桌面/工具/fscan32.exe对本机进行漏洞扫描
   需完成: 对扫描出的漏洞端口进行提交
17. 使用桌面/工具/D盾/D_Safe_Manage.exe对web源码进行扫描
   需完成: 将扫描出的shell连接密码作为flag提交
   需知:  web源码在C:\phpstudy_pro\WWW\*
18. 提交任意文件上传后的shell。执行命令whoami后，将结果上交
   需知: 漏洞为未公开，POC会放在下方，自行下载
```  
  
**主机安全**  
```
问: 为了进行身份鉴别，登录安全，哪个扩展名称直达强制用户输入账号密码
  将要使用本计算机，用户必须输入用户名和密码 勾选
答: netplwiz
```  
  
    快捷键 WIN+R弹出(运行窗口)，输入'  
netplwiz'，打开'用户账户'页面，勾选下图选择框，此处还可以查看到有无其它可以用户及用户分配组  
  
![](https://mmbiz.qpic.cn/mmbiz_png/icdGEWOnYLpMyeQddor3PsaPxut7ibUeGP9oKns41xS4XuicMroK0ssP6f5q2rnx4HUE8TpTCWYo8zUWriaunGa9NQ/640?wx_fmt=png&from=appmsg "")  
  
    当勾选，重启机器后可以看到需要输入密码以登录，点击下面的重置密码设置就行，无密码情况下，旧密码置空![](https://mmbiz.qpic.cn/mmbiz_png/icdGEWOnYLpMyeQddor3PsaPxut7ibUeGPGUmggicLL4KtnJ6sTiaHI07uNpR9HHUibhCU1IUyibncVTGh7d37YiclygQ/640?wx_fmt=png&from=appmsg "")  
  
```
问: 哪个快捷名称可以查看到系统中存在的所有用户及用户组页面
  创建一个名为 security用户，并设置为密码永不过期
答: lusrmgr.msc
```  
  
        快捷键 WIN+R弹出(运行窗口)，输入'  
**lusrmgr.msc**  
'，打开本地用户/组页面，默认情况下administrator和guest用户存在，guest默认禁用，此方法验证查看是否存在其它可疑用户  
  
![](https://mmbiz.qpic.cn/mmbiz_png/icdGEWOnYLpMyeQddor3PsaPxut7ibUeGPx0nCQ0piaBARptxEWVgYVVYb4Tr9joEu9Yu0Fe4dLEj4nQibRfPbMt4w/640?wx_fmt=png&from=appmsg "")  
  
    点击相关用户查看是否勾选密码永不过期及有无更改密码权限等，根据实际情况进行决定  
  
![](https://mmbiz.qpic.cn/mmbiz_png/icdGEWOnYLpMyeQddor3PsaPxut7ibUeGP9iaEygbic4DDLAD3cM05pu7QiaA7AMia19mkNziaesbvAXReCAFZIVhABDw/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/icdGEWOnYLpMyeQddor3PsaPxut7ibUeGPsbJ0IrVc4VSotv9SETCNnhY4Bo9JsKrKoXiac12NKCbI0TwJfrBbRrA/640?wx_fmt=png&from=appmsg "")  
```
问: 哪个快捷名称用于直达安全策略页面来配置密码复杂度和其它复杂度
  设置阈值为5，超过锁定30分钟，并自行测试security用户
答: secpol.msc
```  
  
      
快捷键 WIN+R弹出(运行窗口)，输入'  
secpol.msc'，进入安全策略页面，页面中可对账户策略，防火墙策略，软件策略等进行配置，在账户身份模块中，对账户策略进行配置  
****  
  
![](https://mmbiz.qpic.cn/mmbiz_png/icdGEWOnYLpMyeQddor3PsaPxut7ibUeGPGrDv8oK1y6dxp954h4u0gMNHQ8iaun0QDB73icAXAUlKx6Fnn5hAz37A/640?wx_fmt=png&from=appmsg "")  
  
    默认密码复杂度已启用就是在设置密码时，匹配密码复杂度策略，防止弱口令爆破(最低6位字符，大写字母/小写字母/数字/特殊符号 四选三)  
  
    为了防止暴力破解(远程登录情况下字典爆破)，仍然是secpol.msc命令，查看账户锁定策略，默认不适用则为不开启，修改账户锁定阈值即可配置  
  
![](https://mmbiz.qpic.cn/mmbiz_png/icdGEWOnYLpMyeQddor3PsaPxut7ibUeGPScOEuoQGiciapEoLINteaJb2TYum6w41xPCuNXaLVLGtN2uaAHOK29pQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/icdGEWOnYLpMyeQddor3PsaPxut7ibUeGPQnRgej3uh86EoLwwoYibMywD4Zw7Ybl17T80OVoicx8YED6BKNfJfhWg/640?wx_fmt=png&from=appmsg "")  
  
    此时打开远程桌面连接，我们对test用户爆破，看到超过三次后，账户被锁定  
  
![](https://mmbiz.qpic.cn/mmbiz_png/icdGEWOnYLpMyeQddor3PsaPxut7ibUeGPmR6zjKgnyAwV81Z92WxkylsBDFNYz7XYpIzS6iadLa1Ws85kFKS6SYg/640?wx_fmt=png&from=appmsg "")  
```
问: 如何快速配置远程桌面安全策略，请输入此命令完成以下配置
    将远程桌面安全层配置为RDP，将连接超时时间配置为20分钟
答: gpedit.msc
```  
  
      
快捷键 WIN+R弹出(运行窗口)，输入'  
gpedit.msc  
'，进入'计算机配置->管理模板->Windows组件->远程桌面服务->远程桌面会话主机->安全->远程连接要求使用安全层![](https://mmbiz.qpic.cn/mmbiz_png/icdGEWOnYLpMyeQddor3PsaPxut7ibUeGP3LgCr0rmJrEfibMLFNpgAicmxehkGUzJy0N572pWh9BRgAxbCB4UWYlw/640?wx_fmt=png&from=appmsg "")  
  
  
  
    点击已启用->选择安全层->确定 即自动保存，在实战中，根据情况进行相应配置，此处主要为了在远程传输过程中被明文监听  
  
      
进入  
计算机配置  
->管理模板->  
Windows组件->远程桌面服务-  
>  
远程桌面会话主机->连接->配置活动连接的时间间隔![](https://mmbiz.qpic.cn/mmbiz_png/icdGEWOnYLpMyeQddor3PsaPxut7ibUeGP8Vrv279daSdlzpm13P58Lm5VLEDkqccKZ15r6dQYabvk6YXlEeMEzA/640?wx_fmt=png&from=appmsg "")  
  
  
    点击已启用->输入活动时间间隔->确定 自动保存，实战中根据情况进行配置(需要注意的是,不同的Windows版本，可能文字描述不同，但是步骤一样，此处主要为了在远程传输过程中，远程会话长时间不操作，进行的预处理操作  
```
问: 需要你对C:\sec\hahah.txt文件读取其中flag
    目前没有权限读取，请使用当前用户修改操作此目录权限并读取flag
答: flag{7815696ecbf1c96e6894b779456d330e}
```  
  
     安全原因，当前sec目录被拒绝了所有权限，所有用户都没有权限访问![](https://mmbiz.qpic.cn/mmbiz_png/icdGEWOnYLpMyeQddor3PsaPxut7ibUeGPgemXXwyWdyEGu5F9lttbvvfl4Gh4hcEHT5FeAXDbhE2ia5S7dsQhP1g/640?wx_fmt=png&from=appmsg "")  
  
  
   右击sec目录，点击属性->安全->编辑->users组及administrators组->删除掉所有拒绝权限  
  
![](https://mmbiz.qpic.cn/mmbiz_png/icdGEWOnYLpMyeQddor3PsaPxut7ibUeGPWUB0hhk9pKkBxmwGJxnsmRNE17HXxfTF3ClKmMUSWDicibEJ0l6puibmg/640?wx_fmt=png&from=appmsg "")  
  
    目前是全部允许读取，再次访问sec文件夹后读取到flag，此步骤是等保中对用户权限的分配是否合理，不能多不能少，防止出现权限过大，越权，权限过小又影响正常业务  
  
![](https://mmbiz.qpic.cn/mmbiz_png/icdGEWOnYLpMyeQddor3PsaPxut7ibUeGPu0BiaZMv5RZ2esica869fuK7ibAFdFiacHX22WU0EicnqPTzAYDyjEBsPcg/640?wx_fmt=png&from=appmsg "")  
```
问: 哪个快捷名称打开管理用户页面并执行以下操作
    执行命令后删除你刚才创建的security用户
答: lusrmgr.msc
```  
  
    快捷键 WIN+R弹出(运行窗口)，输入'  
**lusrmgr.msc**  
'，打开本地用户/组页面，找到刚刚创建的security用户，右键删除![](https://mmbiz.qpic.cn/mmbiz_png/icdGEWOnYLpMyeQddor3PsaPxut7ibUeGPXeL6FXqh4SSic9V4TRF6UkStPZiaJaZCPMt1UD7ptYp7GhkX4hTMqPOQ/640?wx_fmt=png&from=appmsg "")  
  
  
    并查看有无其它共享账户，可疑账户，如点击账户->属性->隶属于 查看到用户在哪些组内，避免分配权限组不合理，造成普通用户权限过大![](https://mmbiz.qpic.cn/mmbiz_png/icdGEWOnYLpMyeQddor3PsaPxut7ibUeGPDoQjWpSsB2aiaggVf8tT1Hkx96wDLEeyHTj4qjcvKLzGXLHePfsaSNA/640?wx_fmt=png&from=appmsg "")  
  
```
问: 找到本地策略中其中不合理权限策略，其策略中不合理用户名提交
    在某条策略中，被写入了一个用户可控，这是十分危险的行为
答: hacker$
```  
  
    应等保授予管理用户最小权限，实现权限分离，WIN+R输入'  
secpol.msc  
'，点击本地策略->用户权限分配->允许远程桌面登录服务(看到hacker$用户可远程登录)![](https://mmbiz.qpic.cn/mmbiz_png/icdGEWOnYLpMyeQddor3PsaPxut7ibUeGP1okXoC1wibmPnQfjEOHp0bWOJh2gFqCkolpMSJFS14CACmyuqGhj15Q/640?wx_fmt=png&from=appmsg "")  
  
  
    实战中，权限的分配尤为重要，如被攻击，应急排查此处也是重中之重，可能因此会被写入隐藏用户，然后以此作为后门的一种方式  
```
问: 哪个快捷名称可快速打开安全策略页面
    设置账户登录事件和系统事件进行设置为成功
答: secpol.msc
```  
  
     快捷键 WIN+R弹出(运行窗口)，输入'  
**secpol.msc**  
'，打开安全策略->本地安全策略->审核策略(按照题目要求对账户安全登录事件和系统事件勾选成功)  
  
![](https://mmbiz.qpic.cn/mmbiz_png/icdGEWOnYLpMyeQddor3PsaPxut7ibUeGPoCia8MIZS5T1TsKtELOdM1jWwv7Ox62hVYhmLnlajtdmYBPxMlE4A4Q/640?wx_fmt=png&from=appmsg "")  
  
    勾选成功后，相关定向行为会被记录到Windows日志中  
```
问: 通过Windows日志，查询hacker$用户创建时的事件ID进行提交
答: 4720
```  
  
    快捷键WIN+R输入  
'  
eventvwr.msc'，在Windows日志->安全->查找，输入关键字'hacker$'依次查找相关日志  
  
![](https://mmbiz.qpic.cn/mmbiz_png/icdGEWOnYLpMyeQddor3PsaPxut7ibUeGPsqlgte8KgtKFsBjtLReFWia0D9NhBkZDFrLC0cyMP93Q2YImZ0prolw/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/icdGEWOnYLpMyeQddor3PsaPxut7ibUeGPBVWsHwXdCmxshuFupIbEbB7RrIqh1r6iaNpQY2xxKAMEPVPns9LF0Uw/640?wx_fmt=png&from=appmsg "")  
  
    此处不论对于前期确认日志配置是否生效，还是对后期应急响应都至关重要  
```
问: 需要对Windows日志进行配置，它的日志文件名是?
    将日志最大大小改为204800kb
答: Application.evtx
```  
  
    快捷键WIN+R输入  
'  
eventvwr.msc'，在Windows日志->右侧属性->看到绝对路径   
  
![](https://mmbiz.qpic.cn/mmbiz_png/icdGEWOnYLpMyeQddor3PsaPxut7ibUeGPkNJj8hibibFGzB2lQjxDZmLjoTfKfP1Vud1r6cMkeLKF38OMgYNG58bg/640?wx_fmt=png&from=appmsg "")  
  
    将其大小改为204800kb，然后从旧事件进行覆盖  
  
![](https://mmbiz.qpic.cn/mmbiz_png/icdGEWOnYLpMyeQddor3PsaPxut7ibUeGPzw03MPOWYVcxEbibhTgOMmrTH6mPRibv9cmlIfkViaGzl6dWJXDVvVgEQ/640?wx_fmt=png&from=appmsg "")  
  
    等保要求日志需保存至少6个月，方便后期进行排查追溯等，具体以当时情况为准，是否覆盖按照要求修改  
```
问: 查看“管理审核和安全日志”策略项是否包含了与审计无关的用户组
    找到相关用户组进行提交
答: Users&Guests
```  
  
    正常情况下，此策略默认只有Administrators用户组可控，主要考察了对于管理日志的权限，防止普通用户权限过大，导致被攻击后低用户高权限清除日志  
  
      
WIN+R输入'  
secpol.msc  
'，点击本地策略->用户权限分配->管理审核和安全日志，查看到不应出现的用户组  
  
![](https://mmbiz.qpic.cn/mmbiz_png/icdGEWOnYLpMyeQddor3PsaPxut7ibUeGP3ygMiaeBNGsia7Bicb8vmOkyaqyF0KcyKynHHNicr2lF6PE1ZGibVU2UEkg/640?wx_fmt=png&from=appmsg "")  
```
问: 应最小安装原则，哪个快捷名称打开组件查看页面，查看是否存在多余组件
答: dcomcnfg
```  
  
      
快捷键WIN+R输入  
'  
dcomcnfg'，在组件服务->计算机->我的电脑->COM+应用程序查看组件  
  
![](https://mmbiz.qpic.cn/mmbiz_png/icdGEWOnYLpMyeQddor3PsaPxut7ibUeGPX6K11Ml93P3uq2FmkfC9hUB6x26BtY9fLlZ1nLnfuuKKLNtrgicqRFg/640?wx_fmt=png&from=appmsg "")  
```
问: 查看多余服务及卸载相关服务应用的快捷名称是
答: appwiz.cpl
```  
  
      
WIN+R输入'  
appwiz.cpl  
'，看到当前系统中安装的所有服务，这个很常用，也方便后期进行排查和卸载  
  
![](https://mmbiz.qpic.cn/mmbiz_png/icdGEWOnYLpMyeQddor3PsaPxut7ibUeGPc82F3iaic5q9PCE5dZvH4E2cwuwPhFsKXHKpjevckPe8d7pSF0W2aBvw/640?wx_fmt=png&from=appmsg "")  
```
问: 哪个快捷名称查看系统开启的所有服务并进行启停
    模拟对phone service进行启动
答: services.msc
```  
  
      
   
快捷键WIN+R输入  
'  
services.msc'，查看是否存在可疑或运维不清楚的服务，英文模式下输入首字母可快速定位，输入P定位到需要开启的 Phone service服务，右键点击启动  
  
![](https://mmbiz.qpic.cn/mmbiz_png/icdGEWOnYLpMyeQddor3PsaPxut7ibUeGPicP8iaNcpFedl5haFD1eQsAEPT47cWrXYkuxuAXKibeRM1NuKXdk7YOOg/640?wx_fmt=png&from=appmsg "")  
      
其实这里就相当于linux中的service phone.service start 动作，在正常使用过程中，进行排查进程服务是否异常，这里会用到  
```
问: 在Windows中开启了共享服务，请关闭名为php$的共享服务，提交关闭命令
答: net share php$ /delete
```  
  
    Windows默认开启139 445端口，而对外共享的目录是最薄弱的地方，打开cmd->输入命令 net share->查看开放共享目录  
  
![](https://mmbiz.qpic.cn/mmbiz_png/icdGEWOnYLpMyeQddor3PsaPxut7ibUeGPSLclmq4LkBkics7V2ZVJs13d91s50kDyfjL9eiaoKsonicw0njRojtV0A/640?wx_fmt=png&from=appmsg "")  
  
    执行net share php$ /delete 再次查看共享服务，可看到php共享服务已关闭  
  
![](https://mmbiz.qpic.cn/mmbiz_png/icdGEWOnYLpMyeQddor3PsaPxut7ibUeGP3VQCvuxWNC6TK7Q45kcbxDUNXfTa9b0EoeRfQwNDPpy4U7fBVo7VpQ/640?wx_fmt=png&from=appmsg "")  
  
    如果说共享了一些高危目录，如WEB目录，再加上可能未验证的情况下，可能导致攻击者上传shell文件，从而getshell，如果说正常情况下不使用共享功能，可关闭掉相应端口  
```
查看开放端口命令 netstat -an 排查有无开放高危可疑端口
此处不在赘述
```  
```
firewall.cpl 命令配置防火墙，入站规则用来对于IP加入白名单黑名单等
由于当前环境需要上云及后期测试，暂不开启防火墙
现实中以具体环境进行开启载入
```  
  
  
**漏洞扫描**  
```
问: 使用桌面/工具/fscan32.exe对本机进行漏洞扫描
    对扫描出的漏洞端口进行提交
答案: 3306&6379
```  
  
   fscan32目录下开启cmd，输入命令 fscan32.exe -h 127.0.0.1 -np，得到扫描的端口及存在的漏洞(如出现被系统查杀fscan，自行关闭病毒威胁与防护)  
  
![](https://mmbiz.qpic.cn/mmbiz_png/icdGEWOnYLpMyeQddor3PsaPxut7ibUeGPo1w4YSbVVn4sCMUZicLzkA0nicX3GrmzJL5P3JEIOxEs9pDe6qlUBjJg/640?wx_fmt=png&from=appmsg "")  
  
    mysql数据库弱口令和redis未授权访问，所以答案为3306&6379，至于为什么不用其它主机漏扫，我用了goby和其它工具，发现误报率高，而且很慢  
  
**代码审计**  
```
问: 使用桌面/工具/D盾/D_Safe_Manage.exe对web源码进行扫描
    将扫描出的shell连接密码作为flag提交
    web源码在C:\phpstudy_pro\WWW\*
答: flag{34656b0c612be3729ffdcc40b63a9a33}
```  
  
    由于源代码是未公开漏洞，此处不做真实代码审计，但最后会放POC进行利用，以D盾进行演示，源代码及漏洞POC鸣谢：  
道一安全  
  
  
    打开D盾后，将WWW目录直接拖进去，进行快速扫描，最终看到几个可疑文件，进行逐一排查  
  
![](https://mmbiz.qpic.cn/mmbiz_png/icdGEWOnYLpMyeQddor3PsaPxut7ibUeGPudm1IMq9Au5CA8ZGOcavHRueJPOD1YSuLZ41ukIXqK7KgFwyGmvSxg/640?wx_fmt=png&from=appmsg "")  
  
    在 C:\phpstudy_pro\WWW\src\system\data\fonts\index.php文件中看到一句话木马文件  
  
![](https://mmbiz.qpic.cn/mmbiz_png/icdGEWOnYLpMyeQddor3PsaPxut7ibUeGP0olHF3hzemP48Kk6luZXg5pyWXyeTibsYXJcdrWiciamib6fpaXiaEL7mng/640?wx_fmt=png&from=appmsg "")  
  
**渗透测试**  
```
问: 提交任意文件上传后的shell。执行命令whoami后，将结果上交
    漏洞为未公开，POC会放在下方，自行下载
答: win-f8aldv845hd\administrator
```  
```
漏洞POC下载:
https://ckxkzyk.lanzouo.com/iSqw81xt8lpi
```  
  
    桌面浏览器访问127.0.0.1即可，看到如下图即为成功，如访问超时，重启桌面phpstudy即可  
  
![](https://mmbiz.qpic.cn/mmbiz_png/icdGEWOnYLpMyeQddor3PsaPxut7ibUeGP7e8dLzGUwTiajyxkia66j8P8aUgTAEskhM0W3R1qibQhibl2yicSwXC4YfA/640?wx_fmt=png&from=appmsg "")  
  
    这里我shell用的是system函数，具体怎么用看自己个人习惯  
  
![](https://mmbiz.qpic.cn/mmbiz_png/icdGEWOnYLpMyeQddor3PsaPxut7ibUeGPEG91icuCsmZicBYrKqvicFVhzgTAl3fot5K3TbibBCibPic7NyTYm00pLV7w/640?wx_fmt=png&from=appmsg "")  
```
访问后台: ip/admin
账号: admin 
密码: password
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/icdGEWOnYLpMyeQddor3PsaPxut7ibUeGPNhglhb3DNBW8OEibJPpvbsHIMOLM6ibiaCD0jMEqxyicazLyRC1Fx2xfYw/640?wx_fmt=png&from=appmsg "")  
  
    然后管理文件->编辑->点击查看，访问后文件存在，输入whoami命令，拿到结果  
  
![](https://mmbiz.qpic.cn/mmbiz_png/icdGEWOnYLpMyeQddor3PsaPxut7ibUeGPKaEAK8KAb5vabU3A8mv98bNMakn9My0KJJMDdKjG8K5kicXAWW1Uxvw/640?wx_fmt=png&from=appmsg "")  
  
    ![](https://mmbiz.qpic.cn/mmbiz_png/icdGEWOnYLpMyeQddor3PsaPxut7ibUeGPODEVoaBzjjeg5Q0kibm1w9DbSa5OiaT8bI21euPA0WH6ibf3JGAZ7whtg/640?wx_fmt=png&from=appmsg "")  
  
  
    此处需要注意的是，图片马的图片尽量越小越好，图片大了里面内容就多，在当作php解析时，可能会提前将图片中某些字符作为php解析，造成报错  
  
![](https://mmbiz.qpic.cn/mmbiz_png/icdGEWOnYLpMyeQddor3PsaPxut7ibUeGP5bAo5rmLT4kIjcLr1HH0d3VjaWKdjDMicz6B6B8LIqNz4QiaghDvuQicQ/640?wx_fmt=png&from=appmsg "")  
  
**0x03 总结**  
  
    本次测评过程以答题式趣味学习，在娱乐中学习，深度解析等保测评在现实生活中的重要性，没有做中间件和数据库测评，因为用的是PHP study，没有独立安装相关完全用例，完全测评不太容易实现，比如说数据库的安全策略，需要更改配置文件，但是PHP study是内置配置，有相关学习意愿的师傅可参考我之前发的文章自行本地复现，当然，本次测评仅供学习参考，希望能为您在现实面试、排错、项目上线前提供帮助，环境内工具及源码禁止对外非法攻击，否则后果自负！  
  
**玄机邀请码抽奖**  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/icdGEWOnYLpNFmaibjiblRPm0aA0rnNUZqJvJrp9GeQ5c8bRZRxdeXJnIFRic8RGuTKycd8meXcoRibTpzMmaGrvjiag/640?wx_fmt=gif&wxfrom=5&wx_lazy=1&tp=webp "")  
  
