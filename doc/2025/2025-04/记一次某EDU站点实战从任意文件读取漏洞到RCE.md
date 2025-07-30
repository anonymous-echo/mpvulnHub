#  记一次某EDU站点实战从任意文件读取漏洞到RCE   
原创 Mstir  星悦安全   2025-04-14 06:36  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_jpg/lSQtsngIibibSOeF8DNKNAC3a6kgvhmWqvoQdibCCk028HCpd5q1pEeFjIhicyia0IcY7f2G9fpqaUm6ATDQuZZ05yw/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
点击上方  
蓝字  
关注我们 并设为  
星标  
## 0x01 过程  
  
前年的事情，漏洞已提交并修复，这里着重讲思路及漏  
洞  
利用  
最大化.  
  
一开始是模糊测试扫描到一个接口，发现这个接口可以去读取任意文件，并且返回Base64编码后的内容.  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/uicic8KPZnD5fJnx9TgIWEeBDVOn7icZRqMPWyOhvxZh43MPhOCMpspedmlXPMJiaehs2vfmdC3UddI6v6qPc89jZg/640?wx_fmt=png&from=appmsg "")  
  
这里是需要看读取权限  
的大小，若权限足够大，才可以读取到root用户的 history 历史命令的.  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/uicic8KPZnD5fJnx9TgIWEeBDVOn7icZRqMtYS14Govd8MKFrwTR3p2zI6mOdzYuzVLdeueIN5X6L6n1hx1q0JDXw/640?wx_fmt=png&from=appmsg "")  
  
可以看到这里是能发现目标系统的网站目录及组件信息，为Tomcat 8.5.50  
  
任意文件读取可利用路径点   
小Tips :  
  
```
/root/.ssh/authorized_keys //如需登录到远程主机，需要到.ssh目录下，新建authorized_keys文件，并将id_rsa.pub内容复制进去/root/.ssh/id_rsa //ssh私钥,ssh公钥是id_rsa.pub/root/.ssh/id_ras.keystore //记录每个访问计算机用户的公钥/root/.ssh/known_hosts//ssh会把每个访问过计算机的公钥(public key)都记录在~/.ssh/known_hosts。当下次访问相同计算机时，OpenSSH会核对公钥。如果公钥不同，OpenSSH会发出警告， 避免你受到DNS Hijack之类的攻击。/etc/passwd // 账户信息/etc/shadow // 账户密码文件/etc/my.cnf //mysql 配置文件/etc/httpd/conf/httpd.conf // Apache配置文件/etc/redhat-release 系统版本 /root/.bash_history //用户历史命令记录文件/root/.mysql_history //mysql历史命令记录文件/var/lib/mlocate/mlocate.db //全文件路径/proc/self/fd/fd[0-9]*(文件标识符)/proc/mounts //记录系统挂载设备/porc/config.gz //内核配置文件/porc/self/cmdline //当前进程的cmdline参数/proc/sched_debug 配置文件可以看到当前运行的进程并可以获得对应进程的pid/proc/pid/cmdline   则可以看到对应pid进程的完整命令行。/proc/net/fib_trie   内网IP/proc/self/environ   环境变量/proc/self/loginuid   当前用户......
```  
  
  
我们直接读取 mlocate.db 文件来得到包含整个系统所有文件的路径信息，然后配合文件读取洞能有个很好的效果.  
  
![1698330865548.png](https://mmbiz.qpic.cn/sz_mmbiz_jpg/uicic8KPZnD5fJnx9TgIWEeBDVOn7icZRqMgrZuNQPbRR9fW05lnWmflic4ICY3ScgF8BpAROpq1thHsribIsqTvjnA/640?wx_fmt=other&from=appmsg "")  
  
这里我们根据之前得到的网站目录的/webapps 目录就能知道源码所在的路径及名称 xxxx.war 这个是可以直接解压的.  
  
解压之后我们用jd-gui反编译一下，就能看到之前文件读取漏洞的代码，顺道又找到好几个文件读取洞.  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/uicic8KPZnD5fJnx9TgIWEeBDVOn7icZRqMPtPoMAv2wyD7HwjIDZibpE0ia4lLUcAWj1UrIxNJ6CwvQ0pJTaibePGCQ/640?wx_fmt=png&from=appmsg "")  
  
如这里的 Download 方法，通过getParam 获取传参path及fileName，然后将其下载下来，非常经典的文件下载漏洞.  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/uicic8KPZnD5fJnx9TgIWEeBDVOn7icZRqMnT23tD24cVWsGxqhdAjGxbkWLrVOHcnb5ehrAjgWA1Ec8qk4vFAuwQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/uicic8KPZnD5fJnx9TgIWEeBDVOn7icZRqMkCIoqLv8AtMvPQWqgzAO80PCR6pZPUCvN9ciat8gxyiberjrCylAEdmg/640?wx_fmt=png&from=appmsg "")  
  
这里还能得到数据库的账密，如果未做网段隔离，是可以直接连接后进行下一步操作的.  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/uicic8KPZnD5fJnx9TgIWEeBDVOn7icZRqMNeluJGUjdTKFNNuy0V8sIFPdFW3zwDeZYibsyaLl2FOQM3YgpXDdibag/640?wx_fmt=png&from=appmsg "")  
  
后面就是找到了Log4j的漏洞触发点，然后直接反弹上线 DayBreak 了.  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/uicic8KPZnD5fJnx9TgIWEeBDVOn7icZRqMHIR2BY25ibViah7jIjYNXGMX13FGg3lEITVqhGMYC9M7JiayK33E907ag/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/uicic8KPZnD5fJnx9TgIWEeBDVOn7icZRqM3to2kKviaYiaUtiaGWyFSHMEaic3GIj4QnFWhfibhD7rxgicRlFXnWyMYpIQ/640?wx_fmt=png&from=appmsg "")  
## 0x02 Jd-gui下载  
  
  
**标签:代码审计，0day，渗透测试，系统，通用，0day，闲鱼，转转**  
  
**Jd-gui关注公众号发送 250414 获取!**  
  
****  
  
  
**开了个星悦安全公开交流6群，🈲发公众号，纯粹研究技术，还会拉一些大佬，希望大家多多交流.**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/uicic8KPZnD5fJnx9TgIWEeBDVOn7icZRqM0Q3FqtiaumC7P9zEWxJicuQ2udXDQPM8GbJWqnhfp5EbHcrjb2vDkiaSA/640?wx_fmt=jpeg&from=appmsg "")  
  
**免责声明:文章中涉及的程序(方法)可能带有攻击性，仅供安全研究与教学之用，读者将其信息做其他用途，由读者承担全部法律及连带责任，文章作者和本公众号不承担任何法律及连带责任，望周知！！!**  
  
