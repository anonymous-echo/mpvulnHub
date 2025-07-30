#  恶意软件伪装成漏洞PoC进行传播   
 关键基础设施安全应急响应中心   2023-07-25 16:07  
  
数据窃取恶意软件伪装成虚假Linux漏洞利用PoC。  
  
近日，Uptycs安全研究人员在GitHub上发现一个虚假的CVE-2023-35829漏洞利用PoC代码，该漏洞利用代码会安装Linux密码窃取恶意软件。  
  
研究人员发现该恶意PoC会尝试进行网络连接、进行非授权的系统访问、以及数据传输。研究人员一共在3个GitHub仓库中发现了该恶意PoC漏洞利用，其中2个易被移除。Uptycs 已将该情报在社区进行了共享，所以该恶意软件感染用户数量可能并不多。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o2iboOkcGbCQbmryM5HNkRDHzoXlQVXHKdeFvLcOwDB7I5H4LEyC4vvzEur0YsoPZNklNbO0KGGgMKw/640?wx_fmt=png&wxfrom=13 "")  
  
图 推送恶意软件的恶意GitHub库  
# 恶意PoC  
  
CVE-2023-35829是一个高位的释放后使用漏洞，影响Linux kernel 6.3.2及之前版本。该虚假PoC声称是CVE-2023-35829的漏洞利用代码。而事实上该虚假PoC只是CVE-2022-34918漏洞利用代码的一个副本。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o2iboOkcGbCQbmryM5HNkRDHzKjRmfwL21QwiavczpzltpKd7OtYahEnibD9nQ0JXYOjzgMarksibrVcsg/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
图 两个PoC代码的比较  
  
恶意PoC利用了namespaces使系统认为其是root shell，虽然其权限仍然在用户namespace中。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o2iboOkcGbCQbmryM5HNkRDHzGzXF4L04DrsQ0WrOC9B6r10mZuxs4FnCjvCwD54LqaOBgZc8xRTjPg/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
图 创建虚假Shell的代码段  
  
启动后，PoC后创建一个kworker文件，并将其路径添加到'/etc/bashrc'文件中以实现在系统中的驻留。  
  
然后会与攻击者的C2服务器取得联系，并从外部URL下载和执行Linux bash脚本。  
  
下载的脚本会访问'/etc/passwd'文件从系统中窃取有价值的数据，修改'~/.ssh/authorized_keys'来授予攻击者远程访问服务器的权限，最后使用curl和'transfer.sh'来窃取数据。  
  
该脚本窃取的数据包括用户名、主机名、受害者home目录的内容。理论上讲，攻击者有服务器的访问权限，因此可以窃取服务器上的所有内容。  
  
Bash脚本会将其操作伪装成kernel级进程来绕过检测，因为系统管理员倾向于信任kernel进程，一般不会对其日志进行审查。  
# 不要信任漏洞利用代码  
  
Uptycs建议下载了该虚假漏洞PoC的用户执行以下操作：  
  
移除未认证的ssh key；  
  
删除kworker文件；  
  
从bashrc文件中移除kworker路径；  
  
Remove any unauthorized ssh keys  
  
检查 /tmp/.iCE-unix.pid。  
  
此外，从互联网下载的PoC代码应在虚拟机等沙箱和管理环境中进行测试，如果有可能的话，还应对在执行前对代码进行检查。向VirusTotal提交可快速识别恶意文件。  
  
使用虚假PoC攻击安全研究人员也并不少见。6月，VulnCheck研究人员就发现一个伪装成安全公司研究人员来推送恶意软件的攻击活动，使用的是Chrome、MS Exchange和Discord 0 day漏洞利用。2022年10月，研究人员发现论文称GitHub上有约10.3%的PoC代码可能是恶意软件。2021年，朝鲜黑客组织Lazarus也是使用虚假PoC来安装后门以攻击安全研究人员。  
  
**参考及来源：**  
  
https://www.bleepingcomputer.com/news/security/fake-linux-vulnerability-exploit-drops-data-stealing-malware/  
  
  
  
原文来源：嘶吼专业版  
  
“投稿联系方式：孙中豪 010-82992251   sunzhonghao@cert.org.cn”  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/iaz5iaQYxGogvC8qicuLNlkT5ibJnwu1leQiabRVqFk4Sb3q1fqrDhicLBNAqVY4REuTetY1zBYuUdic0nVhZR4FHpAfg/640?wx_fmt=jpeg&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
