#  漏洞利用-PoC-in-GitHub+msf简单利用   
原创 兰陵猪猪哼  小黑子安全   2024-04-26 07:46  
  
查找库  
-PoC-in-GitHub  
  
里面集成了几乎所有  
cve  
漏洞  
  
下载：  
https://github.com/nomi-sec/PoC-in-GitHub  
  
演示：  
  
如想要查找  
vulfocus  
靶场中  
    
Metabase  
远程命令执行漏洞  
    
的利用方法。  
  
可以下载一个  
Y  
omm  
闪电文件搜索  
  
Y  
omm  
闪电文件搜索下载：  
https://www.xzji.com/soft/6116.html  
  
1.  
打开文件搜索应用，填写漏洞库的路径，漏洞关键字。点击搜索成功搜索出漏洞文件  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b9ibb0kbHCIlB8erumkIxqyzQSgCRVQu4QxkcEa8nMAswTgG45rfWjAUk7LhN7A9Ff7XwXNKicGUSmF9DtZs0tcw/640?wx_fmt=png&from=appmsg "")  
  
打开文件，里面有漏洞编号和许多漏洞利用地址链接  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b9ibb0kbHCIlB8erumkIxqyzQSgCRVQu4g63Micicj9hpxe8CSF7zC5KYVQsvvqzEuicJArFbicoXribKzX1IFktWGQg/640?wx_fmt=png&from=appmsg "")  
  
打开一个链接，成功获取漏洞利用脚本  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b9ibb0kbHCIlB8erumkIxqyzQSgCRVQu4p7aa8eyS4Qsz64TSfKQJrRwiaejsy7icY4RcAtHeLtNEtyfm3PzibH0Rg/640?wx_fmt=png&from=appmsg "")  
  
模块框架-MetaSploit-Framework（MSF）  
  
MSF  
简介  
  
   
Metasploit  
（  
MSF  
）是一个免费的、可下载的框架  
  
   
它本身附带数百个已知软件漏洞，是一款专业级漏洞攻击工具。  
  
   
当  
H.D. Moore  
在  
2003  
年发布  
Metasploit  
时，计算机安全状况也被永久性地改变了，仿佛一  
  
夜之间，任何人都可以成为黑客。  
  
   
因为只要掌握  
MSF  
的使用方法，每个人都可以使用  
MSF  
来攻击那些未打过补丁或者刚刚打过补丁的漏洞。  
  
   
也因此软件厂商再也不能推迟发布针对已公布漏洞的补丁了，因为  
Metasploit  
团队一直都在努力开发各种攻击工具，并将它们贡献给所有  
Metasploit  
用户。  
  
下载：  
https://docs.metasploit.com/docs/using-metasploit/getting-started/nightly-installers.html  
  
使用：  
https://blog.csdn.net/hackzkaq/article/details/120825347  
  
演示：利用  
vulfocus  
靶场中的  
   
struts2   
代码执行 （  
CVE-2020-17530  
）来演示  
  
启动漏洞环境  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b9ibb0kbHCIlB8erumkIxqyzQSgCRVQu4rDSE021iamJOKXf6E0kzjwklKuvjojEutL6773m0d9WiapHTcMHIOqDA/640?wx_fmt=png&from=appmsg "")  
  
启动  
msf  
，输入：  
msconsole  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b9ibb0kbHCIlB8erumkIxqyzQSgCRVQu4sYwtPs0JShTicjvLPLUJkhffNLbczurZbA9O5apSyvFma2VDwWZ5s8g/640?wx_fmt=png&from=appmsg "")  
  
搜索漏洞关键字获取漏洞利用模块，输入：  
search
struts2  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b9ibb0kbHCIlB8erumkIxqyzQSgCRVQu4lZKJdaEmJzWbX6YqRvuTp7JoWphdJ0PiasoV8SPdHVEgcRQULibej55Q/640?wx_fmt=png&from=appmsg "")  
  
进入模块，输入：  
use   
模块名称  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b9ibb0kbHCIlB8erumkIxqyzQSgCRVQu4uvqibticmIsoWnjDHeMfOgzqkUkaYGS1uGY93RH2KAONn6Us3vBM6UPw/640?wx_fmt=png&from=appmsg "")  
  
查看配置需求，输入：  
show
options  
  
Required  
值为  
yes  
表示必须配置  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b9ibb0kbHCIlB8erumkIxqyzQSgCRVQu4O2fPGhDlnOu4mAyfsRNHL6XurUcFOcEIZ67mhfh1TsBUkAJWq4jhAQ/640?wx_fmt=png&from=appmsg "")  
  
输入：  
set rhosts   
目标  
ip  
  
输入：  
set rport   
目标端口  
  
输入：  
set lhost   
监听地址  
  
输入：  
set lport   
监听端口  
  
输入：  
run  
     
表示开始利用  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b9ibb0kbHCIlB8erumkIxqyzQSgCRVQu4UtKcBMUibEywQN6icF48Wx3jVmDW2govw04iaYryB9L59RzsuBLjqDaGA/640?wx_fmt=png&from=appmsg "")  
  
最后虽然没有绑定成功，但是成功获取  
shell  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b9ibb0kbHCIlB8erumkIxqyzQSgCRVQu49FwmfuibUfwe4SqIDesQOiazh09YjLlosAPhln1BTp8CYfYXuhMNDRYw/640?wx_fmt=png&from=appmsg "")  
  
网络安全技术交流群：wx加我好友，备注“进群”。学习网络安全也可联系  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/b9ibb0kbHCImS2ldibAAaXVDGRKsYsrwDjQmnYKiauv2Vz2eknbKu3CoVokgYhb09xbGUpBxLqSVsdJBDmic1oiclmA/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
QQ群：708769345  
  
  
