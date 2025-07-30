#  Funbox 2靶场复现   
原创 LULU  红队蓝军   2024-11-25 10:01  
  
#   
## 1、信息收集   
  
IP  
```
arp-scan -l
netdiscover -r 192.168.56.0/24

```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ibZ6uZjjH3v6TbjFSZg6RZgdJBNsnSb6yeiazej1oeTGGhaNMuXltzib1vRAIIYziaNG0WicEhrKmHwOAS8YSpUh4Yw/640?wx_fmt=png&from=appmsg "")  
  
目录  
  
扫描端口探测出robots.txt 文件。访问，但没有有用信息，使用工具进行目录扫描  
```
dirsearch -u http://192.168.56.103 -i 200

```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ibZ6uZjjH3v6TbjFSZg6RZgdJBNsnSb6y9wNiaVumPlFwqXPEW7qha6yaPTo1yL8M0NoowVcuh3MdXALiavtB9thA/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ibZ6uZjjH3v6TbjFSZg6RZgdJBNsnSb6yUwAxzQW0C9FGME79LP7hTjXNne9QYSh1hTJVokDJNgtwicmAbUHZK4g/640?wx_fmt=png&from=appmsg "")  
  
端口  
```
nmap -A -sV -T4 -p- 192.16856.103

```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ibZ6uZjjH3v6TbjFSZg6RZgdJBNsnSb6yyQOQLFWIzxiacjamfZBrMD34iakTlem3Bbce2BqvycoRuicKggjicibJGNw/640?wx_fmt=png&from=appmsg "")  
```
21—ftp—ProFTPD 1.3.5e—Anonymous允许匿名登录

22—ssh—OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)

80—http—Apache httpd 2.4.29 ((Ubuntu))

```  
### 分析21端口  
  
ftp协议是文件传输协议，绝大多数的FTP服务器是受密码保护的，因为FTP服务器要求输入用户名和密码。但是如果是连接匿名FTP服务器，并不需要输入真实的用户信息，可以尝试anonymous作为用户名以及使用空密码  
  
在扫描端口时提示 Anonymous FTP login allowed，即允许Anonymous作为用户名以及使用空密码进行登录  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ibZ6uZjjH3v6TbjFSZg6RZgdJBNsnSb6ytlZpiapAmmpObG1F6YC2R8xGb2nYiczeAYW3qIlw5a7QXd8hkGpEUy6Q/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ibZ6uZjjH3v6TbjFSZg6RZgdJBNsnSb6ytL9bSa5DemNCkJLVHbzXqyJbncIGORr2LmibvzaeKSOHhfCqqB70KQw/640?wx_fmt=png&from=appmsg "")  
  
登录匿名FTP服务后，有很多文件，将文件进行下载  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ibZ6uZjjH3v6TbjFSZg6RZgdJBNsnSb6yw8ricULkicTyQVbIO5UyL0bLicUnEqTib5Lf1Tf3dGE05IKMXGMtlwjMfQ/640?wx_fmt=png&from=appmsg "")  
  
我这里下载到/home/kali/Downloads/目录  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ibZ6uZjjH3v6TbjFSZg6RZgdJBNsnSb6yJhB4M02S1WicsA4H6VScYU6QtibglOnuicrqdbjkZ1icT22UgyYgH1icgcg/640?wx_fmt=png&from=appmsg "")  
  
解压文件，需要输入密码  rsa 是一种密码算法  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ibZ6uZjjH3v6TbjFSZg6RZgdJBNsnSb6y5q1RicFY7Fd21iayQXzmiaRxTibd7ht8dHvgec3zy7VWlv4cVtsHd7ImOg/640?wx_fmt=png&from=appmsg "")  
  
这里要使用工具 fcrackzip，破解密码  
  
Fcrackzip (Free/Fast Zip Crack，免费快速Zip密码破解）是一款专门破解zip类型压缩文件密码的工具，能使用字典和指定字符集破解，适用于linux、mac osx 系统  
```
MAC安装指令：
brew install fcrackzip

Linux Ubuntu安装指令：
sudo apt-get install fcrackzip

Windows安装包：
http://blog.rubypdf.com/2008/10/15/fcrackzip-10-windows-version-releases

```  
### 使用fcrackzip工具破解zip密码  
```
fcrackzip -D -p /usr/share/wordlists/rockyou.txt -u 要解密的zip包

```  
  
这里将下载下来的文件挨个进行猜解  
```
fcrackzip -D -p /usr/share/wordlists/rockyou.txt -u cathrine.zip

```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ibZ6uZjjH3v6TbjFSZg6RZgdJBNsnSb6yVQX9Eicm3S0Ov9PLFFV7cZJfJDR5wbNVZmAFoScaCH1icVciaQibfHquXQ/640?wx_fmt=png&from=appmsg "")  
  
**cathrine.zip 密码  catwoman**  
```
fcrackzip -D -p /usr/share/wordlists/rockyou.txt -u tom.zip

```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ibZ6uZjjH3v6TbjFSZg6RZgdJBNsnSb6yk9nHGl8yJCo7iaW02S3QFibfGCeav4ibEVDDp8bxNKNlv2yIEVaTKRWVw/640?wx_fmt=png&from=appmsg "")  
  
**tom.zip 密码  iubire**  
  
基于得到的密码,对tom.zip 进行解压，得到rsa私有密钥，这个时候通过id_rsa登录ssh  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ibZ6uZjjH3v6TbjFSZg6RZgdJBNsnSb6ywTE8ysrMDKajlKxLJI2X4qSsTnog4J8kXzKjGKWjFIuib6XnWGFFB3g/640?wx_fmt=png&from=appmsg "")  
  
登录  
```
ssh -i id_rsa tom@192.168.56.103

```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ibZ6uZjjH3v6TbjFSZg6RZgdJBNsnSb6yYo0BdtzqMrEibMBDxHFN8GvKv3FfccA0kmL2dLWBg57ECW8XR5Xhq1g/640?wx_fmt=png&from=appmsg "")  
### 使用zip2john破解zip密码  
  
使用zip2john工具将要破解的zip转为hash，在通过john 碰撞。这里就演示tom.zip  cathrine.zip  
```
zip2john tom.zip > 1.txt
john 1.txt

zip2john cathrine.zip > 2.txt
john 2.txt

```  
  
**破解tom.zip密码**  
  
  
**破解cathrine.zip密码**  
  
## 2、提权   
  
suid提权  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ibZ6uZjjH3v6TbjFSZg6RZgdJBNsnSb6yGGxSqCMGKcDibsVyx6Vy0h7fibt89sIgHTWfbKLIj7tTypje8I3bYIuA/640?wx_fmt=png&from=appmsg "")  
  
发现存在-rbash，RBASH 是一种特殊的 shell，它限制了用户的一些操作和权限  
  
绕过rbash, 通过ssh 命令，它的 -t 选项执行/bin/bash 进行绕过  
```
ssh -i id_rsa tom@192.168.56.103 -t bash

```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ibZ6uZjjH3v6TbjFSZg6RZgdJBNsnSb6ySwQLL7VQ3DCx0Bb8pEajnFpfaU67CRm5jlqcyDLRFULZKR6nZP34aQ/640?wx_fmt=png&from=appmsg "")  
  
切换到家目录下，查看隐藏文件  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ibZ6uZjjH3v6TbjFSZg6RZgdJBNsnSb6yicElHbISXcLFDHBF5FdibcVXxt16TpT1vjkgMee9ia6QrQrKjvkyp1PRw/640?wx_fmt=png&from=appmsg "")  
  
发现有两个历史文件  
  
查看.mysql_history，这个文件纪录关于数据库的历史命令  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ibZ6uZjjH3v6TbjFSZg6RZgdJBNsnSb6ytuSkwfOHkP00X9LzSmDb4P37NkHEUMF3fZcrvWLVEROqoWg6zCVeVw/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ibZ6uZjjH3v6TbjFSZg6RZgdJBNsnSb6yqw6oicar0HwlKnAnoKs2g3m3KmqQpF1oYu6wJAXxBibYtibB0XCIQLgRw/640?wx_fmt=png&from=appmsg "")  
  
  
sudo 提权  
  
在Linux系统中，sudo命令允许授权用户以另一个用户（通常是超级用户或root用户）的身份执行命令,需要编辑sudoers文件，该文件定义了哪些用户和用户组可以使用sudo命令以及他们可以运行的命令  
```
比如：要允许用户username使用sudo，在/etc/sudoers文件中添加以下行：
username ALL=(ALL:ALL) ALL

```  
  
这里定义了tom用户能够使用sudo命令不需要输入密码就能得到root的权限  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ibZ6uZjjH3v6TbjFSZg6RZgdJBNsnSb6yNPLuibSyvb3FiaI7HvcVJibeBLLpUQWtwN1uDDaasianATibapUpQfaE5KQ/640?wx_fmt=png&from=appmsg "")  
  
  
flag  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ibZ6uZjjH3v6TbjFSZg6RZgdJBNsnSb6yUHjxwhSleUgU7Q00veHxwGXIiaq4bBpH1JanaquKn3ujERm00TKOY2w/640?wx_fmt=png&from=appmsg "")  
  
