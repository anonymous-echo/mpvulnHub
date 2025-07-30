#  Deep Recon 发现未经身份验证的上传和 IDOR 漏洞 — 获得赏金 $$$   
haidragon  安全狗的自我修养   2025-05-23 07:42  
  
#   
# 初始阶段——选择目标  
  
在 Bugcrowd 上探索通配符程序时，我偶然发现了一个很有潜力的目标。我决定深入挖掘，进行**深入侦察**，这是我非常享受的事情。  
# 侦察阶段  
  
我使用了一个侦察 bash 脚本：  
```
```  
#!/usr/bin/env bashdomain=$1if! [$domain];thenecho"[!] No target provided."echo">> $0 <example.com>"exit1fisubfinder -all -silent -d$domain-o subfinder.txtfindomain -t$domain-u findomain.txtcurl -s"https://crt.sh/?q=%25.${domain}&output=json"| jq -r'.[].name_value'| sed's/\*\.//g'| anew crtsh_subs.txtgithub-subdomains -d$domain-t <Your_Git_Hub_Token>-o github_subs.txtamass enum -passive -norecursive -d$domain-o amass.txtecho"$domain"|dnsgen - |teednsgen.txtecho"$domain"|alterx |teealterx.txtpuredns bruteforce resolvers.txtcatsubfinder.txt findomain.txt amass.txt dnsgen.txt crtsh_subs.txtalterx.txt |uniq-u |teesubdaomins1.txt  
然后，我使用以下方法过滤了活动子域名：  
```
```  
  
之后，我继续收集已发现子域名的子域名  
  
echo  
 “extracts the subdomains”  
  
cat  
 live1.txt|awk   
'{print $1 }'  
 |  
cut  
 -d / -f3 |awk -F:   
'{print $1 }'  
|  
tee  
 subdomain2.txt  
  
echo  
  
"extracts the last 3 segments of each domain"  
  
cat  
 subdomain2.txt|awk -F.   
'{print $(NF-2)"."$(NF-1)"."$NF}'  
|  
uniq  
 -u |  
tee  
 subdomain2_uniq.txt  
  
subfinder -all -silent -dL subdomain2_uniq.txt -o subfinder2.txt  
  
cat  
 subdomain2_uniq.txt |dnsgen - |  
tee  
 dnsgen2.txt  
  
cat  
 subdomain2_uniq.txt |alterx |  
tee  
 alterx2.txt  
  
然后，我使用以下方法过滤了活动子域名：  
```
```  
# 测试阶段  
  
收集到实时主机后，我手动访问了每一个主机 — — 优先考虑状态码**200**，同时也检查其他状态码，如**403**和**404**。  
  
一个子域名脱颖而出。  
  
  
  
  
IDOR + 未经身份验证的文件上传链  
  
我们将子域名称为：  
weird.target.com  
  
它最初显示一个空白页，但经过目录模糊测试后，我发现：  
```
```  
  
  
  
  
我开始测试每个端点，发现/files/all和/files端点列出了与员工和公司相关的所有内部文件。  
  
  
  
  
然后我开始测试/upload端点，它最初响应“错误方法”错误。  
  
  
  
  
于是，我打开了 Burp Suite，将请求方法改为POST，精心设计了一个文件上传请求——令我惊讶的是，文件**无需任何身份验证**就成功上传了。  
  
  
  
  
然后我返回/files/端点并确认文件已成功上传。  
  
  
  
  
上传的文件出现在公司官方邮箱下，看起来像是由合法的内部用户上传的。然后，我尝试通过上传 PHP 有效载荷来实现远程代码执行 (RCE)。虽然文件上传成功，但服务器已配置为阻止 PHP 代码的执行。我还测试了路径遍历，但发现无法实现。之后，我探索了其他端点，例如/delete/和/download/，发现我可以无需任何身份验证即可读取和删除内部文件——因此我立即报告了这个问题，感谢真主，我因我的发现获得了赏金。  
  
此外，我还在与目标相关的另一个域名上发现了一个竞争条件漏洞。如果该公司确认该问题已解决，我计划尽快发布详细的报告。  
  
  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/vBZcZNVQEREkjoibjFst4F2YTlvkRG4zW4Nlt9pZBgFYgFxfVZFxu83EQnESej7ydiblH1UfHqKX3hBfcm76JiaSA/640?wx_fmt=png&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/vBZcZNVQEREkjoibjFst4F2YTlvkRG4zW0h21TYuO94OrIGsD2aHGrUcUYiasibQS5AYJ4a95Ra3zIFIXQ4e8lkFA/640?wx_fmt=png&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/vBZcZNVQEREkjoibjFst4F2YTlvkRG4zW6iapnXQ3Wviaiaiap37xFRqNok6BymcTiacnk07OowXYFowAKYfa9zS6gSA/640?wx_fmt=png&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/vBZcZNVQEREkjoibjFst4F2YTlvkRG4zWiaJkE3jZRR7znMJDXAlibBzibYaGLMlVvsa1xhlQFyv3viaARicSIII7a9A/640?wx_fmt=png&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
#   
  
****  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/vBZcZNVQERHWXCBzZk44eZOKvIGq0RZia2vfZVtmPodgjznTwlY7PXU40F5KQ8xiceJOhLktswpMhec0zQVz07Cw/640?wx_fmt=png&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
****  
**rust语言全栈开发视频教程-第一季(2025最新)**  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/vBZcZNVQERFO4iaNJUiawzlicADlGjS6UCWtUt0Jaibcc4U8aM7H8pSmjNWZHzZC2ibEib1voX6Waqowyd0Mnfce48Hg/640?wx_fmt=png&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/vBZcZNVQERFO3lqcLOMSd2PQZ9GiblkFIKNw2LH9DMNEibhyxpUVNCd907wCN9NroUqTaJgquiapibArIRby4AGMoQ/640?wx_fmt=png&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/vBZcZNVQERFO3lqcLOMSd2PQZ9GiblkFIRnBhWWFJXdzp516ibYibQsicDCzfq1MicKGdv9os1l2nyDAVNSR8b5cPow/640?wx_fmt=png&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
# 详细目录  
# mac/ios安全视频  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/vBZcZNVQERFbBn3mydWukVkxb7u4ibpOneTvEKRymYhW9KMlUWP1RnaXLuZibvPMdGmrdWVV3AMJya9dNxszgOeA/640?wx_fmt=png&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
# QT开发底层原理与安全逆向视频教程  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/vBZcZNVQERGLucgfllJsyUEFRxtnUNkLfUhNeUCnH7x8VtPq0Q2zxZBdhjqiaibsx0rIbaYWMuIibmk5QtNPzsOSw/640?wx_fmt=png&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
linux文件系统存储与文件过滤安全开发视频教程(2024最新)  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/vBZcZNVQERHSM6Wk8NAEmbHHUS2brkROr9JOj6WZCwGz4gE4MlibULVefmhRw2dvJd8ZeYnDpRIm0AV1TmIsuEQ/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
linux高级usb安全开发与源码分析视频教程  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/vBZcZNVQERHCd9Qic4AAIQfFFD7Rabvry4pqowTdAw6HyVbkibwH5NjRTU4Mibeo4JbMRD3XplqCRzg4Kiaib3jchSw/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
**linux程序设计与安全开发**  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/vBZcZNVQERGoVibbKav1DpliaTJ9icDrosqXeWyaMRJdCVWEG0VYLDibSMwUP1L5r9XmLibGkEkSZnXjPD6mWgkib9lA/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
****- ![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/vBZcZNVQERHhezg9PuKylWLTBfCjokEH4eXCW471pNuHpGPzUKCkbyticiayoQ5gxMtoR1AX0QS7JJ2v1Miaibv1lA/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
- #   
  
-   
- w  
i  
n  
d  
o  
w  
s  
网  
络  
安  
全  
防  
火  
墙  
与  
虚  
拟  
网  
卡  
（  
更  
新  
完  
成  
）  
  
- ![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/vBZcZNVQERE5qcRgQueCyt3U01ySnOUp2wOmiaFhcXibibk6kjPoUhTeftn9aOHJjO6mZIIHRCBqIZ1ok5UjibLMRA/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
- w  
i  
n  
d  
o  
w  
s  
文  
件  
过  
滤  
(  
更  
新  
完  
成  
)  
  
- ![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/vBZcZNVQERHhezg9PuKylWLTBfCjokEHmvkF91T2mwk3lSlbG5CELC5qbib3qMOgHvow2cvl6ibicVH4KguzibAQOQ/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
- U  
S  
B  
过  
滤  
(  
更  
新  
完  
成  
)  
  
- ![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/vBZcZNVQERHhezg9PuKylWLTBfCjokEHv0vyWxLx9Sb68ssCJQwXngPmKDw2HNnvkrcle2picUraHyrTG2sSK7A/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
- 游  
戏  
安  
全  
(  
更  
新  
中  
)  
  
- ![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/vBZcZNVQERHhezg9PuKylWLTBfCjokEHzEAlXtdkXShqbkibJUKumsvo65lnP6lXVR7nr5hq4PmDZdTIoky8mCg/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
- i  
o  
s  
逆  
向  
  
- ![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/vBZcZNVQERHhezg9PuKylWLTBfCjokEHmjrTM3epTpceRpaWpibzMicNtpMIacEWvJMLpKKkwmA97XsDia4StFr1Q/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
- w  
i  
n  
d  
b  
g  
  
- ![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/vBZcZNVQERECMA4FBVNaHekaDaROKFEibv9VNhRI73qFehic91I5dsr3Jkh6EkHIRTPGibESZicD7IeA5ocHjexHhw/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
- 还  
有  
很  
多  
免  
费  
教  
程  
(  
限  
学  
员  
)  
  
- ![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/vBZcZNVQERHhezg9PuKylWLTBfCjokEHDvveGEwLYBVsps1sH6rGrSnNZtjD2pzCk4EwhH3yeVNibMMSxsW5jkg/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/vBZcZNVQERECMA4FBVNaHekaDaROKFEibDwwqQLTNPnzDQxtQUF6JjxyxDoNGsr6XoNLicwxOeYfFia0whaxu6VXA/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/vBZcZNVQERECMA4FBVNaHekaDaROKFEibR2Viaxgog8I2gicVHoXJODoqtq7tTVGybA8W0rTYaAkLcp8e2ByCd1QQ/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
- ![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/vBZcZNVQEREEHMPaJ2RMX7CPES3mic42r1Wub102J6lAmEwKIicDfADiajsEReibfvSCbmiaRlGRCQibqfJJia0iak421Q/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
-   
- **windows恶意软件开发与对抗视频教程**  
  
-   
- ![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/vBZcZNVQERFPap5AiahwlmRC2MGPDXSULNssTzKQk8b4K3pttYKPjVL4xPVu1WHTmddAZialrGo8nQB3dJfJvlZQ/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
- ![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/vBZcZNVQERHYgfyicoHWcBVxH85UOBNaPMJPjIWnCTP3EjrhOXhJsryIkR34mCwqetPF7aRmbhnxBbiaicS0rwu6w/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
- ****  
- ![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/vBZcZNVQERHYgfyicoHWcBVxH85UOBNaPZeRlpCaIfwnM0IM4vnVugkAyDFJlhe1Rkalbz0a282U9iaVU12iaEiahw/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
