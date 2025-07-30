#  《DOM型XSS漏洞之document.write触发》   
原创 柠檬赏金猎人  柠檬赏金猎人   2025-02-28 10:22  
  
   
  
### 介绍  
  
使用JavaScript的调用 location.search  
获取数据，再通过document.write  
 函数将数据写入页面。您可以使用网站 URL 进行控制，将数据包含在 select 元素中。  
### 目标  
  
执行跨站点脚本攻击，突破 select 元素并调用 alert  
 函数。  
### 步骤  
1. 1. 下载挖掘 Dom xss 调试插件  
  
```
https://github.com/filedescriptor/untrusted-types/
```  
1. 2. 我们使用 https://portswigger.net/ 靶场，打开插件跟踪调用链，之后console进入源代码  
  
1. ![](https://mmbiz.qpic.cn/sz_mmbiz_png/OkRKg4J9smWuVI6ib2UujEe3AQiaQGamZoWbJVPMy39icH0uBOZCWaQWcoDphrsK2bKc3P7VSoEVgD1DCZTAz64FA/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/OkRKg4J9smWuVI6ib2UujEe3AQiaQGamZogzvMhPpSJrVHvhA3zSogyaNxEWpdQyRFK5txKxhe4wtibV7riaRWO43g/640?wx_fmt=png&from=appmsg "")  
  
  
请注意危险的 JavaScript 源中 location.search  
提取一个 storeId  
 参数。然后，它使用该document.write  
 参数在 select 元素中为库存检查器功能创建一个新选项。  
1. 3. 向 URL 添加查询参数并输入随机字母数字字符串作为其值。请求此修改后的 URL。  
  
1. ![](https://mmbiz.qpic.cn/sz_mmbiz_png/OkRKg4J9smWuVI6ib2UujEe3AQiaQGamZoqJlQmLqyKeWrdNSt5rY3ADeKfzzQcDfSyvibRwnEdlibhrNaN4hiapdbg/640?wx_fmt=png&from=appmsg "")  
  
  
1. 4. 在浏览器中，请注意您的随机字符串现在已列为下拉列表中的选项之一。  
  
1. 5. 右键单击并检查下拉列表，以确认 storeId  
 参数的值已放置在选择元素内。  
  
1. 6. 更改 URL 以在 storeId  
 参数中包含合适的 XSS 负载，如下所示：  
  
```
https://0ae40068042532ea812b57c700890050.web-security-academy.net/product?productId=2&storeId=sdsd%22%3E%3C/select%3E%3Cimg%20src=1%20onerror=alert(1)%3E
```  
  
  
   
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/OkRKg4J9smWuVI6ib2UujEe3AQiaQGamZoplicCoQr39Lj7IiaFicVduUJVULbuEcmjiaIqiahGbIJycC01Gnyktc85gw/640?wx_fmt=png&from=appmsg "")  
  
   
  
  
   
  
仅限交流学习使用，如您在使用本工具或代码的过程中存在任何非法行为，您需自行  
承担相应后果，我们将不承担任何法律及连带责任。  
“如侵权请私聊公众号删文”。  
  
