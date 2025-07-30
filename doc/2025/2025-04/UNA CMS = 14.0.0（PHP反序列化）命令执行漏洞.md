#  UNA CMS <= 14.0.0（PHP反序列化）命令执行漏洞   
原创 zangcc  Eureka安全   2025-04-21 14:41  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/BictawU0A1NPmibPmwrMnlL4Gadw4ibwrvtRsBy8K8ZfSqK9jlcOcY8YNwpuiaLTR7fKcXWl7iauRhoo5HfKH0buFYA/640?wx_fmt=jpeg&from=appmsg "")  
  
  
  
    2025年4月21日，Eureka威胁情报平台监测到了一处新的漏洞预警。在发现这一预警后，  
我们立即展开深入研究，力求全面了解该漏洞的性质、影响范围以及潜在的利用方  
式。  
需要明确的是，此次研究和分享基于技术研究和提升安全意识的目的。我们旨在通过对此漏洞的  
分析，帮助广大安全从业者更好地了解漏洞的成因、存在的风险，以及如何有效进行防范。  
  
    我们在  
此郑重声明，本文的读者应当是出于合法、合规的目的来阅读和使用这些信息。任何未经授权使用  
本文内容对其他系统进行攻击的行为，都与本公众号及作者本人无关。我们强烈谴责任何非法利用  
安全研究的行为，并呼吁所有安全从业者秉持道德和法律准则，共同维护网络安全环境的健康发  
展。  
  
## 0x01 前言  
  
目前UNACMS最新的版本是14.0.0，通杀所有版本。  
  
cms的官方地址仓库：  
```
https://github.com/unacms/una
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BictawU0A1NNibLgiaYRogaECXlDlep9KtWPxTetIcqotgsammh1iaur1Uibohq5jc8JAQ9XHTZoQ7Nwp1oTTUTUtZQ/640?wx_fmt=png&from=appmsg "")  
  
cms官网地址：  
```
https://unacms.com
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BictawU0A1NNibLgiaYRogaECXlDlep9KtWlw6JAlKhchZekPOuvfrAUaw5WCmoCNgUmLYGvgFhKEEAfaB6eZ34tw/640?wx_fmt=png&from=appmsg "")  
  
fofa搜索语法：  
```
body="UNA Community Management System"
```  
  
展示一下poc的效果：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BictawU0A1NNibLgiaYRogaECXlDlep9KtW1xkbXiaM7Wq74KszGw1kUsvuyXNO90UuaJ3s91rh4PzasicncYqAfQMA/640?wx_fmt=png&from=appmsg "")  
  
漏洞细节和漏洞poc在下文中会有介绍。  
  
  
  
  
## 0x02 漏洞描述和细节分析  
  
因为这个cms系统是开源的，所以可以直接从github上面把源码下下来，慢慢分析，github链接在上面有提到，安装搭建的教程可以参考这个：  
  
