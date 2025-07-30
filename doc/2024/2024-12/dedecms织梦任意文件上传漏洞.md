#  dedecms织梦任意文件上传漏洞   
 雾鸣安全   2024-12-24 06:37  
  
雾鸣Team  
  
  
**CNMistSafety**  
  
  
  
漏洞类型：通用型  
  
漏洞版本：≤ V5.7.116  
  
dedecms织梦任意文件上传  
  
1、独家秘制文件环境：  
  
uploads.txt,uploads.html,uploads.php  
  
  
2、文件介绍：  
  
uploads.txt放置需要的危险函数。  
  
uploads.html内容大概意思就是绕过限制危险函数。具体参考file_manage_control  
.  
php文件，基本全局都是这个吊样。  
  
uploads.php内容是辅助uploads.html上传页面的后端，包括调用uploads.txt文件。  
  
  
3、功能使用：  
  
分别将秘制文件上传到文件管理器跟目录。就会得到一个自定义的上传页面，然后根据自定义的上传页面进行任意文件上传（直接跳过危险函数限制）。我这里是使用冰蝎lxmtools.php进行getshell测试。测试下来一波，文件管理器是一点脾气都不敢有。  
  
  
更多漏洞更新请查看：https://lixiaoming.net  
  
  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/bQv07rEoSgnASDXC53WkoCVAbC73AzGr2gJ1hkgmLJf47DcQBvKhS65n8gFR9Rfr2aeIbyMIbxguySA37OaCNA/640?wx_fmt=gif "")  
  
  
                             
  
《中华人民共和国网络安全法》  
  
《本文章仅供学习参考，请勿进行违法操作》  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/oYEjKAbwRS6xWic07knBw6a8TWtHe81ZSSYMicq8FZrMs0gbHqibHXN1PzHXSrE6LrSmH03cAWblCQibnZmOibIlzqw/640?wx_fmt=png "")  
  
©2024-雾鸣Team  
  
  
  
