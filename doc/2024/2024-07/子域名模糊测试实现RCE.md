#  子域名模糊测试实现RCE   
原创 玲珑安全官方  芳华绝代安全团队   2024-07-27 23:03  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/1AoMVy0KnkqEMU3uEJcVqvr4Qicict0PZaDVUSfyyYDiauwQTMXZ4S6akHCfmKrS3V2gmUv8FvNxyEm3HZaianjyoQ/640?wx_fmt=jpeg "")  
  
正文  
  
在之前测试一个私人项目时，我报告了admin.Target.com上的Auth Bypass漏洞，这将导致  
**SQLI&RCE**  
 ，该漏洞在报告后仅一天就被修复。  
  
现在重拾该应用程序，对子域进行模糊测试：  
```
ffuf -w /subdomain_megalist.txt -u 'https://adminFUZZ.Target.com' -c  -t 350 -mc all  -fs 0
```  
  
使用此命令，我发现了一个目标：  
admintest.Target.com  
  
访问   
https://admintest.Target.com  
，将被重定向至  
https://admintest.Target.com/admin/login.aspx  
  
阅读一些 js 文件，我发现一个端点：  
https://admintest.Target.com/admin/main.aspx  
  
直接在浏览器中打开它会将我们再次重定向到登录页面，但在 Burp 中却存在如下界面：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1AoMVy0KnkrIh3fQ0qEu1KQd5NWoKNMcibtPic75Fy3dWNEicINsXz64FnqzwyVnDIWbLaicyphJjs7SZTmkTOUH3w/640?wx_fmt=png&from=appmsg "")  
  
可以看到，Content-Length数值是非常大的。  
  
通过测试发现，将返回包中的302 Moved Temporarily改为200 OK，删除Location: /admin/Login.aspx?logout=y，删除html重定向代码，即可访问面板。  
  
再通过深入测试，我发现，绕过的不仅仅是前端，因为可以实现如下漏洞。  
  
我发现adduser.aspx端点用于添加管理员，它对应的返回包和main.aspx相似，因此我们能够修改响应包添加管理员帐户。  
  
添加管理员账户后，我们就可以登录了，接着我们找到了一个端点：  
SQLQuery.aspx  
，输入命令：Select * from users，即可看到所有用户的信息，包括密码、电子邮件、用户名：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1AoMVy0KnkrIh3fQ0qEu1KQd5NWoKNMcBNGFjweDKHgGsM5WTcO5pL8gGLpNiaSLpgzWribBEJvD4JibpXwH6LTCg/640?wx_fmt=png&from=appmsg "")  
  
由于数据库是mssql，尝试使用xp_cmdshell将其升级到RCE。  
  
更改配置：  
```
```  
```
SP_CONFIGURE "show advanced options", 1
RECONFIGURE
SP_CONFIGURE "xp_cmdshell", 1
RECONFIGURE
```  
```
```  
  
输入  
xp_cmdshell ‘whoami’  
，效果如下：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1AoMVy0KnkrIh3fQ0qEu1KQd5NWoKNMcttKGjcZpiaH87w5wFJyey9J2PgrwxyIG9Z7JibpkTL0CsSibMD6tcxMsg/640?wx_fmt=png&from=appmsg "")  
  
总结  
  
1、  
**始终检查 burp 中的重定向响应**  
2、如果在子域名中发现了一个 bug，并且已经修复，请尝试  
**子域名模糊测试**  
```
admin-FUZZ.target.com EG：admin-stg.target.com 
FUZZ-admin.target.com EG：cert-admin.target.com 
adminFUZZ.target.com EG：admintest.target.com 
FUZZadmin.target.com   EG：   testadmin.target.com 
admin.FUZZ.target.com EG：admin.dev.target.com
```  
```
ffuf - w / subdomain_megalist.txt - u 'https://adminFUZZ.Target.com'  - c   - t 350  - mc all   - fs 0 

- t 表示线程，不要太高，否则你可能会错过很多正在工作的子线程

- mc all表示匹配所有响应代码，如200、302、403
```  
  
原文出处：  
https://medium.com/@HX007/subdomain-fuzzing-worth-35k-bounty-daebcb56d9bc  
  
SRC漏洞挖掘培训  
  
[玲珑安全第三期如约而至](http://mp.weixin.qq.com/s?__biz=MzI4NTYwMzc5OQ==&mid=2247493447&idx=1&sn=04e4dfd799d0f22f5adfb1a50032d221&chksm=ebeb05ffdc9c8ce9a3d2916634a4fe3480685bf599150c2e128e20faeae4d2ddd0f12f96b630&scene=21#wechat_redirect)  
  
  
[第二期玲珑安全培训班来啦！](http://mp.weixin.qq.com/s?__biz=MzI4NTYwMzc5OQ==&mid=2247491250&idx=1&sn=0a1a522f09c42654a3eb2f314dfedffa&chksm=ebe8fc0adc9f751c60b0fa5c4c15bbc7947de1b50cbb8ecae11b51882a12612323d761e66f1a&scene=21#wechat_redirect)  
  
  
[玲珑安全第一期SRC培训班即将开课！](http://mp.weixin.qq.com/s?__biz=MzI4NTYwMzc5OQ==&mid=2247486139&idx=1&sn=11eb92b27684e41a86d26673ec4747f1&chksm=ebe8e803dc9f6115e18384bd62789bf5c5d1ad7de522faf92ebb52893a8cef4631a0f1459112&scene=21#wechat_redirect)  
  
  
往期漏洞分享  
  
[SSRF：Microsoft Azure API 管理服务](http://mp.weixin.qq.com/s?__biz=MzI4NTYwMzc5OQ==&mid=2247493949&idx=1&sn=e513345eee2ca4705ed9a3cfca6b03af&chksm=ebeb0b85dc9c829375aefdde0f6fa43a2084b145eda565c6d32b22884a224bc5e0c0cbf6a4c7&scene=21#wechat_redirect)  
  
  
[Oracle Apiary：SSRF获取元数据](http://mp.weixin.qq.com/s?__biz=MzI4NTYwMzc5OQ==&mid=2247493814&idx=1&sn=0ba43e7c5369f4b24e39099fa004d27c&chksm=ebeb0a0edc9c83182a2d59baf9835b84b9c5fc7f135ddb1d1696e30afe56fc9f9d9be4be08d0&scene=21#wechat_redirect)  
[SSRF 之 Azure Digital Twins Explorer](http://mp.weixin.qq.com/s?__biz=MzI4NTYwMzc5OQ==&mid=2247493743&idx=1&sn=3f5fe3b6e83d484107da879b18a6bc6d&chksm=ebeb0ad7dc9c83c160483306e2fe33d83877ad46e08257110a09d6b825e8e76e8669d63fdf30&scene=21#wechat_redirect)  
  
  
[1000美元：重定向的故事](http://mp.weixin.qq.com/s?__biz=MzI4NTYwMzc5OQ==&mid=2247493667&idx=1&sn=2683402e747a6f52ac93832b72d241a3&chksm=ebeb0a9bdc9c838de2d8f05ba64fb39913c0b4d9921d3145a261ecaee229da35831b7f589b59&scene=21#wechat_redirect)  
  
  
[XSS之绕过HttpOnly实现帐户接管](http://mp.weixin.qq.com/s?__biz=MzI4NTYwMzc5OQ==&mid=2247493090&idx=1&sn=1ba61d61aec079462e39b136f244f992&chksm=ebeb075adc9c8e4c3c1408e17621b301baf0e48ca9abf79cfba6e1185403adf1d888a3672f1e&scene=21#wechat_redirect)  
  
  
玲珑安全交流群  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1AoMVy0KnkpZicvO5ibxW4XWMntibKWyYrrgWxUAlQrEUWYwibTzoGef3w8UgeSvjSPCQMNzQHe3qw5zFWtHpL86bw/640?wx_fmt=png&from=appmsg "")  
  
玲珑安全B站免费公开课  
  
https://space.bilibili.com/602205041  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1AoMVy0KnkpVjiaTUMYPLzFcLHPRmjJaYgicYcibBOoTyko1d5gcfhxlu6BMmSFKeQMeqsda7jd3yEiaCekfJjrQXg/640?wx_fmt=png&from=appmsg "")  
  
  
