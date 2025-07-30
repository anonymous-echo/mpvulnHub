#  漏洞案例：提升Self-XSS危害   
原创 玲珑安全  芳华绝代安全团队   2024-10-11 22:47  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1AoMVy0KnkqaXglicqFIVS5OgBzr7tkvR1Awes6RbHS27L144QMPEl5FPgBicWPWMt4xzB8DcuBTyRgNxOz2nRiag/640?wx_fmt=png&from=appmsg "")  
  
  
Self-XSS利用1  
  
目标应用程序为某在线商店，在其注册页面的First Name字段中注入XSS Payload：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1AoMVy0KnkqaXglicqFIVS5OgBzr7tkvR1E25liaZhTyTvcgN6WjzOI0qYOWhdQr5yjJ8YicWRiaiabwJR3OnAsd7lg/640?wx_fmt=png&from=appmsg "")  
  
注册成功，但当我尝试登录我的帐户时，界面显示403 Forbidden，即无法登录我的帐户。  
  
  
我很好奇为什么我无法登录我的帐户，所以我打开了 Burp 并拦截了登录请求，以查看为什么会收到403 Forbidden。我发现客户端向服务器发送了两个请求。  
  
  
第一个请求中包含我的用户名和密码：  
  
POST /login HTTP/2Host：www.example.com  
  
loginID=attacker@gmail.com&password=xxx  
  
  
其返回包为200 OK，返回体中包含我的个人信息，如FirstName、lastName、UID等等。  
  
  
第二个请求中包含我的个人信息：  
  
POST /login HTTP/2  
Host: www.example.com  
  
Data={"eventName":"login","remember":false,"UID":"9046b58424b84429ab2d5b811baer3xc","eventName":"login","remember":false,"UID":"9046b58424b84429ab2d5b811baer3xc","profile":{"firstName":"<svg+Only=1+onload=alert(1)>","lastName":"sssss","email":"attacker@gmail.com","zip":"55551"},"data":{"phoneNumber":"2111443343","smsOptin":false,"dateOfBirth":"11/11/1999","emailOptin":true}}  
  
  
也许服务器在针对第二个请求的处理上存在WAF，所以firstName可能是问题所在。  
  
  
因此我删除了firstName字段，不出所料，我成功登录了我的账户，并实现了Self-XSS：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1AoMVy0KnkqaXglicqFIVS5OgBzr7tkvRe8rsRm3D2sYmvuPYDLHBhIKUVOeGO9t6ev5wZ9gsRe9Dkw3Ok1kx1g/640?wx_fmt=png&from=appmsg "")  
  
  
我尝试通过缓存中毒或缓存欺骗来实现真实的XSS危害，但无功而返。  
  
  
接着，我进入账户设置，将我的电子邮箱改为xx@gmail.com：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1AoMVy0KnkqaXglicqFIVS5OgBzr7tkvRzoDvg5lmGeZjE2jYA7FPNR6YlRn30PeyiaicAMzhBjTJPzC4msNJ1jWQ/640?wx_fmt=png&from=appmsg "")  
  
  
更改后，我收到了一份邮件，通知我的个人信息已更改：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1AoMVy0KnkqaXglicqFIVS5OgBzr7tkvR36xzHMz0vhZzzz1R2WHgl9J3wiaiaBypTDQWsLvQh5OKZy4NRWOwvDCQ/640?wx_fmt=png&from=appmsg "")  
  
点击View web version，  
触发XSS Payload。  
  
  
Self-XSS利用2  
  
接下来是另一个Self-XSS的利用过程。  
  
  
来到目标应用程序的支持中心：  
https://example.com/contact?submitted=false  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1AoMVy0KnkqaXglicqFIVS5OgBzr7tkvRPuVmehIzM9dBF79cSfiaicLUTO51wJChBaOqKMSZdCk99afTYeOZcSoA/640?wx_fmt=png&from=appmsg "")  
  
  
我在每个字段中都注入XSS Payload，接着提交表单。接着我被重定向至感谢页面  
https://example.com/contact?submitted=true：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1AoMVy0KnkqaXglicqFIVS5OgBzr7tkvRVibLPs2BdN2BLtIIqvZNopLDJ5wTLNicWgjh07Xe4Jd4Ok7UAqBXgU8g/640?wx_fmt=png&from=appmsg "")  
  
这里并没有预期的结果发生，但引起我注意的是参数?submitted=，在提交表单之前，它的值是false，而在提交表单之后，它的值变成了true。  
  
  
所以我决定重新访问https://example.com/contact?submitted=false，如图，成功实现Self-XSS：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1AoMVy0KnkqaXglicqFIVS5OgBzr7tkvROU32r8SGrwgqkAjN9pxMhjSfo2ufpezoVQ0mK5GIxick1P5bEtrZ4UQ/640?wx_fmt=png&from=appmsg "")  
  
  
这个Self-XSS 需要太多步骤才能复现，要实现步骤的简化，我们就需要找到一种方法，避免提交后被重定向。  
  
  
一段时间后，我发现在任何字段中输入任何错误的内容，例如在Phone Number字段中输入 LingLongSec 然后提交表单，便可直接实现Self-XSS，而不发生重定向。  
  
  
那么如何实现真实的危害呢？在提交表单时，我拦截了请求，再将该POST请求修改为GET请求，我发现服务器能够正确解析该请求，现在只需将一些参数置空即可：  
  
https://example.com/contact?projectTypes=Other&projectTypes=e"><img+src=x+onerror=alert(1)>&default-method=contactMe&FirstName=&LastName=&Email=&PhoneNumber=&CallTime=  
  
  
原文出处：https://medium.com/@7odamoo/how-could-self-xss-end-with-b8342555cf3e  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1AoMVy0KnkpEuBuEsIpO3r2Z8o3AOdYGNxAsWtFVRysGrjibbuykQOrPiaEQsJibz4hrHIUBHVsq2MZG6VfHoy6bw/640?wx_fmt=png&from=appmsg "")  
  
****  
**培训咨询v**  
  
bc52013 或  linglongsec****  
  
****  
****  
**SRC漏洞挖掘培训**  
  
****  
玲珑安全第一期SRC漏洞挖掘培训  
  
  
玲珑安全第二期SRC漏洞挖掘培训  
  
  
玲珑安全第三期SRC漏洞挖掘培训  
  
  
玲珑安全第四期SRC漏洞挖掘培训  
  
****  
****  
**往期漏洞分享**  
  
****  
账户安全随笔  
  
  
利用XSS、OAuth配置错误实现token窃取及账户接管  
  
  
更改参数实现试用计划延长  
  
  
2300$：分享4个高危业务逻辑漏洞  
  
  
CR/LF注入+Race Condition绕过MFA  
  
  
‍图片元数据不适当处理+大小写绕过速率限制‍  
  
  
破解邀请码实现未授权访问和账户接管  
  
  
[子域名模糊测试实现RCE](http://mp.weixin.qq.com/s?__biz=MzI4NTYwMzc5OQ==&mid=2247494424&idx=1&sn=c29423df3626026c4d87ea402cfc7b5f&chksm=ebeb09a0dc9c80b692dc7fe9822488e3d5a2a9e7a78425d2b022b6665eacba94a6b5ffb8caf5&scene=21#wechat_redirect)  
  
  
  
通过导入功能将权限提升至管理员  
  
  
  
**玲珑安全B站公开课**  
  
https://space.bilibili.com/602205041  
  
  
  
**玲珑安全QQ群**  
  
191400300  
  
  
  
**玲珑安全交流群**  
  
****  
****  
  
