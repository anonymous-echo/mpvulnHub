#  CSRF漏洞   
原创 EBCloud  EBCloud   2024-12-04 08:00  
  
**一、什么是CSRF漏洞**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/7LQTNPfatUDmgiajDzjo4NXTiceySOaCTGRTewiaia9LEebKvJ2zibIG4vhkjMqMVFsY4OAHdazJMxZM50LMjOHQ2GQ/640?wx_fmt=png "")  
  
  
CSRF漏洞允许攻击者在用户不知情的情况下，利用用户在已登录状态下的身份验证信息（如cookie、会话等），向服务器发送恶意请求，从而执行未经用户授权的操作。这些操作可能包括更改密码、删除账户、进行金融交易等，可能导致用户的信息泄露、财产损失或其他不可挽回的后果。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/On3KpSicKJfBkX9sDdcEcFw3NzEHZM2KCvA6G9kgD6E9DZnMGBzZ8o0PprrzZrMLibyFgiaaQKicjSJNk2grnR7J2w/640?wx_fmt=png "")  
  
图片来源于百度  
  
  
  
**二、CSRF漏洞工作原理举例**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/7LQTNPfatUDmgiajDzjo4NXTiceySOaCTGRTewiaia9LEebKvJ2zibIG4vhkjMqMVFsY4OAHdazJMxZM50LMjOHQ2GQ/640?wx_fmt=png "")  
  
  
1、用户登录受信任的A网站，并在浏览器中保持登录状态。此时，用户的身份验证信息（如cookie）会保存在浏览器中。  
  
2、攻击者构建恶意网站B，并在其中嵌入指向A网站的恶意请求。  
  
3、用户访问恶意网站B，或在不知情的情况下点击恶意链接。  
  
4、用户的浏览器在访问恶意网站B时，会携带之前登录A网站时保存的cookie等身份验证信息。  
  
5、恶意网站B利用这些身份验证信息，以用户的身份向A网站发送恶意请求。  
  
6、A网站收到请求后，由于请求中包含了有效的身份验证信息，因此会认为是用户本人发起的请求，并执行相应的操作。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/On3KpSicKJfBkX9sDdcEcFw3NzEHZM2KCJicArsib62mHphH3oyIFV463xZYGe2NFnudqibicKDVzSY4zexyicYp8xOQ/640?wx_fmt=png "")  
  
图片来源于百度  
  
  
  
**三、CSRF漏洞的危害**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/7LQTNPfatUDmgiajDzjo4NXTiceySOaCTGRTewiaia9LEebKvJ2zibIG4vhkjMqMVFsY4OAHdazJMxZM50LMjOHQ2GQ/640?wx_fmt=png "")  
  
  
1、未经授权的数据修改和篡改，如更改用户个人信息、发布恶意内容等。  
  
2、财产操作，如转账、购买商品等，导致用户财产损失。  
  
3、破坏用户数据的一致性，误导用户，降低网站的可信度。、  
  
总而言之，就是攻击者偷取了合法身份，以合法身份发送了恶意请求，在服务器的视角来说该请求是合法请求，但是确达成了攻击者所希望的操作。  
  
  
  
**四、CSRF漏洞的判断方法**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/7LQTNPfatUDmgiajDzjo4NXTiceySOaCTGRTewiaia9LEebKvJ2zibIG4vhkjMqMVFsY4OAHdazJMxZM50LMjOHQ2GQ/640?wx_fmt=png "")  
  
  
**1**  
  
**检查请求参数**  
  
GET类型CSRF的检测：首先尝试去掉请求中的token等验证参数，如果请求仍然成功，那么可能存在CSRF漏洞。接着，尝试去掉referer参数的内容，如果仍然可以成功请求，那么漏洞存在的可能性更大。如果post方式对referer验证特别严格，可以尝试将post请求改写为get请求，看是否能绕过验证。  
  
POST类型CSRF的检测：对于需要POST提交的请求，可以尝试构造一个自动提交的表单，并诱导用户点击。如果表单提交成功，那么可能存在CSRF漏洞。  
  
**2**  
  
**验证Referer字段**  
  
抓取一个正常请求的数据包，去掉Referer字段后再重新提交。如果该提交仍然有效，那么可以基本确定存在CSRF漏洞。  
  
**3**  
  
**确认凭证的有效期**  
  
如果用户的身份验证凭证（如cookie、会话等）在退出或关闭浏览器后仍然有效，或者session没有及时过期，那么可能会导致CSRF攻击。  
  
  
  
**五、CSRF漏洞的防护**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/7LQTNPfatUDmgiajDzjo4NXTiceySOaCTGRTewiaia9LEebKvJ2zibIG4vhkjMqMVFsY4OAHdazJMxZM50LMjOHQ2GQ/640?wx_fmt=png "")  
  
  
**1**  
  
**实施CSRF Token机制**  
  
为每个用户会话生成唯一的CSRF Token，并在每个敏感请求中验证该Token的有效性，将CSRF Token存储在服务器端，确保每次会话开始时更新，并在会话结束时过期。  
  
**2**  
  
**强化请求来源验证**  
  
虽然Referer字段可以被伪造，但可以作为辅助手段，检查请求是否来自受信任的源，同时可以利用浏览器的SameSite Cookie属性，限制Cookie在跨站请求中的使用，增强安全性。  
  
**3**  
  
**采用额外安全层**  
  
在关键操作（如转账、密码修改）时，要求用户输入验证码，增加攻击难度、避免使用GET请求进行敏感操作，使用POST或其他更安全的HTTP方法、提升用户对CSRF攻击等网络安全问题的认识，教育用户不要随便点击不明链接。  
  
  
  
**-END-**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/On3KpSicKJfBkX9sDdcEcFw3NzEHZM2KCFibo3NhiazdNhXSoBvboNAFbuYD02IgFcwWnVzRJWClGjQA3eES01GLA/640?wx_fmt=jpeg "")  
  
**文章作者**  
  
**郭民晟**  
  
