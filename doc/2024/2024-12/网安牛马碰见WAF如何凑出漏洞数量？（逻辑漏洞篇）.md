#  网安牛马碰见WAF如何凑出漏洞数量？（逻辑漏洞篇）   
 进击的HACK   2024-12-04 23:55  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/mpLzTQpY3UPtVrmHAzibGGgNhzn4kWpYuibzqibZty56icKugFQOibSpOeJ86aqg7y9RAWwT9GLSXURgibyX2ELDO4Kg/640?wx_fmt=gif&wxfrom=5&wx_lazy=1&tp=webp "")  
  
前言  
  
  
  
前些天写了那个凑数量的漏洞文章，貌似效果不错......  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/wglPJSKsjauZLsiaVcRFWcOWX8QNeRbDSOzcT0cGgOq0aCMUEW8NOLgeW0dxDT8NEpLcKPF6rQxsCnAXqaJfhWg/640?wx_fmt=jpeg&from=appmsg "")  
  
  
当初熊猫刚入行的时候，新接个渗透项目，起手就是awvs、sqlmap、xray、appscan、owaspzap等等的一系列扫描器莽怼，碰碰运气，结果惨败在waf拦截之下......  
  
![](https://mmbiz.qpic.cn/mmbiz_png/wglPJSKsjavoyGmvuY6d35pDtu8W91dAyfbSVFESsdAGUjO1lvP3bDlxOJPrmlH13PlQZanNWYhsiaRiaelBibePg/640?wx_fmt=png&from=appmsg "")  
  
对于小白来说，工具就是第二生命呀，用都用不上了怎么渗透？  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/wglPJSKsjavoyGmvuY6d35pDtu8W91dAJdEic0wn0T3YrgicExyicDynhdwtib0S0meE8cVrmL06QjAEntT32j852Q/640?wx_fmt=jpeg&from=appmsg "")  
  
有WAF拦截，基本限制了包含特殊字符POC的报文，那渗透报告眼瞅着就要交付了，总不能写个空报告交差吧......  
  
![](https://mmbiz.qpic.cn/mmbiz_png/wglPJSKsjavoyGmvuY6d35pDtu8W91dAaKdpkSdNBI5lAsAV8PSV37ibymcAcEvvibXKcSnicMmYLErKJE1QVCQ4A/640?wx_fmt=png&from=appmsg "")  
  
那肯定是不可以的，上上上期没写逻辑漏洞，今天熊猫就简单说一说逻辑漏洞都有哪些可以凑凑数量（当然，熊猫这些漏洞用来打SRC也很好用![](https://res.wx.qq.com/t/wx_fed/we-emoji/res/assets/newemoji/Yellowdog.png "")  
![](https://res.wx.qq.com/t/wx_fed/we-emoji/res/assets/newemoji/Yellowdog.png "")  
![](https://res.wx.qq.com/t/wx_fed/we-emoji/res/assets/newemoji/2_06.png "")  
![](https://res.wx.qq.com/t/wx_fed/we-emoji/res/assets/newemoji/2_06.png "")  
）~~~  
> 上上上期文章戳这里  
  
> 熊猫，公众号：吐槽网安的熊猫[网安牛马碰见WAF如何凑出渗透报告漏洞数量？](https://mp.weixin.qq.com/s/QqF1pnsX8KLnIpaT05VwdQ?token=1693450083&lang=zh_CN)  
  
  
  
说实话逻辑漏洞这玩意是个随缘枪法，能不能一杆进洞主要看运气和手感，也没个特别固定的模版，所以大家就领会精神即可![](https://res.wx.qq.com/t/wx_fed/we-emoji/res/assets/newemoji/Yellowdog.png "")  
![](https://res.wx.qq.com/t/wx_fed/we-emoji/res/assets/newemoji/Yellowdog.png "")  
。  
  
**WARN**  
  
**提前说明一下：**  
  
**本文章涉及逻辑漏洞主要是提供思路，所有涉及工具只用于安全测试自用，请勿对任何网站进行入侵攻击，小日子的除外......**  
  
  
**愿兄弟们看完文章之后**  
  
**划水越来越多，挖洞越来越丝滑**  
  
**注：本期只发逻辑漏洞，后续会再出一些特殊RCE单独再发一篇文章**  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/wglPJSKsjas9Zl6kQBYfgicUibC6CRGPg26qToz9ts0NJic0of6uibrMGZheo9pf9ZlKR90picqzMG9NRmic3Vtz9QsA/640?wx_fmt=gif&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1 "")  
  
**1.并发短信、邮件轰炸**  
  
漏洞场景：  
  
发现网站存在短信、邮件发送接口，通常在登录、注册、密码找回位置。  
  
漏洞复现：  
  
通过利用BurpSuite或者其它抓包截断工具，抓取发送验证码的数据包，并且进行重放攻击，如重放有过滤就尝试python脚本并发尝试。  
```
注意：
  1.BurpSuite的Repeater重放不能完整的测试出轰炸漏洞；
  2.BurpSuite的Intruder批量发送也不是Fuzz的唯一方式。
```  
  
复现截图：  
  
大家都知道的熊猫就不说了，讲下并发、绕过，切记！！  
BurpSuite的Intruder  
并不是并发，而是有顺序的重放。  
  
**并发轰炸**  
  
  
  
  
**方法1-并发**  
  
先讲讲比较高效的并发测试方式  
```
先本地下载一个BurpSuite并发插件：
https://github.com/PortSwigger/turbo-intruder/releases/tag/1.0.19
```  
  
本地导入插件  
  
![](https://mmbiz.qpic.cn/mmbiz_png/wglPJSKsjat4UMkRov457nDHFgFROMK8VRSKx6eMm0UDibhZs9UfuwuE6hOlBOMYTjdibjHwkRIHGdWttkyibMmSA/640?wx_fmt=png&from=appmsg "")  
  
找到要进行轰炸的接口报文，爆破位置添加%s（没有参数任意位置添加即可）  
  
![](https://mmbiz.qpic.cn/mmbiz_png/wglPJSKsjat4UMkRov457nDHFgFROMK8yhPoH445q0HV7bAJTiayicoS3A8HXy5HdSDQoLJ9ib7YW2G1G8muOuGhQ/640?wx_fmt=png&from=appmsg "")  
  
选择插件  
  
![](https://mmbiz.qpic.cn/mmbiz_png/wglPJSKsjat4UMkRov457nDHFgFROMK8VVMlxzYOtbhx2ZkHhibbWArvTDo4nLCpfrPVBVmoMzicViar7JP16VWpw/640?wx_fmt=png&from=appmsg "")  
  
选择脚本为race.py  
```
这里执行30次（想改就改）
concurrentConnections=30 并发连接数, 默认就好
requestsPerConnection=100 并发连接请求数
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/wglPJSKsjat4UMkRov457nDHFgFROMK81NWvoPPverPCxQrKN3YBv0Xt5ocGLMVKoQqSaRyauWOxrEickasXXZw/640?wx_fmt=png&from=appmsg "")  
  
点击攻击  
  
![](https://mmbiz.qpic.cn/mmbiz_png/wglPJSKsjat4UMkRov457nDHFgFROMK8YGVIfUMibd5sM80iaOeIq7qlABo2Zq8s6JeNQibWkKn6WXwSKyWwbxubw/640?wx_fmt=png&from=appmsg "")  
  
  
     搞定收工![](https://res.wx.qq.com/t/wx_fed/we-emoji/res/assets/newemoji/Yellowdog.png "")  
![](https://res.wx.qq.com/t/wx_fed/we-emoji/res/assets/newemoji/Yellowdog.png "")  
![](https://res.wx.qq.com/t/wx_fed/we-emoji/res/assets/newemoji/Yellowdog.png "")  
~~~~~  
  
  
**绕过轰炸**  
  
  
  
  
**方法2-绕过**  
  
再讲讲常见的绕过过滤进行轰炸方式  
  
1、在前方后面加如下字符：  
```
%86、%00、加空格、+86、0086、86、086、0、/r，/n......
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/wglPJSKsjat4UMkRov457nDHFgFROMK8jfaXGu3QoDSkFn7FjNZZcsJhnA2jJ8pvNHWorjCiaqXTMiagvH95fKDQ/640?wx_fmt=png&from=appmsg "")  
  
2、进行能解析编码，如手机号前加%3编码url编码比如我的号码是17801234567，可以把手机号编为%31%37%38%301234567这个%3在手机号里面随便放（挺有用）；  
  
![](https://mmbiz.qpic.cn/mmbiz_png/wglPJSKsjat4UMkRov457nDHFgFROMK8RYGCftEwXajv5CBZKZwdWq5pI000bzxsvric7w8jsnO5GfpJjiaKJQ1w/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/wglPJSKsjat4UMkRov457nDHFgFROMK8mVtxibicGlcCSvic8iaC8IAzT1n60PmQp7z8JrNqY2s1QIpaUoNIC73WKQ/640?wx_fmt=png&from=appmsg "")  
  
3、修改返回值绕过短信&邮箱轰炸限制如果是前端验证后发送验证码，就可以通过修改返回值；  
  
4、加垃圾字符在前面或者后面加xiongmaozhenshuai；  
  
5、双写绕过但是这里双写不是为了两个手机号收到同一条短信，而是为了能够继续发送验证码。例如：使用phone=1&phone=1绕过、phone=1,1绕过等思路；  
  
6、修改ip绕过有些同样是验证当前IP的，如果当前ip短时间内获取短信或者邮件达到一定次数就会限制，那么就可以修改ip或者使用代理ip来轰炸  
  
......太多了，就不一一说了，有缘者随机试试即可......  
  
  
**2.支付四舍五入漏洞**  
  
漏洞场景：  
  
涉及支付功能。  
  
漏洞复现：  
  
我  
们用  
余额充值为例，余额都是保留到分(也就是0.00)当然有些区块链的网站可能会更精确  
。  
  
如果我们充值0.001会怎么样呢？  
  
![](https://mmbiz.qpic.cn/mmbiz_png/wglPJSKsjat4UMkRov457nDHFgFROMK8FELjibFia99u7yIYnPj0BHv53CRhs9gQVG6GNTQCYm2kMn1dtNWFXDEA/640?wx_fmt=png&from=appmsg "")  
  
那么开发一般会前端判断我们输入的数字，或者直接把后一位四舍五入了。  
  
复现截图：  
  
举例：先充值0.001  
  
![](https://mmbiz.qpic.cn/mmbiz_png/wglPJSKsjat4UMkRov457nDHFgFROMK8Q1ib4856xdLH4RibHZFMAbfpoQSRUBdzictvHx9sTDVZqWCDHEltJoIqA/640?wx_fmt=png&from=appmsg "")  
  
支付宝直接报错，因为第三方支付是只能充值到分的  
  
![](https://mmbiz.qpic.cn/mmbiz_png/wglPJSKsjat4UMkRov457nDHFgFROMK89ibyV8yoLw4keVtF0UicfPSJPmhTytT7nGN42CT2d4Zreic3ugn5diaj2A/640?wx_fmt=png&from=appmsg "")  
  
继续尝试：尝试一下充值  
0.019  
  
![](https://mmbiz.qpic.cn/mmbiz_png/wglPJSKsjat4UMkRov457nDHFgFROMK8p13fWcUTL5nD5ngeG5Z9fwibicBQiaNctk1EXuh9xk3rqYryFrsuUYVuQ/640?wx_fmt=png&from=appmsg "")  
  
充值成功~~~美滋滋![](https://res.wx.qq.com/t/wx_fed/we-emoji/res/assets/newemoji/Yellowdog.png "")  
![](https://res.wx.qq.com/t/wx_fed/we-emoji/res/assets/newemoji/Yellowdog.png "")  
![](https://res.wx.qq.com/t/wx_fed/we-emoji/res/assets/newemoji/Yellowdog.png "")  
~~~  
  
![](https://mmbiz.qpic.cn/mmbiz_png/wglPJSKsjat4UMkRov457nDHFgFROMK866TpiasWZT0N6cSyrTBF0nDESqJ9gCluTb7brDZw0iciaCbPU6Mqqz7UQ/640?wx_fmt=png&from=appmsg "")  
  
**3.API未授权漏洞**  
  
漏洞场景：  
  
发现网站Swagger接口泄露、或者接口很多很随意。  
  
漏洞复现：  
  
这个漏洞基本就是工具开扫就完事了，通过API扫描工具或者本地BurpSuite用熊猫的这个字典来扫描，然后慢慢等就完事了。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/wglPJSKsjat4UMkRov457nDHFgFROMK8S2gotnAJWhbvgeqhdtsX2TGbbPgyyTa6KHxShoqobvjMwAqohq1C7g/640?wx_fmt=png&from=appmsg "")  
  
然后自  
高向低筛选  
返回长度。  
  
有可能这个时候就会扫描到各种乱七八糟的信息泄露![](https://res.wx.qq.com/t/wx_fed/we-emoji/res/assets/newemoji/Yellowdog.png "")  
![](https://res.wx.qq.com/t/wx_fed/we-emoji/res/assets/newemoji/Yellowdog.png "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/wglPJSKsjat4UMkRov457nDHFgFROMK8ulkUleNoIAzpyoVG6TUib6vrBjibA3Z3IgImvFov8IrX8euib7ia6AfxMg/640?wx_fmt=png&from=appmsg "")  
  
美滋滋~~~  
  
工具分享：  
```
Swagger-hack工具：
下载链接：https://github.com/jayus0821/swagger-hack
使用命令：python3 swagger-hack2.0.py -u ip地址
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/wglPJSKsjat4UMkRov457nDHFgFROMK87V0iaNonG0KZ4Ovfmzb1h2E3DQS4XDM6icQqrZxhLCV0VqiaGiaU66sqVA/640?wx_fmt=png&from=appmsg "")  
```
spring-boot漏洞扫描工具：
下载链接：https://github.com/AabyssZG/SpringBoot-Scan
使用命令：python SpringBoot-Scan.py -u url
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/wglPJSKsjat4UMkRov457nDHFgFROMK8RvmsPc8t1HhFRwbOib0HQk5BtRfj88oKOSuEiaqRUngLd5uq3zOSreOQ/640?wx_fmt=png&from=appmsg "")  
  
除此之外js中也会包含API信息（划重点），比如：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/wglPJSKsjat4UMkRov457nDHFgFROMK8529sFD2qanBqlDWWC06TmdYzjjyicqjNcUO96rAvd0MD6p1JGrGCblA/640?wx_fmt=png&from=appmsg "")  
  
复现截图：  
  
API搞到了之后就可以去构造数据包，比如：  
  
/manage/cas/doLogin?userToken=【拼接用户ID】  
  
![](https://mmbiz.qpic.cn/mmbiz_png/wglPJSKsjat4UMkRov457nDHFgFROMK8ATPQ7zcRQzxZ5pCEnJxqcX6oibYb1b30Dfb1QPIzT9ficfNcQdLsa22w/640?wx_fmt=png&from=appmsg "")  
  
再比如：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/wglPJSKsjat4UMkRov457nDHFgFROMK8GU0uU9LkFnVdGGdopzZQDpybvwWl8g3s7OibibAWAddGnnjOBrCrSic5Q/640?wx_fmt=png&from=appmsg "")  
  
GET访问不通，使用POST拼接字符  
  
![](https://mmbiz.qpic.cn/mmbiz_png/wglPJSKsjat4UMkRov457nDHFgFROMK8ctDssib3ovSMGibb4OiaPzFCOEMHYfZ2ldXIXx0GnPsWCswO8j3DScVmA/640?wx_fmt=png&from=appmsg "")  
  
搞定收工~~~~  
  
**4.并发创建（限制绕过）**  
  
漏洞场景：  
  
切记！！！万物皆可并发~~干就完了![](https://res.wx.qq.com/t/wx_fed/we-emoji/res/assets/newemoji/Yellowdog.png "")  
![](https://res.wx.qq.com/t/wx_fed/we-emoji/res/assets/newemoji/Yellowdog.png "")  
，并发使用场景多得很，兄弟们可以凭感觉莽怼。  
  
漏洞复现：  
  
点击创建之后抓包，使用上面分享的那个BurpSuite插件做并发创建处理。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/wglPJSKsjat9m6CKxE20I0ML2uibrprG5epcsf4RdujIFrWQFFjjXvKcLj3jg5GeN10skohqQfj3LETF4c5MXxQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/wglPJSKsjat9m6CKxE20I0ML2uibrprG5fgibkrKCUeqVzUMm3XCr6ic9unP1BnMm1cIeD1u6WKZ5sicd387tsE4Qg/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/wglPJSKsjat9m6CKxE20I0ML2uibrprG5LuofibZK1ialMB5cwvbbuB1myazZFRzGribI6s2Gyeckzes7D1AzaSXXQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/wglPJSKsjat9m6CKxE20I0ML2uibrprG5miaia1kPxicy8dpX6Tib2e4SRIGfmZC25RibBSicMyPETcd8dcHcvAXueBjg/640?wx_fmt=png&from=appmsg "")  
  
复现截图：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/wglPJSKsjat9m6CKxE20I0ML2uibrprG5MLzia1SibR8cyzKsc1iabY1icsI3jYm4zeeMv7UssmTK4ftAISuoSvLD5A/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/wglPJSKsjat9m6CKxE20I0ML2uibrprG5HCvtYJOb7TOj783qJsKiaKWXlAavibRGCo3z1VicAQHwe6MO84MTzIUHQ/640?wx_fmt=png&from=appmsg "")  
  
搞定收工~~~~  
  
**5.认证资源无限调用**  
  
漏洞场景：  
  
存在实名认证、手机号认证位置功能。  
  
漏洞复现：  
  
这个名字是熊猫随便起的，大家领会精神即可~~~  
  
所谓认证资源无限调用，就是网安牛马可以无限调用一些实名认证或者身份核实接口，实现暴力猜解用户个人部分身份信息的行为，上案例！！！  
  
我们通常会碰到B端的身份认证功能界面为这样：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/wglPJSKsjat9m6CKxE20I0ML2uibrprG59kfJTyyGGV4BULFqibhCMIuiaoQqDrIyObl7zyzRUmU6nOlIXagJpqRA/640?wx_fmt=png&from=appmsg "")  
  
前端提交数据，传递至后端，如果数据正确返回：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/wglPJSKsjat9m6CKxE20I0ML2uibrprG5QQrMYiawHBDv6HhcQAA1tzq5qfchlicgBB6CCVv0yetcauwtxk4BEDRw/640?wx_fmt=png&from=appmsg "")  
  
如果数据错误则返回：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/wglPJSKsjat9m6CKxE20I0ML2uibrprG54oxUQJZlk4U0H4WPkwiax3LMESyhvq2iaXJW4qYIj0AyNIkkhSwkkSOQ/640?wx_fmt=png&from=appmsg "")  
  
那我们假设你知道熊猫的名字，知道了熊猫的生日，知道了熊猫的家庭地址，是不是可以通过这个功能猜到熊猫的身份证后4位呢？  
  
![](https://mmbiz.qpic.cn/mmbiz_png/wglPJSKsjat9m6CKxE20I0ML2uibrprG56XuCUIzpQxgGoaDmc1QbNrMQHfGVhGu8fpWJtK1oeib2Hgm3cJtia49g/640?wx_fmt=png&from=appmsg "")  
  
所以我们可以把熊猫的姓名、身份证号前几位输入，然后把后4位或后6位进行爆破，赶紧试试~~~  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/wglPJSKsjat9m6CKxE20I0ML2uibrprG5hnrqNjpckHAHImYTKx3u5RahVClAbyLz8Aoce0hrXOszOiajOn53ftg/640?wx_fmt=jpeg&from=appmsg "")  
  
  
复现截图：  
  
****  
爆破成功~~美滋滋~~~  
  
**6.会话注销失效**  
  
漏洞场景：  
  
莽怼。  
  
漏洞复现：  
  
通过手动点击注销登录之后使用注销的token继续尝试增删改查。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/wglPJSKsjat4UMkRov457nDHFgFROMK8czcuZQXmib0jllfGeiactYlF08AlRY4kI5XGEMT6WS37DdS8whCuiajTQ/640?wx_fmt=png&from=appmsg "")  
  
复现截图：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/wglPJSKsjat4UMkRov457nDHFgFROMK8aLRYHyF04Y6c0iaXAXBKd8GnSUdVeJcia6iaN32EyBiapgBzhwPkQA62sQ/640?wx_fmt=png&from=appmsg "")  
  
**7.会话固定**  
  
漏洞场景：  
  
莽怼。  
  
漏洞复现：  
  
登录前后对比token即可，  
会话一致则存在漏洞，会话不一致则不存在。  
  
复现截图：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/wglPJSKsjat4UMkRov457nDHFgFROMK81nlo7JrjicPFpsd1CvzmZgjIFdXRMNMRibibFLfjo1lu63ubI0n3ibl8Yg/640?wx_fmt=png&from=appmsg "")  
  
  
**5.COOKIE假冒测试（越权漏洞）**  
  
漏洞场景：  
  
莽怼。  
  
漏洞复现：  
  
准备高低权限账户，分别登录并记录token。  
```
管理员token：******管理员******
用户token：******用户******
```  
  
使用低权限token对管理员token进行操作，查看是否可以增删改查，如可以则存在漏洞。  
  
复现截图：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/wglPJSKsjat4UMkRov457nDHFgFROMK8W3bszmmFVJia1wJz3qaXkszfOibiaPxgpRz9ze27pmurKgRPXYoFuFDoQ/640?wx_fmt=png&from=appmsg "")  
  
  
**8.多点认证缺陷**  
  
漏洞场景：  
  
莽怼。  
  
漏洞复现：  
  
本地使用两个浏览器，比如火狐和谷歌，使用相同账户分别登录测试网站，使用任意浏览器内对数据进行增删改查，另一个浏览器刷新查看操作是否成功，如成功，则存在该漏洞。  
  
复现截图：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/wglPJSKsjat4UMkRov457nDHFgFROMK8yHynibxDTZRVIQTUjSRVdUlic6r0sDe7KLWChpptbPvtQ9mTJSibxztxA/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/wglPJSKsjat4UMkRov457nDHFgFROMK8BUNfa50VGVDZia8z5FJUBNyg5kSTb7lgfSpZSzD05zjrAiazz1l1LzTA/640?wx_fmt=png&from=appmsg "")  
  
  
**9.响应报文修改漏洞**  
  
漏洞场景：  
  
所有的结果判定功能点，比如，密码修改是否成功、登录是否成功、是否认证成功、是否下载成功......  
  
漏洞复现：  
  
这个漏洞就全凭感觉和经验了，熊猫只做常规案例分享了。  
  
举例，短信登录位置：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/wglPJSKsjat9m6CKxE20I0ML2uibrprG542ExibXTJ9edWhFImhkUW4HATocMr7juDicwVMibsfHoch7clia4sWepMA/640?wx_fmt=png&from=appmsg "")  
  
随意输入手机号，抓取响应包~~~  
  
![](https://mmbiz.qpic.cn/mmbiz_png/wglPJSKsjat9m6CKxE20I0ML2uibrprG5KsDanZyEDgonPluRYC0djWRkQdIbfxibd81Nvw069lFib07KyvKPxCNw/640?wx_fmt=png&from=appmsg "")  
  
修改false为true尝试  
  
复现截图：  
![](https://mmbiz.qpic.cn/mmbiz_png/wglPJSKsjat9m6CKxE20I0ML2uibrprG5SVRBOeVtj9VLcQWicP1OLnjWBiatuCwyS1XUuboyHRGX2MpDdjnnQFwg/640?wx_fmt=png&from=appmsg "")  
  
  
**10.JS文件溯源**  
  
漏洞场景：  
  
上面的API漏洞说了，js文件其实很重要.......  
  
前些日子熊猫审核公司SRC漏洞时收到个云控制台接管漏洞![](https://res.wx.qq.com/t/wx_fed/we-emoji/res/assets/newemoji/Terror.png "")  
![](https://res.wx.qq.com/t/wx_fed/we-emoji/res/assets/newemoji/Terror.png "")  
！  
  
![](https://mmbiz.qpic.cn/mmbiz_png/wglPJSKsjat9m6CKxE20I0ML2uibrprG5qJMCWAwX8lgxich24O9RO0SDWE5W3xM55XmpJe3icMcDLQoWEu31AQ3g/640?wx_fmt=png&from=appmsg "")  
  
尼玛，吓得菊花一紧！！  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/wglPJSKsjat9m6CKxE20I0ML2uibrprG5vibWLZTLgdvNdgLJUYqibRru372yrzgLz47ic14ok9nyLLS8HcnkbC2GA/640?wx_fmt=jpeg&from=appmsg "")  
  
仔细溯源发现是一个外包项目，立项阶段都是正常安全评审，漏洞修复，安全产品部署，这个项目运行半年后，一些配置需要修改，但是外包的开发人员离职了，临时找了个其他人来顶，因为需求着急，外包远程操作开发在使用webpack工具打包前端项目时，使用dev开发环境，带出配置信息，js里面携带了：  
  
SecretId、SecretKey......  
  
![](https://mmbiz.qpic.cn/mmbiz_png/wglPJSKsjat9m6CKxE20I0ML2uibrprG5xcIHejG4jM5yuQ64YIRMjuPl9eZFfd1sFFPJHRuBA2ktJW1OibR9KpA/640?wx_fmt=png&from=appmsg "")  
  
白帽子拿到了key之后就cf接管创建了个云子账户.......  
  
所以切记！！！js里面有宝藏~~~  
  
漏洞复现：  
  
简单分享个案例，如下是某个edu系统的前端js审核结果  
  
![](https://mmbiz.qpic.cn/mmbiz_png/wglPJSKsjat9m6CKxE20I0ML2uibrprG5C2JflmM5rEicIVzWlDcksJDnyILaMAcEHdKia1f4vA9iaf6wBQ0ficUjhw/640?wx_fmt=png&from=appmsg "")  
  
可以  
发现有个数  
据判定接口（get方法构造请求，post传输参数），如不是很了解推荐可以了解一下ajax~~  
  
复现截图：  
  
剩下就简单了，浏览器hackbar开始盲怼~~  
  
![](https://mmbiz.qpic.cn/mmbiz_png/wglPJSKsjat9m6CKxE20I0ML2uibrprG5hLkG0nnfaNFTcSlGMwUuM9JzFQAt216FPcctzkguUqkYD1vw9X6OGg/640?wx_fmt=png&from=appmsg "")  
  
没想到报错爆出另一个参数，然后构造语法开始对管理员密码重置  
  
![](https://mmbiz.qpic.cn/mmbiz_png/wglPJSKsjat9m6CKxE20I0ML2uibrprG5Ocwa0Otc9OLr7zrmjIFGqpocj0WSQrTdZ3hibWEMj2Ia1BOYfR76qKQ/640?wx_fmt=png&from=appmsg "")  
  
success出现，更改管理员密码的逻辑漏洞到手~~  
  
****  
![](https://mmbiz.qpic.cn/mmbiz_gif/mpLzTQpY3UPtVrmHAzibGGgNhzn4kWpYuibzqibZty56icKugFQOibSpOeJ86aqg7y9RAWwT9GLSXURgibyX2ELDO4Kg/640?wx_fmt=gif&wxfrom=5&wx_lazy=1&tp=webp "")  
  
总结  
  
除以上漏洞外，其实还有好多类似的漏洞，比如条件竞争、密码找回、任意用户接管、枚举、接口重放、参数溢出报错、验证码爆破.......  
  
这些大家都知道的熊猫就不写了，逻辑漏洞最主要的就是经验和手感。  
  
熊猫认为，想找逻辑漏洞主要得把站点功能先搞清楚，不推荐上来就咔咔找SQL注入、RCE这种大漏洞，这些先交给扫描器，主要先熟悉熟悉功能，多挖几个高危逻辑多香呀![](https://res.wx.qq.com/t/wx_fed/we-emoji/res/v1.3.10/assets/newemoji/Yellowdog.png "")  
![](https://res.wx.qq.com/t/wx_fed/we-emoji/res/v1.3.10/assets/newemoji/Yellowdog.png "")  
![](https://res.wx.qq.com/t/wx_fed/we-emoji/res/v1.3.10/assets/newemoji/Yellowdog.png "")  
。  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/wglPJSKsjat9m6CKxE20I0ML2uibrprG5VcN5c389PWIzJPfUvBsakDTib2pNAFwJDKgBvTnFWY2SWjGBUkRAMZw/640?wx_fmt=gif&from=appmsg "")  
  
  
