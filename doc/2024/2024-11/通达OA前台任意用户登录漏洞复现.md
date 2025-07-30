#  通达OA前台任意用户登录漏洞复现   
 WIN哥学安全   2024-11-22 14:37  
  
点击上方  
蓝字关注我们  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qLaXsGgOwmOFETMqV9DfenGIAx8BfvBotFhJrgP7IG9WkIkgCP1Q1DDIVsZVqTiasAS9CT66RJrq9Gj0ibkpdeew/640?&random=0.10577231121717623&wxfrom=5&wx_lazy=1&wx_co=1&wx_fmt=png&random=0.7851078959349969&random=0.3158067333367687&tp=webp&random=0.4344083505988914&random=0.8279133623233357 "")  
  
  
  
免责声明：  
  
由于传播、利用本公众号所提供的信息而造成的任何直接或者间接的后果及损失，均由使用者本人负责，公众号及作者不为此承担任何责任，一旦造成后果请自行承担！如有侵权烦请告知，我们会立即删除并致歉。谢谢！  
## 漏洞描述  
  
通达OA是一套使用比较广泛的办公系统。该漏洞因为使用uid作为身份标识，攻击者在远程且未经授权的情况下，通过利用此漏洞，可以直接绕过登录验证逻辑，伪装为系统管理员身份登录OA系统。通达OA官方于2020年4月17日发布安全更新。  
## 漏洞影响版本  
  
通达OA < 11.5  
  
通达OA 2017版本  
##   
## 漏洞原理  
  
本次复现为2017版本，则重点分析该版本，但原理都是基本相同的，只不过文件路径不同而已。根据POC的代码分析如下，该漏洞涉及的文件包含以下四个：  
  
```
/ispirit/login_code.php
/general/login_code_scan.php
/ispirit/login_code_check.php
/general/index.php
```  
  
  
通达OA源码使用zend5加密 ，分析源码需要先进行解密  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ZAPxzic90CGBb636ckQ1MC08nniczShXsWxoZ0NnvIiayo2V6xbh9jPJwbszsiaAqicUUU6ILxS6lv3uYtup1ibgbSfA/640?wx_fmt=png&from=appmsg "")  
  
使用的解密工具是:SeayDzend，工具使用很简单  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ZAPxzic90CGBb636ckQ1MC08nniczShXsW0toxEJs04icPzEgsnAGibibYA3VgNBf0r2d0Q9EJVRsoIROdrWAdJictpw/640?wx_fmt=png&from=appmsg "")  
### /ispirit/login_code.php：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ZAPxzic90CGBb636ckQ1MC08nniczShXsW8ibrOj8qiciaMsL9mDDTxibibaQcarNq2MMiauc5GLSknttPPbJJEZ0xMPog/640?wx_fmt=png&from=appmsg "")  
  
该文件用来获取codeuid参数，如果不存在，则会自动生成一个codeuid，并且将其写入CODE_LOGIN_PC缓存中（通达OA使用了缓存系统Redis，同时也提供了对缓存的使用方法），但是在18行位置将这个参数显示出来，导致用户可以获取这个参数的值，从而可以绕过后面的验证。  
### /general/login_code_scan.php：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ZAPxzic90CGBb636ckQ1MC08nniczShXsWVVYA6mYmQTjlbRm00D413Uwn5g8GMthMQcjhzUiak7ZlSA156JuRdZg/640?wx_fmt=png&from=appmsg "")  
  
在这一文件中，用户可以控制输入的关键参数uid，在存在漏洞的通达OA版本中，后台数据库里uid对应的用户是admin管理员账户。并且将该数据存储在CODE_INFO_PC缓存中，因为我们在第一个文件中获取的codeuid存储在CODE_LOGIN_PC中，所以这里在复现时需要指明source变量为pc，这里的username则为admin，而type变量需要指明为confirm，原因在后面会进行解释。  
### /ispirit/login_code_check.php：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ZAPxzic90CGBb636ckQ1MC08nniczShXsWOJLicMAccL8EvvEo9RgJRDU66el0fAbVtem1fWzWnp9Uc9sCHZya3Lw/640?wx_fmt=png&from=appmsg "")  
  
这里使用之前存储的两个缓存中的内容，一个用来获取codeuid，一个用来获取通过post传入的uid等关键信息，这里红框就是为什么前一步需要将type设置为confirm。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ZAPxzic90CGBb636ckQ1MC08nniczShXsWyS4LvABQF2r9VbmEwv2tXHmvXpe2qobKfeXmlkeOdD19PPjpCpvTyQ/640?wx_fmt=png&from=appmsg "")  
  
这里是最为关键的位置，代码获取用户可控的参数uid，并依次作为依据直接带入数据库进行查询  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ZAPxzic90CGBb636ckQ1MC08nniczShXsWNicgRvNjBzbBsk6t9mNeMX4KhzDLhm4a3ia5viapXBa3icSVhuKIX9OMFA/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ZAPxzic90CGBb636ckQ1MC08nniczShXsWATlZMicgSGaoGA14Jick40XABrFnSAibhaEJUlwA0Bxoel4eUwYicDlgOA/640?wx_fmt=png&from=appmsg "")  
  
随后将查询的信息直接写入session中，通过这一步，session中包含的就是管理员的身份信息。  
  
以上就是该漏洞的原理，V11版本原理类似，可用对照POC中的步骤进行分析复现。  
## 漏洞复现  
###   
### 环境搭建  
  
通达OA-TDOA11.4_2 建议在虚拟机环境下安装  
```
下载地址：https://cdndown.tongda2000.com/oa/2019/TDOA11.4.exe
```  
  
下载下来一路默认下一步就行！  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ZAPxzic90CGBb636ckQ1MC08nniczShXsWuhdmpffP1c1jTfJ0ibRqgQicRIbC7wT4DPXy5nMfAHbSCBQA2Xh2j9icg/640?wx_fmt=png&from=appmsg "")  
  
安装完成最后需要检测端口  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ZAPxzic90CGBb636ckQ1MC08nniczShXsWUicreZnL0VUczstOfz1h7sNG5vQRtVpUNNlE6ZupJ8u35TQmlicuiaIBQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ZAPxzic90CGBb636ckQ1MC08nniczShXsWVYzWB0W6629LF3swbxRRTBibR2YHQsT1b83ELvCkDMiaJTpyb3uqZ3cA/640?wx_fmt=png&from=appmsg "")  
  
最后点击确定就行  
###   
###   
  
最后点击确定就行  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ZAPxzic90CGBb636ckQ1MC08nniczShXsWIM6kZcnnn1icHGT3vfqz7Cz0Osw8IfA9VkuRytcjmHnlzyF9LibYVI1A/640?wx_fmt=png&from=appmsg "")  
  
### 漏洞利用  
#### code1：手工利用  
  
按照poc中的步骤，首先抓首页的包进行更改，  
  
访问/ispirit/login_code.php  
  
通过返回包获取codeuid  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ZAPxzic90CGBb636ckQ1MC08nniczShXsW9Lm6KEoty9ZNV8FtiaAm3lB6065iaWw9YTQdScLHbsibQJRDgsQVCicYYw/640?wx_fmt=png&from=appmsg "")  
  
而后使用POST方式访问/general/login_code_scan.php提交payload，其中codeuid需要改为上一步中返回的值。  
```
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ZAPxzic90CGBb636ckQ1MC08nniczShXsWfS0nMC3Q0ickwqxzECQlStuHRjsQTPYAjXCEOA63fKmVY0HquVibr1VQ/640?wx_fmt=png&from=appmsg "")  
  
第三步使用GET方式访问/ispirit/login_code_check.php，带上参数codeuid，让后台进行代入查询，并返回携带管理员身份信息的凭证。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ZAPxzic90CGBb636ckQ1MC08nniczShXsWy5AibVODPibOcCmWibSpJqBdpzpwKg0ZjXfWs9zIuKibFlYwia54ic7jCicLQ/640?wx_fmt=png&from=appmsg "")  
  
经过这步后客户端已经拥有了管理员的身份信息，直接访问OA主页/general/index.php，放行该数据包，成功以管理员身份登录OA系统。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ZAPxzic90CGBb636ckQ1MC08nniczShXsWZ90C9QVmEg2ticRsT9cfYTyT0YjhniapnZp7TtpCrERHiavOeComARxqg/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ZAPxzic90CGBb636ckQ1MC08nniczShXsWKAmRW3qTlA6zJUy83AHNnAlCtRhxt6o1go8X3RlfzE7CfsfbZycmTA/640?wx_fmt=png&from=appmsg "")  
#### code2：POC利用  
```
python3 .\POC.py -v 2017 -url http://192.168.142.129/
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ZAPxzic90CGBb636ckQ1MC08nniczShXsWEfAcarphu5vo4KkBGOt3Y59iah8rNSesX3zNSzFYsnyyszKqXCpR5Jg/640?wx_fmt=png&from=appmsg "")  
  
访问主页  
http://192.168.142.129/general/index.php  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ZAPxzic90CGBb636ckQ1MC08nniczShXsWg0LcSLBkaIDmszQRmJxQj1qLrBicQHGTebNlVbGKGqXBkqOWMgPwRicA/640?wx_fmt=png&from=appmsg "")  
  
修改cookie中PHPSESSID的值并刷新页面就会发现登录成功了  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ZAPxzic90CGBb636ckQ1MC08nniczShXsWxiaiaQLiafhZ8nKWibV2LoyWDbQXawYiaYUiczkvVhZAjKagNS165aetvoPA/640?wx_fmt=png&from=appmsg "")  
  
最后修改cookie也可以在bp里面修改  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ZAPxzic90CGBb636ckQ1MC08nniczShXsWdiaY8qvGrVBsIGj9yG0E3afqKj4pRkw6uz67iaH9L6FzC2Eiac5LukBHw/640?wx_fmt=png&from=appmsg "")  
## 修复建议  
  
更新最新版本  
## 复现环境所需安装包以及工具在公众号回复通达OA11.4获取  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ZAPxzic90CGBb636ckQ1MC08nniczShXsWeVS7woVPhY6icYib7q60xQWZZE2mqGygaFSiaSUkFTJVzHfYWsa7ZG7Qw/640?wx_fmt=png&from=appmsg "")  
  
   
  
![](https://mmbiz.qpic.cn/mmbiz_png/3Z3jx4LKk5TD1iasES3VCHUamQS7icwrf6JZmULCiadahEFI5mDic3GDibwWGunCUAVHE6ZwxVk9dWkSxjhSDDsa5nw/640? "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/10TRBCoUes1j2gAJTLU8iaHpiclEJmjlbkghH7k5aYcjRl4SsJRUk8gbzJghLh6VLmyyDGGoHcNgXhNjHicPKJyVw/640? "")  
  
**文章来源：**  
网络安全学习爱好者  
  
![](https://mmbiz.qpic.cn/mmbiz_png/aGXEJwhbnpfOPk98spFicJqUeicXZ5IeibVeYr1aZiaRZibfeDBguT1DWy3YD8gAAyGlonxmXxIQktdoSWjILjM84nQ/640? "")  
  
  
  
  

						  

							  

									  
往期推荐  

						  

						  
  

							  

								  

								[ 几个常见的越权漏洞挖掘案例 ](http://mp.weixin.qq.com/s?__biz=MzkwODM3NjIxOQ==&mid=2247502149&idx=1&sn=ee01e77e7d3727aaeb827ef5d41f4467&chksm=c0c868b1f7bfe1a7811b60bea0916bb33a859945682bd72a7860944126802fe7c992612b834c&scene=21#wechat_redirect)  

							  
  

								[ 12年来最严重的 WordPress 漏洞，可大规模接管管理员权限 ](http://mp.weixin.qq.com/s?__biz=MzkwODM3NjIxOQ==&mid=2247502147&idx=1&sn=6d2c1227899943ee29dc7f1a17b1cf53&chksm=c0c868b7f7bfe1a17c97d31e7cc9145d2ee5475356d4560be1cb0d8c42700331afcc9307ef62&scene=21#wechat_redirect)  

							  
  

								[ 比较有意思的几个漏洞挖掘记录 ](http://mp.weixin.qq.com/s?__biz=MzkwODM3NjIxOQ==&mid=2247502125&idx=1&sn=15f4d48305c47b6a699973c871f1cca0&chksm=c0c868d9f7bfe1cf87cd0eea2b0fe635af7c9ff29d604544b162d17cad57ab3da3ceb45a0b03&scene=21#wechat_redirect)  

							  
  

								[ 分享某单位众测项目漏洞挖掘中的一些手法 ](http://mp.weixin.qq.com/s?__biz=MzkwODM3NjIxOQ==&mid=2247502084&idx=1&sn=d48d54097881a0bd3c994c3d816bb50b&chksm=c0c868f0f7bfe1e617bd8b582860051b3a23f3f7b281943bde2953d490765b13d216d6b3ea50&scene=21#wechat_redirect)  

							  
  

								[ 从404到RCE，挖洞像喝水一样简单 ](http://mp.weixin.qq.com/s?__biz=MzkwODM3NjIxOQ==&mid=2247501990&idx=1&sn=cb10031d31e76ad2a3161edd1b0ae150&chksm=c0c86952f7bfe044a7ca1c516fc7f3622935eb3465254d668faa81f2f08b7bc834755788c98b&scene=21#wechat_redirect)  

							  
  

								[ 一款针对Burp Suite Pro的安全扫描增强工具 ](http://mp.weixin.qq.com/s?__biz=MzkwODM3NjIxOQ==&mid=2247501958&idx=1&sn=c379d63c4be459123cee9b08089e522a&chksm=c0c86972f7bfe064ca6a3367bb823295789d0c298c46bc7a9f7b50985036ed396b238a86629b&scene=21#wechat_redirect)  

							  
  

								[ DudeSuite Web Security Tools 渗透测试工具集 ](http://mp.weixin.qq.com/s?__biz=MzkwODM3NjIxOQ==&mid=2247501938&idx=1&sn=e1a7953ca4719b400b2dd6011482996d&chksm=c0c86986f7bfe09019b5e8608ff79a6fe1e44dcd4b6a9acadd57d09ef84b615abf2c12139c2a&scene=21#wechat_redirect)  

							  
  

								[ 无影(TscanPlus) v2.6发布：弱口令连接校验 ](http://mp.weixin.qq.com/s?__biz=MzkwODM3NjIxOQ==&mid=2247501910&idx=1&sn=48bb76542e5a88c3fbd623fe387e32f5&chksm=c0c869a2f7bfe0b45c85c623f9a521ff19b006449f832d3799c39abae03daaac3471e77c8f26&scene=21#wechat_redirect)  

							  
  

								[ 一次看个爽——攻防演练合集篇 ](http://mp.weixin.qq.com/s?__biz=MzkwODM3NjIxOQ==&mid=2247501889&idx=1&sn=750feacfaa2b710f1fda9c266efc5098&chksm=c0c869b5f7bfe0a331c351f54e8adcefdcbbe45a157989e9321fb7af86ae5ab8ecede810edff&scene=21#wechat_redirect)  

							  
  

								[ 小记一次逆向分析 ](http://mp.weixin.qq.com/s?__biz=MzkwODM3NjIxOQ==&mid=2247501882&idx=1&sn=f81013e8a09e890275367a7efe7e8fdc&chksm=c0c869cef7bfe0d81b92a28f2e98af26c8dd45ff5475e58317f93792b423f51cc3786bd50aed&scene=21#wechat_redirect)  

							  
  

								[ SSRF打穿内网 ](http://mp.weixin.qq.com/s?__biz=MzkwODM3NjIxOQ==&mid=2247501833&idx=1&sn=650a086ea1158057dec8d9fd714b2ade&chksm=c0c869fdf7bfe0eb3ba649469fdffed70500b9acee8bb8e0b81b98b62879b3f441f884b7c56c&scene=21#wechat_redirect)  

							  
  

								[ 红队武器库2.0版本，内含数百款渗透工具 ](http://mp.weixin.qq.com/s?__biz=MzkwODM3NjIxOQ==&mid=2247501849&idx=1&sn=cfa9166999f9242eaac57c9a74b46b74&chksm=c0c869edf7bfe0fb821f3117f5d519e02bc681ee7448562f2164dec9bc430af66fb807ff6584&scene=21#wechat_redirect)  

							  
  

								[ 货拉拉在逻辑漏洞自动化检测的实践 ](http://mp.weixin.qq.com/s?__biz=MzkwODM3NjIxOQ==&mid=2247501830&idx=1&sn=752ab849a1a431aaaa222c3ca3e1f203&chksm=c0c869f2f7bfe0e448f27d906992c10e9ef360481cdca045ff059220ffa21e4354b2d5ac6e90&scene=21#wechat_redirect)  

							  
  

								[ 记一次某yp网站浅挖|挖洞日常 ](http://mp.weixin.qq.com/s?__biz=MzkwODM3NjIxOQ==&mid=2247501777&idx=1&sn=0bab36c86bce72c18361604e5560756a&chksm=c0c86625f7bfef33cbe77ec3252e3d160d2d4b09a2d8b14b80d0285b029d55ecc0ab8ec47bd5&scene=21#wechat_redirect)  

							  
  
  
