#  浅谈常见edu漏洞，逻辑漏洞-越权-接管-getshell，小白如何快速找准漏洞   
薛定谔不喜欢猫  李白你好   2025-04-27 00:02  
  
**免责声明：**  
由于传播、利用本公众号李白你好所提供的信息而造成的任何直接或者间接的后果及损失，均由使用者本人负责，公众号李白你好及作者不为此承担任何责任，一旦造成后果请自行承担！如有侵权烦请告知，我们会立即删除并致歉。谢谢！  
  
  
文章作者：奇安信攻防社区（  
薛定谔不喜欢猫）  
  
文章来源：  
https://forum.butian.net/share/4291  
  
  
**1**  
►  
  
**前言**  
  
  
之前闲来无事承接了一个高校的渗透测试，测试过程中没有什么复杂的漏洞，是一些基础的edu常见漏洞，适合基础学习，于是整理一下和师傅们分享。  
  
今年对某高校进行了渗透测试，发现了一些比较经典的漏洞，写一下和师傅们一起分享。  
  
  
**2**  
►  
  
**正文**  
  
  
1.教务系统登录处短信轰炸  
  
![11).png](https://mmbiz.qpic.cn/mmbiz_png/XoIcX2HtlUAEexdqM366zBuiavFib7LpErtibTDQ5qA69p8tm7HqPAWYLwoL9zof6XKwTEZvBHzh8vxFg6m9HhWmg/640?wx_fmt=png&from=appmsg "")  
  
  
学校的教务系统登录处，发现有一个手机验证码认证  
  
![kappfra2).png](https://mmbiz.qpic.cn/mmbiz_png/XoIcX2HtlUAEexdqM366zBuiavFib7LpErFMxqVwLSWdrrLZXaOJib5LkoLkQ9WHS5otRwyCBEPvibFCqZynBu7jWw/640?wx_fmt=png&from=appmsg "")  
  
  
这里会发送一个验证码  
  
正常来说，每发送一次短信验证码，这个校验码就会自动更新一次，然后会报错：“验证码错误”。  
  
但是这里抓包之后，发现能抓到两个数据包  
  
![attach-1e1244475c6dff0e2087e23915db3711aab85810.png](https://mmbiz.qpic.cn/mmbiz_png/XoIcX2HtlUAEexdqM366zBuiavFib7LpEr0fbs4Y3iblduBuia2Dkiahp0SV3kQ5cjAz4qPSHVa0bWrr8jOHbHF2rbw/640?wx_fmt=png&from=appmsg "")  
  
  
这是第一个数据包，可以发现是对验证码的验证，我们把第一个数据包通过之后，拿到第二个数据包：  
  
![3).png](https://mmbiz.qpic.cn/mmbiz_png/XoIcX2HtlUAEexdqM366zBuiavFib7LpErxyYy77mBDFWEAAQCURmxav0MCXmXW8aPofzJGeCG0VuDeNbFbsL52w/640?wx_fmt=png&from=appmsg "")  
  
可以看到我们的手机号出现在了第二个数据包中  
  
我们点击放到repeater，然后点击send，可以发现一直发送：  
  
![111.png](https://mmbiz.qpic.cn/mmbiz_png/XoIcX2HtlUAEexdqM366zBuiavFib7LpErg6NfpH4aME0bC9BIHjZOVry3fHW2pibfTGice7CZKlkiaIiaH6CV7KT9FQ/640?wx_fmt=png&from=appmsg "")  
  
**原理**  
：正常来说校验码的验证和发送短信应该是在同一个数据包中，这里不严谨的设置，将校验码的验证和发送短信的数据包分成了两个，我们输入正常的验证码，通过第一个验证的数据包，拦截第二个发送短信的验证码，即可实现短信轰炸。  
  
这里分享一下短信轰炸的几种绕过方式：  
#### 1.手机号前面加空格进行绕过  
  
这是挖某专属src时遇到的  
  
![213122.png](https://mmbiz.qpic.cn/mmbiz_png/XoIcX2HtlUAEexdqM366zBuiavFib7LpErWgAGAG9oIOAcNnibet3KE5AAH3J2oupIAlnpO18lWn0L6wPROJedjNQ/640?wx_fmt=png&from=appmsg "")  
  
account为手机号，正常情况下，一个手机号短时间内只能发送一条验证码。  
  
在account中的手机号前面每加一个空格可以突破限制进行多发一次验证码，  
  
![attach-d5386ba03170c8b2e6603e5c0ad7bc221338a481.png](https://mmbiz.qpic.cn/mmbiz_png/XoIcX2HtlUAEexdqM366zBuiavFib7LpErmiboV9gbicK2icX6WdjSNQsPSsQGk4U7pJ2jicxG286D7ewVsuKpjWrlSw/640?wx_fmt=png&from=appmsg "")  
  
burp设置两个载荷  
  
第一个载荷用于填充空格，设置为50（这样设置，一个手机号就可以发送成功50条短信）  
  
第二个载荷用于循环遍历手机号，可以设置遍历10万甚至更多的手机号  
#### 2.加字母等垃圾字符绕过或者+86  
#### 3.伪造XF头  
## 2.校内某实训平台任意用户注册、任意用户登录、修改任意用户密码、验证码爆破  
  
![5(1).png](https://mmbiz.qpic.cn/mmbiz_png/XoIcX2HtlUAEexdqM366zBuiavFib7LpErpeNmicuXIURa0ibiaVHfyOiaWFMOiaibfgZC1Q8ut84KyqaOAyOQWjkKmfibw/640?wx_fmt=png&from=appmsg "")  
  
这是校内某实训平台，我们先点击注册功能点。  
  
![111P(1)(1).png](https://mmbiz.qpic.cn/mmbiz_png/XoIcX2HtlUAEexdqM366zBuiavFib7LpEriaLJxynmeQoC9xphyZjZKMdotdqrYKHx5dYBvPcKHpy2KZaqhoHcNfw/640?wx_fmt=png&from=appmsg "")  
  
  
我们点击获取验证码，然后进行抓包：  
  
![12312GR(1)(1).png](https://mmbiz.qpic.cn/mmbiz_png/XoIcX2HtlUAEexdqM366zBuiavFib7LpErPAYynSic6LQOpOOUWvqXr8OrrO54JufEiciaIkJNKOZ1Ytgnq3vIV7ulQ/640?wx_fmt=png&from=appmsg "")  
  
可以看到手机号被编在了url里，我们这里使用“,”去拼接手机号，这样就可以把验证码同时发送给两个手机号，并且收到的验证码相同。好比我知道你的手机号，拿你手机号去注册，我根本不需要知道你的验证码，因为验证码也会发到我手机上。  
  
![1233213123zCywpV(1)(1).png](https://mmbiz.qpic.cn/mmbiz_png/XoIcX2HtlUAEexdqM366zBuiavFib7LpErgf2Go3Qcic8KXkqBbowPwVq3qTeDHVKUuKUZ5xB9fXvBGEEaxssG8Pg/640?wx_fmt=png&from=appmsg "")  
  
![123321(1)(1).png](https://mmbiz.qpic.cn/mmbiz_png/XoIcX2HtlUAEexdqM366zBuiavFib7LpEru8hRZR65Czic74CnDzD9yzZjAcS6el01K1YjXibjh5wlHPAhibJ2DM5mw/640?wx_fmt=png&from=appmsg "")  
  
修改密码功能点也是相同，我这里不进行过多赘述  
#### 验证码爆破  
  
![ka12332132123123)(1).png](https://mmbiz.qpic.cn/mmbiz_png/XoIcX2HtlUAEexdqM366zBuiavFib7LpErdYOYAg2NTffpGSmowxPGibh2e7nVn5UccJN5ClbkAGrP8PeA21BA7wg/640?wx_fmt=png&from=appmsg "")  
  
正常发送验证码，然后在填写验证码的地方，随意输入四位数  
  
![attach-f9667d233ce6573b5439c68f327ddd189343fee5.png](https://mmbiz.qpic.cn/mmbiz_png/XoIcX2HtlUAEexdqM366zBuiavFib7LpEr674sictUwIS8tbI4ClTSNmEnBkmwnZuOsTQM1pY8Dbn1DFicq5Lo8JOw/640?wx_fmt=png&from=appmsg "")  
  
![3213121322131)(1).png](https://mmbiz.qpic.cn/mmbiz_png/XoIcX2HtlUAEexdqM366zBuiavFib7LpErTMx8skesibz94NYh8kTSp5XjUt4gOWZ5e8fvyaNbiarIj8A7DR9mPvmw/640?wx_fmt=png&from=appmsg "")  
  
可以看到在7710的时候，长度不一样，成功登录进去了。  
  
**修复建议：**  
：对验证码输入次数进行限制  
## 3.越权查看所有学生和教职工个人信息，数万条记录  
  
![2222.png](https://mmbiz.qpic.cn/mmbiz_png/XoIcX2HtlUAEexdqM366zBuiavFib7LpErmSGbGWfvrQ5exMQyCA4Q6SJuyOe2ltzmIu095skNs2t5LCZ5z3rkPA/640?wx_fmt=png&from=appmsg "")  
  
教务系统个人中心处有一个查看最近登陆记录的功能点，发现右上角有个查询，我们抓包尝试：  
  
![1322222)(1).png](https://mmbiz.qpic.cn/mmbiz_png/XoIcX2HtlUAEexdqM366zBuiavFib7LpEr6ic68uSBy2edttreM34Y24yWIgWrJ4npKjbewz1PHOrUeUG4GVFu68Q/640?wx_fmt=png&from=appmsg "")  
  
  
可以看到这里可以看到我们的登陆情况，我们尝试去修改value的值，看看能不能直接越权查看别人的登录信息。但是发现无论修改成什么都会提示登录信息错误。  
  
修改成0、1、-1都不可以，但经过我的尝试发现，只有一个值可以，那就是null！  
  
我们让value=null  
  
![31232213Vq(1)(1).png](https://mmbiz.qpic.cn/mmbiz_png/XoIcX2HtlUAEexdqM366zBuiavFib7LpErB95gqEHFAXEE95qs0UvwJPbqn5mALibUEHfNLDY4R8KdUqhaKlyymjw/640?wx_fmt=png&from=appmsg "")  
  
但是登录的记录明显有点少，而且观察发现好像都是登录失败的记录，这时我发现有个name字段，我把userid改成*：  
  
![123312(1)(1).png](https://mmbiz.qpic.cn/mmbiz_png/XoIcX2HtlUAEexdqM366zBuiavFib7LpErsJhlHevXvENnib4sQru676ZVgo44tWhQiaRicy5A0ks7uEXdXG5icorFvw/640?wx_fmt=png&from=appmsg "")  
  
拿下所有学生和教职工的个人信息，包括姓名、手机号、身份证号、学号、教职工编号、登录ip等  
## 4.教务系统绕过手机验证码换绑手机号  
  
![12332132(1)(1).png](https://mmbiz.qpic.cn/mmbiz_png/XoIcX2HtlUAEexdqM366zBuiavFib7LpErdoLCEK6c2Rp6kdibv57NQAfkjicguussiaVPiakEETAsXryhmVKB6j19Mg/640?wx_fmt=png&from=appmsg "")  
  
  
也是这个教务系统，安全中心有一个换绑手机号的功能点，我们点击发送验证码  
  
![3333.png](https://mmbiz.qpic.cn/mmbiz_png/XoIcX2HtlUAEexdqM366zBuiavFib7LpErKUHm39ic5x54NfibWibQ1ibFb0NR5QEGsGLmOdzmhHJFJ5iaYGJffZ64bSw/640?wx_fmt=png&from=appmsg "")  
  
这里可以看到是修改195开头的那个手机号，然后我们forward  
  
![123312(1111)(1).png](https://mmbiz.qpic.cn/mmbiz_png/XoIcX2HtlUAEexdqM366zBuiavFib7LpEr1TT1tAibTdaqibndZvxLxKIEQ7HviaYFRBwLTF1IUJ8oiab8gYSLCpFtfg/640?wx_fmt=png&from=appmsg "")  
  
  
之后弹出一个验证码，我们输入验证码点击确定  
  
![1231232.png](https://mmbiz.qpic.cn/mmbiz_png/XoIcX2HtlUAEexdqM366zBuiavFib7LpErXU1TMmJQsqCkoDupbbvjfR61AbmQ5nLAGQxM2GDYJHFDxiadkBlMIeQ/640?wx_fmt=png&from=appmsg "")  
  
  
这里的验证码就做的很好，和发送短信的验证码数据包放在一起了，杜绝了短信轰炸。但是我们这里把195开头的手机号修改成我自己的手机号。  
  
![1312BtK(1)(1).png](https://mmbiz.qpic.cn/mmbiz_png/XoIcX2HtlUAEexdqM366zBuiavFib7LpErBwnZ41E78RyVGRqGVulH5LBLXVeQEMaAHwxOlwlWlqRBQyojOCclXA/640?wx_fmt=png&from=appmsg "")  
  
成功让自己的手机号收到验证码，以为皆大欢喜了，结果。  
  
![1111e(1)(1).png](https://mmbiz.qpic.cn/mmbiz_png/XoIcX2HtlUAEexdqM366zBuiavFib7LpErdtEpd3NCNTic0b8e5sN9c4jqQe6WC8ticzhJt3H9QCbL5trYjovND7xw/640?wx_fmt=png&from=appmsg "")  
  
  
显示验证码错误，这是为什么呢？  
  
我们继续审一下错误的数据包，也就是我们抓输入完短信验证码，点“下一步”的那个数据包  
  
![111.png](https://mmbiz.qpic.cn/mmbiz_png/XoIcX2HtlUAEexdqM366zBuiavFib7LpErP6oeeAWSIyxO6OZWLgm7tl4fHJLZ5picmxfem4XuYVmrJAWx8DCdlJQ/640?wx_fmt=png&from=appmsg "")  
  
可以看到居然在“下一步”的地方，对手机号又进行了一次验证，我们将这里的phone改成我自己的手机号，然后forward  
  
![211221O(1)(1).png](https://mmbiz.qpic.cn/mmbiz_png/XoIcX2HtlUAEexdqM366zBuiavFib7LpEre1yWcsPkY3JpbDMib9tPZIUQwQfibn9iaoySqNIOa7iaEf2Akx7dMibAn4w/640?wx_fmt=png&from=appmsg "")  
  
成功到达绑定新手机的界面，成功绕过了验证码认证，可以换绑任意用户的手机号。  
## 5.校内某平台druid未授权访问，导致泄露用户session，可以实现任意用户接管  
  
![111Bc(1)(1).png](https://mmbiz.qpic.cn/mmbiz_png/XoIcX2HtlUAEexdqM366zBuiavFib7LpEr1HqsGy26Q5RlJC1Ua6QYibvtYlVuMbby4YQLVR0iaeoJd0VdzIEJRf1A/640?wx_fmt=png&from=appmsg "")  
  
这是校内的一个实习平台，url为“https://xxx.edu.cn/shixi/”  
  
然后之前读文章读到了一个druid的未授权拼接，/ / druid /  
 /  
  
于是尝试拼接 ：“https://xxx.edu.cn/shixi/druid/index.html”  
  
![2221)(1).png](https://mmbiz.qpic.cn/mmbiz_png/XoIcX2HtlUAEexdqM366zBuiavFib7LpEr4ORwENBMLR1NnJJeyJP1cNNttzQN3O7pxss7FK6zRXNI78qw4M9bVg/640?wx_fmt=png&from=appmsg "")  
  
可以看到是有druid的未授权访问，这里会泄露很多东西，比如数据库信息，数据库查询语句、访问记录等等。我们这里搞一下session。  
  
可以看到有一个session监控：  
  
![3333hPXD(1)(1).png](https://mmbiz.qpic.cn/mmbiz_png/XoIcX2HtlUAEexdqM366zBuiavFib7LpErlcC0IpuqxUaqypLibp6sqbic2D9xGmaTxiap5XvNea1XDapkaHhiaabx9g/640?wx_fmt=png&from=appmsg "")  
  
可以看到这里有登录过系统的用户的session，我们要做的就是把session收集起来。这里我有个比较好用的方法，可以ctrl+a复制全页，然后粘贴到excel里，然后选中session列，就可以快速的把session复制到txt里了。  
  
![44444Zc(1)(1).png](https://mmbiz.qpic.cn/mmbiz_png/XoIcX2HtlUAEexdqM366zBuiavFib7LpErmfkia2n2XHTZWjFicrl9LRBl35XmkYHE5lYopGNeT5wv5xuDUiaJmrR8w/640?wx_fmt=png&from=appmsg "")  
  
可以看到我们把session这样收集到了txt里，然后打开yakit  
  
把txt导入到yakit的pyload里，然后去抓一下登录窗口的数据包：  
  
![5555tPEr(1)(1).png](https://mmbiz.qpic.cn/mmbiz_png/XoIcX2HtlUAEexdqM366zBuiavFib7LpErQNfI8txmZdRibyoTnXphiadicpbdqia2QEZ9ib79z7H3LhP8J1Zjujb1ibOw/640?wx_fmt=png&from=appmsg "")  
  
可以看到cookie有个jessionid，我们把他的值设置成标签，然后去拼接刚才的session的payload去批量访问：  
  
![666666(1)(1).png](https://mmbiz.qpic.cn/mmbiz_png/XoIcX2HtlUAEexdqM366zBuiavFib7LpEribNrsJpZeECziaTR6V1EiaT3MDdIG1vsCsVBUgWqHDkNnynpFcWPZDzJA/640?wx_fmt=png&from=appmsg "")  
  
可以看到有很多200成功访问的，也有一些无法访问的，无法访问的原因主要是因为session是具有时效性的，长时间后这个session可能就会失效，但是只要源源不断的访问这个系统，我们就可以源源不断的盗取新的session。  
  
我们找一个200正常访问的数据包，把里面的session复制下来。  
  
![77777A(1)(1).png](https://mmbiz.qpic.cn/mmbiz_png/XoIcX2HtlUAEexdqM366zBuiavFib7LpErwORgDCjh6B23BjoFZaSn427icabJJBSQWIkAtQOKvKP5PJ3ZhAuw3Aw/640?wx_fmt=png&from=appmsg "")  
  
然后回到网页，打开f12里的存储，替换里面的jsessionid  
  
![1231231.png](https://mmbiz.qpic.cn/mmbiz_png/XoIcX2HtlUAEexdqM366zBuiavFib7LpErJoRgQpqWpWurzEZWnS2uEmRwBtL0vEvv617hlEbmtt9va7fibUZvT2Q/640?wx_fmt=png&from=appmsg "")  
  
然后刷新页面：  
  
![1111111).png](https://mmbiz.qpic.cn/mmbiz_png/XoIcX2HtlUAEexdqM366zBuiavFib7LpEre2LqDnOWSqMfHoDsMmg5pk05Mx31ldicV50icpjH8271iaFQkibQdgofEA/640?wx_fmt=png&from=appmsg "")  
  
可以发现直接接管了别人的账号，登录进了系统。  
## 6.内部系统存在sql注入导致rce  
  
![333.png](https://mmbiz.qpic.cn/mmbiz_png/XoIcX2HtlUAEexdqM366zBuiavFib7LpErJL5oZvQ7K3uHFXRfe03j1NVgRQjotmwEg2SROyYhkslFicKPMCrIIdQ/640?wx_fmt=png&from=appmsg "")  
  
学校新出的一个平台，还是挺重要第一个平台，负责校内事务和档案的，应该还是个通用，很多学校都购买了这个平台。  
  
我在那个平台抓包的时候，这个数据包偶然出现在我的burp里，我一看，居然直接把sql语句写出来了，这不就可以直接利用了吗？  
  
![1233121)(1).png](https://mmbiz.qpic.cn/mmbiz_png/XoIcX2HtlUAEexdqM366zBuiavFib7LpErdFw9VkiaZoBZcKHr7YNPKT6FA9dNGvgicibiag2XwldhibAGjLicVMTtIaVA/640?wx_fmt=png&from=appmsg "")  
  
直接执行select user，可以看到右边直接进行回显了。那个user字段的内容就是回显的。  
  
后来我写报告的时候，怎么找也找不到这个包在哪抓的，没办法，只能转化思路去找js接口。  
  
![123321Vi(1)(1).png](https://mmbiz.qpic.cn/mmbiz_png/XoIcX2HtlUAEexdqM366zBuiavFib7LpErjMLWZk11SP9kG1OF1DTVyTcyF0dSO42rnkm2BbCYMF59ELDWLnG4xg/640?wx_fmt=png&from=appmsg "")  
  
  
可以看到这个data里有sql:t  
  
成功找到了这个接口，然后还有意外收获！  
  
![1111)(1).png](https://mmbiz.qpic.cn/mmbiz_png/XoIcX2HtlUAEexdqM366zBuiavFib7LpErBoicMVI9xjGb84AqwmNxrevJpSp13YfRLFvgM0f3XBzwhjevmkYSp3w/640?wx_fmt=png&from=appmsg "")  
  
![222bqB(1)(1).png](https://mmbiz.qpic.cn/mmbiz_png/XoIcX2HtlUAEexdqM366zBuiavFib7LpEr8pZkjrUmKuQq1q5uHMrTPVgvToAOU8L33JOF1cAGibkGMTzyk1jo1cQ/640?wx_fmt=png&from=appmsg "")  
  
找到了近400个接口，这400个接口基本上都和上面的一样，直接写出了sql的语句，都可能存在sql注入！  
  
那么多接口，第一想法就是爬出来测一下未授权和越权。  
  
然后写了个爬虫python脚本去爬js  
```
import requests  import re  \# #proxy={'https':'127.0.0.1:8080'}  \# url=""  \# headers = {  \#     'cookie':'',  \#     'User-Agent':'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:137.0) Gecko/20100101 Firefox/137.0',  \#     'Username':'',  \#     'Accept':'\*/\*',  \#     'Te':'',  \#     'Priority':'u=',  \#     'Sec-Fetch-User':'',  \#     'Sec-Fetch-Site':'',  \#     'Sec-Fetch-Mode':'',  \#     'Sec-Fetch-Dest':'',  \#     'Upgrade-Insecure-Requests':'',  \#     'Referer':'',  \#     'From':'dzj-pc'  \# }  \# def get\_html(url):  \#     res = requests.get(url = url,verify=False,headers=headers,allow\_redirects=False)  \#     # return res.content  \# #  \# html = get\_html(url = url)  \# print(html.decode("utf-8"))
```  
  
爬出来之后，使用正则去检索我们所需要的东西：  
```
file = open('C:/Users/xxx/Desktop/111.txt','r')  lines = file.read()  apis=re.findall("url:\\"(.\*?)\\"",lines)  for api in apis:  if'?' in api:  print(api.split("?")\[0\])  else:  print(api)
```  
  
. 表示除\n \r 之外的任意单个字符  
  
* 匹配零次或者多次  
  
? 指定为非贪婪模式  
  
然后我们将收集到的api，放到burp里去批量访问  
  
![12(1)(1).png](https://mmbiz.qpic.cn/mmbiz_png/XoIcX2HtlUAEexdqM366zBuiavFib7LpErL7DiaWZ9fWbp7qbA8fYribMhvUlH6Tjglk9Np6iakIyzRr2e8H5Ru7UQA/640?wx_fmt=png&from=appmsg "")  
  
但是没有跑出来，应该是没有未授权漏洞，做了全局验证，逐个删除cookie字段，但还是不行，没有cookie就被深信服的设备拦住了。  
  
那我们回到最开始的sql注入，该如何扩大危害呢？  
  
首先我们要判断数据库类型，于是我继续看js  
  
![122121GO(1)(1).png](https://mmbiz.qpic.cn/mmbiz_png/XoIcX2HtlUAEexdqM366zBuiavFib7LpErKH3V5vLSJf8K3qIDuHlsdKISEKgVePyOJeRAB8ribjDkkyRwdMYX9nw/640?wx_fmt=png&from=appmsg "")  
  
一开始看到了from dual，我以为是oracle数据库，然后尝试了oracle数据的sql语法，发现总是报错。  
  
后来再翻js数据包的时候，发现了这个包：  
  
![11111g(1)(1).png](https://mmbiz.qpic.cn/mmbiz_png/XoIcX2HtlUAEexdqM366zBuiavFib7LpErdGn0jzZ8ibnQ8eGbz7Frjc2BXDiaHlFZYbibclbPicKsRhtiaRydDeHmC3w/640?wx_fmt=png&from=appmsg "")  
  
这个数据包不仅直接暴露了usr_bsp，重要的是告诉了我们这个是postgresql数据库，这个数据库不太了解，我去百度了一下sql语法。发现他和mysql的语法差不多。  
```
select table_name from information_schema.tables where table_schema=''
```  
  
![1111111)(1).png](https://mmbiz.qpic.cn/mmbiz_png/XoIcX2HtlUAEexdqM366zBuiavFib7LpErAEaNTczl6jRSDf10nPCWpLKh2HVDrpoZJv1NgPfZrowqxxe4krTz0g/640?wx_fmt=png&from=appmsg "")  
  
成功注入。然后在征得校方同意后，可以使用postgresql数据库的集成利用工具直接进行rce。  
  
至此，渗透告一段落。  
  
注：严禁未拿到授权就进行渗透测试  
  
  
**3**  
►  
  
**实战攻防**  
  
  
在海量攻击路径中学习实用的攻防套路、攻防Tips，我们的宗旨是让**脚本小子也能打攻防，在HW中捞个1W+分**  
。面对重保、HW、攻防演练等大型活动游刃有余。点击👇了解详情~  
  
  
[](http://mp.weixin.qq.com/s?__biz=MzkwMzMwODg2Mw==&mid=2247511472&idx=1&sn=b5c7a3f793325106e1613b57a7b72afe&chksm=c09adee0f7ed57f61e8c5839c978dd2c8fa72049852b6ba8e90fee40c86600a05ff44fd23927&scene=21#wechat_redirect)  
  
[《实战攻防》第二期，解锁攻防新场景新姿势！](http://mp.weixin.qq.com/s?__biz=MzkwMzMwODg2Mw==&mid=2247511472&idx=1&sn=b5c7a3f793325106e1613b57a7b72afe&chksm=c09adee0f7ed57f61e8c5839c978dd2c8fa72049852b6ba8e90fee40c86600a05ff44fd23927&scene=21#wechat_redirect)  
  
  
  
**4**  
►  
  
**往期精彩**  
  
  
[攻防 | 不出网环境下的渗透测试](http://mp.weixin.qq.com/s?__biz=MzkwMzMwODg2Mw==&mid=2247511670&idx=1&sn=c17d4c92af76040326bce7d5b75b3b93&chksm=c09add26f7ed5430acab9b2d6ddd564559fd3f6644f089eab280bc23f35c48f81b6c6c602cda&scene=21#wechat_redirect)  
  
  
[2025-04-23](http://mp.weixin.qq.com/s?__biz=MzkwMzMwODg2Mw==&mid=2247511670&idx=1&sn=c17d4c92af76040326bce7d5b75b3b93&chksm=c09add26f7ed5430acab9b2d6ddd564559fd3f6644f089eab280bc23f35c48f81b6c6c602cda&scene=21#wechat_redirect)  
  
  
[](http://mp.weixin.qq.com/s?__biz=MzkwMzMwODg2Mw==&mid=2247511670&idx=1&sn=c17d4c92af76040326bce7d5b75b3b93&chksm=c09add26f7ed5430acab9b2d6ddd564559fd3f6644f089eab280bc23f35c48f81b6c6c602cda&scene=21#wechat_redirect)  
  
  
[RUST重构工具免杀知识点及视频教程](http://mp.weixin.qq.com/s?__biz=MzkwMzMwODg2Mw==&mid=2247511639&idx=1&sn=de9ad34239327f817dac29fb3ea52e1e&chksm=c09add07f7ed54117198c0e0c427f85637e07bc954d470d9dcfadddb54660d1198c0459675fa&scene=21#wechat_redirect)  
  
  
[2025-04-21](http://mp.weixin.qq.com/s?__biz=MzkwMzMwODg2Mw==&mid=2247511639&idx=1&sn=de9ad34239327f817dac29fb3ea52e1e&chksm=c09add07f7ed54117198c0e0c427f85637e07bc954d470d9dcfadddb54660d1198c0459675fa&scene=21#wechat_redirect)  
  
  
[](http://mp.weixin.qq.com/s?__biz=MzkwMzMwODg2Mw==&mid=2247511639&idx=1&sn=de9ad34239327f817dac29fb3ea52e1e&chksm=c09add07f7ed54117198c0e0c427f85637e07bc954d470d9dcfadddb54660d1198c0459675fa&scene=21#wechat_redirect)  
  
  
[实战攻防 | 1.6K主机全域沦陷实录：从单点突破到域控接管的终极横向渗透链](http://mp.weixin.qq.com/s?__biz=MzkwMzMwODg2Mw==&mid=2247511605&idx=1&sn=2d4d842ea01a49e6c9808fe2ddbd38ed&chksm=c09add65f7ed5473a66cb19a4ff845c41a46eb6bc975d5986411c9e722663556424b26bd2d26&scene=21#wechat_redirect)  
  
  
[2025-04-18](http://mp.weixin.qq.com/s?__biz=MzkwMzMwODg2Mw==&mid=2247511605&idx=1&sn=2d4d842ea01a49e6c9808fe2ddbd38ed&chksm=c09add65f7ed5473a66cb19a4ff845c41a46eb6bc975d5986411c9e722663556424b26bd2d26&scene=21#wechat_redirect)  
  
  
[](http://mp.weixin.qq.com/s?__biz=MzkwMzMwODg2Mw==&mid=2247511605&idx=1&sn=2d4d842ea01a49e6c9808fe2ddbd38ed&chksm=c09add65f7ed5473a66cb19a4ff845c41a46eb6bc975d5986411c9e722663556424b26bd2d26&scene=21#wechat_redirect)  
  
  
  
