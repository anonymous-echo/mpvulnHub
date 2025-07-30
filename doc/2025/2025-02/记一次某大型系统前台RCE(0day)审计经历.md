#  记一次某大型系统前台RCE(0day)审计经历   
原创 C@ig0  菜狗安全   2025-02-12 01:20  
  
![](https://mmbiz.qpic.cn/mmbiz_png/QtaE6uFmibPlzg5sZKIlTPHGFlkF53seUMNUsR3TKcn9VGDeJTwzichS2dI31pVDLibP6XhejxiakNbBahbqtchM5A/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/QtaE6uFmibPlzg5sZKIlTPHGFlkF53seUgwlRhqQibojuE58lklgLm1hpT7yT88speo9QwTL6dlaFNdP9TvsdL9Q/640?wx_fmt=gif&from=appmsg "")  
  
点击上方蓝字·关注我们  
  
  
免责声明  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/QtaE6uFmibPlzg5sZKIlTPHGFlkF53seUZHdTe6rSPrTwIbY4nGDic3ick7JK8o2LnQqAYibZia3uZmzNvdMZiciaZMPw/640?wx_fmt=gif&from=appmsg "")  
  
  
由于传播、利用本公众号  
菜狗安全  
所提供的信息而造成的任何直接或者间接的后果及损失，均由使用者本人负责，公众号  
菜狗安全  
及作者不为此承担任何责任，一旦造成后果请自行承担！如有侵权烦请告知，会立即删除并致歉。  
  
前言  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/QtaE6uFmibPlzg5sZKIlTPHGFlkF53seUZHdTe6rSPrTwIbY4nGDic3ick7JK8o2LnQqAYibZia3uZmzNvdMZiciaZMPw/640?wx_fmt=gif&from=appmsg "")  
  
  
该篇文章由交流群大佬友情分享，给大佬打call  
  
  
文章目录  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/QtaE6uFmibPlzg5sZKIlTPHGFlkF53seUZHdTe6rSPrTwIbY4nGDic3ick7JK8o2LnQqAYibZia3uZmzNvdMZiciaZMPw/640?wx_fmt=gif&from=appmsg "")  
  
```
0x00介绍
0x01漏洞审计
0x02结尾
```  
## 0x00 前言  
  
此次审计的系统是某大型开源系统，用户量  
不少  
（  
1W+）。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/QtaE6uFmibPn5yDCMOZOzdM7U0ZsCbXIpI8F5b1NhxgCXvovwbaeBPAFO5h2LVGfwqLFhLectIiaF6g2blFJAsYw/640?wx_fmt=png&from=appmsg "")  
  
审计出的漏洞是管理员登录绕过和后台  
getshell，审计的思路与常规不同，利用到了CTF的知识点和逻辑漏洞。  
## 0x01 漏洞审计  
  
该漏洞非常简单，属于在cwe硬编码漏洞，身份令牌一种是正常授权中，一种鉴定是否合法，合法的身份令牌是用户提交的一部分内容混合加密再加上key，key是由rand随机生成32位再配合ua的md5存入配置文件。  
  
该rand函数启动后，会生成一个key，然后生成一个管理员的用户名，如果管理员登录，即可在数据包中看到用户名，在登出的地方未授权。  
  
所以该漏洞的利用实则是多个漏洞配合实现的，先访问登出页面未授权获取用户名，然后根据rand爆破种子，接着生成前32位数，最后配合ua的库组成合法md5。  
  
2025年审计出来的复杂程度前三，未提交cve，cnvd，src。寻找大宝藏去吧，以下内容由混子城市撰写。  
  
审计项目的开始是了解项目的结构，熟悉项目结构之后，我习惯先看鉴权部分是如何构造的。  
  
先看  
login.php  
  
![](https://mmbiz.qpic.cn/mmbiz_png/QtaE6uFmibPn5yDCMOZOzdM7U0ZsCbXIp3x0aCUiccDrAjRnicSe2BOoe0gTO2uo0ZEo9PODibqFicFled1hFVA523Q/640?wx_fmt=png&from=appmsg "")  
  
跟进  
checkLogged函数  
  
![](https://mmbiz.qpic.cn/mmbiz_png/QtaE6uFmibPn5yDCMOZOzdM7U0ZsCbXIpdyq9mQTu55fOQRg3NcIWLqh8cjMHGYZBdMwstCXkYumdjNAqoEExibQ/640?wx_fmt=png&from=appmsg "")  
  
再跟进  
isLogin()函数  
  
![](https://mmbiz.qpic.cn/mmbiz_png/QtaE6uFmibPn5yDCMOZOzdM7U0ZsCbXIp5xkST7OKiajYnY0iazAN4GiauDObANk2eYjJwiaWCp5nLgPZuho08bxDGA/640?wx_fmt=png&from=appmsg "")  
  
先判断  
COOKIE里是否存在AUTH_COOKIE_NAME这个字段，直接全局搜该字段  
  
![](https://mmbiz.qpic.cn/mmbiz_png/QtaE6uFmibPn5yDCMOZOzdM7U0ZsCbXIpWicm4L9nAhecNX5W0tF8bBteKCPibdibCeDBNzSque9KSCobTXw9mCiatw/640?wx_fmt=png&from=appmsg "")  
  
在  
config.php里找到了这个常量，在install.php里找到了该常量的构造方式  
  
![](https://mmbiz.qpic.cn/mmbiz_png/QtaE6uFmibPn5yDCMOZOzdM7U0ZsCbXIprAPXfAoR5b6HfKMFMtTGfWd7GeCsyibyTp9gQn1cJ2HNCnwA97TIWYw/640?wx_fmt=png&from=appmsg "")  
  
跟进  
getRandStr函数  
  
![](https://mmbiz.qpic.cn/mmbiz_png/QtaE6uFmibPn5yDCMOZOzdM7U0ZsCbXIpBeIO5l77E6DyAoX9uE2n3rVpTyKFX7BDxUJqdzQk51sknVR9N4icsYg/640?wx_fmt=png&from=appmsg "")  
  
根据输入的长度和随机字符要求，伪随机生成一个字符串。这里为什么说是伪随机呢？打过  
CTF的看到这个函数就能想到mt_rand的伪随机种子爆破漏洞。具体原理这里不细说，网上一堆CTF比赛wp，看看都能理解。该函数的种子一旦生成是不会变的，除非该程序重启会改变，后面所需的序列都是根据该种子生成的。安装的时候该种子就会生成然后一直不变。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/QtaE6uFmibPn5yDCMOZOzdM7U0ZsCbXIp10Wjmb6Lc5t3gbrcyrrtTpAHam3H83dhFOjsBpbeTznaI2PQPatd6w/640?wx_fmt=png&from=appmsg "")  
  
这里需要注意  
AUTH_KEY是第一次调用，AUTH_COOKIE_NAME是第二次调用，注意理清先后顺序，后面还要用。全局搜索这两个常量，看看有没有泄露的地方，该系统存在注册功能，注册成功就会拿到AUTH_COOKIE_NAME，这是一个方法。这里说其他泄露的地方  
  
![](https://mmbiz.qpic.cn/mmbiz_png/QtaE6uFmibPn5yDCMOZOzdM7U0ZsCbXIpoEYEk36OicEChTNkria5V2ib7EsAYxr5WhibXiaBzgUDLULQ26Tzkb2E4Mw/640?wx_fmt=png&from=appmsg "")  
  
这里的注销行为，也会返回  
AUTH_COOKIE_NAME，那么我们就可以拿到该值  
  
![](https://mmbiz.qpic.cn/mmbiz_png/QtaE6uFmibPn5yDCMOZOzdM7U0ZsCbXIpbteQus0AsOf1Gp7Aqicf9SjmCKeqdMOqKNia6w0pbXibybq8kOuibia57Wg/640?wx_fmt=png&from=appmsg "")  
  
拿到该值取前  
10位爆破种子  
  
![](https://mmbiz.qpic.cn/mmbiz_png/QtaE6uFmibPn5yDCMOZOzdM7U0ZsCbXIpUkDWLLFPLKIzCPa0Z2xFaeHDMGuj8yMuxaPyiaAvZX1qYTMaibKkTpkQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/QtaE6uFmibPn5yDCMOZOzdM7U0ZsCbXIp9JlibmgeicEq1avSS65R1rhlwMaudQyynw3IeicGSOk3lDJib7icR6gHswg/640?wx_fmt=png&from=appmsg "")  
  
然后使用种子爆破工具  
  
![](https://mmbiz.qpic.cn/mmbiz_png/QtaE6uFmibPn5yDCMOZOzdM7U0ZsCbXIp2ZsVzXbT0pxw1B6JhSoFxCDb7jsichRobQ16j8szSK7ia9u6QSIQn8IA/640?wx_fmt=png&from=appmsg "")  
  
前  
32位置为0因为AUTH_COOKIE_NAME顺序是第二次调用，爆破直接拿到种子。根据种子生成脚本，生成前32位内容也就是AUTH_KEY  
  
![](https://mmbiz.qpic.cn/mmbiz_png/QtaE6uFmibPn5yDCMOZOzdM7U0ZsCbXIpN20EztxqibKSqs0cwYwianOZqm8Vwwm3VBkia0YSb9wY4qQLmut1kATZA/640?wx_fmt=png&from=appmsg "")  
  
至此拿到了  
cookie名和AUTH_KEY字段的前半部分。AUTH_KEY的后半部分是MD5(ua值)  
  
![](https://mmbiz.qpic.cn/mmbiz_png/QtaE6uFmibPn5yDCMOZOzdM7U0ZsCbXIp10Wjmb6Lc5t3gbrcyrrtTpAHam3H83dhFOjsBpbeTznaI2PQPatd6w/640?wx_fmt=png&from=appmsg "")  
  
ua需要自己爆破了，结合就能拿到完整的AUTH_KEY值  
  
回到最开始跟进  
validateAuthCookie函数，主要对我们传入的cookie值做验证  
  
![](https://mmbiz.qpic.cn/mmbiz_png/QtaE6uFmibPn5yDCMOZOzdM7U0ZsCbXIpeDdyBhcqoljadwJcTEGPak63huiaxLp8eLpClTHKN2Q9EzUUJibKJskQ/640?wx_fmt=png&from=appmsg "")  
  
过程就是判空，分割，赋值，  
md5处理，验证。  
  
username可以位admin，expiration可以为0，hmac就是hash值，三部分都可以伪造。继续跟进到getUserDataByLogin函数  
  
![](https://mmbiz.qpic.cn/mmbiz_png/QtaE6uFmibPn5yDCMOZOzdM7U0ZsCbXIpkX2nQNADPkfccmGXN8ym4I1FaCwibutgFQ8icJibwTXTZA3TpbfQbe3iag/640?wx_fmt=png&from=appmsg "")  
  
对传入的  
account没有做任何过滤，直接传入数据库，这里直接使用万能密码使该语句为真，同时也能造成SQL注入。  
  
这样就顺利进入后台，后台网站设置可以上传文件的类型，当然上传插件处可以上传  
shell.  
  
结尾  
  
漏洞并不算太复杂，但是这个漏洞如果代码能力不够确实想不到，更重要的是细心和挖掘的思路，能不能想到这个点，这里只能说不愧是大佬了，反正让我来我是找不到![](https://res.wx.qq.com/t/wx_fed/we-emoji/res/assets/newemoji/Yellowdog.png "")  
  
  
  
