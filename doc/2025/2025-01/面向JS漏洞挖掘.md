#  面向JS漏洞挖掘   
原创 molin  千寻安服   2025-01-02 00:57  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qAbTL3m1KPCCVCvbQtU6iaxaBDBgTia36MvOP6QwkWtYUdricL5CZ12BJdfnaSgP64O1XwlU5d0dBaGTsibldbfCJg/640?wx_fmt=png&from=appmsg "")  
  
2025你好呀！  
  
  
面向JS漏洞挖掘  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qAbTL3m1KPCCVCvbQtU6iaxaBDBgTia36Mardd8xRYg14BwFPWsoribfCml0K0adUIJhFYpSJvlbXDibSrPh3eiaCAA/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qAbTL3m1KPCCVCvbQtU6iaxaBDBgTia36MlYM842RR8ATbOmLdcibVHx3PdURia8iayPkibEhJg878kZOQQjZZWibvFCg/640?wx_fmt=png&from=appmsg "")  
  
最近在研究怎么从JS中挖掘更多有用信息，以前在漏洞挖掘的时候没有对js进行细致的挖掘利用，在研究小程序调试解密的时候发现js文件中可获取信息的点、可挖掘漏洞的点还是很多的，花了一段时间积攒了一些漏洞场景，就有了这篇文章了~~有覆盖不全的场景或者其他挖掘方向和挖掘思路，请大佬补充~~  
  
  
  
beginning  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qAbTL3m1KPCCVCvbQtU6iaxaBDBgTia36MrNnqnDTgcJ6ibKkE1pR8AfjtHHfliamEdhcaY84GPGic7BRIicTZBrIeIw/640?wx_fmt=png&from=appmsg "")  
  
**01******  
  
**信息泄露**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qAbTL3m1KPCCVCvbQtU6iaxaBDBgTia36MrNnqnDTgcJ6ibKkE1pR8AfjtHHfliamEdhcaY84GPGic7BRIicTZBrIeIw/640?wx_fmt=png&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qAbTL3m1KPCCVCvbQtU6iaxaBDBgTia36MHfvVhblibTwOuyxfzkYMc9Jj0pibS7hNjQzia3X3YdpbibujHAyykN2IRw/640?wx_fmt=png&from=appmsg "")  
  
开发人员在开发测试阶段方便进行测试，会将一些测试账号信息、云端存储桶密钥、平台appid/appsecret等信息存储于js文件中，通过对js文件进行分析提取获取可利用的泄露信息，以下分享一些在漏洞挖掘中遇到的此类场景的利用手法：  
  
**1. 测试账号泄露**  
  
之前测试发现，开发人员在系统开发过程中为了方便登录测试系统会将测试账号及密码以注释的形式保存在代码中。在测试过程中可以用泄露的账号密码尝试系统登录，或者固定泄露的密码对账号进行爆破。  
  
那如何发现泄露的账号密码？可以先触发一个登录的数据包，获取包里用户名参数，再到浏览器去搜索该参数是否存在对应测试账号泄露，如图：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qAbTL3m1KPCCVCvbQtU6iaxaBDBgTia36MVslI2JrIwZKhZkH5k28wTHLk5QFTjLLcMLr3ZibIrhbcRHP8Wxz44wg/640?wx_fmt=png&from=appmsg "")  
  
当然也有可能登录界面参数和原测试环境参数有不同，所以我梳理了常见的登录账号参数名：username、user、userId、usid、uid、id、name、phone、account、userAccount、mail。密码的话，参数一般为pass、password、pwd、passwd。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qAbTL3m1KPCCVCvbQtU6iaxaBDBgTia36MDztInjBicGXxwqWJX2DLuAsZ9SE3YBCiaOAjVQicv9iaCZD446JRc5QjaA/640?wx_fmt=png&from=appmsg "")  
  
**2. AK/SK泄露**  
  
开发人员将云服务器AK/SK信息保存在js代码中，可以通过泄露信息完成对云服务器的接管。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qAbTL3m1KPCCVCvbQtU6iaxaBDBgTia36M42HRPqDqibI9lCj5UribTJV0C3edl2NV8bjJj4RiaybWSiciabE3VydrLmQ/640?wx_fmt=png&from=appmsg "")  
  
**3. appId/appSecret 泄露**  
  
在小程序js中泄露当前小程序的appId和appSecret，可利用工具通过appId和appSecret生成access_token，获取小程序用户信息、列表信息等，微信官方的说明文档已关闭小程序接口调试功能。推荐一下利用工具API-Explorer，现已支持微信公众号、微信小程序、企业微信、钉钉、飞书等平台的appId/appSecret接管功能，有其他需求评论区提。（工具下载链接见文末）  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qAbTL3m1KPCCVCvbQtU6iaxaBDBgTia36MszCP4oWEotic7vFZViaDIibcjGVNicT41dq93FlyAPdwMEwWLoF77xqUeA/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qAbTL3m1KPCCVCvbQtU6iaxaBDBgTia36MMe5lQS34W1axjwf6Jvuh2Aol9z5HILbdLYVDwGbO1eBhrEE7sXVdWw/640?wx_fmt=png&from=appmsg "")  
  
**4. JWT密钥泄露**  
  
在js代码中搜索jwt，查找代码前后文是否存在jwtKey泄露，或尝试登录等操作获取一个jwtToken通过JWT密钥爆破可以爆破并构造用户cookie，以下是jwtToken工具具体利用方式如下：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qAbTL3m1KPCCVCvbQtU6iaxaBDBgTia36MK2vxC3SMHLYqPqAyJbBcRIaxjySBPgbwtnnROCnhpjW0hFxUGFicWTQ/640?wx_fmt=png&from=appmsg "")  
  
**5. 小程序SessionKey泄露利用**  
  
在之前写过的一篇sessionKey漏洞发掘到漏洞利用的文章中已对该漏洞进行过漏洞挖掘复现，登录授权处系统申请获取微信授权，微信端返回用户会话密钥sessionKey，利用该密钥可对用户授权数据包进行加解密。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qAbTL3m1KPCCVCvbQtU6iaxaBDBgTia36MGTkIU4EpnLsCbqib4ElLNjGk5IUDGe7tr2504dMOvJ3JGv2mga2xHlg/640?wx_fmt=png&from=appmsg "")  
  
**6. mapKey泄露**  
  
mapkey用于第三方网站调用显示及高德地图api进行定位、获取地理标签等服务，网站管理员注册申请的key值，并在系统对地图授权处调用key获取信息，由于地图API后台配置错误，导致ak泄露可以滥用，该mapkey每日调用存在使用上限，滥用会导致地图加载异常。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qAbTL3m1KPCCVCvbQtU6iaxaBDBgTia36Mqbicm8wbKSYgia2LggBSYSqykbV28RX34GBXicrTWNtavebl6ytYdHl3w/640?wx_fmt=png&from=appmsg "")  
  
**7. 内网信息泄露**  
  
部分系统在开发过程中存在内网ip地址泄露，若当前系统存在SSRF漏洞，则可利用该漏洞遍历内网信息。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qAbTL3m1KPCCVCvbQtU6iaxaBDBgTia36MNXghKtw5UzX7ibclcBtrL5XXtfuG5ZOM37l2tmK2U1ibn5TIWlTNeIfg/640?wx_fmt=png&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qAbTL3m1KPCCVCvbQtU6iaxaBDBgTia36MGFJN3YDcneWELxW9kbib5FNoXd0zEAia2SdXTosuKOngX8ISaetNZlFw/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qAbTL3m1KPCCVCvbQtU6iaxaBDBgTia36MrNnqnDTgcJ6ibKkE1pR8AfjtHHfliamEdhcaY84GPGic7BRIicTZBrIeIw/640?wx_fmt=png&from=appmsg "")  
  
**02******  
  
**接口发现**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qAbTL3m1KPCCVCvbQtU6iaxaBDBgTia36MrNnqnDTgcJ6ibKkE1pR8AfjtHHfliamEdhcaY84GPGic7BRIicTZBrIeIw/640?wx_fmt=png&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qAbTL3m1KPCCVCvbQtU6iaxaBDBgTia36M52tg5DFRKOG8sw26TD6klhClibPKXEfdic3s7IwUiafbLtwicMBL76yQoQ/640?wx_fmt=png&from=appmsg "")  
  
在js文件中存在开发人员接口配置信息，包含：接口名、参数设置，利用接口配置信息尝试构造数据包，进行漏洞测试。  
  
**1. 文件上传接口**  
  
代码处搜索upload获取文件上传接口，利用脚本构造文件上传数据包对该接口进行文件上传测试：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qAbTL3m1KPCCVCvbQtU6iaxaBDBgTia36M2Qpy4tianRngLdXNQ3ic0owy0T2f2sTLYicfCqnntjhBDkIKKmRs0y60Q/640?wx_fmt=png&from=appmsg "")  
  
**2. 未授权接口**  
  
提取网站js文件中的接口信息，构造数据包测试未授权漏洞（工具下载链接见文末）：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qAbTL3m1KPCCVCvbQtU6iaxaBDBgTia36Micje83T1Elt3oYSZcgCAOxXBjCELuZVUgonqCHicrZAYm408cNbIPV8w/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qAbTL3m1KPCCVCvbQtU6iaxaBDBgTia36MFDPoz8gwgeoas1KJePAD0utOmts0fJx1Cj0MZvicJMkE5va2WoBIAdw/640?wx_fmt=png&from=appmsg "")  
  
**3. 已废弃接口**  
  
版本更新后未使用但仍存在于代码中的接口，此类接口在系统中无对应功能按钮，但接口本身通过数据包构造仍可正常请求后台信息。例如在登录处，老系统存在注册接口，由于监管标准变更停止使用注册接口的功能按钮，但本身接口数据调用仍可正常实现。还有就是一些比较老的系统在开发之初，代码仅通过账号或账号密码校验，然后在系统漏洞整改过程中重构了代码采用账号、密码、验证码校验，但原有的老校验接口仍未删除，导致可以通过遍历接口来构造登录：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qAbTL3m1KPCCVCvbQtU6iaxaBDBgTia36MoLMG3vFW2u6DGg8foKhbjenbm1FAW0CO6FhShJbw1opCTz9J1mNKcA/640?wx_fmt=png&from=appmsg "")  
  
**4. 根据开发习惯fuzz接口**  
  
啊咧~这个其实来源于平时测试过程中的积累以及gpt使用经验。在批量对未授权接口进行发现过后，可以根据系统的类型来进行接口参数fuzz，例如金融保险行业的合同单号、保单号，在下载接口有遇到没有做随机数重命名的或者权限校验的，然后你可以根据保单编号尝试遍历一下或者根据规则生成一下，看能不能命中一个…就很随机才能遇到一个。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qAbTL3m1KPCCVCvbQtU6iaxaBDBgTia36MicZm2QaRVibfhFuicUVRPErgkNfeb5rjNRRYQERx0LBohBdSq5ibNZJRTQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qAbTL3m1KPCCVCvbQtU6iaxaBDBgTia36MrNnqnDTgcJ6ibKkE1pR8AfjtHHfliamEdhcaY84GPGic7BRIicTZBrIeIw/640?wx_fmt=png&from=appmsg "")  
  
**03******  
  
**数据包解密**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qAbTL3m1KPCCVCvbQtU6iaxaBDBgTia36MrNnqnDTgcJ6ibKkE1pR8AfjtHHfliamEdhcaY84GPGic7BRIicTZBrIeIw/640?wx_fmt=png&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qAbTL3m1KPCCVCvbQtU6iaxaBDBgTia36M52tg5DFRKOG8sw26TD6klhClibPKXEfdic3s7IwUiafbLtwicMBL76yQoQ/640?wx_fmt=png&from=appmsg "")  
  
利用数据包加解密接口、参数名，定位数据包解密函数，进行断点调试。或者搜代码里诸如：AES、RSA、SM4、encrypt这些参数，然后全给打上断点，看访问流量往哪儿跑。但是有遇到那种登录处是一种加密方式、登进去是调用的其他的加密方式，可以去浏览器网络看具体调了那些js，再去js里面断点定位：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qAbTL3m1KPCCVCvbQtU6iaxaBDBgTia36M8ZEq7hOVm8nibneIkfImSWic95XhUdkSZqkcLnnL5oYoLpcl4KosKf5w/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qAbTL3m1KPCCVCvbQtU6iaxaBDBgTia36M5oqhKMEHhbn6wF49pabZL46840bt1xn0570tP6DtSWJXgcnbRDkyTg/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qAbTL3m1KPCCVCvbQtU6iaxaBDBgTia36McjMYkUkm4xFZyPNVaRVrV4UTiab6oY1iaUK86ucolDyh8gTyWlah9VVg/640?wx_fmt=png&from=appmsg "")  
  
在加解密的时候要是遇到随机生成的key，尝试在生成之初就给js代码替换了，写定key，之后好方便生成加解密脚本。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qAbTL3m1KPCCVCvbQtU6iaxaBDBgTia36MCfQCAjBo5sl9ujA49UfVfZFdTu0QVEhYuAnpHSU2OY0hDrVKM6e60w/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qAbTL3m1KPCCVCvbQtU6iaxaBDBgTia36MrNnqnDTgcJ6ibKkE1pR8AfjtHHfliamEdhcaY84GPGic7BRIicTZBrIeIw/640?wx_fmt=png&from=appmsg "")  
  
**04******  
  
**工具汇总**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qAbTL3m1KPCCVCvbQtU6iaxaBDBgTia36MrNnqnDTgcJ6ibKkE1pR8AfjtHHfliamEdhcaY84GPGic7BRIicTZBrIeIw/640?wx_fmt=png&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qAbTL3m1KPCCVCvbQtU6iaxaBDBgTia36M52tg5DFRKOG8sw26TD6klhClibPKXEfdic3s7IwUiafbLtwicMBL76yQoQ/640?wx_fmt=png&from=appmsg "")  
  
工具时用时新，下面是我觉得好用的一些工具，有建议或其他需求github跟一灯师傅提，有需要的自行下载哒~  
  
AK泄露利用工具：  
  
https://github.com/mrknow001/aliyun-accesskey-Tools  
  
appId/appSecret泄露利用工具：  
  
https://github.com/mrknow001/API-Explorer  
  
SessionKey泄露利用工具：  
  
https://github.com/mrknow001/BurpAppletPentester  
  
  
  
**监制丨船长、铁子**  
  
**策划丨Cupid**  
  
**美工丨molin**  
  
  
  
