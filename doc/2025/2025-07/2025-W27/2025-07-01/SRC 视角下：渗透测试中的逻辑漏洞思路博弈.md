> **原文链接**: https://mp.weixin.qq.com/s?__biz=Mzk0Mzc1MTI2Nw==&mid=2247492309&idx=1&sn=971b6609659bdf8e5a1c6cd2c264177b

#  SRC 视角下：渗透测试中的逻辑漏洞思路博弈  
一天要喝八杯水  神农Sec   2025-07-01 01:00  
  
扫码加圈子  
  
获内部资料  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/b7iaH1LtiaKWXLicr9MthUBGib1nvDibDT4r6iaK4cQvn56iako5nUwJ9MGiaXFdhNMurGdFLqbD9Rs3QxGrHTAsWKmc1w/640?wx_fmt=jpeg&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/b96CibCt70iaaJcib7FH02wTKvoHALAMw4fchVnBLMw4kTQ7B9oUy0RGfiacu34QEZgDpfia0sVmWrHcDZCV1Na5wDQ/640?wx_fmt=png&wxfrom=13&wx_lazy=1&wx_co=1&tp=wxpic "")  
  
  
#   
  
网络安全领域各种资源，EDUSRC证书站挖掘、红蓝攻防、渗透测试等优质文章，以及工具分享、前沿信息分享、POC、EXP分享。  
不定期分享各种好玩的项目及好用的工具，欢迎关注。加内部圈子，文末有彩蛋（知识星球优惠卷）。  
#   
  
文章作者：  
一天要喝八杯水  
  
文章来源：https://forum.butian.net/share/4441  
  
**渗透测试中的逻辑漏洞思路博弈**  
  
  
  
渗透测试人员堪称代码世界的 "超级侦探"，手握 
```
Burp Suite
```

  
 这把 "神奇放大镜"，进入甲方的资产海洋遨游,在其中对着页面疯狂改参数、发请求，却总被系统用平淡入手的响应打发，如同在广阔的太平洋掷入一枚石子,不泛起一丝涟漪; 要么直接拦截请求让人气的砸电脑。开局登录框更是 "经典打卡圣地"，测 
```
API
```

  
 接口这边要扮成研究正常逻辑的好学生，那边得秒变设计注入 
```
Payload
```

  
 的 脑洞大师,还得时刻提防 
```
WAF
```

  
悄无声息送你一张
```
404
```

  
飞机票✈️, 漏洞挖掘本就是逆天而行,挖不到才是正常的  
  
最近挖到的中高危漏洞，既没靠 
```
0day
```

  
 这种 "王炸"，也没搞复杂利用链 "炫技"，纯靠瞪大眼睛当 "人肉扫描器"，连标点符号都不放过地逐行比对参数和响应。直到某个昏昏欲睡的下午，随手改了个藏在 
```
JSON
```

  
 数据深处的小参数，系统突然像短路反馈了全新的信息，反常的响应直接暴露未授权访问的 "马脚"。当时激动得差点把咖啡泼到键盘上，看着满地咖啡渍才顿悟 —— 原来倒掉的咖啡，比直接喝咖啡提神一百倍  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUUEKA08QI3Kr3kaLgUaG29ARsqJXEB9MTLGrjm7ua91eH7scDadXAXRuYaktmE3kUBGkEdlPUYNQ/640?wx_fmt=png&from=appmsg "null")  
## 无限抽奖币  
  
新的功能点往往被常规功能点所裹挟,黑盒测试的我们只能点点点,当坚持到隐秘功能点出现的那一刻,漏洞已经是呼之欲出了  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUUEKA08QI3Kr3kaLgUaG29QDic6nYF8mdyqsnJqricd25YIIMAg4L76tOGzIJpfeyT9tlPUCGuvL8Q/640?wx_fmt=png&from=appmsg "null")  
  
微信搜索厂商资产找到一处不起眼的资产,
```
20
```

  
币一次并且可得实物  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUUEKA08QI3Kr3kaLgUaG29gUsHEN9Fic3Jj9B18CudOrmxFgdueXIbqd70wXwwPdA65yic3xxpUoKg/640?wx_fmt=png&from=appmsg "null")  
  
初始币是
```
100
```

  
当我小心翼翼的尝试投币点进行一些,自定投币数量,修改返回包控制所得物品,并发签到等操作时,结果洞还没挖到我的游戏币就已经快测没了,真的是天塌了  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUUEKA08QI3Kr3kaLgUaG29efNM6Pfl7ner4ibv1BzRLNHId7VfURx8m1jRgicbJbJkBcoGs3YDaENw/640?wx_fmt=png&from=appmsg "null")  
  
当时已经非常晚了到了12点,当我最后一次爪子进行抓娃娃的时候,修改请求包发现还是一无所获,悬着的心最终还是死了,已经准备
```
win+x+u u
```

  
 光速下播,但游戏币消失的时候又出现了新的功能点,这让我死去的心又再次燃烧起来  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUUEKA08QI3Kr3kaLgUaG29jDLicJdKZIU8S9pskAibescpSmUZmy2ficribOO8NzyluLKB2aNxX8F0QA/640?wx_fmt=png&from=appmsg "null")  
  
分享赚币,点击后
```
BP
```

  
记录接口,在历史记录逐个对数据包进行查看,最终凭借经验锁定
```
/app/point/doll/share
```

  
接口就是关键的数值包,它的值所控制的就是所得金币数量  

```
points=15

```

  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUUEKA08QI3Kr3kaLgUaG29z7xTJbYobibWJAKtZVRXSrdCcodfYzI0HDoz9g022N5tT32tHwhedHQ/640?wx_fmt=png&from=appmsg "null")  
  
思路都理清了那还说啥,直接重发狠狠的输入最大数值  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUUEKA08QI3Kr3kaLgUaG29ibJE28H2ICJicuereYCp8blWrVnfyDRnyhEicEOdzobV6bibzs0pRl7MSg/640?wx_fmt=png&from=appmsg "null")  
  
不出意外成功,爽吃一中,又可以多买几个馒头恰了,这次渗透告诉我,不测试完所有功能点就绝对不轻言放弃,不要自己跟自己说丧气话,因为大多数人在一个站比如测试越权发现有鉴权,就下定义觉得这个站已经没有越权了,这是万万不行的,作为白帽子最后是把所有思路穷尽才算是一次完整的渗透测试,细心再细心,虽然这样很枯燥但是长此以往相信肯定会有所收获  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUUEKA08QI3Kr3kaLgUaG29Q1IO5nNPv7B8FaNoHtMWEk551pOjzb3ASQibHzWPvDXFH2BiaZNsFqnQ/640?wx_fmt=png&from=appmsg "null")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUUEKA08QI3Kr3kaLgUaG29ucTWBIibx7mM7hmp2nH4e7GkP5HV4A8IJzwpqZFdWuiaRbQrCMoXIIWg/640?wx_fmt=png&from=appmsg "null")  
## 可控所得优惠卷  
  
功能点购入某些物品系统会赠送一部分优惠卷,但大多是一些小额优惠卷,除非购买昂贵的服务才会赠送价格不菲的优惠卷,利用低级服务所得优惠卷,通过手法找到高等级优惠卷对应
```
token
```

  
，替换后造成刷优惠卷效果  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUUEKA08QI3Kr3kaLgUaG29nBKcnyQZ1icVqj6jVfUXlEndSDqf4YBCI6SvpggsUFaS5UVKcF4K4lg/640?wx_fmt=png&from=appmsg "null")  
  
站点特征较明显,省略一些前期发现步骤,快进到数据包分析,选择一个商品服务进行下单,
```
BP
```

  
记录所有流量,通过逐个分析定位到此接口为关键的创建订单包,将其测试发送到重发起等待进一步测试  

```
https://xxxxx/restapi/soa2/19691/orderCreate?_fxpcqlnired

```

  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUUEKA08QI3Kr3kaLgUaG291AvpRp81w9186bRPTwNq8yd3fJodzkQ72ulwGdPIUru7Oab9z5wWkg/640?wx_fmt=png&from=appmsg "null")  
  
进行小程序看先前创建的订单,看有没有可以操作的业务,观察到订单创建后成功支付会相对应的赠送优惠卷  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUUEKA08QI3Kr3kaLgUaG29TzibicpiaugpQ3qVOhWZXaLlxiaBiaRAzwdCzSe01ODVGPUUntdpS5u1r9w/640?wx_fmt=png&from=appmsg "null")  
  
都是一些不起眼的小福利卷,跟
```
QQ
```

  
空间兰博基尼
```
5
```

  
元代金券不能说没有区别只能说一模一样  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUUEKA08QI3Kr3kaLgUaG29zeU3ibpia6ZQQ5RVibntniaNvMiaLNIPMMkbXxEO6HOuYvrVcZSWhD2eqWA/640?wx_fmt=png&from=appmsg "null")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUUEKA08QI3Kr3kaLgUaG29MGDP1WOnXcCpEf2nHKl2VnZn7icNGKSIjX5E9de3ZxiaFwibZ9J4WiaDxA/640?wx_fmt=png&from=appmsg "null")  
  
将创建订单接口发送到重发器后,观察数据包,这种涉及多个流程的业务数据包一般都很多参数,有的是关键参数,有的是多余参数用于迷惑,通过"人肉扫描器"一段段观察,定位到
```
data
```

  
 数据体记录了优惠卷对应的
```
token
```

  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUUEKA08QI3Kr3kaLgUaG29r6szaTyAaes3LM3mJ5lAqQBqwSAsBoZpmjc2xPicPGlasTdUZd9jHTg/640?wx_fmt=png&from=appmsg "null")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUUEKA08QI3Kr3kaLgUaG29gAyxZPJKIbPay6ehpt3yYqH1XWEl5l3iab9sOQQLKq9arR9tVBkJm4w/640?wx_fmt=png&from=appmsg "null")  
  
通过一系列手法,找到了其他优惠卷的
```
token
```

  
,然后对先前的三处优惠卷
```
token
```

  
进行替换.并且全是一模一样的,意味着我可以通过低级服务自定义所得优惠卷,并且叠加  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUUEKA08QI3Kr3kaLgUaG29sianvfMY39maGqoJsQs9l5Bfp2MFcj5ZEZx9klxJk1FumgibdicNouuQQ/640?wx_fmt=png&from=appmsg "null")  
  
当前替换后再次创建新订单,先前的三张低级优惠卷已经被替换为了三张豪车打车减免卷,并且只需要我知道任意卷的
```
token
```

  
,就可以得到对应券,还可以叠加字段进行复用  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUUEKA08QI3Kr3kaLgUaG29YwTdWk6WaFibAzW8TTt5HDvZ7ScK6KJ5kReFMx635jzHlC4ia01Tag9Q/640?wx_fmt=png&from=appmsg "null")  
## 普通的CSRF  
  
如今各种逻辑漏洞,云攻防,
```
Top10
```

  
 为主流的今天,最基础的
```
CSRF
```

  
往往是同其他漏洞结合利用,但忽略了单个
```
CSRF
```

  
所能造成的影响,我理解的是只要功能涉及到主观操作场景,如修改信息,增加收货地址,发送邮件...等等需要主观意愿才能进行,并且请求中并没有发现
```
token
```

  
或其他校验字段均可以尝试
```
CSRF
```

  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUUEKA08QI3Kr3kaLgUaG29uDnwtUZUpbrqs87J4OGo6kwtkaqXPZBd3E4PZYgGp3Cjzejp1ADvNQ/640?wx_fmt=png&from=appmsg "null")  
  
正常用户修改绑定的邮箱需要输入交易密码才可以修改，但是功能点的个人信息接口可以直接修改绑定的邮箱,制作
```
post
```

  
请求的
```
csrf
```

  
数据包发送受害者点击, 就会自动修改绑定邮箱及个人信息为我们所设置的  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUUEKA08QI3Kr3kaLgUaG29uGhXBDYtIvGa1V1JMSib8oVYqEOplhmrnLKsviaicCwhqjwpwvnjRD2Bg/640?wx_fmt=png&from=appmsg "null")  
  
为不影响业务,实名认证后准备两个小号相互测试  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUUEKA08QI3Kr3kaLgUaG29XMf7fk5MLFG1JLWfib7y1gdibQHTiazBgvic3y6eeppdCPwEW79umbO7Jw/640?wx_fmt=png&from=appmsg "null")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUUEKA08QI3Kr3kaLgUaG29wib0LwiadqlGuvxGQfW5rrglw3wibt3LDj5fMCOibicJXoF4FicQQnAlJF0g/640?wx_fmt=png&from=appmsg "null")  
  
对个人信息进行修改,
```
BP
```

  
记录所有的流量,此接口为更新信息  

```
/fund/apl/postUserinfo

```

  
观察更新个人信息功能第一是携带了邮箱更新,如上所示,正常我们单独修改关键的邮箱是需要交易密码的, 因为站点是一处涉及基金交易,但是普通的修改个人信息却是可以直接修改邮箱,跳过交易密码,第二是请求包没有
```
token
```

  
等其他涉及状态码字段,那么是不是可以尝试一下
```
CSRF
```

  
呢  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUUEKA08QI3Kr3kaLgUaG29LrFIuhb6wMfn1YyQ5ia9n99HlApjiaejNzbc3tdOd9x8rYhh9Uibu2rfA/640?wx_fmt=png&from=appmsg "null")  
  
将更新
```
POST
```

  
请求右键制作为
```
CSRFPOC
```

  
 把生成的代码拷贝一下随意改一下信息为自定义的,然后本地作为
```
html
```

  
文件  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUUEKA08QI3Kr3kaLgUaG29k0Wrn9AUPjTXLf9WCu9oPDp1Is9kocl2LbmysCJd0XphCiaoatJEhyw/640?wx_fmt=png&from=appmsg "null")  
  

```
poc.html
```

  
 用当前小号登录的浏览器去打开,点击后返回修改成功  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUUEKA08QI3Kr3kaLgUaG29OEx9KQg5C3LHNJXspljzico68y3ia72CdtZbVWpWOsBfR6Qjs1Noty0w/640?wx_fmt=png&from=appmsg "null")  
  
刷新站点,当前的个人信息包括邮箱已经是我们所设置的,
```
CSRF
```

  
 攻击成功  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUUEKA08QI3Kr3kaLgUaG29exI3s3ErRe0ibDVer5EIPLibVbR6Wj2IFPXl3luJYYbeypxYvmPozBzw/640?wx_fmt=png&from=appmsg "null")  
## 网站泄露导致接管  
  
写多了企业
```
SRC
```

  
报告,现如今刚刚初入社会投身于工作当中,下班后再去花精力挖掘
```
SRC
```

  
可能是越来越少,还是怀念大学的时光没有压力,别管挖没挖到洞,你只管去挖剩下的交给时间,现在如果下班没有产出其实还是挺浪费时间的,因为本来是可以利用这个时间再去学习一些新知识,提高自己技术....分享一个在近期在公司渗透测试一个单位的过程,最终也是拿下网站超级管理员  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUUEKA08QI3Kr3kaLgUaG29oHsKdaOSGfx97Gv98KtuEmFJ4Kcj5qia0RYkKooXypQ4NpEibPslNW0Q/640?wx_fmt=png&from=appmsg "null")  
  
企业
```
SRC
```

  
大多目标较少,且会给出具体的域名范围,工作渗透项目因为是会有地区网信办授权,所以给我某一地区庞大的单位,从中进行渗透,海量的资产梳理不是一件简单的事情  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUUEKA08QI3Kr3kaLgUaG29pt1CtiagOn7bmcXZ9ajkEUdW2X8OBfBibugl91ACEicWzdR8AXMamXomg/640?wx_fmt=png&from=appmsg "null")  
### 测绘资产处理  
  
众多单位名有些是存在备案网址的,这些才是有效资产可以进行渗透,那么无备案的单位如果排除呢？测绘网站
```
hunter
```

  
可以很好的做到这一点，它支持企业备案名称进行查询,这是其他
```
fofa 360
```

  
 都没有的,所有在攻防项目还是企业渗透开局海量单位名
```
hunter
```

  
是最佳的选择,唯一缺点这个打法比较吃积分  

```
icp.name=&#34;xxx&#34;

```

  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUUEKA08QI3Kr3kaLgUaG29cUDHicz33ic2sujkGVgJ1vM9m2kSnicCzJ6yR6RkV4KgEKR5Ymws6UUyw/640?wx_fmt=png&from=appmsg "null")  
  
既然知道
```
hunter
```

  
可以根据备案名查询,那么写一个批量脚本,填入
```
API
```

  
进行调用语法即可  

```
import requests
import base64
import time
import json
import pandas as pd

# 鹰图平台的 API 地址
BASE_URL = &#34;https://hunter.qianxin.com&#34;
SEARCH_ENDPOINT = &#34;/openApi/search&#34;

# 你的 API Key（从鹰图平台获取）
API_KEY = &#34;&#34;# 替换为实际的 API Key

# 字段翻译映射表
FIELD_TRANSLATION = {
&#34;code&#34;: &#34;状态码&#34;,
&#34;message&#34;: &#34;错误信息&#34;,
&#34;data&#34;: &#34;数据部分&#34;,
&#34;total&#34;: &#34;资产总数&#34;,
&#34;time&#34;: &#34;时间&#34;,
&#34;arr&#34;: &#34;资产列表&#34;,
&#34;is_risk&#34;: &#34;风险资产&#34;,
&#34;url&#34;: &#34;URL地址&#34;,
&#34;ip&#34;: &#34;IP地址&#34;,
&#34;port&#34;: &#34;端口号&#34;,
&#34;web_title&#34;: &#34;网站标题&#34;,
&#34;domain&#34;: &#34;域名&#34;,
&#34;is_risk_protocol&#34;: &#34;高危协议&#34;,
&#34;protocol&#34;: &#34;协议类型&#34;,
&#34;base_protocol&#34;: &#34;通讯协议&#34;,
&#34;status_code&#34;: &#34;网站状态码&#34;,
&#34;component&#34;: &#34;应用组件/版本&#34;,
&#34;os&#34;: &#34;操作系统&#34;,
&#34;company&#34;: &#34;备案单位&#34;,
&#34;number&#34;: &#34;备案号&#34;,
&#34;icp_exception&#34;: &#34;备案异常&#34;,
&#34;country&#34;: &#34;国家&#34;,
&#34;province&#34;: &#34;省份&#34;,
&#34;city&#34;: &#34;市区&#34;,
&#34;ip_tag&#34;: &#34;IP标签&#34;,
&#34;asset_tag&#34;: &#34;资产标签&#34;,
&#34;vul_list&#34;: &#34;历史漏洞&#34;,
&#34;updated_at&#34;: &#34;探查时间&#34;,
&#34;is_web&#34;: &#34;Web资产&#34;,
&#34;name&#34;: &#34;组件名称&#34;,
&#34;version&#34;: &#34;组件版本&#34;,
&#34;as_org&#34;: &#34;注册机构&#34;,
&#34;isp&#34;: &#34;运营商信息&#34;,
&#34;banner&#34;: &#34;服务标识信息&#34;,
&#34;header&#34;: &#34;HTTP响应头&#34;,
&#34;sha256&#34;: &#34;证书签名哈希算法(SHA256)&#34;,
&#34;consume_quota&#34;: &#34;消耗积分&#34;,
&#34;rest_quota&#34;: &#34;今日剩余积分&#34;
}

# 从 txt 文件读取公司名称列表
def load_company_names(file_path):
try:
        with open(file_path, 'r', encoding='utf-8') as f:
            companies = [line.strip() for line in f.readlines() if line.strip()]
return companies
    except FileNotFoundError:
print(f&#34;错误：文件 {file_path} 不存在&#34;)
return []
    except Exceptionas e:
print(f&#34;读取文件时出错: {e}&#34;)
return []

# 公司名称文件路径
COMPANY_FILE = &#34;dz.txt&#34;

# 加载公司名称列表
company_names = load_company_names(COMPANY_FILE)
if not company_names:
print(&#34;没有可用的公司名称，请检查 gs.txt 文件内容&#34;)
exit()

# 请求参数
page_size = 10# 每页资产条数

# 存储所有检索结果
results = []
no_data_companies = []

for company_name in company_names:
print(f&#34;\n正在查询公司: {company_name}&#34;)
    page = 1
    total_pages = 1
    has_data = False

while page <= total_pages:
        search_query = f'icp.name=&#34;{company_name}&#34;'
        search_encoded = base64.urlsafe_b64encode(search_query.encode(&#34;utf-8&#34;)).decode(&#34;utf-8&#34;)

        params = {
&#34;api-key&#34;: API_KEY,
&#34;search&#34;: search_encoded,
&#34;page&#34;: page,
&#34;page_size&#34;: page_size
        }

try:
            response = requests.get(
                f&#34;{BASE_URL}{SEARCH_ENDPOINT}&#34;,
                params=params,
                timeout=15
            )
            response.raise_for_status()

            data = response.json()

# 转换状态码为是/否
if&#34;code&#34; in data:
                data[&#34;status&#34;] = &#34;是&#34;if data[&#34;code&#34;] == 200else&#34;否&#34;

if data.get(&#34;code&#34;) == 429:
print(f&#34;公司 {company_name} 请求过多，等待15秒后重试...&#34;)
                time.sleep(15)
continue

if data.get(&#34;code&#34;) != 200:
print(f&#34;公司 {company_name} 检索失败: {data.get('message')}&#34;)
break

            total = data.get(&#34;data&#34;, {}).get(&#34;total&#34;, 0)
            total_pages = (total + page_size - 1) // page_size

if data.get(&#34;data&#34;, {}).get(&#34;arr&#34;):
                has_data = True

# 移除banner字段
for item in data[&#34;data&#34;][&#34;arr&#34;]:
if&#34;banner&#34; in item:
                        del item[&#34;banner&#34;]

                results.append({
&#34;company_name&#34;: company_name,
&#34;page&#34;: page,
&#34;data&#34;: data
                })

print(f&#34;公司 {company_name} 第 {page}/{total_pages} 页检索完成，共 {total} 条结果&#34;)
            page += 1
            time.sleep(1.5)

        except requests.exceptions.RequestException as e:
print(f&#34;公司 {company_name} 请求失败: {e}&#34;)
break

if not has_data:
        no_data_companies.append(company_name)

# 统计结果
total_companies = len(company_names)
no_data_count = len(no_data_companies)
print(f&#34;\n总共查询了 {total_companies} 个公司，其中 {no_data_count} 个未查询到数据。&#34;)

# 保存原始JSON结果
timestamp = time.strftime(&#34;%Y%m%d_%H%M%S&#34;)
filename = f&#34;search_results_{timestamp}.json&#34;
with open(filename, &#34;w&#34;, encoding=&#34;utf-8&#34;) as f:
    json.dump(results, f, ensure_ascii=False, indent=4)

# 保存无数据公司名单
no_data_filename = f&#34;no_data_companies_{timestamp}.txt&#34;
with open(no_data_filename, &#34;w&#34;, encoding=&#34;utf-8&#34;) as f:
    f.write(&#34;\n&#34;.join(no_data_companies))

# 准备Excel数据
excel_data = []
for result in results:
    company_name = result[&#34;company_name&#34;]
    status = result[&#34;data&#34;].get(&#34;status&#34;, &#34;否&#34;)  # 获取状态码转换结果

for item in result[&#34;data&#34;][&#34;data&#34;][&#34;arr&#34;]:
        row = {&#34;公司名称&#34;: company_name, &#34;请求状态&#34;: status}

# 添加所有字段到行数据
for field, translation in FIELD_TRANSLATION.items():
if field in item:
                row[translation] = item[field]
            elif field in result[&#34;data&#34;]:
                row[translation] = result[&#34;data&#34;][field]

        excel_data.append(row)

# 创建DataFrame
df = pd.DataFrame(excel_data)

# 保存为Excel文件
excel_filename = f&#34;search_results_{timestamp}.xlsx&#34;
df.to_excel(excel_filename, index=False)

print(f&#34;\n所有公司检索完成，结果已保存到 {filename}&#34;)
print(f&#34;查询不到的公司名称已保存到 {no_data_filename}&#34;)
print(f&#34;Excel表格已保存到 {excel_filename}&#34;)

```

  
填入公司名在
```
dz.txt
```

  
 结束好后会生成
```
json
```

  
 格式文件和
```
xlsh
```

  
 文件  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUUEKA08QI3Kr3kaLgUaG29OeLNZz1rE7uyPI6dUkoH23ibeeLx8Dia9XFH3U2687GGpicz4gWhgdhrA/640?wx_fmt=png&from=appmsg "null")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUUEKA08QI3Kr3kaLgUaG29YgXb1kPODRzVKxVtc6nIRJImCModpCa0GzNPLOjEkNfjZez7t54pkA/640?wx_fmt=png&from=appmsg "null")  
  
通过这个步骤收集到的域名资产我一般是保留
```
200
```

  
状态码,之后便会开始
```
nuclei
```

  
和
```
afrog
```

  
同步进行扫描,收取漏洞标准没有限制所以在手工测试前,配置好的自动化工具就会帮我们找好一些
```
swagger
```

  
泄露 ,目录遍历,以及一些
```
CVE
```

  
 和高危的端口服务,可以再进行弱口令的爆破等等  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUUEKA08QI3Kr3kaLgUaG29f6VZAy95q2oa1h4fUt0DUaicwPF73zsLRKmiaHM7fLYRz77H3sF2h2Lw/640?wx_fmt=png&from=appmsg "null")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUUEKA08QI3Kr3kaLgUaG29icN5Kp37WC2hNUKN2HxcqVbtPpmwAIQW5ZtvU2Nseh8LWCTJsdpjIEQ/640?wx_fmt=png&from=appmsg "null")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUUEKA08QI3Kr3kaLgUaG296Ly2ebt3mW2p7Inqwl2ck2t2KlACrXjl0Cyia5dzZrm5cic058iabw1Iw/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUUEKA08QI3Kr3kaLgUaG29zMmG7RMn1SGPibKazsHFrDeRnzARHgxCRF30zSp9NfYiaqUV2l8BNnjg/640?wx_fmt=png&from=appmsg "null")  
### 渗透实战  
  
当资产在被扫描器轮番测试时，这个时间就开始逐一对资产进行手工测试,开局一个首页,看起来确实没什么功能点,现在可以选择的测试是目录扫描和接口未授权  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUUEKA08QI3Kr3kaLgUaG29hQCsdKrHv2fOl1cFn1B9AW36MHDCuibnEPtjRQMHAgrNpEKicQ95G8ew/640?wx_fmt=png&from=appmsg "null")  
  
打开我的
```
dirsearch
```

  
为了应对不同的目标架构还有需求,需要在多个不同的命令行参数间转换,各位白帽师傅可以让
```
ai
```

  
 辅助写一个
```
bat
```

  
 脚本去调用工具不同的参数从而在单个目标 多个目标,递归目标间迅速切换  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUUEKA08QI3Kr3kaLgUaG29JHQePKbaWaKJrN4cp5ian1ebjZzkxVvY6Hj9IB1VhqWF92h1efZCNNA/640?wx_fmt=png&from=appmsg "null")  
  
相信大家都发现了出现了一个
```
Admin
```

  
目录大概率是网站管理后台  

```
http://xxxxx.com/Admin/

```

  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUUEKA08QI3Kr3kaLgUaG29zEYV8m79utwjSicicAEt4CFmniaS6s7TbDC0GI6WQZiaHiaqH9vlmZygcmQ/640?wx_fmt=png&from=appmsg "null")  
  
提示超时,那么应该是进行鉴权 了,状态码
```
301
```

  
调整到了网站管理登录页面  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUUEKA08QI3Kr3kaLgUaG29btUVYdk5UeRicVwqnwibRyUkB3jj089dMqjmxfa0fE93HO6WkT0WHpOg/640?wx_fmt=png&from=appmsg "null")  
  
登录框先尝试了简单的弱口令
```
admin admin
```

  
 几个经典账号密码,均失败,注意到网站标题是
```
xx
```

  
网络,这个时候我在想这个会不会是个框架呢,遂寻找是否有相关文章  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUUEKA08QI3Kr3kaLgUaG29juT5xPEY0Q0jPaCicF9gVGx5HicDwyPYEeBFadNkZbfoSicEXzIxurDxA/640?wx_fmt=png&from=appmsg "null")  
  
查询到了对应的服务商企业,但却十分小众,并没有公开的漏洞,开始测试接口看着能不能信息泄露,但是接口同样少的可怜,此时常规思路已经穷尽,站点还是没有拿下,哈基W 还是办不到吗。。。  
  
此时只剩下两个选择,继续尝试突破登录框,虽然有验证码但是开启验证码插件还是可以继续爆破的不过完全是听天由命,二是继续在目录处做操作,既然一开始就可以爆破出登录框,证明站点防护并不是特别好,第一层目录就是
```
admin
```

  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUUEKA08QI3Kr3kaLgUaG296BD8bdpB0QpXlsTKgXGqrtVcXbiaYYwzibknATBia82NhLsCXtukzbndg/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUUEKA08QI3Kr3kaLgUaG29iceav28urRQiajw9e361H2lw1daGLqpIeXkKO55xH08PXaY5dRrYtYzA/640?wx_fmt=png&from=appmsg "null")  
  
回到第一步查看
```
dirsearch
```

  
 结果,我擦看我发现了什么,朴实无华的
```
password.txt
```

  
 不会吧不会把 不会真有人把密码写进目录然后没有删掉吧,开什么玩笑啊 居然这么简单吗  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUUEKA08QI3Kr3kaLgUaG29pokDPFb8b0nKr3cXtz2g7YibKYxrwTNNpqp7hwhBCiatUnapkzzVKlYQ/640?wx_fmt=png&from=appmsg "null")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUUEKA08QI3Kr3kaLgUaG29icuuGb2D9UKkKvIuObs1NSXJQlSLoHE4NpxtpqYGfrSpmAGbjrQeJ6w/640?wx_fmt=png&from=appmsg "null")  
  
一气呵成,拿下后台,点到为止  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUUEKA08QI3Kr3kaLgUaG290bgYaal1jP0mawibKUr9yxic0S75epjBMAGK526eGA13wwYI5gDIavpA/640?wx_fmt=png&from=appmsg "null")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUUEKA08QI3Kr3kaLgUaG29ic5icWwGS6YtgibA2126k8V5Dp9JmmF9C0vPSgE08KSbsSZYbN10Fyckg/640?wx_fmt=png&from=appmsg "null")  
## 总结  
  
没有华而不实的屠龙术只有重复99个数据包,仅有第100个数据包产生了惊喜,唯有点滴的付出,你坚持的东西总有一天会反过来拥抱你; 之前文章觉得过于死板加入一些诙谐幽默的叙事方法,让各位读者阅读我的文章不像是一本正经的聊技术,更是像一位朋友一般分享着我的挖掘经历以及心态转换过程,看的开心又能学到技术;欢迎学习交流,往后会在社区投稿更多实战案例。  
  
  
**内部小圈子详情介绍**  
  
  
  
我们是  
神农安全  
，点赞 + 在看  
 铁铁们点起来，最后祝大家都能心想事成、发大财、行大运。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/mngWTkJEOYJDOsevNTXW8ERI6DU2dZSH3Wd1AqGpw29ibCuYsmdMhUraS4MsYwyjuoB8eIFIicvoVuazwCV79t8A/640?wx_fmt=png&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/MVPvEL7Qg0F0PmZricIVE4aZnhtO9Ap086iau0Y0jfCXicYKq3CCX9qSib3Xlb2CWzYLOn4icaWruKmYMvqSgk1I0Aw/640?wx_fmt=gif&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
**内部圈子介绍**  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/MVPvEL7Qg0F0PmZricIVE4aZnhtO9Ap08Z60FsVfKEBeQVmcSg1YS1uop1o9V1uibicy1tXCD6tMvzTjeGt34qr3g/640?wx_fmt=gif&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
  
**圈子专注于更新src/红蓝攻防相关：**  
  

```
1、维护更新src专项漏洞知识库，包含原理、挖掘技巧、实战案例
2、知识星球专属微信“小圈子交流群”
3、微信小群一起挖洞
4、内部团队专属EDUSRC证书站漏洞报告
5、分享src优质视频课程（企业src/EDUSRC/红蓝队攻防）
6、分享src挖掘技巧tips
7、不定期有众测、渗透测试项目（一起挣钱）
8、不定期有工作招聘内推（工作/护网内推）
9、送全国职业技能大赛环境+WP解析（比赛拿奖）
```

  
  
  
  
**内部圈子**  
**专栏介绍**  
  
知识星球内部共享资料截屏详情如下  
  
（只要没有特殊情况，每天都保持更新）  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWWYcoLuuFqXztiaw8CzfxpMibRSekfPpgmzg6Pn4yH440wEZhQZaJaxJds7olZp5H8Ma4PicQFclzGbQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWWYcoLuuFqXztiaw8CzfxpMibgpeLSDuggy2U7TJWF3h7Af8JibBG0jA5fIyaYNUa2ODeG1r5DoOibAXA/640?wx_fmt=png&from=appmsg "")  
  
  
**知识星球——**  
**神农安全**  
  
星球现价   
￥45元  
  
如果你觉得应该加入，就不要犹豫，价格只会上涨，不会下跌  
  
星球人数少于900人 45元/年  
  
星球人数少于1000人 60元/年  
  
（新人优惠卷20，扫码或者私信我即可领取）  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWU0bsia0ju14OCUfVMSnyJJX4SAHwM2uxfzyQ99oMpk5ib5iavqd6nQicUWV26KKYYvm9e9AkIXKBYFBg/640?wx_fmt=png&from=appmsg "")  
  
欢迎加入星球一起交流，券后价仅45元！！！ 即将满900人涨价  
  
长期  
更新，更多的0day/1day漏洞POC/EXP  
  
  
  
**内部知识库--**  
**（持续更新中）**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUw2r3biacicUOicXUZHWj2FgFu12KTxgSfI69k7BChztff43VObUMsvvLyqsCRYoQnRKg1ibD7A0U3bQ/640?wx_fmt=png&from=appmsg "")  
  
  
**知识库部分大纲目录如下：**  
  
知识库跟  
知识星球联动，基本上每天保持  
更新，满足圈友的需求  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUw2r3biacicUOicXUZHWj2FgFhXF33IuCNWh4QOXjMyjshticibyeTV3ZmhJeGias5J14egV36UGXvwGSA/640?wx_fmt=png&from=appmsg "")  
  
  
知识库和知识星球有师傅们关注的  
EDUSRC  
和  
CNVD相关内容（内部资料）  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUw2r3biacicUOicXUZHWj2FgFKDNucibvibBty5UMNwpjeq1ToHpicPxpNwvRNj3JzWlz4QT1kbFqEdnaA/640?wx_fmt=png&from=appmsg "")  
  
  
还有网上流出来的各种  
SRC/CTF等课程视频  
  
量大管饱，扫描下面的知识星球二维码加入即可  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUw2r3biacicUOicXUZHWj2FgFxYMxoc1ViciafayxiaK0Z26g1kfbVDybCO8R88lqYQvOiaFgQ8fjOJEjxA/640?wx_fmt=png&from=appmsg "")  
  
  
  
不会挖CNVD？不会挖EDURC？不会挖企业SRC？不会打nday和通杀漏洞？  
  
直接加入我们小圈子：  
知识星球+内部圈子交流群+知识库  
  
快来吧！！  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUMULI8zm64NrH1pNBpf6yJ5wUOL9GnsxoXibKezHTjL6Yvuw6y8nm5ibyL388DdDFvuAtGypahRevg/640?wx_fmt=png&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1 "")  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_jpg/b7iaH1LtiaKWUMULI8zm64NrH1pNBpf6yJO0FHgdr6ach2iaibDRwicrB3Ct1WWhg9PA0fPw2J1icGjQgKENYDozpVJg/640?wx_fmt=other&tp=webp&wxfrom=5&wx_lazy=1 "")  
  
  
神农安全知识库内部配置很多  
内部工具和资料💾，  
玄机靶场邀请码+EDUSRC邀请码等等  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWXjm2h60OalGLbwrsEO8gJDNtEt0PfMwXQRzn9EDBdibLWNDZXVVjog7wDlAUK1h3Y7OicPQCYaw2eA/640?wx_fmt=png&from=appmsg "")  
  
  
快要护网来临，是不是需要  
护网面试题汇总  
？  
问题+答案（超级详细🔎）  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWXjm2h60OalGLbwrsEO8gJDbLia1oCDxSyuY4j0ooxgqOibabZUDCibIzicM6SL2CMuAAa1Qe4UIRdq1g/640?wx_fmt=png&from=appmsg "")  
  
  
最后，师傅们也是希望找个  
好工作，那么常见的  
渗透测试/安服工程师/驻场面试题目，你值得拥有！！！  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWXjm2h60OalGLbwrsEO8gJDicYew8gfSB3nicq9RFgJIKFG1UWyC6ibgpialR2UZlicW3mOBqVib7SLyDtQ/640?wx_fmt=png&from=appmsg "")  
  
  
内部小圈子——  
圈友反馈  
（  
良心价格  
）  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWW0s5638ehXF2YQEqibt8Hviaqs0Uv6F4NTNkTKDictgOV445RLkia2rFg6s6eYTSaDunVaRF41qBibY1A/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWW0s5638ehXF2YQEqibt8HviaRhLXFayW3gyfu2eQDCicyctmplJfuMicVibquicNB3Bjdt0Ukhp8ib1G5aQ/640?wx_fmt=png&from=appmsg "")  
  
  
****  
**神农安全公开交流群**  
  
有需要的师傅们直接扫描文章二维码加入，然后要是后面群聊二维码扫描加入不了的师傅们，直接扫描文章开头的二维码加我（备注加群）  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/b7iaH1LtiaKWUxMYhvbNTx2MbdTb6DpIaX7AicI3tqibhLhQcrwZ2PH9XygJXxdlKwt3lqOqYlCJUE8IBHw43Ox2zQ/640?wx_fmt=jpeg&from=appmsg "")  
  
    

```
申明：本公众号所分享内容仅用于网络安全技术讨论，切勿用于违法途径，所有渗透都需获取授权，违者后果自行承担，与本号及作者无关，请谨记守法.

```

  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/b7iaH1LtiaKWW8vxK39q53Q3oictKW3VAXz4Qht144X0wjJcOMqPwhnh3ptlbTtxDvNMF8NJA6XbDcljZBsibalsVQ/640?wx_fmt=gif "")  
  
  
  
