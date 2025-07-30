#  安全课堂｜关于小程序AppSecret密钥泄露漏洞官方   
枇杷五星加强版  黑伞安全   2023-09-01 13:24  
  
为进一步提升小程序的安全性和用户体验，目前平台对提审的小程序均需进行安全检测，在检测过程中发现仍有许多小程序存在安全漏洞，其中涉及AppSecret密钥泄露漏洞，希望通过以下相关的漏洞介绍、案例分析和修复建议，开发者能更加了解如何对该漏洞进行防御。  
  
**一、漏洞介绍**  
  
AppSecret是小程序的唯一凭证密钥，也是获取小程序全局唯一后台接口调用凭证（access_token  
）的重要参数，需要开发者妥善保管至后台服务器中，并严格保密，不向任何第三方等透露。小程序若存在AppSecret密钥泄露漏洞的情况，会造成身份信息仿冒、敏感数据外泄等严重后果，开发者应及时发现该漏洞并快速修复相应问题。  
  
**二、漏洞案例**  
  
某小程序因为AppSecret泄露，导致攻击者可以通过调用API获取该小程序敏感数据，如接口调用凭证、用户信息、用户使用数据等，造成了极大的安全风险。  
  
通过以下展示我们可以明晰该小程序敏感数据外泄的原因，测试者先对小程序网络请求进行抓包，发现请求响应中包含了appid和AppSecret敏感信息：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/0aGWwHGxPqZlPQ32CniaibJXpQFd9w0LwT1hX41G9wLIQh5NTcHr7lTsQibmpupKb3Sb77WjQOsTj0VXyFWtANoMA/640?wx_fmt=png "")  
﻿ ﻿  
  
通过上述获取的appid和AppSecret敏感信息，可以利用接口获取到相应的access_token：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ZS0VQrDMfGpUYX7ibOULIib3JJbc1gvugz67PhAhpNnEo0XdBuZpZzIy8bZsulStngwfKqmyDCicZ4yNC5F2WjYhw/640?wx_fmt=png "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/0aGWwHGxPqZlPQ32CniaibJXpQFd9w0LwTLzBcy1lxxTR5TIWNwZnXdm8lSfUN0Jpauic1MMD7kX4qZCMPA7AVWcQ/640?wx_fmt=png "")  
  
最后可以实现使用access_token调用该小程序所有后台接口的目的，后台服务端接口  
已涵盖数据、运维、消息等多方面场景能力。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ZS0VQrDMfGpUYX7ibOULIib3JJbc1gvugzCfo0aLtZvm5ZIo1IqxM6WrdYoA0HYWFBNZyHv45Qs8usnIBSJSW2Dw/640?wx_fmt=png "")  
  
下面我们再具体举几个利用access_token调用小程序后台接口的例子：  
  
1.获取小程序用户评论  
  
![](https://mmbiz.qpic.cn/mmbiz_png/0aGWwHGxPqZlPQ32CniaibJXpQFd9w0LwTq1e0qibPxC84iacl7Q5tzUIUetEzQ965J0v6m1Ix9AdpomNg48J4pYhg/640?wx_fmt=png "")  
  
2.获取小程序用户访问数据  
  
![](https://mmbiz.qpic.cn/mmbiz_png/0aGWwHGxPqZlPQ32CniaibJXpQFd9w0LwTHFg52o0Y9ZbhOhXpAqBmhGkFVknWtgaOXl57zqRCfUKHI5Guw5xyng/640?wx_fmt=png "")  
  
3.冒用小程序身份给用户发送消息  
  
![](https://mmbiz.qpic.cn/mmbiz_png/0aGWwHGxPqZlPQ32CniaibJXpQFd9w0LwTB1kiaiaFDb0u51C1Aw3YMjweg1Sz6G4NdLbV6XqrA6HuNSiaGoK2TPLiag/640?wx_fmt=png "")  
  
﻿  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ZS0VQrDMfGpUYX7ibOULIib3JJbc1gvugzfWAo2O3SuK0H4diaibVUuzXRPt2xPACH9yxsDC1JoOmJBzOwkghWmDAg/640?wx_fmt=png "")  
  
AppSecret密钥泄露漏洞其他的危害包括但不限于：冒用小程序身份给用户发送客服消息/模板消息、获取小程序session_key（用于解密微信侧提供的用户敏感数据）、获取小程序运维信息、日志等敏感信息、更改小程序相关的配置等。  
  
**三、漏洞修复**  
  
若小程序存在相应的AppSecret密钥泄露漏洞问题，请开发者尽快根据以下修复指引进行调整，以便消除风险：  
  
1.后端API接口请勿把AppSecret敏感信息返回给前端  
（包括前端请求或小程序代码内传输、记录AppSecret）  
；  
  
2.  
立即  
登录小程序管理后台  
，在【开发-开发管理-开发设置】中对AppSecret进行重置。由于Appsecret存在历史泄露且仍然有效，务必进行重置才可消除风险，以免被攻击者恶意利用，请尽快按指引进行修复；  
  
3.  
对AppSecret进行重置后，请及时修改后台代码，以免无法使用微信API  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ZS0VQrDMfGpUYX7ibOULIib3JJbc1gvugz62KOqwMwG7ibolCm0QUxNzhN0HbiasiaicichxehaCKcxUPRu9L8MGJw6zQ/640?wx_fmt=png "")  
  
**其他常见问题**  
  
**Q1: 小程序提审不通过，显示小程序AppSecret存在历史泄露且仍然有效，是否需要重置AppSecret？**  
  
A1: 需要，请重置AppSecret后再提审，若审核通过，说明该问题已消除，若审核不通过，说明仍存在明文的AppSecret，需进一步排查并去除  
AppSecret字段及其对应值  
。  
  
**Q2: 重置小程序AppSecret会影响到线上小程序吗？**  
  
A2: auth.getAccessToken需要使用AppSecret进行调用入参，重置AppSecret后，如果用新的AppSecret去获取access_token,那么旧的access_token会在5分钟内失效，如果未使用新的AppSecret，旧的access_token会在两小时内失效，故即使重置AppSecret，access_token仍有一定的缓冲期，可及时修改后台代码，不会对线上小程序造成影响。  
  
  
  
来自https://developers.weixin.qq.com/community/minihome/doc/0004a84fcb0bb0e89eddbaa5156401?blockType=99  
  
