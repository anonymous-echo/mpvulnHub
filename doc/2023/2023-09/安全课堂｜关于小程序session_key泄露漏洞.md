#  安全课堂｜关于小程序session_key泄露漏洞   
枇杷五星加强版  黑伞安全   2023-08-31 18:10  
  
为进一步提升小程序的安全性和用户体验，目前平台对提审的小程序均需进行安全检测，在检测过程中发现仍有许多小程序存在安全漏洞，其中涉及session_key泄露漏洞，希望通过以下相关的漏洞介绍、案例分析和修复建议，开发者能更加了解如何对该漏洞进行防御。  
  
**一、漏洞介绍**  
  
为了保证数据安全，微信会对用户数据进行加密传输处理，所以小程序在获取微信侧提供的用户数据（如手机号）时，就需要进行相应的解密，这就会涉及到session_key，具体流程可参考开放数据校验与解密  
开发文档。  
  
session_key指的是会话密钥，可以简单理解为微信开放数据AES加密的密钥，它是微信服务器给开发者服务器颁发的身份凭证，这个数据正常来说是不能通过任何方式泄露出去的。小程序若存在session_key泄露漏洞的情况，则代表微信侧传递的用户数据有被泄露、篡改等风险，开发者应及时发现该漏洞并快速修复相应问题。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ZS0VQrDMfGoPJXv1HLe4tYUkxO4hKpjbfRa8pjMwJ0E67sfVbSfWDJKd8JYSrI0MVJBAoQFDY6VH1A3oiax3ATw/640?wx_fmt=png "")  
  
  
**二、漏洞案例**  
  
某小程序因为session_key泄露，导致该小程序可以使用任意手机号进行登录，造成了极大的安全风险。  
  
我们可以很明显地看到，下列请求中的session_key已经被泄露：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/0aGWwHGxPqZlPQ32CniaibJXpQFd9w0LwT2lf9XsE941hiczFRfVuPG5waKYbvrxbXkLTUu5p4c0OaficGwibprRFSQ/640?wx_fmt=png "")  
  
通过获取该session_key，我们可以结合iv解密出密文：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/0aGWwHGxPqZlPQ32CniaibJXpQFd9w0LwTGDMoBz9dGqAibZG5duT3YVkPMwia9q5E964Z9B7K5icz5YxtEDZwHp07A/640?wx_fmt=png "")  
  
只需如下脚本即可进行解密，所以攻击者也可利用同样的信息去篡改用户数据，然后加密后返回给服务器，从而达到使用任意手机号进行登录的目的。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/0aGWwHGxPqZlPQ32CniaibJXpQFd9w0LwTHa7Exos8wUX1gDmbic0SudylticghPRiayT2wY1CUcSibOEnhw59YIAu3A/640?wx_fmt=png "")  
  
**三、漏洞修复**  
  
通过上述案例，我们了解到session_key泄露会对小程序造成的危害，而导致session_key泄露的原因则可能有以下两种：  
  
1.通过auth.code2Session  
接口获取用户openid时，返回小程序的数据中包含了session_key字段，以泄露的url：/api/get_openid.php?code=xxxx为例，具体的表现如下图所示：  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ZS0VQrDMfGoPJXv1HLe4tYUkxO4hKpjbaIdvuunicE9QPP7IuZQsn0n6MzMiaibUWLWjOmibfbNZv2pDgVWMxFozSQ/640?wx_fmt=png "")  
  
  
  
查看后端get_openid.php的源码，经排查发现$response 变量包含了session_key字段，开发者应去掉变量中的session_key字段，若需获取openid，应只提取该字段返回小程序即可。  
  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ZS0VQrDMfGoPJXv1HLe4tYUkxO4hKpjb65QdQicngoXpgWlQQcmgZg88ZBJ8LP2XH5NVaC1cIhc6s3gnWiacOPAg/640?wx_fmt=png "")  
  
  
2.在解密开放数据时，使用了错误的方式，以获取手机号接口为例，通过事件回调获取微信服务器返回的加密数据（encryptedData和iv）后，将服务端中的session_key传送至小程序前端，直接在前端进行解密：﻿  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ZS0VQrDMfGoPJXv1HLe4tYUkxO4hKpjbpYm9nbfUYZps1qbtRiauJqsViafeb261NaM0WZnZT2nFFfJgLfm8RVWQ/640?wx_fmt=png "")  
  
这种方式是绝对不可取的，正确的流程应该是将加密数据（encryptedData和iv）传至服务端后，结合服务端中的session_key进行解密获取手机号，然后返回给小程序。另外，目前平台已对获取手机号接口进行了安全升级，建议开发者使用新版本  
，以增强小程序的安全性。  
  
若小程序存在相应的session_key泄露漏洞问题，请开发者尽快自查并修复漏洞：  
  
请尽快在网络请求中，去除请求和响应中的session_key字段及其对应值，后续也不应该将session_key传到小程序客户端等服务器外的环境，以便消除风险。  
  
  
**其他常见问题**  
  
**Q1: 如何进行相应的修复，是需要把session_key字段更换个名字就可以了吗？**  
  
A1: 不是，更换字段名无法从根本上消除风险，session_key这个字段及对应值不应该传到小程序客户端等服务器外的环境，需去除请求和响应中的所有相关信息，才可对该漏洞问题进行修复。  
  
**Q2: 解密开放数据的正确方式是什么？**  
  
A2: 以获取手机号接口为例，通过事件回调获取微信服务器返回的加密数据（encryptedData和iv），将加密数据传至服务端后，结合服务端中的session_key进行解密获取手机号，然后返回给小程序。而不应将服务端中的session_key传送至小程序前端，直接在前端进行解密。  
  
  
**﻿相关文章**  
# 安全课堂｜关于小程序AppSecret密钥泄露漏洞  
# 安全课堂｜关于小程序云AK/SK泄露漏洞  
  
  
