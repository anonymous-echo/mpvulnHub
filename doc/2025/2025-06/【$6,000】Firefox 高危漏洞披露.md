#  【$6,000】Firefox 高危漏洞披露   
原创 骨哥说事  骨哥说事   2025-06-04 01:08  
  
<table><tbody><tr><td data-colwidth="557" width="557" valign="top" style="word-break: break-all;"><h1 data-selectable-paragraph="" style="white-space: normal;outline: 0px;max-width: 100%;font-family: -apple-system, system-ui, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;letter-spacing: 0.544px;background-color: rgb(255, 255, 255);box-sizing: border-box !important;overflow-wrap: break-word !important;"><strong style="outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;"><span style="outline: 0px;max-width: 100%;font-size: 18px;box-sizing: border-box !important;overflow-wrap: break-word !important;"><span style="color: rgb(255, 0, 0);"><strong><span style="font-size: 15px;"><span leaf="">声明：</span></span></strong></span><span style="font-size: 15px;"></span></span></strong><span style="outline: 0px;max-width: 100%;font-size: 18px;box-sizing: border-box !important;overflow-wrap: break-word !important;"><span style="font-size: 15px;"><span leaf="">文章中涉及的程序(方法)可能带有攻击性，仅供安全研究与教学之用，读者将其信息做其他用途，由用户承担全部法律及连带责任，文章作者不承担任何法律及连带责任。</span></span></span></h1></td></tr></tbody></table>#   
  
#   
  
****# 防走失：https://gugesay.com/archives/4415  
  
******不想错过任何消息？设置星标****↓ ↓ ↓**  
****  
#   
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/hZj512NN8jlbXyV4tJfwXpicwdZ2gTB6XtwoqRvbaCy3UgU1Upgn094oibelRBGyMs5GgicFKNkW1f62QPCwGwKxA/640?wx_fmt=png&from=appmsg "")  
  
# 概述  
  
近期有白帽子在 Firefox 账户的 API 端点https://api.accounts.firefox.com/v1/account/destroy  
 中发现一处 IDOR 漏洞，该漏洞允许使用SSO（即Google登录）进行身份验证的攻击者，通过他们的电子邮件地址删除受害者用户的账户，服务器未能验证发起删除请求的会话是否属于被删除的账户本人。  
# 漏洞披露  
  
Firefox 账户 API 存在一个高危漏洞，允许经过身份验证的攻击者通过使用攻击者会话发送 POST /v1/account/destroy  
 请求，从而永久删除任意用户账户（需在 JSON 中包含受害者的电子邮件和 authPW（密码散列）），服务器未经验证发起的请求会话是否属于被删除账户。  
## 复现步骤  
1. 登录到受害者的账户  
  
1. 使用Burp Suite拦截删除账户时的请求https://api.accounts.firefox.com/v1/account/destroy  
，JSON内容如下：  
  
```
{"email": "victims344@gmail.com","authPW": "42b4c2940fe2efecce851a2d8e9754d0f1cb1d37e3ccaabb060f9ac21900caff"}
```  
1. 取消请求  
  
1. 登录攻击者帐户  
  
1. 同样，使用Burp Suite拦截同一端点的请求https://api.accounts.firefox.com/v1/account/destroy  
，在删除账户时将其发送到Repeater并取消请求 6.在攻击者的请求中，将JSON内容替换为受害者的数据：  
  
```
{"email": "victims344@gmail.com","authPW": "42b4c2940fe2efecce851a2d8e9754d0f1cb1d37e3ccaabb060f9ac21900caff"}
```  
  
![file](https://mmbiz.qpic.cn/sz_mmbiz_png/hZj512NN8jmajvcicY3Zr5vib5ibmn5Rf6Dgy4wu85tqzic6SwsIh26o8hVUe9xTP2C7yu99z8dpMiciaqZqxliclicrQg/640?wx_fmt=png&from=appmsg "")  
7. 服务器顺利接受请求并删除了受害者账户，即使该请求来自攻击者会话![file](https://mmbiz.qpic.cn/sz_mmbiz_png/hZj512NN8jmajvcicY3Zr5vib5ibmn5Rf6DiaeHxce9ia1oibPCblHOyDBmOD7AxfpsJxn8gGfPMg9NHluXZmpAKDh3g/640?wx_fmt=png&from=appmsg "")  
  
# 赏金结算  
  
![file](https://mmbiz.qpic.cn/sz_mmbiz_png/hZj512NN8jmajvcicY3Zr5vib5ibmn5Rf6D69LZqibYe7xmibYE5fibwOibpAStltQ0iaYgvZDzKnSlmBibNrwiaS5WH7HIA/640?wx_fmt=png&from=appmsg "")  
  
  
报告原文：https://hackerone.com/reports/3154983  
  
- END -  
  
****  
  
**加入星球，随时交流：**  
  
**********（会员统一定价）：128元/年（0.35元/天）******  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/hZj512NN8jnMJtHJnShkTnh3vR3fmaqicPicANic6OEsobrpRjx5vG6mMTib1icuPmuG74h2bxC4eP6nMMzbs5QaSlw/640?wx_fmt=jpeg&from=appmsg "")  
  
**感谢阅读，如果觉得还不错的话，欢迎分享给更多喜爱的朋友～**  
  
  
