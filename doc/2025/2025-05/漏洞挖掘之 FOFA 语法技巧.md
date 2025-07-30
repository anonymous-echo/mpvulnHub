#  漏洞挖掘之 FOFA 语法技巧   
原创 骨哥说事  骨哥说事   2025-05-15 06:16  
  
<table><tbody><tr><td data-colwidth="557" width="557" valign="top" style="word-break: break-all;"><h1 data-selectable-paragraph="" style="white-space: normal;outline: 0px;max-width: 100%;font-family: -apple-system, system-ui, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;letter-spacing: 0.544px;background-color: rgb(255, 255, 255);box-sizing: border-box !important;overflow-wrap: break-word !important;"><strong style="outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;"><span style="outline: 0px;max-width: 100%;font-size: 18px;box-sizing: border-box !important;overflow-wrap: break-word !important;"><span style="color: rgb(255, 0, 0);"><strong><span style="font-size: 15px;"><span leaf="">声明：</span></span></strong></span><span style="font-size: 15px;"></span></span></strong><span style="outline: 0px;max-width: 100%;font-size: 18px;box-sizing: border-box !important;overflow-wrap: break-word !important;"><span style="font-size: 15px;"><span leaf="">文章中涉及的程序(方法)可能带有攻击性，仅供安全研究与教学之用，读者将其信息做其他用途，由用户承担全部法律及连带责任，文章作者不承担任何法律及连带责任。</span></span></span></h1></td></tr></tbody></table>#   
  
#   
  
****# 防走失：https://gugesay.com/archives/4267  
  
******不想错过任何消息？设置星标****↓ ↓ ↓**  
****  
#   
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/hZj512NN8jlbXyV4tJfwXpicwdZ2gTB6XtwoqRvbaCy3UgU1Upgn094oibelRBGyMs5GgicFKNkW1f62QPCwGwKxA/640?wx_fmt=png&from=appmsg "")  
  
![file](https://mmbiz.qpic.cn/sz_mmbiz_png/hZj512NN8jnhfoOtcQgngZmTQoAg8mhSeFibicHNbHerjNvP98gMydjc8GsVJktDcLcibtMA8SyYqcXpEbOfRKmWg/640?wx_fmt=png&from=appmsg "")  
  
  
假设以 example.com 为目标网站：  
  
domain="example.com"  
  
![file](https://mmbiz.qpic.cn/sz_mmbiz_png/hZj512NN8jnhfoOtcQgngZmTQoAg8mhSLf7m9vdn3ajEnrPAuHvSt8FwnIU1GDPbtc1nrtw0kFfvSdgYbJyNiaw/640?wx_fmt=png&from=appmsg "")  
  
  
然后会发现下方有数百个 Favicons：  
  
![file](https://mmbiz.qpic.cn/sz_mmbiz_png/hZj512NN8jnhfoOtcQgngZmTQoAg8mhSibutiaJcMC1KdkKQqXO85FYial09dJ0dllth5BEiakOTicibpsTAwKPYtFKQ/640?wx_fmt=png&from=appmsg "")  
  
  
单击任意一个图标，哈希值会自动添加到现有 dork 中：  
  
domain="example.com" && icon_hash="xxxxxxxxxx"  
  
此时在左侧可以选择对存在云 WAF 的站点进行过滤：  
  
![file](https://mmbiz.qpic.cn/sz_mmbiz_png/hZj512NN8jnhfoOtcQgngZmTQoAg8mhSib1MdzSicrwYeS5w3pmT1yVo4HeicP9YnjeCS8I5UwQib5rhvyLS6OILsA/640?wx_fmt=png&from=appmsg "")  
  
  
然后针对非 443端口的 HTTPS 站点进行再次过滤：  
```
domain="example.com" && protocol="https" && port!="443"domain="example.com" && protocol="https" && port!="443" && port!="80"
```  
  
![file](https://mmbiz.qpic.cn/sz_mmbiz_png/hZj512NN8jnhfoOtcQgngZmTQoAg8mhS89Ww6C3dAoTzkLNVYGIiaWib5s4fgzORMVlDFcO5Ghj03sdt9XQluV2w/640?wx_fmt=png&from=appmsg "")  
  
  
再针对非 80 端口的 HTTP 站点进行过滤：  
```
domain="example.com" && protocol="http" && port!="80"domain="example.com" && protocol="http" && port!="80" && port!="443"
```  
  
![file](https://mmbiz.qpic.cn/sz_mmbiz_png/hZj512NN8jnhfoOtcQgngZmTQoAg8mhSxHXIqnjrDnOtPp4SibFTuf6E03kP0icnSZAXBJ3y0Kzs7T9ply3ZYKNA/640?wx_fmt=png&from=appmsg "")  
  
## 搜索云存储桶  
  
domain="example.com" && body="ListBucketResult"  
  
![file](https://mmbiz.qpic.cn/sz_mmbiz_png/hZj512NN8jnhfoOtcQgngZmTQoAg8mhSibIgxW1RF2iaOuGndSyC9zhXe21ElnFkf39xavU1oJQzLicamKuJKckUQ/640?wx_fmt=png&from=appmsg "")  
  
  
![file](https://mmbiz.qpic.cn/sz_mmbiz_png/hZj512NN8jnhfoOtcQgngZmTQoAg8mhS6Fjicqe7DQX3FpByS4ZzMaCVdicjkKrib4EiaIXqdbLpVgxjw1vmbibjZbw/640?wx_fmt=png&from=appmsg "")  
  
  
如果名称分配了关键字 “public”,那它就基本没什么用了。  
```
<ListBucketResult xmlns="http://s3.amazonaws.com/doc/...."><Name>....public.....</Name>
```  
  
其他情况的话，我们可以分析目标是否为刻意公开还是无意公开。  
  
现实案例：  
  
https://osintteam.blog/p4-bug-in-healthcare-company-979db17df4dd  
## 端点或其它类似搜索  
```
body="http_request_duration_seconds_sum"body="http_requests_in_flight"body="http_responses_total"body="http_request_duration_seconds_bucket"body="http_request_duration_seconds_count"body="flask_http_request_duration_seconds_sum"body="python_gc_objects_uncollectable_total"body="process_virtual_memory_bytes"body="process_resident_memory_bytes"body="http_request_duration_highr_seconds_bucket"body="kasiopea_assignment_total"body="by_path_counter_total"#combine with below using && operatorbody="GET"body="POST"body="PUT"body="/api"body="/auth"body="password"body="security"body="roles"body="groups"body="/v1"body="/v2"domain="example.com"#extrasbody="ghc_gcdetails_elapsed_seconds"body="ghc_gcdetails_par_max_copied_bytes"body="ghc_max_mem_in_use_bytes"body="ghc_gcs_total"
```  
## 关键路径与端点测试  
  
![file](https://mmbiz.qpic.cn/sz_mmbiz_png/hZj512NN8jnhfoOtcQgngZmTQoAg8mhSNibpCOddSB7cWppOaiaLlE9sjtK59JxMC1jwR62icfyvssrhHhF0t0E7A/640?wx_fmt=png&from=appmsg "")  
  
  
![file](https://mmbiz.qpic.cn/sz_mmbiz_png/hZj512NN8jnhfoOtcQgngZmTQoAg8mhSWSbqskWiamDNzU40I5d0CoZCHLUzsSoRIhV0kIjaMfzOvWvCiaJIx1nQ/640?wx_fmt=png&from=appmsg "")  
  
### 注册功能寻找  
```
body="register" && body="login"body="register" && body="login" && domain="example.com"
```  
  
![file](https://mmbiz.qpic.cn/sz_mmbiz_png/hZj512NN8jnhfoOtcQgngZmTQoAg8mhSQ8k5MHRhqAgHUzu5CkCRGNdBpXTtUSLJOuU50kk2ykFrlicL5CLvClw/640?wx_fmt=png&from=appmsg "")  
  
### API 端点  
```
body="/api/v1" && domain="example.com"body="/api/v2" && domain="example.com"
```  
  
![file](https://mmbiz.qpic.cn/sz_mmbiz_png/hZj512NN8jnhfoOtcQgngZmTQoAg8mhS7MdqfK0pSY7Xf0BI3MyqRSGF6hzHr5Y8P1FhY7oaTZcalWI0jGiaUUQ/640?wx_fmt=png&from=appmsg "")  
  
### 管理员端点  
  
body="/admin" && domain="example.com"  
  
![file](https://mmbiz.qpic.cn/sz_mmbiz_png/hZj512NN8jnhfoOtcQgngZmTQoAg8mhSeQZtgKqNmOumjiboY4JianpITdvV5AXngk8ujMPibqoPZXMHnYaicGfmicA/640?wx_fmt=png&from=appmsg "")  
  
### 信息泄露  
```
body="any file name that leads to info disc" && domain="example.com"
```  
  
举例：  
  
body="config.txt" && domain="example.com"  
  
![file](https://mmbiz.qpic.cn/sz_mmbiz_png/hZj512NN8jnhfoOtcQgngZmTQoAg8mhSWaXLGJof6XOibfGCGcNvWbUTg826mPfDS07XBKuG9wfN5FOD0UD0icXA/640?wx_fmt=png&from=appmsg "")  
  
## JS 中的 API 密钥  
```
body="any_api_key_name_you_know" && domain="example.com"#example for algolia api keybody="algolia_api_key" && domain="example.com"body="algolia_application_id" && domain="example.com"
```  
  
![file](https://mmbiz.qpic.cn/sz_mmbiz_png/hZj512NN8jnhfoOtcQgngZmTQoAg8mhSqmFbQd31fzEN5SAguDK2TszPM1URMCiaxEpo0XEKOTJ188cibEQENiauw/640?wx_fmt=png&from=appmsg "")  
  
## 将任何字符串与历史已知漏洞端点匹配  
  
比如，以前你知道 sub2.sub1.example.tld  通过 “xyz” 参数容易受到 RXSS 的攻击，那么可以查看端点的页面源代码，匹配一些唯一的关键字、短语、字符串、函数、对象或变量名称。  
  
body="keyword1" && body="keyword2" && domain="example.com"  
  
为了方便找到历史易受攻击的端点，可以通过 HackerOne 披露的报告或 OpenBugBounty 进行了搜索：  
```
#hackeronesite:hackerone.com inurl:reports "domain.tld"#openbugbountyhttps://www.openbugbounty.org/reports/domain/example.com
```  
  
![file](https://mmbiz.qpic.cn/sz_mmbiz_png/hZj512NN8jnhfoOtcQgngZmTQoAg8mhSv4ot4Xs1fibok6wyT4sK8SAZqSibGt1iccmS0icqK9tzp18Iicx9pcgfhNQ/640?wx_fmt=png&from=appmsg "")  
  
  
你学到了吗？  
  
原文：https://medium.com/legionhunters/fofa-dorking-for-bug-hunters-a35c80bbab6e  
  
- END -  
  
**加入星球，随时交流：**  
  
**********（会员统一定价）：128元/年（0.35元/天）******  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/hZj512NN8jnMJtHJnShkTnh3vR3fmaqicPicANic6OEsobrpRjx5vG6mMTib1icuPmuG74h2bxC4eP6nMMzbs5QaSlw/640?wx_fmt=jpeg&from=appmsg "")  
  
**感谢阅读，如果觉得还不错的话，欢迎分享给更多喜爱的朋友～**  
  
