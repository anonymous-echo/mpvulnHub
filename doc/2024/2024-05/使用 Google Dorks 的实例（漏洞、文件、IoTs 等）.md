#  使用 Google Dorks 的实例（漏洞、文件、IoTs 等）   
原创 imBobby  imBobby的自留地   2024-05-29 16:05  
  
家人们  
  
![](https://mmbiz.qpic.cn/mmbiz_png/N54nkicAryTwsT9yeMRD1auQd19icsHklEnUl9QciaK7NgLU3bhUBqzcZK2hYAiazOrH0eV8HD2VWRm8zZQGibz2gcg/640?wx_fmt=png "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/El0PBhdhMicvsxbKV2SmzsFItYX1bq8Y1JZz7DnFkjf8Y4EwSHeoqa7y2A7qgVeKTeWlVNqpFowdEicWlKEktrOQ/640?wx_fmt=png "")  
  
  
点击上方  
蓝字关注我  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/n1ERZiaQ19eFxSAHlD3qZdPo0sb0iakOOpTX4YqnczT7M0KReFj76w5zhs3C7QKynYKAbYGuic4iaAIvB3vdU3QyDw/640?wx_fmt=png "")  
  
  
[开源情报的应用：Google Dorks](http://mp.weixin.qq.com/s?__biz=MzI5MjI4ODU4Nw==&mid=2247487071&idx=1&sn=c31711a32ae0f5c3f0960029aadc36ad&chksm=ec02ef7bdb75666d800d79b5a446fa677588c7fe1e0220c05e12272add02379e292c7f08911d&scene=21#wechat_redirect)  
  
  
[打造强大的安全运营中心：解读 OSINT 工具](http://mp.weixin.qq.com/s?__biz=MzI5MjI4ODU4Nw==&mid=2247486818&idx=1&sn=0d78d5b3a5248c941b619edc61729293&chksm=ec02ec46db75655040d98513e399d2caa0ff4e5b1c279772a255c5066a1d503504c120245d7f&scene=21#wechat_redirect)  
  
  
之前有讲过 Google Dorks，实际上用好 Google Dorks 能收集到很多有用情报，且不仅限于 Google、Bing、Baidu 之类的都能用，以下是一些常用 Dorks：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/xbwallc9kvULG5MWqbTHuoyjVolz5gpgWEicJt39n4tqgPQQArR0vfia7ELOU1rWXBCR7wfJkLwTxYTXQOibuK9Tw/640?wx_fmt=png "")  
  
DB 相关  
  
![](https://mmbiz.qpic.cn/mmbiz_png/a0SYcmmbRDXw8jLia9vBlGgGWibheo9M1CzG21VRUPhFZWOugAMicLSmEx9wPKQ9fdTdG7G5yfhNvq4gJ41O7KUvQ/640?wx_fmt=png "")  
  
```
inurl：/phpmyadmin/index.php
intext:"phpMyAdmin MySQL-Dump" filetype:sql
inurl:/db/websql/
inurl:/phpPgAdmin/index.php
intext:"phpPgAdmin — Login"
```  
  
例如，我直接搜最后一行：  
```
intext:"phpPgAdmin — Login"
```  
  
搜索引擎显示：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/aiarKdLqgA00MlJv8Yia13gMJ7nVyIia2mhiaGd0EMq93BV0KjwYNricARZAslWhENSsYYAB8LMtFhNa494TJmDgBfg/640?wx_fmt=png&from=appmsg "")  
  
我就直接点第一个：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/aiarKdLqgA00MlJv8Yia13gMJ7nVyIia2mhqBsj1UChMmAicqNI0efXoia0ZtuECPbTNhMMyDaZiaibFPzqItYU50B33w/640?wx_fmt=png&from=appmsg "")  
  
相信师傅们已经按耐不住激动的心颤抖的的手了，狩猎欲望开始高涨！上面那个版本有点高，可以搜搜低版本的。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/xbwallc9kvULG5MWqbTHuoyjVolz5gpgWEicJt39n4tqgPQQArR0vfia7ELOU1rWXBCR7wfJkLwTxYTXQOibuK9Tw/640?wx_fmt=png "")  
  
漏洞相关  
  
![](https://mmbiz.qpic.cn/mmbiz_png/a0SYcmmbRDXw8jLia9vBlGgGWibheo9M1CzG21VRUPhFZWOugAMicLSmEx9wPKQ9fdTdG7G5yfhNvq4gJ41O7KUvQ/640?wx_fmt=png "")  
  
  
举例：  
```
intext:"Warning: mysql_connect()" intext:"on line" filetype:php
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/aiarKdLqgA00MlJv8Yia13gMJ7nVyIia2mh36f83Hr0v61Oy0N9ZXmZGUnXibBeowwMAlAgRGFbqLJbH1SibH1KS6Zg/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/xbwallc9kvULG5MWqbTHuoyjVolz5gpgWEicJt39n4tqgPQQArR0vfia7ELOU1rWXBCR7wfJkLwTxYTXQOibuK9Tw/640?wx_fmt=png "")  
  
目录列表类  
  
![](https://mmbiz.qpic.cn/mmbiz_png/a0SYcmmbRDXw8jLia9vBlGgGWibheo9M1CzG21VRUPhFZWOugAMicLSmEx9wPKQ9fdTdG7G5yfhNvq4gJ41O7KUvQ/640?wx_fmt=png "")  
  
```
intitle:"Index of" inurl:/admin
```  
  
例如：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/aiarKdLqgA00MlJv8Yia13gMJ7nVyIia2mh7hUc6licXO6ibxKhNXqcCd0mB1Hjkyef4v4VnZY3BFvYWLz36JCnv3iag/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/aiarKdLqgA00MlJv8Yia13gMJ7nVyIia2mhLa2KnLAxMztaaxmnbpsOGA6tFnP7AQZHFMq6ibicAHxMXgegxia0s0j9A/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/xbwallc9kvULG5MWqbTHuoyjVolz5gpgWEicJt39n4tqgPQQArR0vfia7ELOU1rWXBCR7wfJkLwTxYTXQOibuK9Tw/640?wx_fmt=png "")  
  
公网摄像头之类  
  
![](https://mmbiz.qpic.cn/mmbiz_png/a0SYcmmbRDXw8jLia9vBlGgGWibheo9M1CzG21VRUPhFZWOugAMicLSmEx9wPKQ9fdTdG7G5yfhNvq4gJ41O7KUvQ/640?wx_fmt=png "")  
  
```
inurl:"view/index.shtml"
intitle:"camera" inurl:/cgi-bin/login
```  
  
结果：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/aiarKdLqgA00MlJv8Yia13gMJ7nVyIia2mh3FrvlsC1bn8ZsHaxB9BmZZslheick4oToxAUvURuUHzl6XT5472mqrQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/aiarKdLqgA00MlJv8Yia13gMJ7nVyIia2mheCrYW9Eic6AfYPcxuAEnYssesaCUHvCibDU3jJDYgt0GMCcYShbVu3JA/640?wx_fmt=png&from=appmsg "")  
  
接下来就不自己搜了，各位师傅开动脑筋一定有各种好玩的 Dorks 可以写，记得分享给我哦！  
  
![](https://mmbiz.qpic.cn/mmbiz_png/xbwallc9kvULG5MWqbTHuoyjVolz5gpgWEicJt39n4tqgPQQArR0vfia7ELOU1rWXBCR7wfJkLwTxYTXQOibuK9Tw/640?wx_fmt=png "")  
  
附：常用基本运算符  
  
![](https://mmbiz.qpic.cn/mmbiz_png/a0SYcmmbRDXw8jLia9vBlGgGWibheo9M1CzG21VRUPhFZWOugAMicLSmEx9wPKQ9fdTdG7G5yfhNvq4gJ41O7KUvQ/640?wx_fmt=png "")  
  
  
**引号 ""**：搜索包含确切短语的结果，例如：  
```
"open-source intelligence"
```  
  
**减号 -**：排除包含特定词的结果，例如：  
```
"open-source intelligence" -services
```  
  
**星号***：通配符，替代任意单词，例如：  
```
"open-source * tools"
```  
  
**范围 ..**：搜索指定范围内的数字，例如：  
```
2017..2023
```  
  
**OR**：结果包含任一关键词，例如：  
```
"AAA" OR "BBB"
```  
  
**AND**：结果包含所有关键词，例如：  
```
"AAA" AND "BBB"
```  
  
**site:**：限制结果来自特定网站，例如：  
```
site:xxx.com "social engineering"
```  
  
**inurl:**：结果URL中包含指定词语，例如：  
```
inurl:social-engineering
```  
  
**intitle:**：结果标题中包含指定词语，例如：  
```
intitle:OSINT
```  
  
**filetype:**：搜索特定文件类型的结果，例如：  
```
filetype:pdf "open-source intelligence"
```  
  
**cache:**：查看网页的缓存版本，例如：  
```
cache:example.com（这个用好了是挖坟神器）
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/xbwallc9kvULG5MWqbTHuoyjVolz5gpgWEicJt39n4tqgPQQArR0vfia7ELOU1rWXBCR7wfJkLwTxYTXQOibuK9Tw/640?wx_fmt=png "")  
  
组合  
  
![](https://mmbiz.qpic.cn/mmbiz_png/a0SYcmmbRDXw8jLia9vBlGgGWibheo9M1CzG21VRUPhFZWOugAMicLSmEx9wPKQ9fdTdG7G5yfhNvq4gJ41O7KUvQ/640?wx_fmt=png "")  
  
#### 结合引号和减号，例如：  
```
"internal memo" -template
```  
  
**结合OR和AND**，例如：  
```
"data breach" AND ("internal memo" OR "confidential report")
```  
  
**结合site:和filetype:**，例如：  
```
site:example.com filetype:pdf "financial report"
```  
  
**结合星号和引号**，例如：  
```
"project * plan" filetype:docx
```  
#### 查找内部备忘录，例如：  
```
"internal memo" site:company.com
```  
  
**查找公司培训材料**，例如：  
```
"training material" OR "employee handbook" filetype:ppt OR filetype:pdf
```  
  
**查找敏感文件**，例如：  
```
"confidential" OR "sensitive" filetype:pdf OR filetype:docx
```  
  
**查找特定年份的报告**，例如：  
```
 "annual report" 2017..2023 filetype:pdf
```  
  
  
点点赞 点点关注 点点文末广告 抱拳了家人  
们  
  
![](https://mmbiz.qpic.cn/mmbiz_png/pw5Hicso39PGOb8dTalNBlicn49LltgJL0HibFjtQZCvBfYlsIYpEbkaGY2FKCJCuYicBcWhWYVKJjntLKgy3KsDkA/640?wx_fmt=png "")  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/n1ERZiaQ19eFxSAHlD3qZdPo0sb0iakOOpAVYB7vIib80GMZr13Tathwr9icPop3uvtYktNrK3o57306ZpAMvrQkQw/640?wx_fmt=png "")  
  
  
创作不易  
  
关注一下  
  
帮忙点点**文末**  
广告  
  
![](https://mmbiz.qpic.cn/mmbiz_png/aiarKdLqgA03QZG72saoicpUqrFtSwLxaf2CUUa9CI653XJIBnIKCUGRM3Hcx9W8CpYQc7FMPKGs5B7c5OAByiaAw/640?&wx_fmt=png "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/aiarKdLqgA03QZG72saoicpUqrFtSwLxafiaLyEjZtQAVaicwJnv2vIHmejBx0JibAX3MXLqVo5DpHKXR5ocRLicBbcQ/640?wx_fmt=jpeg&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/F2wnYmdhCKX4xJFIliargOh8rjoIKSoofLt1hZaDxID3CsJ9pVYGgcaFuKtt8FRwWIcWHRgzzPhOTick6rzX5v0Q/640?wx_fmt=png "")  
  
  
