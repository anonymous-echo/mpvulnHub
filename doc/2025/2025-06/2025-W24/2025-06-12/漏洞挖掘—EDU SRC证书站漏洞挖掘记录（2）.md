#  漏洞挖掘—EDU SRC证书站漏洞挖掘记录（2）  
原创 haosha  网安日记本   2025-06-11 23:01  
  
**免责声明：请勿利用文章内的相关技术从事非法测试，由于传播、利用此文所提供的信息或者工具而造成的任何直接或者间接的后果及损失，均由使用者本人负责，所产生的一切不良后果与文章作者无关。该文章仅供学习用途使用。**  
  
**前言**  
  
**最近工作有些忙，又是好久没有更新了，前端时间EDU SRC新上了一个证书站，还正好是我朋友的学校，这么好的机会当然要好好测试一下。**  
  
**直接借一个统一门户账号，没有任何手法，纯靠脸皮厚。**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Un8INe529cicc7b9szM3sMVY8nS0ibyQGnczOCejTuqIV0ZLfkWmuAXJOdv1h5eKEnUHMn7CvyDGBLpl4f5fzokw/640?wx_fmt=png&from=appmsg "")  
  
一、通过Druid弱口令发现越权  
  
    因为这一次是有账号的，就没有做信息收集，在登录统一门户之后直接访问WEB VPN系统，把能登录的系统都点了一遍。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Un8INe529cicc7b9szM3sMVY8nS0ibyQGn8uwoaAMJzOEiau4WanOw9r5sQ8FpG2QMVNjZJq5g8Yp0Cu6cAAcdj4A/640?wx_fmt=png&from=appmsg "")  
  
    在点击其中一个管理系统的时候看到了熟悉的图标，这不是若依吗，  
直接利用burp工具爆破目录，获得了druid登录页面路径。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Un8INe529cicc7b9szM3sMVY8nS0ibyQGnVxQZSOUV2Tk33286hGdBfyl9mc3AibYxsS9v43dPVBWPaibfMGclsjdA/640?wx_fmt=png&from=appmsg "")  
  
     
 接着爆破弱口令，同样也是运气很好，利用druid弱口令成功登录系统。下一步就是查看Session监控、URI监控，可惜这里Session监控中没有任何信息，但是在URI监控中到是有意外收获。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Un8INe529cicc7b9szM3sMVY8nS0ibyQGnlnpf9bmaPrvorPiaUXQcdlRSHgRvNriaJaZKJ7cZb3iaOYJCEXX9IUr4A/640?wx_fmt=png&from=appmsg "")  
  
**这里翻找了一下URI信息，其中存在了大量访问记录，拼接路径尝试进行访问，发现可以越权访问到其他学生的信息，也可以下载文件，文件中还存在学生和教师的手写签名。**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Un8INe529cicc7b9szM3sMVY8nS0ibyQGnXMnOeKuYB8GI1TJTPeo7InP5lAmP6gpDqrxEFxic9IWPO9ibtTTCUlqw/640?wx_fmt=png&from=appmsg "")  
  
**接着往下翻找，还有大量页面存在同样的问题，甚至还有一些教师权限的页面也是可以查看，同时也有页面可以进行添加信息，上传文件等操作。**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Un8INe529cicc7b9szM3sMVY8nS0ibyQGnYYTmztIb295siaAxqPzwQUGrasdwIEeVYnkP5c9ibHSEyomSSlsiaMcZA/640?wx_fmt=png&from=appmsg "")  
  
二、越权下载敏感信息文件  
  
**依旧是WEB VPN中点击系统进行登录，这次登录了一个学生信息管理系统，这种系统当然要去找一下有没有存在敏感信息，看看能不能越权。**  
  
**翻找功能点，在个人信息界面处没有发现存在敏感信息，接着点一点，发现存在一个下载功能，可以下载PDF或者Excel文件，同时下载后的文件中存在学生身XX号码、校内邮箱名等敏感信息。**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Un8INe529cicc7b9szM3sMVY8nS0ibyQGn52GibTb48HKmVEAh6qaJIiaXj2En5y01KAfmRZlvDGw6G124Qib3T9j7A/640?wx_fmt=png&from=appmsg "")  
  
**勾选好数据项后点击 “导出” 按钮，进行抓包。（数据包大致如下，删改了一些敏感内容，仅供参考）**  
```
POST /api/personal/Export/saveAndExportFile HTTP/1.1
Host: webvpn.XXXXX.edu.cn
Cookie: 
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:139.0) Gecko/20100101 Firefox/139.0
Accept: application/json
Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
Accept-Encoding: gzip, deflate
Content-Type: application/json;charset=utf-8
Connection: close

{
  "value":{
    "name":"",
      "exportTableList":[
        {
          "parentId":"root",
          "name":"数字档案",
        },
        {
          "parentId":"21",
          "isLeaf":1,
          "sjkbm":"XS_JBXX",
          "name":"学生基本信息",
        }
      ],
      "exportTemplateNum":"",
      "type":"2",
      "userId":"2021010101",
      "fileType":"PDF",
      "title":"个人信息"
  }
}
```  
  
**可以发现请求包中存在 userId 参数，更改参数可以越权下载别人的文件，导致泄露敏感信息。**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Un8INe529cicc7b9szM3sMVY8nS0ibyQGnibTm25jsYM45P5Uz1eQO8ytyqAVxo5WBJCQdibm3wwuWqWOh3FvyDp1Q/640?wx_fmt=png&from=appmsg "")  
  
    打完收工，半小时下机，有账号确实是爽。  
  
结尾  
  
    其实可以发现现在外部网站基本上已经很难出现漏洞，如果有账号可以更快速的挖掘漏洞，有时候账号才是制胜关键，弱口令才是   
“最严重” 漏洞。  
  
    还有在此前挖掘泄露敏感信息的漏洞时常常会依赖  
 hae 等识别敏感信息的工具。像这次返回包中只返回   
true 接着就下载文件，这样的返回包是没办法识别出信息的，所以还是需要细心，把每个功能点都关注到。  
  
