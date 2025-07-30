#  某小型CMS漏洞复现审计   
 蚁景网安   2024-12-30 08:30  
  
**SQL注入**  
  
漏洞复现：  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/5znJiaZxqldzO5IqmicGWF5n2tTv68cQF07GodwnLHp5f4NGkXLhHVw4mQzzaKK4nV7c1ojK1kHRRoyjoHJc2zFA/640?wx_fmt=other&from=appmsg "null")  
  
登陆后台，点击页面删除按钮，抓包：  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/5znJiaZxqldzO5IqmicGWF5n2tTv68cQF02pV1ATibvxU4h2IiazzxNBeG3TBiaZgtFcHkUrrE5HNMfz3pr5OVyO4oA/640?wx_fmt=other&from=appmsg "null")  
  
rid参数存在sql注入，放入sqlmap检测成功：  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/5znJiaZxqldzO5IqmicGWF5n2tTv68cQF0u0MkwOuIJ6MdbuyWOcCN8w38tRp241d0KHgQQHoHRs5tbVibQiabd9bw/640?wx_fmt=other&from=appmsg "null")  
  
代码分析：  
  
Ctrl+Shift+F检索路由：  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/5znJiaZxqldzO5IqmicGWF5n2tTv68cQF0FEytsXUW9PTO0jsKS4txW5JYQs2Uz6EX3SSsqI04qOicjG2081kKH8Q/640?wx_fmt=other&from=appmsg "null")  
  
定位具体代码，为删除功能：  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/5znJiaZxqldzO5IqmicGWF5n2tTv68cQF0ZPoLw6kCsBFaRIGBgibQtJkslaNNSEwfIdHeQibyWbB2yTjOKBjN0rWA/640?wx_fmt=other&from=appmsg "null")  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/5znJiaZxqldzO5IqmicGWF5n2tTv68cQF0CiaqEiaaPR1ErFCmnbR2NibD7ibrb1ScBVakk90OZdt16lJFkfHG1qv2Sw/640?wx_fmt=other&from=appmsg "null")  
  
发现deleteByIds调用了传参rid,跟进：  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/5znJiaZxqldzO5IqmicGWF5n2tTv68cQF08Du8NmXzf49SvsEUm2AWJRY2kqR1l41YHibfAeLKV8Hs61L8g5lKPXw/640?wx_fmt=other&from=appmsg "null")  
  
发现进入Dao层，此处依旧调用的deleteByIds，于是找ICommonDao接口实现类：  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/5znJiaZxqldzO5IqmicGWF5n2tTv68cQF0naU2SJsSQEKPpibaYWranQuUpELO9OIL4a1ukjrrghAcoqFdweibBUgQ/640?wx_fmt=other&from=appmsg "null")  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/5znJiaZxqldzO5IqmicGWF5n2tTv68cQF07nUItxicBog30Fx1MSj8TZWBybaibBDNwMRVpAAiaxiazmQlbsgv4a3VIA/640?wx_fmt=other&from=appmsg "null")  
  
定位到该类，发现以ids参数接受原先用户传入的rid参数，并在new一个sql对象后，直接将ids参数进行拼接，并通过原生jdbc执行返回结果。  
  
**模板注入**  
  
内容管理-文件管理-themes-flatweb-about.html，选择编辑，插入payload：  
```
<#assign
value="freemarker.template.utility.Execute"?new()>${value("calc.exe")}
```  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/5znJiaZxqldzO5IqmicGWF5n2tTv68cQF0tItS2TEZo2hhPb2BmG7x2SCWxCDGcZO94Pj6W5ibryplTNL5PR4IrDA/640?wx_fmt=other&from=appmsg "null")  
  
访问首页，点击关与我们：  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/5znJiaZxqldzO5IqmicGWF5n2tTv68cQF0wRhf9XZqL4Sd2s5sWQARfjUyt44NjyCoSrYtwdXd8xVwsbkSYYNNRQ/640?wx_fmt=other&from=appmsg "null")  
  
执行命令，弹出计算机：  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/5znJiaZxqldzO5IqmicGWF5n2tTv68cQF00qK4LBtYuJl6sydhRe9MxkWp8NxCTGPVWE38qEBPuNRJoc1xE9r0Zw/640?wx_fmt=other&from=appmsg "null")  
  
代码分析：  
  
配置文件存在freemark  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/5znJiaZxqldzO5IqmicGWF5n2tTv68cQF0Xs4UntKzvI4n9dichBCgBh5x0VIqeeaa1eVTz6PD5Ul64Ufz3IMrWHQ/640?wx_fmt=other&from=appmsg "null")  
  
**文件上传**  
  
漏洞复现：  
  
这个CMS感觉上传文件路径不是很好找，所以上传时先找个合适的目录再点击上传文件。  
  
文件管理处点击admin进入目录：  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/5znJiaZxqldzO5IqmicGWF5n2tTv68cQF04rF7ymz3JVdo5dJs60ianMIm103ialttWILyld3DTiatlP6FtZeiakMOdw/640?wx_fmt=other&from=appmsg "null")  
  
再点击文件上传：  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/5znJiaZxqldzO5IqmicGWF5n2tTv68cQF0Wqf8xJpTCWgRLRNH15l9CceGKYmSrzj0ZnBV9Vh0noacEnLCkrwyUQ/640?wx_fmt=other&from=appmsg "null")  
  
通过上传jsp马，不过需要以jspx或者jspf后缀绕过上传。  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/5znJiaZxqldzO5IqmicGWF5n2tTv68cQF09SFGKGuZgZfzMgJxib5duWDXCNW1bd46vf5DQzLm4loNdXYWlSFJsHw/640?wx_fmt=other&from=appmsg "null")  
  
代码分析：  
上传时抓包，根据路由全局搜索：  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/5znJiaZxqldzO5IqmicGWF5n2tTv68cQF0Cgic6Oibcp7fs7JgXtSicfqEE9nwicWrrrSNh8j0OZmWC85eWp8qytCp2Q/640?wx_fmt=other&from=appmsg "null")  
  
定位到具体代码段：  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/5znJiaZxqldzO5IqmicGWF5n2tTv68cQF0au1koPHwGzhtrUD1XmicDxxkL9noOeKUNGM47FoMul61U2h4TuQOdyQ/640?wx_fmt=other&from=appmsg "null")  
  
用filePath参数接受path参数与file参数拼接，再从filePth参数中取出文件名赋值给fname参数。  
  
跟进getSuffix：  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/5znJiaZxqldzO5IqmicGWF5n2tTv68cQF05OHabXDJpicgzOvEWaDfibVje5OE8NDEIZMgJG4LicyMtc72plSjibMlMw/640?wx_fmt=other&from=appmsg "null")  
  
发现只是以简单点来获取后缀。  
  
检测是否为jsp文件后，如果不为则进入为空判断，并以FileOutputStream与write直接上传写入。  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/5znJiaZxqldzO5IqmicGWF5n2tTv68cQF0FQFoR0mVu8jr8IPWL5nX0vLksnTrCnpKs4FaBRKiaHic5hbjAxL4N0UQ/640?wx_fmt=other&from=appmsg "null")  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/5znJiaZxqldzO5IqmicGWF5n2tTv68cQF0s2JMUz8icJ14dnQmJcoIPt2tVuHPnAQJtGzLVJrrx7ricjRhzL1AsiaRg/640?wx_fmt=other&from=appmsg "null")  
  
**任意文件删除**  
  
漏洞复现：  
  
上传jsp马后，点击右方删除文件，抓包。  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/5znJiaZxqldzO5IqmicGWF5n2tTv68cQF0zOXpRBtFVEQyHnSvpkcQ3NTByNQzMTO30k51SWfn4IhHWhjrDefzEw/640?wx_fmt=other&from=appmsg "null")  
  
将下方数据包改为admin上级目录，删除我先前上传但没找到路径的test.jspx文件，删除成功：  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/5znJiaZxqldzO5IqmicGWF5n2tTv68cQF0eeLUBbgwrvE0fMKk9AKySQPuYhOcYulsmV4KrtU0mASKprVw6Ol3MQ/640?wx_fmt=other&from=appmsg "null")  
  
代码分析：  
  
根据数据包在IDEA全局搜索，定位到delete代码段：  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/5znJiaZxqldzO5IqmicGWF5n2tTv68cQF0VlbpdQEHCFDbkbRuJPticaGG0zkwibibFW7IB3ibLZgvr0zlZjiaIE00H8A/640?wx_fmt=other&from=appmsg "null")  
  
该方法接收三个参数：path、name 和 data，这些参数通过 @RequestParam
注解从请求中提取，并进行简单拼接，赋值给file对象，此时file对象代表实际的文件名称。  
  
跟进delete方法：  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/5znJiaZxqldzO5IqmicGWF5n2tTv68cQF0PicG5U9S3jTzWcrPUe7hlC0R0rCsicqepDY4HP0G09CWyoqeP0nSgDyA/640?wx_fmt=other&from=appmsg "null")  
  
发现对传入的path参数进行了检查，继续跟进：  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/5znJiaZxqldzO5IqmicGWF5n2tTv68cQF0ibWlsmf0hV8lPUNY2WgQkQxFF8gKmXhQibWGOBplSHicXFhibOWpq2QWvg/640?wx_fmt=other&from=appmsg "null")  
  
发现仅仅采用java自带的类java.security.AccessController下的checkPermission(Permission
perm)静态方法校验权限。  
  
如果权限满足便直接通过fs.delete()方法删除，造成任意文件删除漏洞。  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/7QRTvkK2qC6iavic0tIJIoZCwKvUYnFFiaibgSm6mrFp1ZjAg4ITRicicuLN88YodIuqtF4DcUs9sruBa0bFLtX59lQQ/640?wx_fmt=gif&wxfrom=5&wx_lazy=1&tp=webp "")  
  
学习  
网安实战技能课程  
，戳  
“阅读原文”  
  
  
