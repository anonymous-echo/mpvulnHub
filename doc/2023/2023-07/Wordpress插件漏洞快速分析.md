#  Wordpress插件漏洞快速分析   
king  360Quake空间测绘   2023-07-11 17:16  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/R2O64T36XGtjMlxWDMfM5u12pNWlzF15rH7JldHprEyCEy8QXeKRCWeDUfgFQsyfIHJt86XZibNdAKJzyRddN1Q/640?wx_fmt=png "")  
  
Wordpress有众多插件每日都有很多漏洞爆出，如何快速分析这些漏洞呢，下面拿cve-2023-25970漏洞举例，  
  
Zendrop – Global Dropshippin插件存在任意文件上传，大部分插件在wordpress官网都有代码变更历史，直接去官网找到变更代码。  
  
下图可以看见上传正则明显存在问题，只要后缀存在png,jpg,gif就可以直接上传了：  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/R2O64T36XGtjMlxWDMfM5u12pNWlzF15bBCv80QPbzBFQkevcdbRNNlLMQJHm6e37XHS04mSOh9Q3iaEibL3kruA/640?wx_fmt=png "")  
  
现在问题在于如何访问到这一步，我们可以看到是_saveFile这个函数出了问题，追溯代码看看哪里调用就行，最终到最后发现是如下代码最终调用了_saveFile，这个是wordpress rest api调用。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/R2O64T36XGtjMlxWDMfM5u12pNWlzF157HW33CJrLMJY0oWddxjzNVycNaEnhKaRa9YetRYlicHVqsriaicKkv38w/640?wx_fmt=png "")  
  
Namespace就是主路径，rest_base就是子路径，直接拼接以下路径就可以了index.php/wp-json/a2c/v1/bridge-action  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/R2O64T36XGtjMlxWDMfM5u12pNWlzF15pWXp75JppWZUwZExQDem9ZibZOkmwAB0y26Z7uJB2gUcOaVnlf3K4Kg/640?wx_fmt=png "")  
  
然后构建参数就行了，因为_saveFile是基于M1_Bridge_Action_Savefile类下 找一下哪里调用的  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/R2O64T36XGtjMlxWDMfM5u12pNWlzF15pyIwQmwib40SEyjAH675rtP8icUGicFuca3tcvPUmWhhP0g4OVJT6ibfgA/640?wx_fmt=png "")  
  
可以看见run函数中action只要是Savefile就可以走到漏洞函数中了  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/R2O64T36XGtjMlxWDMfM5u12pNWlzF15ntcgjrfwm17iaeYibXxu9KWial2HoFvQvex16dJkJKD1tiaotZw3QfbYRw/640?wx_fmt=png "")  
  
现在就可以成功进行上传了，下图可以看见已经成功上传了php文件。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/R2O64T36XGtjMlxWDMfM5u12pNWlzF15TK8btDmaQISnh3Yh4VEicIBX9I6V4VnUsrKhNaqI3SPu8IeXAe37bTg/640?wx_fmt=png "")  
  
那么像这这种rest api的怎么利用quake测绘找到呢，对于wordpress来说wp-json泄露了很多接口，我们随机找一个wordpress，因为这个插件是基于Zendrop的页面从会有shop页面，所以找返回包里存在shop关键字就行。  
  
搜索语法：app:"WordPressCMS博客系统" and response:"/shop"  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/R2O64T36XGtjMlxWDMfM5u12pNWlzF15BgDr0eQ4GibWBb00DKq9pX9KQnB8kUn1m6KIC2Gw6bInibRGvMefpfdg/640?wx_fmt=png "")  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/R2O64T36XGtjMlxWDMfM5u12pNWlzF157QsA0pB0RDhV6pnibbfEyyH1PRkEIYKrNgcl6LlKDhgVh42nDxibJG0g/640?wx_fmt=png "")  
  
或者用图像数据接口搜索也可以。  
  
访问index.php/wp-json接口，这个接口泄露了wordpress可以调用的rest api。可以看见存在这个我们分析这个插件的接口，说明安装了这个插件，可以进行利用。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/R2O64T36XGtjMlxWDMfM5u12pNWlzF15XSGFwzbAUc9BQ0nZtmUFhAGdHhH4lS0Vlw9BFSwXSMqiau1AU9NO6og/640?wx_fmt=png "")  
  
以上就是关于WordPerss插件如何快速分析进行利用，这边在给大家推荐一下quake的图像数据的img_ocr语法，识别图片关键字。渗透有时候会有奇效，可以直接发现某些漏洞，比如img_ocr: "whoami"就可以发现某些未授权vnc  
  
   
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/R2O64T36XGtjMlxWDMfM5u12pNWlzF15iaX9ehR4Ehc5eb0ia8NyzMSkRiaCfC97kdyVt1TDpNmCqQoZthLQhUGHA/640?wx_fmt=png "")  
  
比如有些WordPerss插件会自定义路由，有时候response没有关键字进行识别，就可以利用img_ocr进行图像文字识别去查找特定插件。  
  
  
  
**欢迎进群**  
  
  
  
添加管理员微信号：**quake_360**  
  
备注 您的账号 邀请加入技术交流群  
  
  
  
