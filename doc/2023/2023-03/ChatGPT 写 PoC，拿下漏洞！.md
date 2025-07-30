#  ChatGPT 写 PoC，拿下漏洞！   
 渊龙Sec安全团队   2023-03-24 19:51  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/GGOWG0fficjLTMIjhRPrloPMpJ4nXfwsIjLDB23mjUrGc3G8Qwo770yYCQAnyVhPGKiaSgfVu0HKnfhT4v5hSWcQ/640?wx_fmt=gif&wxfrom=5&wx_lazy=1 "")  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/GGOWG0fficjIHqLb6QW9NRrYuR6zILLb40LViafmR6IhJE39n1R6pica4pDia71aibEibr8QyUnvokoLibrfylAh0ydqg/640?wx_fmt=jpeg "")  
  
  
Goby社区第   
23  
   
篇技术分享文章  
  
全文共：  
3901  
   
字    
   
预计阅读时间：  
10  
   
分钟  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/GGOWG0fficjKzq4TFicia2yUjianoH80KtrWElvrR0XQbqBDCHC68DicU6TwYLR54jEJE3rqy2icwicrV85dICfKrJsOQ/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
   
**01**  
**前言******  
  
ChatGPT（Chat Generative Pre-trained Transformer）是当今备受瞩目的智能AI聊天机器人之一。它不仅能够实现基本的语言交流，还具备许多强大的功能，例如文章撰写、代码脚本编写、翻译等等。那么我们是否可以利用 ChatGpt 去辅助我们完成一些工作呢？比如当一个产品存在安全风险需要漏洞检测时，我们就需要编写对应的POC来实现。目前  
进行  
多次验证，我们初步证实了这个实验的可行性，可以训练   
ChatGPT 去编写简单的 PoC，但是它对细节的把控并不够完善，例如对输出内容进行匹配的正则表达式的编写和一些复杂逻辑的处理等存在一定的误差，还需要人工干预修改处理  
。  
另外  
我们利用比对的方式验证了   
ChatGP  
T   
的一些  
安全  
猜想  
和训练模型的准确性  
。如下是将其与   
Goby 实战化网络攻防工具所结合进行利用检测的实现效果：  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/GGOWG0fficjIHqLb6QW9NRrYuR6zILLb4Oqg7umXyxqCV3KkHHeRcXliabaSxxQwbQVFYx0tibm8X5UZUcbiapOXbQ/640?wx_fmt=gif "")  
  
##   
  
![](https://mmbiz.qpic.cn/mmbiz_png/GGOWG0fficjKzq4TFicia2yUjianoH80KtrWElvrR0XQbqBDCHC68DicU6TwYLR54jEJE3rqy2icwicrV85dICfKrJsOQ/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
   
**02 训练过程**  
  
我们利用 ChatGPT 与 Goby 结合编写 PoC 与 EXP 有两种方法：半自动编写和全自动编写（过程中使用 ChatGPT-Plus 账号）。  
  
半自动编写利用 ChatGPT 进行语言格式转换，转换后生成的代码可能存在细节问题，需要进一步排错完善，最后修改对应的语句和函数内容完成 PoC 与 EXP 的编写。  
  
全自动编写通过将使用到的代码模板、漏洞详细信息给到 ChatGPT，让它自动生成对应模板的 PoC，在给出详细信息时需要注意信息的完整与准确。目前可以实现自动编写简单的 PoC，对于EXP来说还需要进一步训练 ChatGPT 对 Goby 内置函数的使用等。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/GGOWG0fficjKzq4TFicia2yUjianoH80KtrWElvrR0XQbqBDCHC68DicU6TwYLR54jEJE3rqy2icwicrV85dICfKrJsOQ/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
   
**03 CVE-2010-2861**  
  
Adobe ColdFusion 是一款高效的网络应用服务器开发环境。Adobe ColdFusion 9.0.1 及之前版本的管理控制台中存在多个目录遍历漏洞。远程攻击者可借助向   
/CFIDE/administrator/enter.cfm  
 和   
/CFIDE/administrator/archives/index.cfm   
等发送的 locale 参数读取任意文件。  
  
**3.1 半自动编写**  
  
首先尝试让 ChatGPT 将 CVE-2010-2861 目录遍历漏洞的 Python 格式 EXP 转换为 Go 语言格式的代码，这样可以利用 ChatGPT 代替人工完成代码解释及代码转换的过程。  
  
我们在漏洞公开平台中选取该漏洞的 EXP 代码：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/GGOWG0fficjIHqLb6QW9NRrYuR6zILLb4j87WPYaz9NIlAYxuheazNc1ictHGywc10ZKWxmvyXhsX1CaIsShPduw/640?wx_fmt=png "")  
  
在使用 ChatGPT 将相应漏洞的 EXP 代码转换之前，先演示一下原始 Python 代码的执行效果，具体如下：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/GGOWG0fficjIHqLb6QW9NRrYuR6zILLb45e289glFh274vpykibkKSianIzs3icNO2B6QGibnR20mm8ugfBPoOSXgYw/640?wx_fmt=png "")  
  
开始转化格式：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/GGOWG0fficjIHqLb6QW9NRrYuR6zILLb4sKkDLV6KRrC2wmSLegIx8klb2ERFrvv8UX05iblvNicALNicicPSXgpUHA/640?wx_fmt=png "")  
  
此外，他还提供了该程序的使用方法。然而，每次 ChatGPT 的回答都可能不完全相同。此前的回答中并没有详细说明函数的具体用法，但在另一个回答中给出了以下解释：（如果需要，可在问题中增加“并介绍函数的具体用法”）  
  
![](https://mmbiz.qpic.cn/mmbiz_png/GGOWG0fficjIHqLb6QW9NRrYuR6zILLb4gve7ValN9dC70taRkTDbC7ktN9cK7LodOtOc1CxuV103hFJvjRlYiag/640?wx_fmt=png "")  
  
最后进行代码调试后，发现无法立即使用，未能成功读取所需的文件内容：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/GGOWG0fficjIHqLb6QW9NRrYuR6zILLb4DrbnkoW1pr9SvUebNUJeCgF2IZ1k91ASiaHtjiaK4ztj29TDNIAkMlew/640?wx_fmt=png "")  
  
那么就需要开始排错，以下是排错过程：  
  
检查正则匹配后字符串是否为空：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/GGOWG0fficjIHqLb6QW9NRrYuR6zILLb4L7lNNDm2boM3Lc4g7FnnicSibVEMSEQZfqtvITaExXAZpqXLvR21SsyA/640?wx_fmt=png "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/GGOWG0fficjIHqLb6QW9NRrYuR6zILLb4Kmhibibm3LDecWFFQ0jqUwGaRcfcFiaZMtnZSIQaXk61BbLEYMiboibdLxg/640?wx_fmt=png "")  
  
检查返回包内容是否正常，有无所需内容，如下返回数据包显示正常：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/GGOWG0fficjIHqLb6QW9NRrYuR6zILLb48skrSdeicX4En5bVMftSEuhuRXdSRWjhzuLo8U8fhjFyK9nehhkdngA/640?wx_fmt=png "")  
  
判断正则表达式有问题，无法匹配到对应内容：  
  
通过排查发现正则表达式中没有正确匹配，因此无法将文件的内容正确取出，做出以下修改，修改后内容具体如下：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/GGOWG0fficjIHqLb6QW9NRrYuR6zILLb4LscffUgUyIazWD6dKQFoaZqc3PTQJYdLSAbbniaGnE6XYOjWDRUKgyQ/640?wx_fmt=png "")  
  
修改前：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/GGOWG0fficjIHqLb6QW9NRrYuR6zILLb4QJFL7cSFFWUTNSHVxh9dXeskRI0Nia2KWZep8B05JsCEfia1w9WQj62Q/640?wx_fmt=png "")  
  
最终执行结果，完成 Python—Go 的转化：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/GGOWG0fficjIHqLb6QW9NRrYuR6zILLb4BSK9LPY6DfEiaibEr7AIwYYKH5DS3cMIbhonkWh5nobEaGhJGtlxqDibw/640?wx_fmt=png "")  
  
前面我们已经成功将 Python 格式的EXP转换为了 Go 语言格式，现在尝试将其转换为 Goby 格式的 PoC 和 EXP。  
  
由于 Goby 使用的是基于 Go 语言开发的自研漏洞框架，为方便用户使用，其中已有很多内置函数可供用户使用，所以只需要利用上述部分代码即可完成 PoC 和 EXP，以下是 EXP 修改的大致说明与详细内容：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/GGOWG0fficjIHqLb6QW9NRrYuR6zILLb4tBsAcPe4XNFibF03vOztR8qhbeMk4mCzNkh5J6vzktp89ctjIfRTuqQ/640?wx_fmt=png "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/GGOWG0fficjIHqLb6QW9NRrYuR6zILLb4dMqtKnqEHxFKgPln2BGsq70FqJlum0bq8Q5Zj1ufBwptRFeuekHKPg/640?wx_fmt=png "")  
  
修改 import 内容：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/GGOWG0fficjIHqLb6QW9NRrYuR6zILLb4wMRiaOGPFffaUMcJG5Xic65uHbUB3lkV8Jmwc1owia1lia1Nic4U5XLtTrg/640?wx_fmt=png "")  
  
由于生成的 EXP 在命令行使用时需要手动输入参数：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/GGOWG0fficjIHqLb6QW9NRrYuR6zILLb4yBnAdFX3HZbSgj3bCVUERkzmb8s1NySnZDiaZr6YJiaHQictfffpg7Vag/640?wx_fmt=png "")  
  
那么在 PoC 转化时，需要重新定义常量，并利用 Goby 中的   
httpclient.FixUrl.IP  
 与   
httpclient.FixUrl.Port  
 获取测试的 IP 和端口号，确定测试的文件路径 path：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/GGOWG0fficjIHqLb6QW9NRrYuR6zILLb4lRz6Gh8qKYicQIYSvial4zP4ytKLuYG5PNKo3KiaHJQkdxHjc2ZCL82RQ/640?wx_fmt=png "")  
  
接着在 PoC 中添加条件判断语句，判断漏洞存在的特征，并返回 true（有漏洞）：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/GGOWG0fficjIHqLb6QW9NRrYuR6zILLb4W39LAnFArC0E69R4biaf9R626zlZIQ65Mvc4jtNrvKFBdehtjmoCqfA/640?wx_fmt=png "")  
  
最后删除多余的输出打印代码即可完成 PoC 转化，如：![](https://mmbiz.qpic.cn/mmbiz_png/GGOWG0fficjIHqLb6QW9NRrYuR6zILLb4hAAibH7pHxm5VclezkdufiaMP2jia2EpzEiaG8MjY0FC1WCZg65xibyn5Zg/640?wx_fmt=png "")  
  
  
EXP 转化时，需重新定义变量，利用 Goby 中的   
expResult.HostInfo.IP  
 与   
expResult.HostInfo.Port  
 获取测试的IP和端口号，利用   
ss.Params["filePath"]  
. (string) 获取用户输入的 EXP 参数——测试文件路径 filePath：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/GGOWG0fficjIHqLb6QW9NRrYuR6zILLb4WlDxNZwhDqIibubU1oeIRJnxqoVM2ibOjqkbWDmCib5v8298Dliaia2IL2Q/640?wx_fmt=png "")  
  
接着在 EXP 代码中添加条件判断语句，判断 EXP 是否执行成功，并输出 EXP 执行结果，完成 EXP 转化：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/GGOWG0fficjIHqLb6QW9NRrYuR6zILLb4nAHfZiaEXLmlS48BNflpQG5qEh3o1AWd146C0eNG3heFCYiaPhGpUia2Q/640?wx_fmt=png "")  
  
**3.2 全自动编写**  
  
在使用 ChatGPT 与人工相结合编写后，我们进一步尝试使用它来撰写 Goby 格式的 PoC。  
  
首先将 Goby 格式的模板给出：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/GGOWG0fficjIHqLb6QW9NRrYuR6zILLb4sxgsXQMZK7Dq168xAWLrubrTYY9nlRgCc2VlRbvfiaTOPzmFDUeJItQ/640?wx_fmt=png "")  
  
接着将漏洞的编号、产品、类型、Url、漏洞文件、参数和判断成功条件给出，说明相关的字段格式，我们最终得到了下面的代码，它已经可以通过 Goby 前端的编译，并可以成功地生成简单的 PoC：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/GGOWG0fficjIHqLb6QW9NRrYuR6zILLb4Xhq8kKdibIqicUK5LTlS5GQzsfPhuN4QfNn0lFtNzEbENZTJQVeszScg/640?wx_fmt=png "")  
  
模型训练初步完成，继续使用第二个案例验证模型完善程度：![](https://mmbiz.qpic.cn/mmbiz_png/GGOWG0fficjIHqLb6QW9NRrYuR6zILLb4Yejib3wDf09ef9ELqIlgU0aFPDuImWtXkcx1WYmWjfEavvupKqrjsIA/640?wx_fmt=png "")  
  
  
发现 Name 字段还是存在格式错误，再次训练修改（若验证中 Name 字段等输出正确，那么即可跳过此纠错步骤）：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/GGOWG0fficjIHqLb6QW9NRrYuR6zILLb4w13hzQrm8vlbMHDoDFdSxiax1IS0ZVgicq3yOGAZ2am9KqUr30vFN9fw/640?wx_fmt=png "")  
  
最后使用第三个案例进行验证最终的训练结果，训练成功：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/GGOWG0fficjIHqLb6QW9NRrYuR6zILLb4oXibv0ia3L50Nq9B8yFicYyWbuCc1odT19p2DgVHrRcjicKT3kmv23wCtw/640?wx_fmt=png "")  
  
将代码放入 Goby 中，并填入缺少的漏洞描述信息（后续还可继续深入训练），运行效果如下：  
  
  
   
![](https://mmbiz.qpic.cn/mmbiz_png/GGOWG0fficjKzq4TFicia2yUjianoH80KtrWElvrR0XQbqBDCHC68DicU6TwYLR54jEJE3rqy2icwicrV85dICfKrJsOQ/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
   
**04 自我学习**  
  
  
当我们在利用 ChatGPT 去帮助编写一个新鲜出炉的 0day 漏洞或者其他机密漏洞的检测 PoC 这个过程当中，是否会导致程序注入或信息泄露等问题呢？也就是说当模型训练完成后，其他用户提问相关的内容，ChatGPT 是否会直接将训练好的模型或数据直接输出呢？  
  
为了验证 ChatGPT 自我学习的猜想是否存在，分别通过“不同会话”与“不同账户”来进行训练。经过以下实践，得到的结论是 ChatGPT 并不会进行跨会话与跨账号的自我学习，训练好的模型与数据是掌握在 OpenAI 手中的，其他用户并不会得到相关的模型，所以目前还不存在相关信息数据泄露的安全风险，但日后的情况还需要根据 OpenAI 采取的决策做判断。  
  
**4.1 不同会话比对**  
  
将使用的模板（此处省略示意图）和漏洞信息给出，可以看到 PoC 中的 Name 和 Desc ription 字段并没有按照上一个会话中的训练模式来进行填充，因此在不同会话当中 ChatGPT 并不会自我学习，每个会话间的训练模型独立：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/GGOWG0fficjIHqLb6QW9NRrYuR6zILLb4zicygFeGTHAvNzEsKtPILlt6CaFq7JHpxkze5FRKuyzsJwDmrrN70Kg/640?wx_fmt=png "")  
  
**4.2 不同账号比对**  
  
同样将模板（此处省略示意图）和漏洞信息给出，也可以看到 PoC 中的相关字段并没有按照之前的训练模型来进行填充，由此可得知 ChatGPT 并不会跨账号自我学习：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/GGOWG0fficjIHqLb6QW9NRrYuR6zILLb4Pe9fXzzYOWqrjfEf58QD2haFcRDKfxxWcs3rKicEZPJfVAQD8FDCL9w/640?wx_fmt=png "")  
  
****  
****  
   
![](https://mmbiz.qpic.cn/mmbiz_png/GGOWG0fficjKzq4TFicia2yUjianoH80KtrWElvrR0XQbqBDCHC68DicU6TwYLR54jEJE3rqy2icwicrV85dICfKrJsOQ/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
   
**05 ChatGPT3与4**  
  
ChatGPT4 已经更新上线，那么去使用 ChatGPT4 进行同样的全自动编写训练和 ChatGPT3 训练出来的模型有什么区别呢？答案是 ChatGPT4 要比 3 更“聪明灵动”一些，模型的生成更为准确。  
  
我们将所需要的各种信息给出，经过一次训练后（此处省略部分示意图），达到了下图中正确的效果：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/GGOWG0fficjIHqLb6QW9NRrYuR6zILLb4hEUkZKQnFzA0L1GQfOnsG7Pml6ZItcHuQQiaXwpYpiboJGhG8BlcVHsw/640?wx_fmt=png "")  
  
另外我们进行了 10 轮的训练，针对模型中的Name字段进行比对，来判断 ChatGPT3 与 4 的 PoC 编写准确率，发现均会出现概率性的出错情况，其中 3 的模型输出准确率要比 4 低一些，在一定情况下仍需进行纠错训练，如下表格所示：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/GGOWG0fficjIHqLb6QW9NRrYuR6zILLb4dVjgJBjhRIsGhzzMicVtYhqCMbCCF3Xc6ib2rrgpaS2ZgXsHKtdB2Hmg/640?wx_fmt=png "")  
  
  
   
![](https://mmbiz.qpic.cn/mmbiz_png/GGOWG0fficjKzq4TFicia2yUjianoH80KtrWElvrR0XQbqBDCHC68DicU6TwYLR54jEJE3rqy2icwicrV85dICfKrJsOQ/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
   
**06 总结**  
  
总的来说，ChatGPT 确实能够帮助完成一部分的工作，对于日常的工作例如编写漏洞 PoC，可以利用它的代码转换能力加速编写；也可以将漏洞的详细信息给出，利用 ChatGPT 训练合适的模型，直接输出一份简单的漏洞验证 PoC 代码，更加便捷快速。但它所提供的回答内容并不一定能直接复制使用，还需要进行一些人工的修正来完善。另外目前我们也可以相对放心去使用 ChatGPT，它并不会将单个用户的训练模型数据输出给其他用户来使用（不混淆会话可能是担心用户数据互相污染），但日后还需要针对 OpenAI 总部所作出的决策来进一步判断。因此 ChatGPT 的合理使用，可以辅助提高一定的工作效率，若日后可以再延续进一步的训练开发，比如是否可以利用其编写信息描述规范且较为复杂的 PoC 甚至是 EXP，或者将其工程化批量完成内容去探索更多的应用场景和潜力。  
  
**参考**  
  
[1] https://gobysec.net/exp  
  
[2] https://www.exploit-db.com/exploits/14641  
  
[3] https://zhuanlan.zhihu.com/p/608738482?utm_source=wechat_session&utm_medium=social&utm_oi=1024775085344735232  
  
[4] [用ChatGPT来生成编码器与配套Webshell](https://mp.weixin.qq.com/s?__biz=MzI0MDI5MTQ3OQ==&mid=2247484598&idx=1&sn=3b59424c1a1cc58697de17a60e7e5072&scene=21#wechat_redirect)  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/GGOWG0fficjKzq4TFicia2yUjianoH80KtrWfiaAtUngV8rgLh0bIibv9SumD1Y9ZmphGxK9lKiakkOWDp2gRsLjZInPg/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
**最新 Goby 使用技巧分享**  
**：**  
  
[• ](http://mp.weixin.qq.com/s?__biz=MzI4MzcwNTAzOQ==&mid=2247510124&idx=1&sn=de3aef91a47b6472d987c2fb7e6f3f6e&chksm=eb8443ccdcf3cadaa4c0ceb1905e14a9d7f3f01bf44f272bd0821c7359db0a847d8533c7abe2&scene=21#wechat_redirect)  
[Shell中的幽灵王者-JAVAWEB内存马【认知篇】](http://mp.weixin.qq.com/s?__biz=MzI4MzcwNTAzOQ==&mid=2247521497&idx=1&sn=50e062aa20930102e6b787711d0e214a&chksm=eb847f79dcf3f66f1ac0d14065fdef2576393e9142f36c5add4e738eebbf3b71410a79e759ef&scene=21#wechat_redirect)  
  
  
[• ](http://mp.weixin.qq.com/s?__biz=MzI4MzcwNTAzOQ==&mid=2247510124&idx=1&sn=de3aef91a47b6472d987c2fb7e6f3f6e&chksm=eb8443ccdcf3cadaa4c0ceb1905e14a9d7f3f01bf44f272bd0821c7359db0a847d8533c7abe2&scene=21#wechat_redirect)  
[Goby反序列化漏洞一键打入内存马【利用篇】](http://mp.weixin.qq.com/s?__biz=MzI4MzcwNTAzOQ==&mid=2247521997&idx=1&sn=d3c444f95c97f06b1d24240a91bd898d&chksm=eb847d6ddcf3f47b0c50ab4a97b2adbee3241149d9a3ac5a56958e76ac33ede48e0bbd108952&scene=21#wechat_redirect)  
  
  
[• Corp0ra1 | 记一次不停的自我追问式学习(下)](http://mp.weixin.qq.com/s?__biz=MzI4MzcwNTAzOQ==&mid=2247505258&idx=1&sn=7ff14823c497fb2734d14435ee5caeb9&chksm=eb843ecadcf3b7dc718e2bdb11fba1415582d7410c12d990931d0d8358a924e5363df4135590&scene=21#wechat_redirect)  
  
  
[• mesosaur | IP库？信息？资产？拿来吧你！](http://mp.weixin.qq.com/s?__biz=MzI4MzcwNTAzOQ==&mid=2247509617&idx=1&sn=3e3e7df89231add9c55eb051b5a8c8ea&chksm=eb844dd1dcf3c4c797b2b3c78588a269fec6fba092be86c6661b77d0487aca35f5ba32b2ad81&scene=21#wechat_redirect)  
  
  
[• ](http://mp.weixin.qq.com/s?__biz=MzI4MzcwNTAzOQ==&mid=2247491982&idx=1&sn=32af9069f2cc46ca4e976949bf59fb9b&chksm=eb840a2edcf38338aa47e684a294e3adb420fa79c1fbabe890344ab6d04f1e9fbb71a6d1824e&scene=21#wechat_redirect)  
[ybdt | 还在手动收集资产？你比别人慢了一步](http://mp.weixin.qq.com/s?__biz=MzI4MzcwNTAzOQ==&mid=2247509945&idx=1&sn=6a9a013fc8ff29dce7ff46c8ce0c8244&chksm=eb844c19dcf3c50f66cd66e484ceeb989a4c08118b71d50a849bda0ba51e33eb30b30eeaf8ef&scene=21#wechat_redirect)  
  
  
更多 >>  插件分享  
  
  
  
Goby 欢迎表哥/表姐们加入我们的社区大家庭，一起交流技术、生活趣事、奇闻八卦，结交无数白帽好友。  
  
也欢迎投稿到 Goby（Goby 介绍/扫描/口令爆破/漏洞利用/插件开发/ PoC 编写/ IP 库使用场景/ Webshell 等文章均可），审核通过后可加 5000-10000 社区积分哦，我们在积分商城准备了好礼，快来加入微信群体验吧~~~  
- 微信群：公众号发暗号  
“加群”  
，参与积分商城、抽奖等众多有趣的活动  
  
- 获取版本：https://gobysec.net/sale  
  
![](https://mmbiz.qpic.cn/mmbiz_png/GGOWG0fficjIaeEP9ZkuBRxk7BicMlGFoEZnkVh7ib8GaBYw8lrh8SqACnTUZXlXclC9ZRfOFuvB3gTWHOPvH8icyg/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
