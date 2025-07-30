#  Deepseek 有多强？延时注入检测 POC 只需一步，即可获取完美 POC 模板！   
原创 xazlsec  信安之路   2025-02-14 03:12  
  
上篇文章，在提供了一个漏洞数据包后，一步达到需求，今天来测试一个比较复杂一些的需求，在编写 Nuclei POC 时，针对延时注入的接口，需要请求多次才能让测试结果更加准确，判断条件非常规的关键词匹配，而是根据请求的时间来判断，所以今天使用 Deepseek 来一步完成我们的需求。  
  
我们知道某个通用系统的某接口存在 SQL 注入漏洞，以下内容是经过多次调试总结而来，可以一步到位获取我所需的 POC，比如：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/sGfPWsuKAfevia0qH8oBt30ib3sKBKia29q52Rl5B8iaZPgS2L4pXJGSv7KgFOj61AEeRibONh1P4BrHon2C1YQvLGw/640?wx_fmt=png&from=appmsg "")  
  
输出结果：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/sGfPWsuKAfevia0qH8oBt30ib3sKBKia29qHicppYDRhH0amPaKE4cyAMLKlyic3eHM2YFybGxNOzPrGicQiaEl3fPvKg/640?wx_fmt=png&from=appmsg "")  
  
我们测试一下看看效果：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/sGfPWsuKAfevia0qH8oBt30ib3sKBKia29qnDCHYQqruy3MKqDxZP7jpwicrGQdYdyPZBtbzyeJvExZHAFfE2NEDwg/640?wx_fmt=png&from=appmsg "")  
  
验证无任何问题，尝试实战看看：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/sGfPWsuKAfevia0qH8oBt30ib3sKBKia29q7qGpvBjON6QEqv6R6GtUPe3WMJib8bdh8dtgehdFMficUK174ZPJSavA/640?wx_fmt=png&from=appmsg "")  
  
检测 POC 无任何问题，尝试使用 sqlmap 验证是否漏洞真实存在：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/sGfPWsuKAfevia0qH8oBt30ib3sKBKia29qeZkbFm8icvtyOesa9KibKSjgzGPCYoJ5pnO9S3wbIKCuNRMgxvwNuFlA/640?wx_fmt=png&from=appmsg "")  
  
确认无误， AI 并非一条指令就能满足你的需求，需要你不断的调试，给予其指引，从而一步一步达到你所需要的结果，而这个过程中积累的经验，就是你与他人的区别，信安之路文库开设了一个新的文集《AI + 信息安全》将收录我在信安之路上所使用的 AI 技术，欢迎订阅！  
  
![](https://mmbiz.qpic.cn/mmbiz_png/sGfPWsuKAfc1ibbG6mEdqV5Xpw0yu9UxtIoLlhiazxU4NakInEiam1mOnHHYw4pVq3nrrCc8tpnn5ictdhmNLUaHuA/640?wx_fmt=png&from=appmsg "")  
  
