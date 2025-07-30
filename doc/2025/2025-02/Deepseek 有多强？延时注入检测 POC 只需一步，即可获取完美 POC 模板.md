#  Deepseek 有多强？延时注入检测 POC 只需一步，即可获取完美 POC 模板   
信安之路  搞安全的面具侠   2025-02-16 08:30  
  
上篇文章，在提供了一个漏洞数据包后，一步达到需求，今天来测试一个比较复杂一些的需求，在编写 Nuclei POC 时，针对延时注入的接口，需要请求多次才能让测试结果更加准确，判断条件非常规的关键词匹配，而是根据请求的时间来判断，所以今天使用 Deepseek 来一步完成我们的需求。  
  
我们知道某个通用系统的某接口存在 SQL 注入漏洞，以下内容是经过多次调试总结而来，可以一步到位获取我所需的 POC，比如：  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/sGfPWsuKAfevia0qH8oBt30ib3sKBKia29q52Rl5B8iaZPgS2L4pXJGSv7KgFOj61AEeRibONh1P4BrHon2C1YQvLGw/640?wx_fmt=png&from=appmsg "")  
  
输出结果：  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/sGfPWsuKAfevia0qH8oBt30ib3sKBKia29qHicppYDRhH0amPaKE4cyAMLKlyic3eHM2YFybGxNOzPrGicQiaEl3fPvKg/640?wx_fmt=png&from=appmsg "")  
  
我们测试一下看看效果：  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/sGfPWsuKAfevia0qH8oBt30ib3sKBKia29qnDCHYQqruy3MKqDxZP7jpwicrGQdYdyPZBtbzyeJvExZHAFfE2NEDwg/640?wx_fmt=png&from=appmsg "")  
  
验证无任何问题，尝试实战看看：  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/sGfPWsuKAfevia0qH8oBt30ib3sKBKia29q7qGpvBjON6QEqv6R6GtUPe3WMJib8bdh8dtgehdFMficUK174ZPJSavA/640?wx_fmt=png&from=appmsg "")  
  
检测 POC 无任何问题，尝试使用 sqlmap 验证是否漏洞真实存在：  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/sGfPWsuKAfevia0qH8oBt30ib3sKBKia29qeZkbFm8icvtyOesa9KibKSjgzGPCYoJ5pnO9S3wbIKCuNRMgxvwNuFlA/640?wx_fmt=png&from=appmsg "")  
  
转载：  
   
信安之路  
  
