#  高质量企业+eduSRC漏洞挖掘实战资料分享   
原创 Mstir  星悦安全   2024-12-07 05:54  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/lSQtsngIibibSOeF8DNKNAC3a6kgvhmWqvoQdibCCk028HCpd5q1pEeFjIhicyia0IcY7f2G9fpqaUm6ATDQuZZ05yw/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
点击上方  
蓝字  
关注我们 并设为  
星标  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/uicic8KPZnD5en9kQhb3nnROIcxYGLotMhFLBxM8rnB5nPPprKQty1SvBIMBDfCTh6TByaMickmJvTT2KK9mwbDZQ/640?wx_fmt=png&from=appmsg "")  
  
  
part 01  
  
一、SRC挖掘  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/DW3j9hNYCMJVseXY6McdprBe3flnjV1nkg9wLWFDt7Eheic43k4VD2AdbuVRRxuXrfNmjAeicCL4YFq8NbSx1kDg/640?&wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
BETTER  
  
![](https://mmbiz.qpic.cn/mmbiz_png/fHwBpeeZQkz05RHr4N0taQB5vTwLfcM2e4gIOLDc6cXZicKkGWQLWkAF6Ob28ETm4iaRZKovaNGXnUX8r7rJ3ib3A/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/jW0cyQc5LAE8XqrBDVuOHhCCXiaCH0PCdQaG4MiaA4flIcPy6RCI1CeelQqc6zficMAUCibrgINN3Gib1bE3r8TP8AA/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
1.平时挖掘SRC的时候，时常感觉挖不到洞？其实应该是思路没走正，走正了思路，方能快速挖掘出多种不同类型的漏洞。其实现在SRC挖掘里，常规漏洞还是占比较大的比例，但逻辑漏洞，从几年前开始就大展拳脚了，现在也是比较容易碰见的.  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/uicic8KPZnD5en9kQhb3nnROIcxYGLotMhhHrXgxM9LBPgrrZkx9q3y4XYhj7iaMHMLf1yicpiaImNicuRT3E02lXibxw/640?wx_fmt=png&from=appmsg "")  
  
  
2.现在src挖掘里，移动端的漏洞也是占了相当一部分的比例，XSS也是不可小觑.  
  
  
3.  
有时候挖不到洞，或许是信息收集不到位，这里可以从多个层面去搜集信息，Fofa，鹰图，360安全测绘，zoomye等网络空间搜索引擎都去看一遍，肯定会有不重合的子域，端口等信息.  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/uicic8KPZnD5en9kQhb3nnROIcxYGLotMh5DQy1Xp7KIJDM5rxV4RwCnDToRkBkgA4wZ6qooJ0F1kibd6PI03e3YA/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/uicic8KPZnD5en9kQhb3nnROIcxYGLotMhUxeXTXZQibDNsCuzE4BqwWOmZv6hbSgfuRHY0vGVfWarpoMRIdWl21A/640?wx_fmt=png&from=appmsg "")  
  
  
  
4.现在 Nuclei 已经开始普遍性在漏洞挖掘中使用，我个人使用下来确实觉得这个工具真心不错，挖EDU的时候就找到了非常多的可能的漏洞信息，当然，默认的导出格式是比较难以分辨的，最好将数据存储在云上好查看.  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/uicic8KPZnD5en9kQhb3nnROIcxYGLotMheUj5x3JymW87F9rnmFJWc8sPrPFXe49JujVAp5S7g6Wa1HCZlN4PeQ/640?wx_fmt=png&from=appmsg "")  
  
  
5.当然，现在常规漏洞还是有挺多存在的，这里就得考验到你的漏洞收集能力，整合网络上能搜集到的所有Nday，或者自己去挖掘一些0day，1day等，在edu的SRC挖掘中也是可以通杀一片.  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/uicic8KPZnD5en9kQhb3nnROIcxYGLotMhibAMJflO2DVYU7kqY8SlQgY0PwkPia7Bzhl1mW0n3cMV8LEsfZhbb2Vg/640?wx_fmt=png&from=appmsg "")  
  
  
6.edusrc挖掘中，也可以有针对性地去挖某个OA，或者CMS，用一些老的Nday打，也许能捡捡漏，大头早就被人批量挖完提交了，除非是自己审计的0day之流，才能通杀一片.  
  
![](https://mmbiz.qpic.cn/mmbiz_png/X4K2loV6ggicQLkSRWXjR0vcQZibMwOdOqDQubJzjpEfdgTnxMdIrgrKvyBuxr6BWYJfCOxOIlibibWiaXiaT8rP3H5Q/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
  
**这里我整理了471个SRC漏洞挖掘资料，都比较新，且都是实战类型的，大家可以下载学习.**  
  
****  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/uicic8KPZnD5en9kQhb3nnROIcxYGLotMh1fTiavRg46u4xuTI6tMG6veDpnDkU8eImUe0m4PHYdeZPVgMSF3GzMg/640?wx_fmt=png&from=appmsg "")  
  
****  
```
下载地址:https://pan.quark.cn/s/0ccc1d33bdae

```  
  
  
**PS:关注公众号，持续更新最新文章!!**  
  
  
  
  
下方二维  
码添加好友，回复关键词   
**星悦安全**  
进群  
  
![](https://mmbiz.qpic.cn/mmbiz_png/pPVXCo8Wd8CGA5xDtuNnCSVGd0ibW86zZaJ6tr5ib17xnMbupUibq24HQEl4gRoptsVgCBSNnwBEGmSn3a4ftXVzQ/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
![](https://mmbiz.qpic.cn/mmbiz_png/pPVXCo8Wd8AOzYX7kxefGbGGZg3g1ltkN30q9hceg23PiczgUqMT0EE9w0fLK9uw1eKWwQX9TljXQe1OQeHRZ2Q/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
**免责声明:****文章中涉及的程序(方法)可能带有攻击性，仅供安全研究与教学之用，读者将其信息做其他用途，由读者承担全部法律及连带责任，文章作者和本公众号不承担任何法律及连带责任，望周知！！!**  
  
