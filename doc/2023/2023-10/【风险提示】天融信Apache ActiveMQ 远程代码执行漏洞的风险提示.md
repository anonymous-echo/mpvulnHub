#  【风险提示】天融信Apache ActiveMQ 远程代码执行漏洞的风险提示   
原创 天融信应急响应  天融信阿尔法实验室   2023-10-26 17:10  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/H6W1QCHf9dEUVE5zjonz9KVLuIKD1PH76micZInVWk3AtIcz1gibQUaGVMaibS47WuSic1dmN7MpfpicBKJJH9gTU6w/640?wx_fmt=png "")  
  
**0x00 背景介绍**  
  
10月26日,天融信阿尔法实验室监测到Apache ActiveMQ官方发布 5.18.3 版本与 5.17.6 版本，修复了一个远程代码执行漏洞。POC已公开并发现在野利用。  
  
  
**0x01 漏洞描述**  
  
  
攻击者可构造恶意请求向Apache
ActiveMQ的61616端口发送恶意数据，ActiveMQ对传入的TCP数据没有进行校验。最终能直接执行任意命令，接管ActiveMQ服务器。  
  
复现截图：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/H6W1QCHf9dEUVE5zjonz9KVLuIKD1PH7Q38tB0fN1OmUgkc0Jh64YE8GyzyzCUPbFmITlNZppapUiazqDU3Cz2g/640?wx_fmt=png "")  
  
**0x02 漏洞编号**  
  
暂无  
  
**0x03 漏洞等级**  
##   
  
高危  
  
**0x04 受影响版本**  
  
Apache ActiveMQ < 5.18.3  
  
Apache ActiveMQ < 5.17.6  
  
**0x05 修复建议**  
  
  
当前官方已发布最新版本，建议受影响的用户及时更新升级到最新版本。  
  
下载链接：https://github.com/apache/activemq/tags  
## 0x06 声明  
  
  
天融信阿尔法实验室拥有对此公告的修改和解释权，如欲转载，必须保证此公告的完整性。由于传播、利用此公告而造成的任何后果，均由使用者本人负责，天融信阿尔法实验室不为此承担任何责任。  
  
天融信阿尔法实验室成立于2011年，一直以来，阿尔法实验室秉承“攻防一体”的理念，汇聚众多专业技术研究人员，从事攻防技术研究，在安全领域前瞻性技术研究方向上不断前行。作为天融信的安全产品和服务支撑团队，阿尔法实验室精湛的专业技术水平、丰富的排异经验，为天融信产品的研发和升级、承担国家重大安全项目和客户服务提供强有力的技术支撑。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/H6W1QCHf9dGfIEDOlNXXDTqOpRkEkicJakNxM37lzr8eRJRibEfxkwBibg9KpVh6nibXHoG4xC6KyGFtTd4TOe6GyA/640?wx_fmt=png "")  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/H6W1QCHf9dGfIEDOlNXXDTqOpRkEkicJawf8nKyKatopPJiaayibAUCvfTVFKfxVDInq2TiaUib6xhmhpLK4Zqscgyg/640?wx_fmt=jpeg "")  
  
天融信  
  
阿尔法实验室  
  
长按二维码关注我们  
  
  
