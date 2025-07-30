#  【已支持识别检测】Ollama配置不当未授权访问漏洞（CNVD-2025-04094）   
原创 NS-CERT  绿盟科技CERT   2025-03-05 17:26  
  
**通告编号:NS-2025-0010**  
  
2025-03-04  
  
<table><tbody><tr><td style="margin: 5px 10px;border-color: rgb(216, 216, 216);word-break: break-all;" valign="top"><strong><span style="font-size: 14px;">TA</span></strong><strong><span style="font-size: 14px;">G：</span></strong></td><td style="margin: 5px 10px;border-color: rgb(216, 216, 216);word-break: break-all;" valign="top"><span style="font-size: 14px;"><strong>Ollama、未授权访问、CNVD-2025-04094</strong></span></td></tr><tr><td style="margin: 5px 10px;border-color: rgb(216, 216, 216);word-break: break-all;" valign="top"><span style="color: rgb(0, 0, 0);"><strong><span style="font-size: 14px;">漏洞危害：</span></strong></span><span style="color: rgb(255, 0, 0);"><strong><span style="font-size: 14px;"></span></strong></span></td><td style="margin: 5px 10px;border-color: rgb(216, 216, 216);word-break: break-all;" valign="top"><span style="color: rgb(0, 0, 0);font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;"><strong><span style="font-size: 14px;">攻击者利用此漏洞，可实现未授权访问。</span></strong></span></td></tr><tr><td style="margin: 5px 10px;border-color: rgb(216, 216, 216);word-break: break-all;" valign="top"><strong><span style="font-size: 14px;">版本：</span></strong></td><td style="margin: 5px 10px;border-color: rgb(216, 216, 216);word-break: break-all;" valign="top"><strong><span style="font-size: 14px;">1.0<br/></span></strong></td></tr></tbody></table>  
  
**1**  
  
  
**漏洞概述**  
  
  
近日，绿盟科技监测到网上披露了Ollama配置不当未授权访问漏洞（CNVD-2025-04094）；由于Ollama默认未设置身份验证和访问控制功能，当用户将服务（默认为11434端口）对公网开放时，未经身份验证的攻击者可直接调用其API接口，从而窃取敏感模型资产、投喂虚假信息、系统配置篡改或滥用模型推理资源等。目前漏洞细节已披露，且发现在野利用，请相关用户尽快采取措施进行防护。  
  
Ollama是一款开源AI模型项目，用于快速启动llama等开源大模型的运行环境，简化了大语言模型在本地的部署、运行和管理过程。Ollama默认部署时仅允许本地访问，监听于127.0.0.1，未启用身份认证机制。  
  
  
参考链接：  
  
https://www.cnvd.org.cn/webinfo/show/10976  
  
  
**SEE MORE →**  
  
  
**2****影响范围**  
  
**受影响版本**  
  
Ollama全版本注：若Ollama未配置身份认证且直接对公网开放则存在此安全风险。  
  
  
**3****漏洞检测**  
  
**3.1  人工排查**  
  
相关用户可以通过下列命令对Ollama情况进行排查：  
<table><tbody><tr style="height:20px;"><td valign="top" style="border-width: 2px;border-color: windowtext;background: rgb(216, 216, 216);" height="20"><p style="text-align:left;line-height: 125%;"><span style="font-size: 14px;letter-spacing: normal;line-height: 1.57em;font-family:微软雅黑, &#34;Microsoft YaHei&#34;;">sudo netstat -tulpn | grep   11434</span></p></td></tr></tbody></table>  
若输出类似下列内容，则表示服务仅允许本地访问:  
<table><tbody><tr style="height:20px;"><td valign="top" style="border-width: 2px;border-color: windowtext;background: rgb(216, 216, 216);" height="20"><p style="text-align:left;line-height: 125%;"><span style="font-size: 14px;letter-spacing: normal;line-height: 1.57em;font-family:微软雅黑, &#34;Microsoft YaHei&#34;;">tcp 0 0 127.0.0.1:11434   0.0.0.0:* LISTEN 1234/ollama</span></p></td></tr></tbody></table>  
若输出包含0.0.0.0:11434或:::11434，则表示服务对公网开放，存在未授权访问风险：  
<table><tbody><tr style="height:20px;"><td valign="top" style="border-width: 2px;border-color: windowtext;background: rgb(216, 216, 216);" height="20"><p style="text-align:left;line-height: 125%;"><span style="font-size: 14px;letter-spacing: normal;line-height: 1.57em;font-family:微软雅黑, &#34;Microsoft YaHei&#34;;">tcp 0 00.0.0.0:11434   0.0.0.0:* LISTEN 5678/ollama</span></p></td></tr></tbody></table>  
**3.2  工具检测**  
  
绿盟科技自动化渗透测试工具（EZ）内部版已支持Ollama的服务识别和未授权访问风险检测，可直接使用web模块进行扫描检测。（注：内部版请联系绿盟销售人员获取）  
  
工具下载链接：  
https://github.com/m-sec-org/EZ/releases  
  
   
新用户请注册  
M-SEC  
社区（  
https://msec.nsfocus.com  
）申请证书进行使用：  
  
![image.png](https://mmbiz.qpic.cn/mmbiz_png/VvfsuOanecqbRYN2ibLpX6VMiaBicibl5zEuDUrM9hibwDiaib52oWjOx1glkWvdlHW9gia17npkFaYB099FVYPnwttFow/640?wx_fmt=png&from=appmsg "")  
  
注：社区版本将于近日发布上述功能  
  
  
**4****漏洞防护**  
  
**4.1  防护措施**  
  
目前Ollama官方暂未发布修复版本，请相关用户尽快采取下列措施进行防护：  
  
1、若Ollama只提供本地服务，设置环境变量Environment="OLLAMA_HOST=127.0.0.1"，仅允许本地访问。  
  
2、若Ollama需提供公网服务，可选择以下方法添加认证机制：  
  
（1）修改config.yaml、settings.json配置文件，限定可访问Ollama服务的IP地址；  
  
（2）通过反向代理进行身份验证和授权（如使用OAuth2.0协议），防止未经授权用户访问；  
  
（3）通过防火墙等设备配置IP白名单，仅允许可信IP的访问请求。  
  
  
**END**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qR4ORTNELImFwJM2rh6GKbnrurdFA28jJ8chUPyC1U6aW3jhenqEiaXkmeGVmfOnvAJy8j3My901JQ7emHaicYzA/640?wx_fmt=png "")  
           
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qR4ORTNELImFwJM2rh6GKbnrurdFA28jib7icfic0lJJHh3eLRpIXiaia08KqOSEibBsz64vlOH9aqicu3lmjccEeAFWQ/640?wx_fmt=jpeg "")  
          
  
**声明**  
  
本安全公告仅用来描述可能存在的安全问题，绿盟科技不为此安全公告提供任何保证或承诺。由于传播、利用此安全公告所提供的信息而造成的任何直接或者间接的后果及损失，均由使用者本人负责，绿盟科技以及安全公告作者不为此承担任何责任。              
  
绿盟科技拥有对此安全公告的修改和解释权。如欲转载或传播此安全公告，必须保证此安全公告的完整性，包括版权声明等全部内容。未经绿盟科技允许，不得任意修改或者增减此安全公告内容，不得以任何方式将其用于商业目的。              
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qR4ORTNELImFwJM2rh6GKbnrurdFA28jib7icfic0lJJHh3eLRpIXiaia08KqOSEibBsz64vlOH9aqicu3lmjccEeAFWQ/640?wx_fmt=jpeg "")  
  
  
**绿盟科技CERT**  
****  
∣  
微信公众号  
  
![绿盟科技CERT公众号.jpg](https://mmbiz.qpic.cn/mmbiz_jpg/VvfsuOanecqbRYN2ibLpX6VMiaBicibl5zEuJ46cTTiaGk5LYx26NZyP34IsibogsxSbnnQKT90Q0S9GwJB2lLt6KUkg/640?wx_fmt=jpeg&from=appmsg "绿盟科技CERT公众号.jpg")  
  
![](https://mmbiz.qpic.cn/mmbiz/Hu8hctxHqSW0nSJn8p8OHVEQwHicSwTibFJMBE650AxdzfISoeY8woe2QsgCINIBrccBOOUft2HuU0GsNQWibSG7g/640?wx_fmt=png "")  
  
长按识别二维码，关注网络安全威胁信息  
  
