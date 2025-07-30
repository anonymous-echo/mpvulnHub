#  黑客利用已修复的Fortinet FortiGate设备漏洞获取Root权限   
 信息安全大事件   2025-04-14 10:04  
  
Fortinet发现威胁攻击者使用了一种复杂的后利用技术，即使在初始漏洞修复后仍能维持对FortiGate设备的未授权访问。  
  
根据Fortinet最新调查报告，攻击者利用了三个已知漏洞（FG-IR-22-398、FG-IR-23-097和FG-IR-24-015）入侵FortiGate设备。这些漏洞对应的CVE编号分别为：  
- CVE-2022-42475：与FG-IR-22-398关联  
  
- CVE-2023-27997：与FG-IR-23-097关联  
  
- CVE-2024-21762：可能与FG-IR-24-015相关但尚未确认  
  
     攻击技术分析  
  
攻击者采用了一种新颖手法：在SSL-VPN语言文件目录中创建用户文件系统与根文件系统之间的符号链接。这使得攻击者能够以只读方式访问设备配置文件等关键文件，同时规避检测。  
  
更令人担忧的是，这种符号链接在设备更新修复原始漏洞后仍可能持续存在。Fortinet通过内部遥测和第三方合作确认，该攻击活动不受地域或行业限制。但从未启用SSL-VPN功能的客户不受此问题影响。  
  
     应急响应措施  
  
Fortinet在发现该技术后立即启动产品安全事件响应团队(PSIRT)，采取了以下缓解措施：  
- 发布AV/IPS特征库以检测和清除恶意符号链接  
  
- 修改FortiOS 7.6.2、7.4.7、7.2.11、7.0.17和6.4.16版本，消除符号链接并加固SSL-VPN功能  
  
- 直接通知受影响客户，敦促其升级至最新版本、检查配置，并将现有设置视为可能已遭入侵  
  
Fortinet安全发言人Carl Windsor表示："此事件反映了威胁攻击者不断演变的战术，凸显了严格网络安全卫生的重要性。我们致力于通过主动解决方案和透明沟通帮助客户应对威胁。"  
  
     安全加固建议  
  
根据Fortinet 2023年下半年全球威胁态势报告，攻击者平均在漏洞公开后4.76天内就会加以利用。为此，Fortinet建议所有客户：  
- 立即升级至已修复版本  
  
- 执行社区资源中列出的恢复步骤  
  
- 启用最新安全功能，包括编译时加固、虚拟补丁、固件完整性验证等  
  
美国网络安全和基础设施安全局(CISA)在4月11日的公告中进一步建议管理员：  
- 升级至指定FortiOS版本以清除恶意文件  
  
- 检查设备配置并重置可能暴露的凭证  
  
- 在应用补丁前可临时禁用SSL-VPN功能  
  
安全公司WatchTowr创始人报告称，在其客户群（包括关键基础设施组织）中已发现与Fortinet漏洞相关的后门部署。他呼吁业界重视Fortinet的警报，并反思当前对关键系统高危漏洞的响应流程。  
  
据美国国家标准与技术研究院(NIST)数据，2024年已记录超过4万个漏洞。Fortinet强调，保持警惕并及时更新是应对当前网络威胁的最佳防御。  
<table><tbody><tr class="ue-table-interlace-color-single js_darkmode__1" style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;background-color: rgb(28, 28, 28);visibility: visible;color: rgb(205, 205, 205) !important;"><td data-colwidth="557" width="557" valign="top" style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 5px 10px;outline: 0px;overflow-wrap: break-word !important;word-break: break-all;hyphens: auto;border: 1px solid rgb(76, 76, 76);max-width: 100%;box-sizing: border-box !important;background-color: rgb(255, 218, 169);visibility: visible;color: rgb(25, 25, 25) !important;"><section style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;line-height: normal;visibility: visible;"><span style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;font-size: 12px;visibility: visible;color: rgb(0, 0, 0);"><span leaf="" style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;visibility: visible;">尊敬的读者：</span><span leaf="" style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;visibility: visible;"><br/></span><span leaf="" style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;visibility: visible;">感谢您花时间阅读我们提供的这篇文章。我们非常重视您的时间和精力，并深知信息对您的重要性。</span><span leaf="" style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;visibility: visible;"><br/></span><span leaf="" style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;visibility: visible;">我们希望了解您对这篇文章的看法和感受。我们真诚地想知道您是否认为这篇文章为您带来了有价值的资讯和启示，是否有助于您的个人或职业发展。</span><span leaf="" style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;visibility: visible;"><br/></span><span leaf="" style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;visibility: visible;">如果您认为这篇文章对您非常有价值，并且希望获得更多的相关资讯和服务，我们愿意为您提供进一步的定制化服务。请通过填写我们提供的在线表单，与我们联系并提供您的邮箱地址或其他联系方式。我们将定期向您发送相关资讯和更新，以帮助您更好地了解我们的服务和文章内容。</span></span></section><section style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;line-height: normal;visibility: visible;"><span leaf="" style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;visibility: visible;"><br/></span></section><section style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;line-height: normal;text-indent: 0em;visibility: visible;"><span style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;color: rgb(0, 0, 0);visibility: visible;"><span leaf="" style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;visibility: visible;">                   </span></span><span leaf="" style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;visibility: visible;"><img data-src="https://mmbiz.qpic.cn/sz_mmbiz_png/JqliagemfTA5N8G6ZVujodYTTD7NSaxFG5suXlkibicfoGRzCk6vHhCUBx7ST8b4AxdsFVNNAH4ltePBWX4AxKY0A/640?wx_fmt=other&amp;wxfrom=5&amp;wx_lazy=1&amp;wx_co=1&amp;tp=webp" alt="图片" class="rich_pages wxw-img" data-ratio="1" data-s="300,640" data-type="png" data-w="1000" style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;vertical-align: bottom;height: auto !important;font-family: 宋体;font-size: 14px;letter-spacing: 0.578px;text-align: center;visibility: visible !important;width: 119px !important;" data-cropselx1="0" data-cropselx2="119" data-cropsely1="0" data-cropsely2="119" data-backw="106" data-backh="106" data-imgfileid="100006629"/></span></section><section style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;line-height: normal;text-indent: 0em;visibility: visible;"><span style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;font-family: 宋体;font-size: 12px;letter-spacing: 0.578px;text-align: center;color: rgb(0, 0, 0);visibility: visible;"><span leaf="" style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;visibility: visible;">                               扫描二维码，参与调查</span></span></section><section style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;line-height: normal;"><span leaf="" style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;"><br/></span></section></td></tr></tbody></table>  
  
  
**END**  
  
  
  
点击下方，关注公众号  
  
获取免费咨询和安全服务  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/JqliagemfTA5OxIlGh6IbpxrTJHkcY5DZ4O80nevX4Ev7IHvjZfPZDDMxibSVWk4IdYfaYpuhBgz2iaWS5tzXZLJw/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
  
  
安全咨询/安全集成/安全运营  
  
专业可信的信息安全应用服务商！  
  
http://www.jsgjxx.com  
  
  
