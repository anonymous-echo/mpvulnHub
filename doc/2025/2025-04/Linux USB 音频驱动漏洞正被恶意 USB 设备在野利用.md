#  Linux USB 音频驱动漏洞正被恶意 USB 设备在野利用   
 信息安全大事件   2025-04-11 10:00  
  
漏洞概述  
  
Linux内核中的USB音频驱动存在一个可能导致内存越界读取的关键漏洞，该漏洞已由SUSE公司的Takashi Iwai通过最新补丁修复。攻击者若获得系统物理访问权限，可利用恶意USB设备实现权限提升、篡改系统内存或执行任意代码。  
  
Linux基金会Greg Kroah-Hartman于2024年12月14日提交的修复补丁，显著提升了使用USB音频设备系统的驱动稳定性和安全性。  
  
攻击原理  
  
当USB音频设备提供的描述符中bLength值小于预期结构大小时，漏洞就会被触发。原始代码中驱动程序盲目假设描述符完整，并尝试读取其时钟ID或引脚数组等字段。  
  
若描述符因硬件缺陷或人为篡改被截断，驱动程序可能越过已分配的内存缓冲区，读取到相邻非目标区域。这种越界读取可能泄露内核内存中的敏感数据（如指针或用户信息），或通过访问无效内存地址导致系统崩溃。  
  
最坏情况下，熟练的攻击者可结合其他漏洞利用链实现权限提升或任意代码执行，但此类攻击需要精确控制USB设备并存在其他漏洞配合。  
  
安全增强措施  
  
该漏洞源于驱动程序未验证USB音频设备提供的时钟描述符bLength字段。缺乏这些检查时，长度不足的畸形或恶意构造描述符可能触发越界内存访问，导致系统崩溃或遭受攻击。  
  
补丁（commit ab011f7439d9bbfd34fd3b9cef4b2d6d952c9bb9）在时钟描述符验证函数中引入了严格的完整性检查。虽然仅修改了sound/usb/clock.c文件的24行代码，但对依赖Linux进行音频处理的发烧友、开发者和企业影响重大。  
  
该漏洞最初由Google的Benoît Sevens报告，补丁已反向移植到稳定内核分支，确保各发行版用户都能获得安全增强。时钟选择器描述符（包含可变长度数组和附加字段）针对USB Audio Class（UAC）2和3版本进行了更全面的验证。  
  
用户可通过下载linux-ab011f7439d9bbfd34fd3b9cef4b2d6d952c9bb9.tar.gz更新内核获取该补丁。这一进展体现了Linux社区持续快速修复漏洞、维护系统健壮性的承诺。  
  
<table><tbody><tr class="ue-table-interlace-color-single js_darkmode__1" style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;background-color: rgb(28, 28, 28);visibility: visible;color: rgb(205, 205, 205) !important;"><td data-colwidth="557" width="557" valign="top" style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 5px 10px;outline: 0px;overflow-wrap: break-word !important;word-break: break-all;hyphens: auto;border: 1px solid rgb(76, 76, 76);max-width: 100%;box-sizing: border-box !important;background-color: rgb(255, 218, 169);visibility: visible;color: rgb(25, 25, 25) !important;"><section style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;line-height: normal;visibility: visible;"><span style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;font-size: 12px;visibility: visible;color: rgb(0, 0, 0);"><span leaf="" style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;visibility: visible;">尊敬的读者：</span><span leaf="" style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;visibility: visible;"><br/></span><span leaf="" style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;visibility: visible;">感谢您花时间阅读我们提供的这篇文章。我们非常重视您的时间和精力，并深知信息对您的重要性。</span><span leaf="" style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;visibility: visible;"><br/></span><span leaf="" style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;visibility: visible;">我们希望了解您对这篇文章的看法和感受。我们真诚地想知道您是否认为这篇文章为您带来了有价值的资讯和启示，是否有助于您的个人或职业发展。</span><span leaf="" style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;visibility: visible;"><br/></span><span leaf="" style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;visibility: visible;">如果您认为这篇文章对您非常有价值，并且希望获得更多的相关资讯和服务，我们愿意为您提供进一步的定制化服务。请通过填写我们提供的在线表单，与我们联系并提供您的邮箱地址或其他联系方式。我们将定期向您发送相关资讯和更新，以帮助您更好地了解我们的服务和文章内容。</span></span></section><section style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;line-height: normal;visibility: visible;"><span leaf="" style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;visibility: visible;"><br/></span></section><section style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;line-height: normal;text-indent: 0em;visibility: visible;"><span style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;color: rgb(0, 0, 0);visibility: visible;"><span leaf="" style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;visibility: visible;">                   </span></span><span leaf="" style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;visibility: visible;"><img alt="图片" class="rich_pages wxw-img" data-backh="106" data-backw="106" data-cropselx1="0" data-cropselx2="119" data-cropsely1="0" data-cropsely2="119" data-imgfileid="100006629" data-ratio="1" data-s="300,640" data-src="https://mmbiz.qpic.cn/sz_mmbiz_png/JqliagemfTA5N8G6ZVujodYTTD7NSaxFG5suXlkibicfoGRzCk6vHhCUBx7ST8b4AxdsFVNNAH4ltePBWX4AxKY0A/640?wx_fmt=other&amp;wxfrom=5&amp;wx_lazy=1&amp;wx_co=1&amp;tp=webp" data-type="png" data-w="1000" style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;vertical-align: bottom;height: auto !important;font-family: 宋体;font-size: 14px;letter-spacing: 0.578px;text-align: center;visibility: visible !important;width: 119px !important;"/></span></section><section style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;line-height: normal;text-indent: 0em;visibility: visible;"><span style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;font-family: 宋体;font-size: 12px;letter-spacing: 0.578px;text-align: center;color: rgb(0, 0, 0);visibility: visible;"><span leaf="" style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;visibility: visible;">                               扫描二维码，参与调查</span></span></section><section style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;line-height: normal;"><span leaf="" style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;"><br/></span></section></td></tr></tbody></table>  
  
  
**END**  
  
  
  
点击下方，关注公众号  
  
获取免费咨询和安全服务  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/JqliagemfTA5OxIlGh6IbpxrTJHkcY5DZ4O80nevX4Ev7IHvjZfPZDDMxibSVWk4IdYfaYpuhBgz2iaWS5tzXZLJw/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
  
  
安全咨询/安全集成/安全运营  
  
专业可信的信息安全应用服务商！  
  
http://www.jsgjxx.com  
  
  
  
