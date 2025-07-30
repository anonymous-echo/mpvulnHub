#  高危 PHP 漏洞可绕过验证加载恶意内容   
 信息安全大事件   2025-04-01 18:00  
  
PHP的libxml流组件中发现一个高危漏洞，可能影响依赖DOM或SimpleXML扩展处理HTTP请求的Web应用程序。该漏洞编号为CVE-2025-1219，源于处理重定向资源时对content-type标头的错误处理，可能导致文档解析错误和验证绕过等安全风险。  
  
受影响PHP版本包括：  
- 8.1.32以下版本  
  
- 8.2.28以下版本  
  
- 8.3.18以下版本  
  
- 8.4.5以下版本  
  
漏洞技术细节  
  
当HTTP流包装器跟随重定向时，该漏洞会触发。系统未在执行后续请求前清除先前捕获的标头，而是将多个请求的标头追加到同一数组中，导致最终数组包含所有请求的标头（最后请求的标头位于末尾）。  
  
函数php_libxml_input_buffer_create_filename()或php_libxml_sniff_charset_from_stream()会扫描该数组寻找content-type标头以确定响应字符集。但系统会从上至下顺序处理标头，并在遇到首个content-type标头时停止。根据PHP报告，该标头可能不对应最终包含待解析HTML正文的响应，从而导致文档可能以错误字符集解析，引发安全隐患。  
  
攻击者可利用该漏洞通过操纵字符集检测来改变文档解析方式，具体表现为：  
- 文档可能被错误解读，改变其原意  
  
- 若文档解析错误，验证流程可能被绕过  
  
- 使用->saveHtml()等方法导出文档时，可能保留原始字符集导致意外输出  
  
- 使用PHP的DOM或SimpleXML扩展处理HTTP请求的应用程序尤其易受攻击。  
  
漏洞验证实例  
  
概念验证(PoC)展示了漏洞利用方式：  
- 重定向脚本(redirect.php)发送指定字符集(utf-16)的content-type标头并重定向到其他资源  
  
- 通过PHP的DOMDocument或SimpleXML扩展访问时，系统错误地使用初始content-type标头而非最终响应的标头进行解析  
  
该行为可导致解析错误和验证绕过，例如导出的HTML内容在篡改后仍保留原始字符集。  
  
PHP开发团队已在以下版本修复该问题：  
- PHP 8.1.32  
  
- PHP 8.2.28  
  
- PHP 8.3.19  
  
- PHP 8.4.5  
  
缓解措施  
  
为防范CVE-2025-1219漏洞，强烈建议用户将PHP升级至上述已修复版本：  
- 使用php -v命令检查当前版本  
  
- 通过包管理器更新系统，或从php.net下载更新后的二进制文件  
  
- 更新后重启所有依赖PHP的服务  
  
CVE-2025-1219暴露了PHP使用libxml流处理HTTP重定向时的关键缺陷，对通过HTTP请求解析文档的应用程序构成风险。该漏洞再次凸显定期更新软件以应对新兴安全威胁的重要性。  
<table><tbody><tr class="ue-table-interlace-color-single js_darkmode__3" style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;background-color: rgb(28, 28, 28);visibility: visible;color: rgb(205, 205, 205) !important;"><td data-colwidth="557" width="557" valign="top" style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 5px 10px;outline: 0px;overflow-wrap: break-word !important;word-break: break-all;hyphens: auto;border: 1px solid rgb(76, 76, 76);max-width: 100%;box-sizing: border-box !important;background-color: rgb(255, 218, 169);visibility: visible;color: rgb(25, 25, 25) !important;"><section style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;line-height: normal;visibility: visible;"><span style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;font-size: 12px;visibility: visible;color: rgb(0, 0, 0);"><span leaf="" style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;visibility: visible;">尊敬的读者：</span><span leaf="" style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;visibility: visible;"><br/></span><span leaf="" style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;visibility: visible;">感谢您花时间阅读我们提供的这篇文章。我们非常重视您的时间和精力，并深知信息对您的重要性。</span><span leaf="" style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;visibility: visible;"><br/></span><span leaf="" style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;visibility: visible;">我们希望了解您对这篇文章的看法和感受。我们真诚地想知道您是否认为这篇文章为您带来了有价值的资讯和启示，是否有助于您的个人或职业发展。</span><span leaf="" style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;visibility: visible;"><br/></span><span leaf="" style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;visibility: visible;">如果您认为这篇文章对您非常有价值，并且希望获得更多的相关资讯和服务，我们愿意为您提供进一步的定制化服务。请通过填写我们提供的在线表单，与我们联系并提供您的邮箱地址或其他联系方式。我们将定期向您发送相关资讯和更新，以帮助您更好地了解我们的服务和文章内容。</span></span></section><section style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;line-height: normal;visibility: visible;"><span leaf="" style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;visibility: visible;"><br/></span></section><section style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;line-height: normal;text-indent: 0em;visibility: visible;"><span style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;color: rgb(0, 0, 0);visibility: visible;"><span leaf="" style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;visibility: visible;">                   </span></span><span leaf="" style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;visibility: visible;"><img data-src="https://mmbiz.qpic.cn/sz_mmbiz_png/JqliagemfTA5N8G6ZVujodYTTD7NSaxFG5suXlkibicfoGRzCk6vHhCUBx7ST8b4AxdsFVNNAH4ltePBWX4AxKY0A/640?wx_fmt=other&amp;wxfrom=5&amp;wx_lazy=1&amp;wx_co=1&amp;tp=webp" alt="图片" class="rich_pages wxw-img" data-ratio="1" data-s="300,640" data-type="png" data-w="1000" style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;vertical-align: bottom;height: auto !important;font-family: 宋体;font-size: 14px;letter-spacing: 0.578px;text-align: center;visibility: visible !important;width: 119px !important;" data-cropselx1="0" data-cropselx2="119" data-cropsely1="0" data-cropsely2="119" data-backw="106" data-backh="106" data-imgfileid="100006629"/></span></section><section style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;line-height: normal;text-indent: 0em;visibility: visible;"><span style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;font-family: 宋体;font-size: 12px;letter-spacing: 0.578px;text-align: center;color: rgb(0, 0, 0);visibility: visible;"><span leaf="" style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;visibility: visible;">                               扫描二维码，参与调查</span></span></section><section style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;line-height: normal;"><span leaf="" style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;"><br/></span></section></td></tr></tbody></table>  
  
  
**END**  
  
  
  
点击下方，关注公众号  
  
获取免费咨询和安全服务  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/JqliagemfTA5OxIlGh6IbpxrTJHkcY5DZ4O80nevX4Ev7IHvjZfPZDDMxibSVWk4IdYfaYpuhBgz2iaWS5tzXZLJw/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
  
  
安全咨询/安全集成/安全运营  
  
专业可信的信息安全应用服务商！  
  
http://www.jsgjxx.com  
  
  
