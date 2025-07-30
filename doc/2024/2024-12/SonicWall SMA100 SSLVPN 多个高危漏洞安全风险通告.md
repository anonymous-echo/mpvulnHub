#  SonicWall SMA100 SSLVPN 多个高危漏洞安全风险通告   
 奇安信 CERT   2024-12-06 07:55  
  
●   
点击↑蓝字关注我们，获取更多安全风险通告  
  
  
<table><tbody style="-webkit-tap-highlight-color: transparent;outline: 0px;visibility: visible;"><tr style="-webkit-tap-highlight-color: transparent;outline: 0px;visibility: visible;"><td valign="middle" align="center" rowspan="1" colspan="4" style="-webkit-tap-highlight-color: transparent;padding: 5px 10px;outline: 0px;word-break: break-all;hyphens: auto;border-color: rgb(70, 118, 217);background-color: rgb(70, 118, 217);visibility: visible;"><p style="-webkit-tap-highlight-color: transparent;outline: 0px;line-height: 1.5em;visibility: visible;"><span style="-webkit-tap-highlight-color: transparent;outline: 0px;color: rgb(255, 255, 255);letter-spacing: 0px;visibility: visible;"><strong style="-webkit-tap-highlight-color: transparent;outline: 0px;visibility: visible;"><span style="-webkit-tap-highlight-color: transparent;outline: 0px;font-size: 13px;letter-spacing: 0px;visibility: visible;">漏洞概述</span></strong><br style="-webkit-tap-highlight-color: transparent;outline: 0px;visibility: visible;"/></span></p></td></tr><tr style="-webkit-tap-highlight-color: transparent;outline: 0px;visibility: visible;"><td valign="middle" align="left" width="136" style="-webkit-tap-highlight-color: transparent;padding: 5px 10px;outline: 0px;word-break: break-all;hyphens: auto;border-color: rgb(70, 118, 217);visibility: visible;"><p style="-webkit-tap-highlight-color: transparent;outline: 0px;line-height: 1em;visibility: visible;"><span style="-webkit-tap-highlight-color: transparent;outline: 0px;font-size: 13px;letter-spacing: 0px;visibility: visible;"><strong style="-webkit-tap-highlight-color: transparent;outline: 0px;visibility: visible;"><span style="-webkit-tap-highlight-color: transparent;outline: 0px;letter-spacing: 0px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;visibility: visible;">漏洞名称</span></strong></span></p></td><td valign="middle" align="left" rowspan="1" colspan="3" style="-webkit-tap-highlight-color: transparent;padding: 5px 10px;outline: 0px;word-break: break-all;hyphens: auto;border-color: rgb(70, 118, 217);visibility: visible;"><p style="-webkit-tap-highlight-color: transparent;outline: 0px;line-height: 1em;visibility: visible;"><span style="-webkit-tap-highlight-color: transparent;outline: 0px;font-size: 13px;caret-color: red;letter-spacing: 0px;visibility: visible;">SonicWall SMA100 SSLVPN 多个高危漏洞</span></p></td></tr><tr style="-webkit-tap-highlight-color: transparent;outline: 0px;visibility: visible;"><td valign="middle" align="left" rowspan="1" colspan="1" width="136" style="-webkit-tap-highlight-color: transparent;padding: 5px 10px;outline: 0px;word-break: break-all;hyphens: auto;border-color: rgb(70, 118, 217);visibility: visible;"><p style="-webkit-tap-highlight-color: transparent;outline: 0px;line-height: 1em;visibility: visible;"><span style="-webkit-tap-highlight-color: transparent;outline: 0px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;visibility: visible;"><span style="-webkit-tap-highlight-color: transparent;outline: 0px;font-size: 13px;visibility: visible;"><strong style="-webkit-tap-highlight-color: transparent;outline: 0px;visibility: visible;">漏洞编号</strong></span></span></p></td><td valign="middle" align="left" rowspan="1" colspan="3" style="-webkit-tap-highlight-color: transparent;padding: 5px 10px;outline: 0px;word-break: break-all;hyphens: auto;border-color: rgb(70, 118, 217);visibility: visible;"><p style="-webkit-tap-highlight-color: transparent;outline: 0px;line-height: 1em;visibility: visible;"><span style="-webkit-tap-highlight-color: transparent;outline: 0px;color: rgb(0, 0, 0);font-size: 13px;caret-color: rgb(255, 0, 0);font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;visibility: visible;"><span style="-webkit-tap-highlight-color: transparent;outline: 0px;font-family: &#34;Helvetica Neue&#34;, Helvetica, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei&#34;, 微软雅黑, Arial, sans-serif;letter-spacing: 0.578px;text-decoration-style: solid;text-decoration-color: rgb(0, 0, 0);visibility: visible;">CVE-2024-45318</span>,CVE-2024-53703</span></p></td></tr><tr style="-webkit-tap-highlight-color: transparent;outline: 0px;visibility: visible;"><td valign="middle" align="left" colspan="1" rowspan="1" width="136" style="-webkit-tap-highlight-color: transparent;padding: 5px 10px;outline: 0px;word-break: break-all;hyphens: auto;border-color: rgb(70, 118, 217);visibility: visible;"><p style="-webkit-tap-highlight-color: transparent;outline: 0px;line-height: 1em;visibility: visible;"><strong style="-webkit-tap-highlight-color: transparent;outline: 0px;visibility: visible;"><span style="-webkit-tap-highlight-color: transparent;outline: 0px;font-size: 13px;visibility: visible;"><strong style="-webkit-tap-highlight-color: transparent;cursor: text;color: rgb(0, 0, 0);caret-color: rgb(255, 0, 0);font-family: 微软雅黑, &#34;Microsoft YaHei&#34;, sans-serif;visibility: visible;max-inline-size: 100%;outline: none 0px !important;"><span style="-webkit-tap-highlight-color: transparent;cursor: text;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;visibility: visible;max-inline-size: 100%;outline: none 0px !important;">公开时间</span></strong></span></strong></p></td><td valign="middle" align="left" colspan="1" rowspan="1" width="157" style="-webkit-tap-highlight-color: transparent;padding: 5px 10px;outline: 0px;word-break: break-all;hyphens: auto;border-color: rgb(70, 118, 217);visibility: visible;"><p style="-webkit-tap-highlight-color: transparent;outline: 0px;line-height: 1em;visibility: visible;"><span style="-webkit-tap-highlight-color: transparent;outline: 0px;color: rgb(0, 0, 0);font-size: 13px;caret-color: rgb(255, 0, 0);font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;visibility: visible;">2024-12-05</span></p></td><td valign="middle" align="left" colspan="1" rowspan="1" width="166" style="-webkit-tap-highlight-color: transparent;padding: 5px 10px;outline: 0px;word-break: break-all;hyphens: auto;border-color: rgb(70, 118, 217);visibility: visible;"><p style="-webkit-tap-highlight-color: transparent;outline: 0px;line-height: 1em;visibility: visible;"><strong style="-webkit-tap-highlight-color: transparent;outline: 0px;visibility: visible;"><span style="-webkit-tap-highlight-color: transparent;outline: 0px;font-size: 13px;visibility: visible;"><strong style="-webkit-tap-highlight-color: transparent;cursor: text;color: rgb(0, 0, 0);caret-color: rgb(255, 0, 0);font-family: 微软雅黑, &#34;Microsoft YaHei&#34;, sans-serif;visibility: visible;max-inline-size: 100%;outline: none 0px !important;"><span style="-webkit-tap-highlight-color: transparent;cursor: text;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;visibility: visible;max-inline-size: 100%;outline: none 0px !important;">影响量级</span></strong></span></strong></p></td><td valign="middle" align="left" colspan="1" rowspan="1" width="98" style="-webkit-tap-highlight-color: transparent;padding: 5px 10px;outline: 0px;word-break: break-all;hyphens: auto;border-color: rgb(70, 118, 217);visibility: visible;"><p style="-webkit-tap-highlight-color: transparent;outline: 0px;line-height: 1em;visibility: visible;"><span style="-webkit-tap-highlight-color: transparent;outline: 0px;color: rgb(0, 0, 0);font-size: 13px;caret-color: rgb(255, 0, 0);font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;visibility: visible;">十万级</span></p></td></tr><tr style="-webkit-tap-highlight-color: transparent;outline: 0px;visibility: visible;"><td valign="middle" align="left" width="136" style="-webkit-tap-highlight-color: transparent;padding: 5px 10px;outline: 0px;word-break: break-all;hyphens: auto;border-color: rgb(70, 118, 217);visibility: visible;"><p style="-webkit-tap-highlight-color: transparent;outline: 0px;line-height: 1em;visibility: visible;"><span style="-webkit-tap-highlight-color: transparent;outline: 0px;font-size: 13px;letter-spacing: 0px;visibility: visible;"><strong style="-webkit-tap-highlight-color: transparent;cursor: text;color: rgb(0, 0, 0);font-size: 17px;caret-color: rgb(255, 0, 0);font-family: 微软雅黑, &#34;Microsoft YaHei&#34;, sans-serif;visibility: visible;max-inline-size: 100%;outline: none 0px !important;"><span style="-webkit-tap-highlight-color: transparent;cursor: text;font-size: 13px;letter-spacing: 0px;visibility: visible;max-inline-size: 100%;outline: none 0px !important;">奇安信评级</span></strong></span></p></td><td valign="middle" align="left" width="157" style="-webkit-tap-highlight-color: transparent;padding: 5px 10px;outline: 0px;word-break: break-all;hyphens: auto;border-color: rgb(70, 118, 217);visibility: visible;"><p style="-webkit-tap-highlight-color: transparent;outline: 0px;line-height: 1em;visibility: visible;"><span style="-webkit-tap-highlight-color: transparent;outline: 0px;letter-spacing: 0px;visibility: visible;"><strong style="-webkit-tap-highlight-color: transparent;cursor: text;color: rgb(255, 0, 0);caret-color: rgb(255, 0, 0);font-family: 微软雅黑, &#34;Microsoft YaHei&#34;, sans-serif;visibility: visible;max-inline-size: 100%;outline: none 0px !important;"><span style="-webkit-tap-highlight-color: transparent;cursor: text;font-size: 13px;letter-spacing: 0px;visibility: visible;max-inline-size: 100%;outline: none 0px !important;">高危</span></strong></span></p></td><td valign="middle" align="left" width="166" style="-webkit-tap-highlight-color: transparent;padding: 5px 10px;outline: 0px;word-break: break-all;hyphens: auto;border-color: rgb(70, 118, 217);visibility: visible;"><p style="-webkit-tap-highlight-color: transparent;outline: 0px;line-height: 1em;visibility: visible;"><strong style="-webkit-tap-highlight-color: transparent;outline: 0px;visibility: visible;"><span style="-webkit-tap-highlight-color: transparent;outline: 0px;font-size: 13px;letter-spacing: 0px;visibility: visible;">CVSS 3.1分数</span></strong></p></td><td valign="middle" align="left" width="98" style="-webkit-tap-highlight-color: transparent;padding: 5px 10px;outline: 0px;word-break: break-all;hyphens: auto;border-color: rgb(70, 118, 217);visibility: visible;"><p style="-webkit-tap-highlight-color: transparent;outline: 0px;line-height: 1em;visibility: visible;"><span style="-webkit-tap-highlight-color: transparent;outline: 0px;color: rgb(255, 0, 0);visibility: visible;"><span style="-webkit-tap-highlight-color: transparent;outline: 0px;font-size: 13px;letter-spacing: normal;visibility: visible;"><strong style="-webkit-tap-highlight-color: transparent;outline: 0px;visibility: visible;">8.1</strong></span></span></p></td></tr><tr style="-webkit-tap-highlight-color: transparent;outline: 0px;visibility: visible;"><td valign="middle" align="left" colspan="1" rowspan="1" width="136" style="-webkit-tap-highlight-color: transparent;padding: 5px 10px;outline: 0px;word-break: break-all;hyphens: auto;border-color: rgb(70, 118, 217);visibility: visible;"><p style="-webkit-tap-highlight-color: transparent;outline: 0px;line-height: 1em;visibility: visible;"><span style="-webkit-tap-highlight-color: transparent;outline: 0px;font-size: 13px;visibility: visible;"><strong style="-webkit-tap-highlight-color: transparent;outline: 0px;visibility: visible;">威胁类型</strong></span></p></td><td valign="middle" align="left" colspan="1" rowspan="1" width="157" style="-webkit-tap-highlight-color: transparent;padding: 5px 10px;outline: 0px;word-break: break-all;hyphens: auto;border-color: rgb(70, 118, 217);visibility: visible;"><p style="-webkit-tap-highlight-color: transparent;outline: 0px;line-height: 1em;visibility: visible;"><span style="-webkit-tap-highlight-color: transparent;outline: 0px;font-size: 13px;visibility: visible;"><span style="-webkit-tap-highlight-color: transparent;outline: 0px;letter-spacing: normal;caret-color: rgb(255, 0, 0);visibility: visible;">代码执行</span></span></p></td><td valign="middle" align="left" colspan="1" rowspan="1" width="166" style="-webkit-tap-highlight-color: transparent;padding: 5px 10px;outline: 0px;word-break: break-all;hyphens: auto;border-color: rgb(70, 118, 217);visibility: visible;"><p style="-webkit-tap-highlight-color: transparent;outline: 0px;line-height: 1em;visibility: visible;"><strong style="-webkit-tap-highlight-color: transparent;cursor: text;color: rgb(0, 0, 0);caret-color: rgb(255, 0, 0);font-family: 微软雅黑, &#34;Microsoft YaHei&#34;, sans-serif;visibility: visible;max-inline-size: 100%;outline: none 0px !important;"><span style="-webkit-tap-highlight-color: transparent;cursor: text;font-size: 13px;visibility: visible;max-inline-size: 100%;outline: none 0px !important;">利用可能性</span></strong></p></td><td valign="middle" align="left" colspan="1" rowspan="1" width="98" style="-webkit-tap-highlight-color: transparent;padding: 5px 10px;outline: 0px;word-break: break-all;hyphens: auto;border-color: rgb(70, 118, 217);visibility: visible;"><p style="-webkit-tap-highlight-color: transparent;outline: 0px;line-height: 1em;visibility: visible;"><strong style="-webkit-tap-highlight-color: transparent;cursor: text;caret-color: rgb(255, 0, 0);color: rgb(255, 0, 0);font-family: 微软雅黑, &#34;Microsoft YaHei&#34;, sans-serif;visibility: visible;max-inline-size: 100%;outline: none 0px !important;"><span style="-webkit-tap-highlight-color: transparent;cursor: text;font-size: 13px;visibility: visible;max-inline-size: 100%;outline: none 0px !important;"><strong style="-webkit-tap-highlight-color: transparent;outline: 0px;font-family: system-ui, -apple-system, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;letter-spacing: 0.544px;visibility: visible;">高</strong></span></strong></p></td></tr><tr style="-webkit-tap-highlight-color: transparent;outline: 0px;visibility: visible;"><td valign="middle" colspan="1" rowspan="1" align="left" width="136" style="-webkit-tap-highlight-color: transparent;padding: 5px 10px;outline: 0px;word-break: break-all;hyphens: auto;border-color: rgb(70, 118, 217);visibility: visible;"><p style="-webkit-tap-highlight-color: transparent;outline: 0px;line-height: 1em;visibility: visible;"><span style="-webkit-tap-highlight-color: transparent;outline: 0px;font-size: 13px;visibility: visible;"><strong style="-webkit-tap-highlight-color: transparent;outline: 0px;visibility: visible;"><span style="-webkit-tap-highlight-color: transparent;outline: 0px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;visibility: visible;">POC状态</span></strong></span></p></td><td valign="middle" colspan="1" rowspan="1" align="left" width="157" style="-webkit-tap-highlight-color: transparent;padding: 5px 10px;outline: 0px;word-break: break-all;hyphens: auto;border-color: rgb(70, 118, 217);visibility: visible;"><p style="-webkit-tap-highlight-color: transparent;outline: 0px;line-height: 1em;visibility: visible;"><span style="-webkit-tap-highlight-color: transparent;outline: 0px;font-size: 13px;letter-spacing: normal;caret-color: rgb(255, 0, 0);visibility: visible;">未公开</span></p></td><td valign="middle" colspan="1" rowspan="1" align="left" width="166" style="-webkit-tap-highlight-color: transparent;padding: 5px 10px;outline: 0px;word-break: break-all;hyphens: auto;border-color: rgb(70, 118, 217);visibility: visible;"><p style="-webkit-tap-highlight-color: transparent;outline: 0px;line-height: 1em;visibility: visible;"><span style="-webkit-tap-highlight-color: transparent;outline: 0px;font-size: 13px;visibility: visible;"><strong style="-webkit-tap-highlight-color: transparent;outline: 0px;visibility: visible;"><span style="-webkit-tap-highlight-color: transparent;outline: 0px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;visibility: visible;">在野利用状态</span></strong></span></p></td><td valign="middle" colspan="1" rowspan="1" align="left" width="98" style="-webkit-tap-highlight-color: transparent;padding: 5px 10px;outline: 0px;word-break: break-all;hyphens: auto;border-color: rgb(70, 118, 217);visibility: visible;"><p style="-webkit-tap-highlight-color: transparent;outline: 0px;line-height: 1em;visibility: visible;"><span style="-webkit-tap-highlight-color: transparent;outline: 0px;font-size: 13px;color: rgb(0, 0, 0);font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;visibility: visible;"><span style="-webkit-tap-highlight-color: transparent;outline: 0px;visibility: visible;"><span style="-webkit-tap-highlight-color: transparent;outline: 0px;font-family: system-ui, -apple-system, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;letter-spacing: 0.544px;visibility: visible;">未发现</span></span><strong style="-webkit-tap-highlight-color: transparent;outline: 0px;color: rgb(255, 0, 0);font-family: system-ui, -apple-system, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;letter-spacing: 0.544px;text-wrap-style: initial;visibility: visible;"><span style="-webkit-tap-highlight-color: transparent;outline: 0px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;visibility: visible;"><span style="-webkit-tap-highlight-color: transparent;outline: 0px;font-family: system-ui, -apple-system, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;letter-spacing: 0.544px;visibility: visible;"></span></span></strong></span></p></td></tr><tr style="-webkit-tap-highlight-color: transparent;outline: 0px;visibility: visible;"><td valign="middle" colspan="1" rowspan="1" align="left" width="136" style="-webkit-tap-highlight-color: transparent;padding: 5px 10px;outline: 0px;word-break: break-all;hyphens: auto;border-color: rgb(70, 118, 217);visibility: visible;"><p style="-webkit-tap-highlight-color: transparent;outline: 0px;line-height: 1em;visibility: visible;"><span style="-webkit-tap-highlight-color: transparent;outline: 0px;font-size: 13px;visibility: visible;"><strong style="-webkit-tap-highlight-color: transparent;outline: 0px;visibility: visible;"><span style="-webkit-tap-highlight-color: transparent;outline: 0px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;visibility: visible;">EXP状态</span></strong></span></p></td><td valign="middle" colspan="1" rowspan="1" align="left" width="157" style="-webkit-tap-highlight-color: transparent;padding: 5px 10px;outline: 0px;word-break: break-all;hyphens: auto;border-color: rgb(70, 118, 217);visibility: visible;"><p style="-webkit-tap-highlight-color: transparent;outline: 0px;line-height: 1em;visibility: visible;"><span style="-webkit-tap-highlight-color: transparent;outline: 0px;font-size: 13px;letter-spacing: normal;caret-color: rgb(255, 0, 0);visibility: visible;">未公开</span></p></td><td valign="middle" colspan="1" rowspan="1" align="left" width="166" style="-webkit-tap-highlight-color: transparent;padding: 5px 10px;outline: 0px;word-break: break-all;hyphens: auto;border-color: rgb(70, 118, 217);visibility: visible;"><p style="-webkit-tap-highlight-color: transparent;outline: 0px;line-height: 1em;visibility: visible;"><span style="-webkit-tap-highlight-color: transparent;outline: 0px;font-size: 13px;visibility: visible;"><strong style="-webkit-tap-highlight-color: transparent;outline: 0px;visibility: visible;"><span style="-webkit-tap-highlight-color: transparent;outline: 0px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;visibility: visible;">技术细节状态</span></strong></span></p></td><td valign="middle" colspan="1" rowspan="1" align="left" width="98" style="-webkit-tap-highlight-color: transparent;padding: 5px 10px;outline: 0px;word-break: break-all;hyphens: auto;border-color: rgb(70, 118, 217);visibility: visible;"><p style="-webkit-tap-highlight-color: transparent;outline: 0px;line-height: 1em;visibility: visible;"><span style="-webkit-tap-highlight-color: transparent;outline: 0px;font-size: 13px;color: rgb(0, 0, 0);font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;visibility: visible;"><span style="-webkit-tap-highlight-color: transparent;outline: 0px;visibility: visible;font-family: system-ui, -apple-system, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;letter-spacing: 0.544px;">未公开</span></span><span style="-webkit-tap-highlight-color: transparent;outline: 0px;font-size: 13px;color: rgb(0, 0, 0);font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;visibility: visible;"><strong style="-webkit-tap-highlight-color: transparent;outline: 0px;letter-spacing: 0.544px;font-family: system-ui, -apple-system, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;visibility: visible;"><span style="-webkit-tap-highlight-color: transparent;outline: 0px;color: rgb(255, 0, 0);font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;visibility: visible;"><span style="-webkit-tap-highlight-color: transparent;outline: 0px;font-family: system-ui, -apple-system, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;letter-spacing: normal;caret-color: rgb(255, 0, 0);visibility: visible;"></span></span></strong></span></p></td></tr><tr style="-webkit-tap-highlight-color: transparent;outline: 0px;visibility: visible;"><td valign="middle" colspan="4" rowspan="1" align="left" style="-webkit-tap-highlight-color: transparent;padding: 5px 10px;outline: 0px;word-break: break-all;hyphens: auto;border-color: rgb(70, 118, 217);visibility: visible;"><p style="-webkit-tap-highlight-color: transparent;outline: 0px;line-height: 1em;visibility: visible;"><strong style="-webkit-tap-highlight-color: transparent;outline: 0px;visibility: visible;"><span style="-webkit-tap-highlight-color: transparent;outline: 0px;font-size: 13px;visibility: visible;">危害描述：</span></strong><span style="-webkit-tap-highlight-color: transparent;outline: 0px;font-size: 13px;letter-spacing: 0.544px;text-align: justify;visibility: visible;">该漏洞可能使攻击者能够远程执行代码，获取系统控制权，从而造成严重的安全威胁。</span></p></td></tr></tbody></table>  
  
  
**0****1**  
  
**漏洞详情**  
  
**>**  
**>**  
**>**  
**>**  
  
**影响组件**  
  
SonicWall SMA100 SSLVPN是一款为中小企业设计的SSL VPN设备，旨在提供安全的远程访问解决方案，允许用户通过加密的网络连接安全地访问内部网络资源。  
  
**>**  
**>**  
**>**  
**>**  
  
**漏洞描述**  
  
近日，奇安信CERT监测到官方修复 **SonicWall SMA100 SSLVPN web管理页面栈缓冲区溢出漏洞(CVE-2024-45318)** 和 **SonicWall SMA100 mod_httprp栈缓冲区溢出漏洞(CVE-2024-53703)**，SonicWall SMA100 SSLVPN的Web管理界面和Apache Web服务器加载的mod_httprp库分别存在两个栈缓冲区溢出漏洞，这些漏洞可能允许远程攻击者执行任意代码，造成系统敏感数据泄露甚至服务器被接管等严重安全威胁。**鉴于此漏洞影响范围较大，建议客户尽快做好自查及防护。**  
  
  
  
**02**  
  
**影响范围**  
  
**>**  
**>**  
**>**  
**>**  
  
**影响版本**  
  
  
SMA 100 Series (SMA 200, 210, 400, 410, 500v) <= 10.2.1.13-72sv  
  
**>**  
**>**  
**>**  
**>**  
  
**其他受影响组件**  
  
无  
  
  
**03**  
  
**处置建议**  
  
**>**  
**>**  
**>**  
**>**  
  
**安全更新**  
  
SonicWall官方已经发布了修复这些漏洞的固件版本。用户应立即升级到官方推荐的固定版本，即SMA 100系列的10.2.1.14-75sv或更高版本。  
  
官方补丁下载地址：  
  
https://www.sonicwall.com/zh-cn/support  
  
**修复缓解措施：**  
  
1.限制对SMA100 SSLVPN管理接口的访问，只允许受信任的IP地址范围访问管理界面，以减少潜在攻击者的机会；  
  
2.关注SonicWall的官方安全通告，以便在新的漏洞或威胁出现时及时获得信息，并采取相应的防护措施。  
  
  
  
**04**  
  
**参考资料**  
  
[1]  
https://nvd.nist.gov/vuln/detail/CVE-2024-45318  
  
[2]https://psirt.global.sonicwall.com/vuln-detail/SNWLID-2024-0018  
  
  
**05**  
  
**时间线**  
  
2024年12月06日，奇安信 CERT发布安全风险通告。  
  
  
  
**06**  
  
**漏洞情报服务**  
  
  
奇安信ALPH  
A威胁分析平台已支持漏洞情报订阅服务：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EkibxOB3fs4ibpFEkqfMZfO3smS6RKd9BY9IJ0MPzeiashvK2XLpdl3XtTtCD91h0jS26fqvuWpEMXgmXa85qLkoA/640?wxfrom=5&wx_lazy=1&wx_co=1&wx_fmt=other&tp=webp "漏洞订阅上线.png")  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/3tG2LbK7WG3tezJEzJsicLSWCGsIggLbcfk4LB5WK7pdSwMksxPOAoHuibjQpBlEId4nyIIw52n2J8N8MowYZcjA/640?wxfrom=5&wx_lazy=1&wx_co=1&wx_fmt=other&tp=webp "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EkibxOB3fs4ibpFEkqfMZfO3smS6RKd9BYBVaibvBq1vXprZIc191LXKibdiaApA16q3UgmibQDv4yW09qT88J3jRUfA/640?wxfrom=5&wx_lazy=1&wx_co=1&wx_fmt=other&tp=webp "CERT LOGO.png")  
  
**奇安信 CERT**  
  
**致力于**  
第一时间为企业级用户提供**权威**漏洞情报和**有效**  
解决方案。  
  
  
点击↓**阅读原文**，到**ALPHA威胁分析平台**  
订阅更多漏洞信息。  
  
