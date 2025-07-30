#  Cisco Small Business远程代码执行漏洞安全风险通告   
原创 QAX CERT  奇安信 CERT   2022-06-17 19:07  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EkibxOB3fs4icrhoWdKnhTgicSjB9pXdeZwDibNIBAEMegibEdG1vrjOibsq887TUz3ztMkM6Qvibic7r26sqbUIbicOMYg/640?wx_fmt=png "https://image.ipaiban.com/upload-ueditor-image-20201112-1605175807303084927.png")  
  
奇安信CERT  
  
**致力于**  
第一时间  
为企业级用户提供安全风险  
**通告**  
和  
**有效**  
解决方案。  
  
  
**安全通告**  
  
  
  
近日，奇安信CERT监测到官方发布了Cisco Small Business 远程代码执行漏洞(CVE-2022-20825)通告，Cisco Small Business 路由器 Web 管理界面存在栈溢出漏洞，由于对用户请求的 HTTP 数据包输入验证不足，此漏洞可能允许未经身份验证的远程攻击者在受影响的设备上以 root 权限执行任意代码或导致拒绝服务。  
  
  
**利用此漏洞需要访问 Web 管理界面，如果目标设备开启远程管理功能，则未经身份验证的远程攻击者可在受影响的设备上以 root 权限执行任意代码，否则攻击者需要通过某些手段接入本地 LAN 网络才可以利用此漏洞。**  
**默认情况下，远程管理功能处于禁用状态。**  
  
  
**鉴于此漏洞影响范围较大且相关产品已进入停服流程，建议用户尽快采取缓解措施或迁移至安全产品。**  
  
****  
<table><tbody><tr><td style="padding: 5px 10px;border-color: rgb(221, 221, 221);" width="74"><p><strong><span style="font-size: 14px;">漏洞名称</span></strong></p></td><td colspan="3" style="padding: 5px 10px;border-color: rgb(221, 221, 221);"><p><span style="font-size: 14px;">Cisco Small Business 远程代码执行漏洞(CVE-2022-20825)</span></p></td></tr><tr><td style="padding: 5px 10px;border-color: rgb(221, 221, 221);" width="95"><p><strong><span style="font-size: 14px;">公开时间</span></strong></p></td><td style="padding: 5px 10px;border-color: rgb(221, 221, 221);" width="172"><p><span style="font-size: 14px;">2022-06-15</span></p></td><td style="padding: 5px 10px;border-color: rgb(221, 221, 221);" width="135"><p><strong><span style="font-size: 14px;">更新时间</span></strong></p></td><td style="padding: 5px 10px;border-color: rgb(221, 221, 221);" width="302"><p><span style="font-size: 14px;">2022-06-17</span></p></td></tr><tr><td style="padding: 5px 10px;border-color: rgb(221, 221, 221);" width="113"><p><strong><span style="font-size: 14px;">CVE编号</span></strong></p></td><td style="padding: 5px 10px;border-color: rgb(221, 221, 221);" width="184"><p><span style="font-size: 14px;">CVE-2022-20825</span></p></td><td style="padding: 5px 10px;border-color: rgb(221, 221, 221);" width="147"><p><strong><span style="font-size: 14px;">其他编号</span></strong></p></td><td style="padding: 5px 10px;border-color: rgb(221, 221, 221);" width="297"><p><span style="font-size: 14px;">QVD-2022-9317</span></p></td></tr><tr><td style="padding: 5px 10px;border-color: rgb(221, 221, 221);" width="125"><p><strong><span style="font-size: 14px;">威胁类型</span></strong></p></td><td style="padding: 5px 10px;border-color: rgb(221, 221, 221);" width="187"><p><span style="font-size: 14px;">代码执行</span></p></td><td style="padding: 5px 10px;border-color: rgb(221, 221, 221);" width="153"><p><strong><span style="font-size: 14px;">技术类型</span></strong></p></td><td style="padding: 5px 10px;border-color: rgb(221, 221, 221);" width="289"><p><span style="font-size: 14px;">栈缓冲区溢出</span></p></td></tr><tr><td style="padding: 5px 10px;border-color: rgb(221, 221, 221);" width="133"><p><strong><span style="font-size: 14px;">厂商</span></strong></p></td><td style="padding: 5px 10px;border-color: rgb(221, 221, 221);" width="186"><p><span style="font-size: 14px;">Cisco</span></p></td><td style="padding: 5px 10px;border-color: rgb(221, 221, 221);" width="156"><p><strong><span style="font-size: 14px;">产品</span></strong></p></td><td style="padding: 5px 10px;border-color: rgb(221, 221, 221);" width="285"><p><span style="font-size: 14px;">Cisco Small Business RV Series Routers</span></p></td></tr><tr><td colspan="4" align="center" valign="middle" style="padding: 5px 10px;border-color: rgb(221, 221, 221);"><p><strong><span style="font-size: 14px;">风险等级</span></strong></p></td></tr><tr><td colspan="2" align="center" valign="middle" style="padding: 5px 10px;border-color: rgb(221, 221, 221);"><p><strong><span style="font-size: 14px;">奇安信CERT风险评级</span></strong></p></td><td colspan="2" align="center" valign="middle" style="padding: 5px 10px;border-color: rgb(221, 221, 221);"><p><strong><span style="font-size: 14px;">风险等级</span></strong></p></td></tr><tr><td colspan="2" align="center" valign="middle" style="padding: 5px 10px;border-color: rgb(221, 221, 221);"><p><span style="font-size: 14px;color: rgb(255, 0, 0);">高危</span></p></td><td colspan="2" align="center" valign="middle" style="padding: 5px 10px;border-color: rgb(221, 221, 221);"><p><span style="font-size: 14px;color: rgb(12, 118, 240);">蓝色（一般事件）</span></p></td></tr><tr><td colspan="4" align="center" valign="middle" style="padding: 5px 10px;border-color: rgb(221, 221, 221);"><p><strong><span style="font-size: 14px;">现时威胁状态</span></strong></p></td></tr><tr><td align="center" valign="middle" style="padding: 5px 10px;border-color: rgb(221, 221, 221);" width="138"><p><strong><span style="font-size: 14px;">POC状态</span></strong></p></td><td align="center" valign="middle" style="padding: 5px 10px;border-color: rgb(221, 221, 221);" width="184"><p><strong><span style="font-size: 14px;">EXP状态</span></strong></p></td><td align="center" valign="middle" style="padding: 5px 10px;border-color: rgb(221, 221, 221);" width="157"><p><strong><span style="font-size: 14px;">在野利用状态</span></strong></p></td><td align="center" valign="middle" style="padding: 5px 10px;border-color: rgb(221, 221, 221);" width="283"><p><strong><span style="font-size: 14px;">技术细节状态</span></strong></p></td></tr><tr><td align="center" valign="middle" style="padding: 5px 10px;border-color: rgb(221, 221, 221);" width="142"><p><strong><span style="font-size: 14px;">未知</span></strong></p></td><td align="center" valign="middle" style="padding: 5px 10px;border-color: rgb(221, 221, 221);" width="183"><p><strong><span style="font-size: 14px;">未知</span></strong></p></td><td align="center" valign="middle" style="padding: 5px 10px;border-color: rgb(221, 221, 221);" width="157"><p><strong><span style="font-size: 14px;">未知</span></strong></p></td><td align="center" valign="middle" style="padding: 5px 10px;border-color: rgb(221, 221, 221);" width="282"><p><strong><span style="font-size: 14px;">未知</span></strong></p></td></tr><tr><td style="padding: 5px 10px;border-color: rgb(221, 221, 221);" width="145"><p><strong><span style="font-size: 14px;">漏洞描述</span></strong></p></td><td colspan="3" style="padding: 5px 10px;border-color: rgb(221, 221, 221);"><p><span style="font-size: 14px;">Cisco Small Business 路由器 Web 管理界面存在栈溢出漏洞，由于对用户请求的 HTTP 数据包输入验证不足，此漏洞可能允许未经身份验证的远程攻击者在受影响的设备上以 root 权限执行任意代码或导致拒绝服务。</span></p></td></tr><tr><td style="padding: 5px 10px;border-color: rgb(221, 221, 221);" width="147"><p><strong><span style="font-size: 14px;">影响版本</span></strong></p></td><td colspan="3" style="padding: 5px 10px;border-color: rgb(221, 221, 221);"><p><span style="font-size: 14px;">Cisco Small Business   RV110W</span></p><p><span style="font-size: 14px;">Cisco Small Business   RV130</span></p><p><span style="font-size: 14px;">Cisco Small Business   RV130W</span></p><p><span style="font-size: 14px;">Cisco Small Business   RV215W</span></p></td></tr><tr><td style="padding: 5px 10px;border-color: rgb(221, 221, 221);" width="148"><p><strong><span style="font-size: 14px;">不受影响版本</span></strong></p></td><td colspan="3" style="padding: 5px 10px;border-color: rgb(221, 221, 221);"><p><span style="font-size: 14px;">Cisco Small Business   RV132W</span></p><p><span style="font-size: 14px;">Cisco Small Business   RV160</span></p><p><span style="font-size: 14px;">Cisco Small Business   RV160W</span></p></td></tr><tr><td style="padding: 5px 10px;border-color: rgb(221, 221, 221);" width="149"><p><strong><span style="font-size: 14px;">其他受影响组件</span></strong></p></td><td colspan="3" style="padding: 5px 10px;border-color: rgb(221, 221, 221);"><p draggable="true"><span style="font-size: 14px;">无</span></p></td></tr></tbody></table>  
  
风险等级  
  
奇安信 CERT风险评级为：  
高危  
  
风险等级：  
蓝色（一般事件）  
  
  
威胁评估  
  
<table><tbody><tr><td style="word-break: break-all;padding: 5px 10px;" width="27"><p><strong><span style="font-size: 14px;">漏洞名称</span></strong></p></td><td colspan="4" style="padding: 5px 10px;" width="470"><p><span style="font-size: 14px;">Cisco Small Business 远程代码执行漏洞(CVE-2022-20825)</span></p></td></tr><tr><td style="word-break: break-all;padding: 5px 10px;" width="65"><p><strong><span style="font-size: 14px;">CVE编号</span></strong></p></td><td align="center" valign="middle" style="padding: 5px 10px;" width="87"><p><span style="font-size: 14px;">CVE-2022-20825</span></p></td><td colspan="2" style="word-break: break-all;padding: 5px 10px;" width="245"><p><strong><span style="font-size: 14px;">其他编号</span></strong></p></td><td align="center" valign="middle" style="padding: 5px 10px;" width="81"><p><span style="font-size: 14px;">QVD-2022-9317</span></p></td></tr><tr><td style="word-break: break-all;padding: 5px 10px;" width="27"><p><strong><span style="font-size: 14px;">CVSS 3.1评级</span></strong></p></td><td align="center" valign="middle" style="padding: 5px 10px;" width="87"><p><span style="font-size: 14px;color: rgb(255, 0, 0);">高危</span></p></td><td colspan="2" style="word-break: break-all;padding: 5px 10px;" width="105"><p><strong><span style="font-size: 14px;">CVSS 3.1分数</span></strong></p></td><td align="center" valign="middle" style="padding: 5px 10px;word-break: break-all;" width="81"><p><strong><span style="font-size: 14px;">9.8</span></strong><span style="font-size: 14px;"></span></p></td></tr><tr><td rowspan="8" style="word-break: break-all;padding: 5px 10px;" width="27"><p><strong><span style="font-size: 14px;">CVSS向量</span></strong></p></td><td colspan="2" align="center" valign="middle" style="word-break: break-all;padding: 5px 10px;" width="221"><p><strong><span style="font-size: 14px;">访问途径（AV）</span></strong></p></td><td colspan="2" align="center" valign="middle" style="padding: 5px 10px;"><p><strong><span style="font-size: 14px;">攻击复杂度（AC）</span></strong></p></td></tr><tr><td colspan="2" align="center" valign="middle" style="padding: 5px 10px;" width="231"><p><span style="font-size: 14px;">网络</span></p></td><td colspan="2" align="center" valign="middle" style="padding: 5px 10px;" width="105"><p><span style="font-size: 14px;">低</span></p></td></tr><tr><td colspan="2" align="center" valign="middle" style="word-break: break-all;padding: 5px 10px;" width="253"><p><strong><span style="font-size: 14px;">所需权限（PR）</span></strong></p></td><td colspan="2" align="center" valign="middle" style="padding: 5px 10px;" width="105"><p><strong><span style="font-size: 14px;">用户交互（UI）</span></strong></p></td></tr><tr><td colspan="2" align="center" valign="middle" style="padding: 5px 10px;" width="264"><p><span style="font-size: 14px;">不需要</span></p></td><td colspan="2" align="center" valign="middle" style="padding: 5px 10px;" width="105"><p><span style="font-size: 14px;">不需要</span></p></td></tr><tr><td colspan="2" align="center" valign="middle" style="word-break: break-all;padding: 5px 10px;" width="269"><p><strong><span style="font-size: 14px;">影响范围（S）</span></strong></p></td><td colspan="2" align="center" valign="middle" style="padding: 5px 10px;" width="105"><p><strong><span style="font-size: 14px;">机密性影响（C）</span></strong></p></td></tr><tr><td colspan="2" align="center" valign="middle" style="padding: 5px 10px;" width="271"><p><span style="font-size: 14px;">不变</span></p></td><td colspan="2" align="center" valign="middle" style="padding: 5px 10px;" width="105"><p><span style="font-size: 14px;">高</span></p></td></tr><tr><td colspan="2" align="center" valign="middle" style="word-break: break-all;padding: 5px 10px;" width="272"><p><strong><span style="font-size: 14px;">完整性影响（I）</span></strong></p></td><td colspan="2" align="center" valign="middle" style="padding: 5px 10px;" width="105"><p><strong><span style="font-size: 14px;">可用性影响（A）</span></strong></p></td></tr><tr><td colspan="2" align="center" valign="middle" style="padding: 5px 10px;" width="273"><p><span style="font-size: 14px;">高</span></p></td><td colspan="2" align="center" valign="middle" style="padding: 5px 10px;" width="105"><p><span style="font-size: 14px;">高</span></p></td></tr><tr><td style="word-break: break-all;padding: 5px 10px;" width="27"><p><strong><span style="font-size: 14px;">危害描述</span></strong></p></td><td colspan="4" style="padding: 5px 10px;word-break: break-all;" width="470"><p><span style="font-size: 14px;">Cisco Small Business 路由器 Web 管理界面存在栈溢出漏洞，由于对用户请求的 HTTP 数据包输入验证不足，此漏洞可能允许未经身份验证的远程攻击者在受影响的设备上以 root 权限执行任意代码或导致拒绝服务。</span></p></td></tr></tbody></table>  
  
处置建议  
  
**1. 远程管理功能检测方案**  
  
打开Web管理界面，选择"**基础设置 > 远程管理**"。如果选中了**启用**复选框，则表示此设备已启用远程管理功能。  
  
**如没有相关业务需求，建议关闭设备的远程管理功能****。**  
  
  
**2. 解决方案**  
  
由于此漏洞影响的相关产品已进入停服流程，厂商不会发布解决此漏洞的相关补丁，建议客户迁移到 Cisco Small Business RV132W、RV160 或 RV160W 路由器。  
  
  
参考资料  
  
[1]https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sb-rv-overflow-s2r82P9v  
  
  
时间线  
  
2022年6月17日，  
奇安信 CERT发布安全风险通告  
  
  
点击**阅读原文**  
到奇安信NOX-安全监测平台查询更多漏洞详情  
