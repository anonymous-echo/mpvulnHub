#  3CXDesktop App 代码执行漏洞安全风险通告   
 奇安信 CERT   2023-03-31 14:08  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EkibxOB3fs4icrhoWdKnhTgicSjB9pXdeZwDibNIBAEMegibEdG1vrjOibsq887TUz3ztMkM6Qvibic7r26sqbUIbicOMYg/640?wx_fmt=png "https://image.ipaiban.com/upload-ueditor-image-20201112-1605175807303084927.png")  
  
奇安信CERT  
  
**致力于**  
第一时间  
为企业级用户提供  
**权威**  
漏洞情报和  
**有效**  
解决方案。  
  
  
**安全通告**  
  
  
  
3CXDesktop App 是一款跨平台桌面电话应用程序，适用于Linux、MacOS 和 Windows。  
3CXDesktop 允许用户通过聊天、消息、视频和语音进行交互。  
3CX在全球190多个国家和地区  
提供服务，拥有超过1200万日活用户和60万以上的客户群体。  
其网站上列出的客户包括汽车、航空航天、金融、食品饮料、政府、酒店和制造等多个行业的知名企业。  
  
  
近日，奇安信CERT监测到**3****CXDesktop App代码执行漏洞(CVE-2023-29059)**，3CXDesktop App 部分版本在构建安装程序时，内嵌了攻击者特制的恶意代码，在程序安装时会执行恶意代码，并进一步下载恶意负载到目标环境中执行。**鉴于该产品用量较多，建议客户尽快做好自查及防护。**  
  
  
  
<table><tbody><tr style="height:25px;"><td style="border-color: rgb(221, 221, 221);" height="25" width="74"><p style="text-align:justify;"><span style="font-size: 14px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;"><strong>漏洞名称</strong></span></p></td><td colspan="3" style="border-color: rgb(221, 221, 221);border-left-width: initial;border-left-style: none;" height="25"><p style="text-align:justify;"><span style="font-size: 14px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">3CXDesktop App 代码执行漏洞</span></p></td></tr><tr style="height:25px;"><td style="border-color: rgb(221, 221, 221);border-top-width: initial;border-top-style: none;" height="25" width="95"><p style="text-align:justify;"><span style="font-size: 14px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;"><strong>公开时间</strong></span></p></td><td style="border-top: none rgb(221, 221, 221);border-left: none rgb(221, 221, 221);border-bottom-color: rgb(221, 221, 221);border-right-color: rgb(221, 221, 221);" height="25" width="163"><p style="text-align:justify;"><span style="font-size: 14px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">2023-03-30</span></p></td><td style="border-top: none rgb(221, 221, 221);border-left: none rgb(221, 221, 221);border-bottom-color: rgb(221, 221, 221);border-right-color: rgb(221, 221, 221);" height="25" width="124"><p style="text-align:justify;"><span style="font-size: 14px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;"><strong>更新时间</strong></span></p></td><td style="border-top: none rgb(221, 221, 221);border-left: none rgb(221, 221, 221);border-bottom-color: rgb(221, 221, 221);border-right-color: rgb(221, 221, 221);" height="25" width="132"><p style="text-align:justify;"><span style="font-size: 14px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">2023-03-31</span></p></td></tr><tr style="height:25px;"><td style="border-color: rgb(221, 221, 221);border-top-width: initial;border-top-style: none;" height="25" width="112"><p style="text-align:justify;"><span style="font-size: 14px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;"><strong>CVE</strong><strong>编号</strong></span></p></td><td style="border-top: none rgb(221, 221, 221);border-left: none rgb(221, 221, 221);border-bottom-color: rgb(221, 221, 221);border-right-color: rgb(221, 221, 221);" height="25" width="172"><p style="text-align:justify;"><span style="font-size: 14px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">CVE-2023-29059</span></p></td><td style="border-top: none rgb(221, 221, 221);border-left: none rgb(221, 221, 221);border-bottom-color: rgb(221, 221, 221);border-right-color: rgb(221, 221, 221);" height="25" width="134"><p style="text-align:justify;"><span style="font-size: 14px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;"><strong>其他编号</strong></span></p></td><td style="border-top: none rgb(221, 221, 221);border-left: none rgb(221, 221, 221);border-bottom-color: rgb(221, 221, 221);border-right-color: rgb(221, 221, 221);" height="25" width="139"><p style="text-align:justify;"><span style="font-size: 14px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">QVD-2023-7890</span></p></td></tr><tr style="height:25px;"><td style="border-color: rgb(221, 221, 221);border-top-width: initial;border-top-style: none;" height="25" width="120"><p style="text-align:justify;"><span style="font-size: 14px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;"><strong>威胁类型</strong></span></p></td><td style="border-top: none rgb(221, 221, 221);border-left: none rgb(221, 221, 221);border-bottom-color: rgb(221, 221, 221);border-right-color: rgb(221, 221, 221);" height="25" width="171"><p style="text-align:justify;"><span style="font-size: 14px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">代码执行</span></p></td><td style="border-top: none rgb(221, 221, 221);border-left: none rgb(221, 221, 221);border-bottom-color: rgb(221, 221, 221);border-right-color: rgb(221, 221, 221);" height="25" width="138"><p style="text-align:justify;"><span style="font-size: 14px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;"><strong>技术类型</strong></span></p></td><td style="border-top: none rgb(221, 221, 221);border-left: none rgb(221, 221, 221);border-bottom-color: rgb(221, 221, 221);border-right-color: rgb(221, 221, 221);" height="25" width="141"><p style="text-align:justify;"><span style="font-size: 14px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">内嵌的恶意代码</span></p></td></tr><tr style="height:25px;"><td style="border-color: rgb(221, 221, 221);border-top-width: initial;border-top-style: none;" height="25" width="125"><p style="text-align:justify;"><span style="font-size: 14px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;"><strong>厂商</strong></span></p></td><td style="border-top: none rgb(221, 221, 221);border-left: none rgb(221, 221, 221);border-bottom-color: rgb(221, 221, 221);border-right-color: rgb(221, 221, 221);" height="25" width="168"><p style="text-align:justify;"><span style="font-size: 14px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">3CX</span></p></td><td style="border-top: none rgb(221, 221, 221);border-left: none rgb(221, 221, 221);border-bottom-color: rgb(221, 221, 221);border-right-color: rgb(221, 221, 221);" height="25" width="139"><p style="text-align:justify;"><span style="font-size: 14px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;"><strong>产品</strong></span></p></td><td style="border-top: none rgb(221, 221, 221);border-left: none rgb(221, 221, 221);border-bottom-color: rgb(221, 221, 221);border-right-color: rgb(221, 221, 221);" height="25" width="142"><p style="text-align:justify;"><span style="font-size: 14px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">3CXDesktop App</span></p></td></tr><tr style="height:25px;"><td colspan="4" style="border-color: rgb(221, 221, 221);border-top-width: initial;border-top-style: none;" height="25"><p style="text-align:center;"><span style="font-size: 14px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;"><strong>风险等级</strong></span></p></td></tr><tr style="height:25px;"><td colspan="2" style="border-color: rgb(221, 221, 221);border-top-width: initial;border-top-style: none;" height="25"><p style="text-align:center;"><span style="font-size: 14px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;"><strong>奇安信</strong><strong>CERT</strong><strong>风险评级</strong></span></p></td><td colspan="2" style="border-top: none rgb(221, 221, 221);border-left: none rgb(221, 221, 221);border-bottom-color: rgb(221, 221, 221);border-right-color: rgb(221, 221, 221);" height="25"><p style="text-align:center;"><span style="font-size: 14px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;"><strong>风险等级</strong></span></p></td></tr><tr style="height:25px;"><td colspan="2" style="border-color: rgb(221, 221, 221);border-top-width: initial;border-top-style: none;" height="25"><p style="text-align:center;"><span style="font-size: 14px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;"><strong><span style="color: red;">高危</span></strong></span></p></td><td colspan="2" style="border-top: none rgb(221, 221, 221);border-left: none rgb(221, 221, 221);border-bottom-color: rgb(221, 221, 221);border-right-color: rgb(221, 221, 221);" height="25"><p style="text-align:center;"><span style="font-size: 14px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;"><strong><span style="color: rgb(0, 112, 192);">蓝色（一般事件）</span></strong></span></p></td></tr><tr style="height:25px;"><td colspan="4" style="border-color: rgb(221, 221, 221);border-top-width: initial;border-top-style: none;" height="25"><p style="text-align:center;"><span style="font-size: 14px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;"><strong>现时威胁状态</strong></span></p></td></tr><tr style="height:25px;"><td style="border-color: rgb(221, 221, 221);border-top-width: initial;border-top-style: none;" height="25" width="128"><p style="text-align:center;"><span style="font-size: 14px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;"><strong>POC</strong><strong>状态</strong></span></p></td><td style="border-top: none rgb(221, 221, 221);border-left: none rgb(221, 221, 221);border-bottom-color: rgb(221, 221, 221);border-right-color: rgb(221, 221, 221);" height="25" width="166"><p style="text-align:center;"><span style="font-size: 14px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;"><strong>EXP</strong><strong>状态</strong></span></p></td><td style="border-top: none rgb(221, 221, 221);border-left: none rgb(221, 221, 221);border-bottom-color: rgb(221, 221, 221);border-right-color: rgb(221, 221, 221);" height="25" width="139"><p style="text-align:center;"><span style="font-size: 14px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;"><strong>在野利用状态</strong></span></p></td><td style="border-top: none rgb(221, 221, 221);border-left: none rgb(221, 221, 221);border-bottom-color: rgb(221, 221, 221);border-right-color: rgb(221, 221, 221);" height="25" width="142"><p style="text-align:center;"><span style="font-size: 14px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;"><strong>技术细节状态</strong></span></p></td></tr><tr style="height:25px;"><td style="border-color: rgb(221, 221, 221);border-top-width: initial;border-top-style: none;" height="25" width="130"><p style="text-align:center;"><span style="font-size: 14px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">未发现</span></p></td><td style="border-top: none rgb(221, 221, 221);border-left: none rgb(221, 221, 221);border-bottom-color: rgb(221, 221, 221);border-right-color: rgb(221, 221, 221);" height="25" width="166"><p style="text-align:center;"><span style="font-size: 14px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">未发现</span></p></td><td style="border-top: none rgb(221, 221, 221);border-left: none rgb(221, 221, 221);border-bottom-color: rgb(221, 221, 221);border-right-color: rgb(221, 221, 221);" height="25" width="139"><p style="text-align:center;"><span style="font-size: 14px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;"><strong><span style="color: red;">已发现</span></strong></span></p></td><td style="border-top: none rgb(221, 221, 221);border-left: none rgb(221, 221, 221);border-bottom-color: rgb(221, 221, 221);border-right-color: rgb(221, 221, 221);" height="25" width="141"><p style="text-align:center;"><span style="font-size: 14px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">未公开</span></p></td></tr><tr style="height:75px;"><td style="border-color: rgb(221, 221, 221);border-top-width: initial;border-top-style: none;" height="75" width="131"><p style="text-align:justify;"><span style="font-size: 14px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;"><strong>漏洞描述</strong></span></p></td><td colspan="3" style="border-top: none rgb(221, 221, 221);border-left: none rgb(221, 221, 221);border-bottom-color: rgb(221, 221, 221);border-right-color: rgb(221, 221, 221);" height="75"><p style="text-align:justify;margin-top: 8px;line-height: 150%;"><span style="line-height: 150%;font-size: 14px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">3CXDesktop App 部分版本在构建安装程序时，内嵌了攻击者特制的恶意代码，程序安装时会执行恶意代码，并进一步下载恶意负载到目标环境中执行。</span></p></td></tr><tr style="height:75px;"><td style="border-color: rgb(221, 221, 221);border-top-width: initial;border-top-style: none;" height="75" width="132"><p style="text-align:justify;"><span style="font-size: 14px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;"><strong>影响版本</strong></span></p></td><td colspan="3" style="border-top: none rgb(221, 221, 221);border-left: none rgb(221, 221, 221);border-bottom-color: rgb(221, 221, 221);border-right-color: rgb(221, 221, 221);" height="75"><p><span style="font-size:14px;">Electron Mac 3CXDesktop App = 18.11.1213</span></p><p><span style="font-size:14px;">Electron Mac 3CXDesktop App = 18.12.402</span></p><p><span style="font-size:14px;">Electron Mac 3CXDesktop App = 18.12.407</span></p><p><span style="font-size:14px;">Electron Mac 3CXDesktop App = 18.12.416</span></p><p><span style="font-size:14px;">Electron Windows 3CXDesktop App shipped in Update 7 =   18.12.407</span></p><p><span style="font-size:14px;">Electron Windows 3CXDesktop App shipped in Update 7 =   18.12.416</span></p></td></tr><tr style="height:75px;"><td style="border-color: rgb(221, 221, 221);border-top-width: initial;border-top-style: none;" height="75" width="132"><p style="text-align:justify;"><span style="font-size: 14px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;"><strong>其他受影响组件</strong></span></p></td><td colspan="3" style="border-top: none rgb(221, 221, 221);border-left: none rgb(221, 221, 221);border-bottom-color: rgb(221, 221, 221);border-right-color: rgb(221, 221, 221);" height="75"><p style="text-align:justify;margin-top: 8px;margin-bottom: 8px;line-height: 150%;"><span style="line-height: 150%;font-size: 14px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">无</span></p></td></tr></tbody></table>  
  
  
威胁评估  
  
<table><tbody><tr style="height:25px;"><td style="border-color: rgb(221, 221, 221);" height="25" width="77"><p style="text-align:justify;"><span style="font-size: 14px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;"><strong>漏洞名称</strong></span></p></td><td colspan="4" style="border-color: rgb(221, 221, 221);border-left-width: initial;border-left-style: none;" height="25" width="70"><p style="text-align:center;"><span style="font-size: 14px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">3CXDesktop App 代码执行漏洞</span></p></td></tr><tr style="height:25px;"><td style="border-color: rgb(221, 221, 221);border-top-width: initial;border-top-style: none;" height="25" width="77"><p style="text-align:justify;"><span style="font-size: 14px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;"><strong>CVE</strong><strong>编号</strong></span></p></td><td style="border-top: none rgb(221, 221, 221);border-left: none rgb(221, 221, 221);border-bottom-color: rgb(221, 221, 221);border-right-color: rgb(221, 221, 221);" height="25" width="98"><p style="text-align:center;"><span style="font-size: 14px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">CVE-2023-29059</span></p></td><td colspan="2" style="border-top: none rgb(221, 221, 221);border-left: none rgb(221, 221, 221);border-bottom-color: rgb(221, 221, 221);border-right-color: rgb(221, 221, 221);" height="25" width="213"><p style="text-align:justify;"><span style="font-size: 14px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;"><strong>其他编号</strong></span></p></td><td style="border-top: none rgb(221, 221, 221);border-left: none rgb(221, 221, 221);border-bottom-color: rgb(221, 221, 221);border-right-color: rgb(221, 221, 221);" height="25" width="104"><p style="text-align:center;"><span style="font-size: 14px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">QVD-2023-7890</span></p></td></tr><tr style="height:25px;"><td style="border-color: rgb(221, 221, 221);border-top-width: initial;border-top-style: none;" height="25" width="77"><p style="text-align:justify;"><span style="font-size: 14px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;"><strong>CVSS 3.1</strong><strong>评级</strong></span></p></td><td style="border-top: none rgb(221, 221, 221);border-left: none rgb(221, 221, 221);border-bottom-color: rgb(221, 221, 221);border-right-color: rgb(221, 221, 221);" height="25" width="98"><p style="text-align:center;"><span style="font-size: 14px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;"><strong><span style="color: red;">高危</span></strong></span></p></td><td colspan="2" style="border-top: none rgb(221, 221, 221);border-left: none rgb(221, 221, 221);border-bottom-color: rgb(221, 221, 221);border-right-color: rgb(221, 221, 221);" height="25" width="204"><p style="text-align:justify;"><span style="font-size: 14px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;"><strong>CVSS 3.1</strong><strong>分数</strong></span></p></td><td style="border-top: none rgb(221, 221, 221);border-left: none rgb(221, 221, 221);border-bottom-color: rgb(221, 221, 221);border-right-color: rgb(221, 221, 221);" height="25" width="104"><p style="text-align:center;"><span style="font-size: 14px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;"><strong>9.6</strong></span></p></td></tr><tr style="height:25px;"><td rowspan="8" style="border-color: rgb(221, 221, 221);border-top-width: initial;border-top-style: none;" height="25" width="77"><p style="text-align:justify;"><span style="font-size: 14px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;"><strong>CVSS</strong><strong>向量</strong></span></p></td><td colspan="2" style="border-top: none rgb(221, 221, 221);border-left: none rgb(221, 221, 221);border-bottom-color: rgb(221, 221, 221);border-right-color: rgb(221, 221, 221);" height="25" width="70"><p style="text-align:center;"><span style="font-size: 14px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;"><strong>访问途径（</strong><strong>AV</strong><strong>）</strong></span></p></td><td colspan="2" style="border-top: none rgb(221, 221, 221);border-left: none rgb(221, 221, 221);border-bottom-color: rgb(221, 221, 221);border-right-color: rgb(221, 221, 221);" height="25"><p style="text-align:center;"><span style="font-size: 14px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;"><strong>攻击复杂度（</strong><strong>AC</strong><strong>）</strong></span></p></td></tr><tr style="height:25px;"><td colspan="2" style="border-top: none rgb(221, 221, 221);border-left: none rgb(221, 221, 221);border-bottom-color: rgb(221, 221, 221);border-right-color: rgb(221, 221, 221);" height="25" width="238"><p style="text-align:center;"><span style="font-size: 14px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">网络</span></p></td><td colspan="2" style="border-top: none rgb(221, 221, 221);border-left: none rgb(221, 221, 221);border-bottom-color: rgb(221, 221, 221);border-right-color: rgb(221, 221, 221);" height="25" width="204"><p style="text-align:center;"><span style="font-size: 14px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">低</span></p></td></tr><tr style="height:25px;"><td colspan="2" style="border-top: none rgb(221, 221, 221);border-left: none rgb(221, 221, 221);border-bottom-color: rgb(221, 221, 221);border-right-color: rgb(221, 221, 221);" height="25" width="238"><p style="text-align:center;"><span style="font-size: 14px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;"><strong>用户认证（</strong><strong>Au</strong><strong>）</strong></span></p></td><td colspan="2" style="border-top: none rgb(221, 221, 221);border-left: none rgb(221, 221, 221);border-bottom-color: rgb(221, 221, 221);border-right-color: rgb(221, 221, 221);" height="25" width="204"><p style="text-align:center;"><span style="font-size: 14px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;"><strong>用户交互（</strong><strong>UI</strong><strong>）</strong></span></p></td></tr><tr style="height:25px;"><td colspan="2" style="border-top: none rgb(221, 221, 221);border-left: none rgb(221, 221, 221);border-bottom-color: rgb(221, 221, 221);border-right-color: rgb(221, 221, 221);" height="25" width="238"><p style="text-align:center;"><span style="font-size: 14px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">无</span></p></td><td colspan="2" style="border-top: none rgb(221, 221, 221);border-left: none rgb(221, 221, 221);border-bottom-color: rgb(221, 221, 221);border-right-color: rgb(221, 221, 221);" height="25" width="204"><p style="text-align:center;"><span style="font-size: 14px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">需要</span></p></td></tr><tr style="height:25px;"><td colspan="2" style="border-top: none rgb(221, 221, 221);border-left: none rgb(221, 221, 221);border-bottom-color: rgb(221, 221, 221);border-right-color: rgb(221, 221, 221);" height="25" width="238"><p style="text-align:center;"><span style="font-size: 14px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;"><strong>影响范围（</strong><strong>S</strong><strong>）</strong></span></p></td><td colspan="2" style="border-top: none rgb(221, 221, 221);border-left: none rgb(221, 221, 221);border-bottom-color: rgb(221, 221, 221);border-right-color: rgb(221, 221, 221);" height="25" width="204"><p style="text-align:center;"><span style="font-size: 14px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;"><strong>机密性影响（</strong><strong>C</strong><strong>）</strong></span></p></td></tr><tr style="height:25px;"><td colspan="2" style="border-top: none rgb(221, 221, 221);border-left: none rgb(221, 221, 221);border-bottom-color: rgb(221, 221, 221);border-right-color: rgb(221, 221, 221);" height="25" width="238"><p style="text-align:center;"><span style="font-size: 14px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">改变</span></p></td><td colspan="2" style="border-top: none rgb(221, 221, 221);border-left: none rgb(221, 221, 221);border-bottom-color: rgb(221, 221, 221);border-right-color: rgb(221, 221, 221);" height="25" width="204"><p style="text-align:center;"><span style="font-size: 14px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">高</span></p></td></tr><tr style="height:25px;"><td colspan="2" style="border-top: none rgb(221, 221, 221);border-left: none rgb(221, 221, 221);border-bottom-color: rgb(221, 221, 221);border-right-color: rgb(221, 221, 221);" height="25" width="238"><p style="text-align:center;"><span style="font-size: 14px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;"><strong>完整性影响（</strong><strong>I</strong><strong>）</strong></span></p></td><td colspan="2" style="border-top: none rgb(221, 221, 221);border-left: none rgb(221, 221, 221);border-bottom-color: rgb(221, 221, 221);border-right-color: rgb(221, 221, 221);" height="25" width="204"><p style="text-align:center;"><span style="font-size: 14px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;"><strong>可用性影响（</strong><strong>A</strong><strong>）</strong></span></p></td></tr><tr style="height:25px;"><td colspan="2" style="border-top: none rgb(221, 221, 221);border-left: none rgb(221, 221, 221);border-bottom-color: rgb(221, 221, 221);border-right-color: rgb(221, 221, 221);" height="25" width="238"><p style="text-align:center;"><span style="font-size: 14px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">高</span></p></td><td colspan="2" style="border-top: none rgb(221, 221, 221);border-left: none rgb(221, 221, 221);border-bottom-color: rgb(221, 221, 221);border-right-color: rgb(221, 221, 221);" height="25" width="204"><p style="text-align:center;"><span style="font-size: 14px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">低</span></p></td></tr><tr style="height:75px;"><td style="border-color: rgb(221, 221, 221);border-top-width: initial;border-top-style: none;" height="75" width="77"><p style="text-align:justify;"><span style="font-size: 14px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;"><strong>危害描述</strong></span></p></td><td colspan="4" style="border-top: none rgb(221, 221, 221);border-left: none rgb(221, 221, 221);border-bottom-color: rgb(221, 221, 221);border-right-color: rgb(221, 221, 221);word-break: break-all;" height="75" width="70"><p style="text-align:justify;margin-top: 8px;margin-bottom: 8px;line-height: 150%;"><span style="line-height: 150%;font-size: 14px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">在程序安装时会执行恶意代码，并进一步下载恶意负载到目标环境中执行。</span></p></td></tr></tbody></table>  
  
处置建议  
  
**官方暂未发布修复程序，受影响用户可以使用下面的缓解方案来缓解此漏洞。**  
  
  
**缓解方案：**  
  
使用PWA App，PWA App的安装方法可以参考下面链接：  
  
https://www.3cx.com/user-manual/web-client/  
  
  
**入侵检测指标(IOC)：**  
  
akamaicontainer[.]com  
  
akamaitechcloudservices[.]com  
  
azuredeploystore[.]com  
  
azureonlinecloud[.]com  
  
azureonlinestorage[.]com  
  
dunamistrd[.]com  
  
glcloudservice[.]com  
  
journalide[.]org  
  
msedgepackageinfo[.]com  
  
msstorageazure[.]com  
  
msstorageboxes[.]com  
  
officeaddons[.]com  
  
officestoragebox[.]com  
  
pbxcloudeservices[.]com  
  
pbxphonenetwork[.]com  
  
pbxsources[.]com  
  
qwepoi123098[.]com  
  
sbmsa[.]wiki  
  
sourceslabs[.]com  
  
visualstudiofactory[.]com  
  
zacharryblogs[.]com  
  
akamaicontainer[.]com  
  
akamaitechcloudservices[.]com  
  
azuredeploystore[.]com  
  
azureonlinecloud[.]com  
  
azureonlinestorage.com  
  
convieneonline[.]com  
  
dunamistrd[.]com  
  
glcloudservice[.]com  
  
journalide[.]org  
  
msedgepackageinfo[.]com  
  
msstorageazure[.]com  
  
msstorageboxes[.]com  
  
officeaddons[.]com  
  
officestoragebox[.]com  
  
pbxcloudeservices[.]com  
  
pbxphonenetwork[.]com  
  
pbxsources[.]com  
  
qwepoi123098[.]com  
  
Soyoungjun[.]com  
  
aa124a4b4df12b34e74ee7f6c683b2ebec4ce9a8edcf9be345823b4fdcf5d868  
  
59e1edf4d82fae4978e97512b0331b7eb21dd4b838b850ba46794d9c7a2c0983  
  
92005051ae314d61074ed94a52e76b1c3e21e7f0e8c1d1fdd497a006ce45fa61  
  
5407cda7d3a75e7b1e030b1f33337a56f293578ffa8b3ae19c671051ed314290  
  
b86c695822013483fa4e2dfdf712c5ee777d7b99cbad8c2fa2274b133481eadb  
  
e6bbc33815b9f20b0cf832d7401dd893fbc467c800728b5891336706da0dbcec  
  
11be1803e2e307b647a8a7e02d128335c448ff741bf06bf52b332e0bbf423b03  
  
7986bbaee8940da11ce089383521ab420c443ab7b15ed42aed91fd31ce833896  
  
c485674ee63ec8d4e8fde9800788175a8b02d3f9416d0e763360fff7f8eb4e02  
  
B5E318240401010E4453E146E3E67464DD625CFEF9CD51C5015D68550EE8CC09  
  
AA4E398B3BD8645016D8090FFC77D15F926A8E69258642191DEB4E68688FF973  
  
  
参考资料  
  
[1]https://www.3cx.com/blog/news/desktopapp-security-alert/  
  
[2]https://www.3cx.com/user-manual/web-client/  
  
  
时间线  
  
2023年3月31日，奇安信 CERT发布安全风险通告。  
  
  
点击**阅读原文**  
到奇安信NOX-安全监测平台查询更多漏洞详情  
  
