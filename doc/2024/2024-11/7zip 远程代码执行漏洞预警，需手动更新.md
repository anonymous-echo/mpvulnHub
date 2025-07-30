#  7zip 远程代码执行漏洞预警，需手动更新   
 二道情报贩子   2024-11-22 07:10  
  
7-zip zstandard 解压缩整数下溢远程代码执行漏洞  
<table><tbody><tr><td msttexthash="7326319" msthash="24" style="padding: 0px 0px 20px;vertical-align: top;font-weight: bold;" width="220">CVE 编号</td><td style="padding: 0px 0px 20px;vertical-align: top;">CVE-2024-11477漏洞</td></tr><tr><td msttexthash="8427770" msthash="26" style="padding: 0px 0px 20px;vertical-align: top;font-weight: bold;" width="220">CVSS 评分</td><td style="padding: 0px 0px 20px;vertical-align: top;"><span style="">7.8</span></td></tr></tbody></table>  
  
<table><tbody><tr><td msttexthash="12903085" msthash="32" style="padding: 0px 0px 20px;vertical-align: top;font-weight: bold;" width="220">漏洞详情</td><td style="padding: 0px 0px 20px;vertical-align: top;"><p msttexthash="683788898" msthash="33" style="margin-bottom: 25px;">此漏洞允许远程攻击者在受影响的 7-Zip 安装上执行任意代码。要利用此漏洞，需要与此库交互，但攻击媒介可能因实施而异。</p><p style="margin-bottom: 25px;"><span style="">具体缺陷存在于 Zstandard 解压缩的实现中。此问题是由于未正确验证用户提供的数据而导致的，这可能导致在写入内存之前出现整数下溢。攻击者可以利用此漏洞在当前进程的上下文中执行代码。</span><br/></p></td></tr><tr><td msttexthash="19181279" msthash="35" style="padding: 0px 0px 20px;vertical-align: top;font-weight: bold;" width="220">其他详细信息</td><td style="padding: 0px 0px 20px;vertical-align: top;"><p msttexthash="21108659" msthash="36" style="margin-bottom: 25px;">已在 7-Zip 24.07 中修复</p><p msttexthash="21108659" msthash="36" style="margin-bottom: 25px;">公告时间2024年11月20日</p></td></tr></tbody></table>  
  
**注意：7zip没有任何更新按钮，必须手动去官网下载然后更新。**  
  
https://www.7-zip.org/  
  
  
需要注意，不要去其他网站下载最新版7zip，基本一大半都是银狐木马！  
  
