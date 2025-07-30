#  思科发布IOS XE无线控制器中的关键漏洞更新   
鹏鹏同学  黑猫安全   2025-05-09 00:58  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/8dBEfDPEceib2KwN20RwmZDqvtb6iabwy50ebugkICEvAP4GuxuuC8zmKGvbEVVNRYQSGynZgC24fewY0XdB90xQ/640?wx_fmt=png&from=appmsg "")  
  
思科针对IOS XE无线控制器系统（漏洞编号CVE-2025-20188，CVSS评分10分）发布安全更新。未经身份验证的远程攻击者可利用该漏洞向受控系统植入任意文件。  
  
攻击者通过向AP镜像下载接口发送特制HTTPS请求，可能获取root权限并执行任意命令。思科安全公告指出："思科IOS XE无线控制器(WLC)的带外AP镜像下载(OoB AP Image Download)功能存在漏洞，允许未经认证的远程攻击者向受影响系统上传任意文件。该漏洞源于系统存在硬编码的JSON Web Token(JWT)，成功利用可导致攻击者上传文件、执行路径遍历并以root权限运行命令。"  
  
该漏洞仅在启用"带外AP镜像下载"功能时存在攻击风险，思科强调该功能默认处于关闭状态。受影响产品包括：  
- 云平台Catalyst 9800-CL无线控制器  
  
- Catalyst 9300/9400/9500系列交换机内置的9800嵌入式无线控制器  
  
- Catalyst 9800系列无线控制器  
  
- Catalyst AP内置无线控制器  
  
用户可通过运行命令"show running-config | include ap upgrade"检测，若返回"ap upgrade method https"则表明功能已启用。思科表示："禁用该功能后，系统将自动切换至CAPWAP协议进行AP镜像更新，且不会影响AP客户端状态。"  
  
目前尚无临时解决方案，但可通过禁用带外AP镜像下载功能缓解风险。思科建议用户在评估业务影响后采取该措施，直至完成补丁升级。思科产品安全事件响应团队(PSIRT)确认尚未发现该漏洞的野外利用案例。  
  
  
