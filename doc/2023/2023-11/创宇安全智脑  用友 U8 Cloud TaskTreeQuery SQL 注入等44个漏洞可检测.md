#  创宇安全智脑 | 用友 U8 Cloud TaskTreeQuery SQL 注入等44个漏洞可检测   
 创宇安全智脑   2023-11-23 19:57  
  
**创宇安全智脑**是基于知道创宇16年来AI+安全大数据在真实攻防场景中的经验积累构建的下一代全场景安全智能算力平台。平台拥有海量真实攻防数据和安全大数据持续生产能力；结合面向多个实战场景的AI智能模型，持续汇聚、萃取和分析，实时输出高精准高价值威胁情报、安全态势、攻防策略；持续全场景赋能知道创宇全产品矩阵和安全托管服务。  
  
  
**创宇安全智脑目前已经联动支撑知道创宇全产品矩阵，包括：创宇盾、抗D保、ScanV、ZoomEye、创宇蜜罐、创宇云图、创宇云影、创宇猎幽、创宇威胁情报网关等。**  
  
  
  
本周累计更新漏洞插件44个，其中重点插件6个。  
  
  
**详情如下：**  
  
**更新列表**  
  
<table><colgroup><col width="58" style="width: 58.5pt;"/><col width="272" style="width: 272.8pt;"/><col width="69" style="width: 69.85pt;"/><col width="48" style="width: 48pt;"/></colgroup><tbody><tr height="24" style="height: 24.75pt;"><td height="24" width="20" x:str="" style="padding-top: 1px;padding-left: 1px;padding-right: 1px;color: rgb(255, 255, 255);font-size: 8pt;font-family: &#34;PingFang SC Regular&#34;;border-top: none;border-right-width: 0.5pt;border-right-color: rgb(255, 255, 255);border-bottom-width: 1.5pt;border-bottom-color: rgb(255, 255, 255);border-left: none;vertical-align: middle;text-wrap: wrap;background: rgb(91, 155, 213);text-align: center;word-break: break-all;">等级</td><td width="366" x:str="" style="padding-top: 1px;padding-left: 1px;padding-right: 1px;color: rgb(255, 255, 255);font-size: 8pt;font-family: &#34;PingFang SC Regular&#34;;border-top: none;border-right-width: 0.5pt;border-right-color: rgb(255, 255, 255);border-bottom-width: 1.5pt;border-bottom-color: rgb(255, 255, 255);border-left-width: 0.5pt;border-left-color: rgb(255, 255, 255);vertical-align: middle;text-wrap: wrap;background: rgb(91, 155, 213);text-align: center;">插件名称</td><td width="45" x:str="" style="padding-top: 1px;padding-left: 1px;padding-right: 1px;color: rgb(255, 255, 255);font-size: 8pt;font-family: &#34;PingFang SC Regular&#34;;border-top: none;border-right-width: 0.5pt;border-right-color: rgb(255, 255, 255);border-bottom-width: 1.5pt;border-bottom-color: rgb(255, 255, 255);border-left-width: 0.5pt;border-left-color: rgb(255, 255, 255);vertical-align: middle;text-wrap: wrap;background: rgb(91, 155, 213);text-align: center;">漏洞<br/>类型</td><td width="40" x:str="" style="padding-top: 1px;padding-left: 1px;padding-right: 1px;color: rgb(255, 255, 255);font-size: 8pt;font-family: &#34;PingFang SC Regular&#34;;border-top: none;border-right: none;border-bottom-width: 1.5pt;border-bottom-color: rgb(255, 255, 255);border-left-width: 0.5pt;border-left-color: rgb(255, 255, 255);vertical-align: middle;text-wrap: wrap;background: rgb(91, 155, 213);text-align: center;">发布<br/>类型</td></tr><tr height="13" style="height: 13.6pt;"><td height="13" width="20" x:str="" style="padding-top: 1px;padding-left: 1px;padding-right: 1px;color: rgb(0, 0, 0);font-size: 8pt;font-family: &#34;PingFang SC Regular&#34;;border-top-width: 1.5pt;border-top-color: rgb(255, 255, 255);border-right-width: 0.5pt;border-right-color: rgb(255, 255, 255);border-bottom-width: 0.5pt;border-bottom-color: rgb(255, 255, 255);border-left: none;vertical-align: top;text-wrap: wrap;background: rgb(189, 215, 238);text-align: center;">严重</td><td width="442" x:str="" style="padding-top: 1px;padding-left: 1px;padding-right: 1px;color: rgb(0, 0, 0);font-size: 8pt;font-family: &#34;PingFang SC Regular&#34;;border-width: 1.5pt 0.5pt 0.5pt;border-color: rgb(255, 255, 255);vertical-align: top;text-wrap: wrap;background: rgb(189, 215, 238);text-align: center;word-break: break-all;">飞企互联 FE 任意文件上传</td><td width="45" x:str="" style="padding-top: 1px;padding-left: 1px;padding-right: 1px;color: rgb(0, 0, 0);font-size: 8pt;font-family: &#34;PingFang SC Regular&#34;;border-width: 1.5pt 0.5pt 0.5pt;border-color: rgb(255, 255, 255);vertical-align: top;text-wrap: wrap;background: rgb(189, 215, 238);text-align: center;">WEB</td><td width="40" x:str="" style="padding-top: 1px;padding-left: 1px;padding-right: 1px;color: rgb(0, 0, 0);font-size: 8pt;font-family: &#34;PingFang SC Regular&#34;;border-top-width: 1.5pt;border-top-color: rgb(255, 255, 255);border-right: none;border-bottom-width: 0.5pt;border-bottom-color: rgb(255, 255, 255);border-left-width: 0.5pt;border-left-color: rgb(255, 255, 255);vertical-align: top;text-wrap: wrap;background: rgb(189, 215, 238);text-align: center;">新增</td></tr><tr height="13" style="height: 13.6pt;"><td height="13" width="20" x:str="" style="padding-top: 1px;padding-left: 1px;padding-right: 1px;color: rgb(0, 0, 0);font-size: 8pt;font-family: &#34;PingFang SC Regular&#34;;border-top-width: 0.5pt;border-top-color: rgb(255, 255, 255);border-right-width: 0.5pt;border-right-color: rgb(255, 255, 255);border-bottom-width: 0.5pt;border-bottom-color: rgb(255, 255, 255);border-left: none;vertical-align: top;text-wrap: wrap;background: rgb(221, 235, 247);text-align: center;">高危</td><td width="442" x:str="" style="padding-top: 1px;padding-left: 1px;padding-right: 1px;color: rgb(0, 0, 0);font-size: 8pt;font-family: &#34;PingFang SC Regular&#34;;border-width: 0.5pt;border-color: rgb(255, 255, 255);vertical-align: top;text-wrap: wrap;background: rgb(221, 235, 247);text-align: center;word-break: break-all;">海翔云平台 getylist_login.do <br/>SQL 注入</td><td width="45" x:str="" style="padding-top: 1px;padding-left: 1px;padding-right: 1px;color: rgb(0, 0, 0);font-size: 8pt;font-family: &#34;PingFang SC Regular&#34;;border-width: 0.5pt;border-color: rgb(255, 255, 255);vertical-align: top;text-wrap: wrap;background: rgb(221, 235, 247);text-align: center;">WEB</td><td width="40" x:str="" style="padding-top: 1px;padding-left: 1px;padding-right: 1px;color: rgb(0, 0, 0);font-size: 8pt;font-family: &#34;PingFang SC Regular&#34;;border-top-width: 0.5pt;border-top-color: rgb(255, 255, 255);border-right: none;border-bottom-width: 0.5pt;border-bottom-color: rgb(255, 255, 255);border-left-width: 0.5pt;border-left-color: rgb(255, 255, 255);vertical-align: top;text-wrap: wrap;background: rgb(221, 235, 247);text-align: center;">新增</td></tr><tr height="13" style="height: 13.6pt;"><td height="13" width="20" x:str="" style="padding-top: 1px;padding-left: 1px;padding-right: 1px;color: rgb(0, 0, 0);font-size: 8pt;font-family: &#34;PingFang SC Regular&#34;;border-top-width: 0.5pt;border-top-color: rgb(255, 255, 255);border-right-width: 0.5pt;border-right-color: rgb(255, 255, 255);border-bottom-width: 0.5pt;border-bottom-color: rgb(255, 255, 255);border-left: none;vertical-align: top;text-wrap: wrap;background: rgb(189, 215, 238);text-align: center;word-break: break-all;">高危</td><td width="442" x:str="" style="padding-top: 1px;padding-left: 1px;padding-right: 1px;color: rgb(0, 0, 0);font-size: 8pt;font-family: &#34;PingFang SC Regular&#34;;border-width: 0.5pt;border-color: rgb(255, 255, 255);vertical-align: top;text-wrap: wrap;background: rgb(189, 215, 238);text-align: center;word-break: break-all;">浙大恩特客户资源管理系统 <br/>MailAction.entphone 任意文件上传</td><td width="45" x:str="" style="padding-top: 1px;padding-left: 1px;padding-right: 1px;color: rgb(0, 0, 0);font-size: 8pt;font-family: &#34;PingFang SC Regular&#34;;border-width: 0.5pt;border-color: rgb(255, 255, 255);vertical-align: top;text-wrap: wrap;background: rgb(189, 215, 238);text-align: center;">WEB</td><td width="40" x:str="" style="padding-top: 1px;padding-left: 1px;padding-right: 1px;color: rgb(0, 0, 0);font-size: 8pt;font-family: &#34;PingFang SC Regular&#34;;border-top-width: 0.5pt;border-top-color: rgb(255, 255, 255);border-right: none;border-bottom-width: 0.5pt;border-bottom-color: rgb(255, 255, 255);border-left-width: 0.5pt;border-left-color: rgb(255, 255, 255);vertical-align: top;text-wrap: wrap;background: rgb(189, 215, 238);text-align: center;">新增</td></tr><tr height="13" style="height: 13.6pt;"><td height="13" width="20" x:str="" style="padding-top: 1px;padding-left: 1px;padding-right: 1px;color: rgb(0, 0, 0);font-size: 8pt;font-family: &#34;PingFang SC Regular&#34;;border-top-width: 0.5pt;border-top-color: rgb(255, 255, 255);border-right-width: 0.5pt;border-right-color: rgb(255, 255, 255);border-bottom-width: 0.5pt;border-bottom-color: rgb(255, 255, 255);border-left: none;vertical-align: top;text-wrap: wrap;background: rgb(221, 235, 247);text-align: center;">高危</td><td width="442" x:str="" style="padding-top: 1px;padding-left: 1px;padding-right: 1px;color: rgb(0, 0, 0);font-size: 8pt;font-family: &#34;PingFang SC Regular&#34;;border-width: 0.5pt;border-color: rgb(255, 255, 255);vertical-align: top;text-wrap: wrap;background: rgb(221, 235, 247);text-align: center;word-break: break-all;">捷诚管理信息系统 <br/>CWSFinanceCommon.asmx SQL注入</td><td width="45" x:str="" style="padding-top: 1px;padding-left: 1px;padding-right: 1px;color: rgb(0, 0, 0);font-size: 8pt;font-family: &#34;PingFang SC Regular&#34;;border-width: 0.5pt;border-color: rgb(255, 255, 255);vertical-align: top;text-wrap: wrap;background: rgb(221, 235, 247);text-align: center;">WEB</td><td width="40" x:str="" style="padding-top: 1px;padding-left: 1px;padding-right: 1px;color: rgb(0, 0, 0);font-size: 8pt;font-family: &#34;PingFang SC Regular&#34;;border-top-width: 0.5pt;border-top-color: rgb(255, 255, 255);border-right: none;border-bottom-width: 0.5pt;border-bottom-color: rgb(255, 255, 255);border-left-width: 0.5pt;border-left-color: rgb(255, 255, 255);vertical-align: top;text-wrap: wrap;background: rgb(221, 235, 247);text-align: center;">新增</td></tr><tr height="13" style="height: 13.6pt;"><td height="13" width="20" x:str="" style="padding-top: 1px;padding-left: 1px;padding-right: 1px;color: rgb(0, 0, 0);font-size: 8pt;font-family: &#34;PingFang SC Regular&#34;;border-top-width: 0.5pt;border-top-color: rgb(255, 255, 255);border-right-width: 0.5pt;border-right-color: rgb(255, 255, 255);border-bottom-width: 0.5pt;border-bottom-color: rgb(255, 255, 255);border-left: none;vertical-align: top;text-wrap: wrap;background: rgb(221, 235, 247);text-align: center;">高危</td><td width="442" x:str="" style="padding-top: 1px;padding-left: 1px;padding-right: 1px;color: rgb(0, 0, 0);font-size: 8pt;font-family: &#34;PingFang SC Regular&#34;;border-width: 0.5pt;border-color: rgb(255, 255, 255);vertical-align: top;text-wrap: wrap;background: rgb(221, 235, 247);text-align: center;word-break: break-all;">广联达 Linkworks GetDeptByDeptCode <br/>SQL注入</td><td width="45" x:str="" style="padding-top: 1px;padding-left: 1px;padding-right: 1px;color: rgb(0, 0, 0);font-size: 8pt;font-family: &#34;PingFang SC Regular&#34;;border-width: 0.5pt;border-color: rgb(255, 255, 255);vertical-align: top;text-wrap: wrap;background: rgb(221, 235, 247);text-align: center;">WEB</td><td width="40" x:str="" style="padding-top: 1px;padding-left: 1px;padding-right: 1px;color: rgb(0, 0, 0);font-size: 8pt;font-family: &#34;PingFang SC Regular&#34;;border-top-width: 0.5pt;border-top-color: rgb(255, 255, 255);border-right: none;border-bottom-width: 0.5pt;border-bottom-color: rgb(255, 255, 255);border-left-width: 0.5pt;border-left-color: rgb(255, 255, 255);vertical-align: top;text-wrap: wrap;background: rgb(221, 235, 247);text-align: center;">新增</td></tr><tr height="13" style="height: 13.6pt;"><td height="13" width="20" x:str="" style="padding-top: 1px;padding-left: 1px;padding-right: 1px;color: rgb(0, 0, 0);font-size: 8pt;font-family: &#34;PingFang SC Regular&#34;;border-top-width: 0.5pt;border-top-color: rgb(255, 255, 255);border-right-width: 0.5pt;border-right-color: rgb(255, 255, 255);border-bottom: none;border-left: none;vertical-align: top;text-wrap: wrap;background: rgb(189, 215, 238);text-align: center;">高危</td><td width="442" x:str="" style="padding-top: 1px;padding-left: 1px;padding-right: 1px;color: rgb(0, 0, 0);font-size: 8pt;font-family: &#34;PingFang SC Regular&#34;;border-top-width: 0.5pt;border-top-color: rgb(255, 255, 255);border-right-width: 0.5pt;border-right-color: rgb(255, 255, 255);border-bottom: none;border-left-width: 0.5pt;border-left-color: rgb(255, 255, 255);vertical-align: top;text-wrap: wrap;background: rgb(189, 215, 238);text-align: center;word-break: break-all;">用友 U8 Cloud TaskTreeQuery <br/>SQL 注入</td><td width="45" x:str="" style="padding-top: 1px;padding-left: 1px;padding-right: 1px;color: rgb(0, 0, 0);font-size: 8pt;font-family: &#34;PingFang SC Regular&#34;;border-top-width: 0.5pt;border-top-color: rgb(255, 255, 255);border-right-width: 0.5pt;border-right-color: rgb(255, 255, 255);border-bottom: none;border-left-width: 0.5pt;border-left-color: rgb(255, 255, 255);vertical-align: top;text-wrap: wrap;background: rgb(189, 215, 238);text-align: center;">WEB</td><td width="40" x:str="" style="padding-top: 1px;padding-left: 1px;padding-right: 1px;color: rgb(0, 0, 0);font-size: 8pt;font-family: &#34;PingFang SC Regular&#34;;border-top-width: 0.5pt;border-top-color: rgb(255, 255, 255);border-right: none;border-bottom: none;border-left-width: 0.5pt;border-left-color: rgb(255, 255, 255);vertical-align: top;text-wrap: wrap;background: rgb(189, 215, 238);text-align: center;">新增</td></tr></tbody></table>  
  
**部分漏洞详情**  
  
  
**新增插件：**  
  
  
**1、海翔云平台 getylist_login.do SQL 注入**  
  
**发布时间：**2023-11-16**漏洞等级：**高危**漏洞来源：**创宇安全智脑**漏洞描述：**海翔云平台是海翔软件在当今新批发、新零售、O2O业态下倾力打造的一款以移动互联网为基础的多终端进销存管理系统。海翔云平台 getylist_login.do 接口存在SQL注入漏洞。未经授权的攻击者可以利用漏洞读取数据库数据，造成数据泄露。**漏洞危害：**未经授权的攻击者可以利用漏洞读取数据库数据，造成数据泄露。**建议解决方案：**官方暂未提供漏洞修复方案，请密切关注官方更新或临时使用创宇盾(https://defense.yunaq.com/)等WAF防护措施。**影响范围：**根据ZoomEye网络空间搜索引擎关键字 app:"海翔云平台" 对潜在可能目标进行搜索，共得到408条IP历史记录。主要分布在中国。（ZoomEye搜索链接：https://www.zoomeye.org/searchResult?q=app%3A%22%E6%B5%B7%E7%BF%94%E4%BA%91%E5%B9%B3%E5%8F%B0%22）  
  
![](https://mmbiz.qpic.cn/mmbiz_png/zCyMfA7bc0wICCeibMhfnIV9R86ia6aTy1vQvLjUFf7nI2Ribm4KOfSuIhKPezwrxBBzY6bfXIk5kF3DnticWj99fQ/640?wx_fmt=png&from=appmsg "")  
  
**区域分布：**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/zCyMfA7bc0wICCeibMhfnIV9R86ia6aTy1aFDWia9ypILKc9fAicxLVA7o5jDSyTEBPUDb3ldORMDMBzSet5icPwUjQ/640?wx_fmt=png&from=appmsg "")  
  
**2、浙大恩特客户资源管理系统 MailAction.entphone 任意文件上传****发布时间：**2023-11-21**漏洞等级：**高危**漏洞来源：**创宇安全智脑**漏洞描述：**浙大恩特客户资源管理系统是恩特软件开发的一款客户资源管理系统。浙大恩特客户资源管理系统 MailAction.entphone 接口存在任意文件上传漏洞。未经授权的远程攻击者可上传恶意文件至服务器，远程执行任意代码，获取系统权限。**漏洞危害：**未经授权的远程攻击者可上传恶意文件至服务器，远程执行任意代码，获取系统权限。**建议解决方案：**官方尚未发布漏洞修复程序，请密切关注官方更新：http://www.entersoft.cn；或使用创宇盾（https://defense.yunaq.com/）等WAF防护措施。**影响范围：**根据ZoomEye网络空间搜索引擎关键字 app:"浙大恩特客户资源管理系统" 对潜在可能目标进行搜索，共得到954条IP历史记录。主要分布在中国。（ZoomEye搜索链接：https://www.zoomeye.org/searchResult?q=app%3A%22%E6%B5%99%E5%A4%A7%E6%81%A9%E7%89%B9%E5%AE%A2%E6%88%B7%E8%B5%84%E6%BA%90%E7%AE%A1%E7%90%86%E7%B3%BB%E7%BB%9F%22）  
  
![](https://mmbiz.qpic.cn/mmbiz_png/zCyMfA7bc0wICCeibMhfnIV9R86ia6aTy1zxvEicgqJosPsVzgwzKFZGv04C2icTfQtEuicLGx928P7HGVvyHxtKMOQ/640?wx_fmt=png&from=appmsg "")  
  
**区域分布：**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/zCyMfA7bc0wICCeibMhfnIV9R86ia6aTy1s62Wcdib2wU7qkSeicibC18Mk5KF1kJG4DmeZcqPV5n3dXT26cTIibS6yw/640?wx_fmt=png&from=appmsg "")  
  
  
**3、捷诚管理信息系统**  
  
**CWSFinanceCommon.asmx SQL注入**  
  
**发布时间：**2023-11-22**漏洞等级：**高危**漏洞来源：**创宇安全智脑**漏洞描述：**捷诚管理信息系统是一款功能全面，可以支持自营、联营到外柜租赁的管理系统。捷诚管理信息系统 CWSFinanceCommon.asmx 接口存在SQL注入漏洞。未经授权的攻击者可以利用该漏洞获取数据库数据，甚至登录系统，控制服务器。**漏洞危害：**未经授权的攻击者可以利用该漏洞获取数据库数据，甚至登录系统，控制服务器。**建议解决方案：**目前官方暂未发布漏洞修复方案，请密切关注官方更新或使用创宇盾  
  
（https://defense.yunaq.com/）等WAF防护措施。**影响范围：**根据ZoomEye网络空间搜索引擎关键字 app:"捷诚管理信息系统" 对潜在可能目标进行搜索，共得到1127条IP历史记录。主要分布在中国。（ZoomEye搜索链接：https://www.zoomeye.org/searchResult?q=app%3A%22%E6%8D%B7%E8%AF%9A%E7%AE%A1%E7%90%86%E4%BF%A1%E6%81%AF%E7%B3%BB%E7%BB%9F%22）  
  
![](https://mmbiz.qpic.cn/mmbiz_png/zCyMfA7bc0wICCeibMhfnIV9R86ia6aTy1QXuB5EpAFVud7IBWl7JrnoNX2U2tRzvSoMzqaAsbf4ic0VjIXiaHztww/640?wx_fmt=png&from=appmsg "")  
  
**区域分布：**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/zCyMfA7bc0wICCeibMhfnIV9R86ia6aTy1Sek3fbo8hEiaecxclsGH32IiakMefHnnmv6aic2YGtpg2XgMljUibDODww/640?wx_fmt=png&from=appmsg "")  
  
  
**4、广联达 Linkworks GetDeptByDeptCode SQL注入**  
  
**发布时间：**2023-11-21**漏洞等级：**高危**漏洞来源：**创宇安全智脑**漏洞描述：**广联达 Linkworks是一种用于协同办公和项目管理的软件工具。广联达 Linkworks 存在SQL注入漏洞。恶意攻击者可以利用该漏洞执行恶意的注入语句，获取敏感数据或篡改数据库。**漏洞危害：**恶意攻击者可以利用该漏洞执行恶意的注入语句，获取敏感数据或篡改数据库。**建议解决方案：**及时更新至最新版本，使用参数化查询或预编译语句并对输入进行过滤和验证，以防止SQL注入攻击。**影响范围：**根据ZoomEye网络空间搜索引擎关键字 app:"广联达 Linkworks" 对潜在可能目标进行搜索，共得到6102条IP历史记录。主要分布在中国。（ZoomEye搜索链接：https://www.zoomeye.org/searchResult?q=app%3A%22%E5%B9%BF%E8%81%94%E8%BE%BE%20Linkworks%22）  
  
![](https://mmbiz.qpic.cn/mmbiz_png/zCyMfA7bc0wICCeibMhfnIV9R86ia6aTy13dNic1mSfLggjMIov6sw19VbxpJ9CwklfUmTiaibnPp6Fg5rGUFFMiaqicg/640?wx_fmt=png&from=appmsg "")  
  
**区域分布：**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/zCyMfA7bc0wICCeibMhfnIV9R86ia6aTy1Uef3GJSb18bHic4c5uHhGysRbqfwibJZ81dR6lu8lWoJg8kgxVvSoDOA/640?wx_fmt=png&from=appmsg "")  
  
  
**5、用友 U8 Cloud TaskTreeQuery SQL 注入**  
  
**发布时间：**2023-11-21**漏洞等级：**高危**漏洞来源：**创宇安全智脑**漏洞描述：**用友 U8 Cloud 是一种基于企业互联网理念设计的云 ERP 整体解决方案。用友 U8 Cloud 存在SQL注入漏洞。恶意攻击者可以利用该漏洞执行恶意的注入语句，获取敏感数据或篡改数据库。**漏洞危害：**恶意攻击者可以利用该漏洞执行恶意的注入语句，获取敏感数据或篡改数据库。**建议解决方案：**及时更新至最新版本，使用参数化查询或预编译语句并对输入进行过滤和验证，以防止SQL注入攻击。**影响范围：**根据ZoomEye网络空间搜索引擎关键字 app:"用友U8 Cloud" 对潜在可能目标进行搜索，共得到9529条IP历史记录。主要分布在中国。（ZoomEye搜索链接：https://www.zoomeye.org/searchResult?q=app%3A%22%E7%94%A8%E5%8F%8BU8%20Cloud%22）  
  
![](https://mmbiz.qpic.cn/mmbiz_png/zCyMfA7bc0wICCeibMhfnIV9R86ia6aTy1zicavflGocTGxYV7pIcw54kQReZTzNqsmUtD70Y3jlFk9RzBNrg0m7Q/640?wx_fmt=png&from=appmsg "")  
  
**区域分布：**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/zCyMfA7bc0wICCeibMhfnIV9R86ia6aTy1KAzEPoQcCkL7x3TcJMNYxpLq7FRFgPbGsxz0s3yO1Aj8WZcufABJyg/640?wx_fmt=png&from=appmsg "")  
  
  
ScanV  
  
  
  
为网站及业务系统提供全生命周期的外部攻击面管理（EASM）能力，从攻击者视角出发，开展漏洞监测、漏洞响应、漏洞预警等深度漏洞治理工作，实时更新漏洞情报数据，持续性跟踪风险、快速定位威胁。  
  
WebSOC  
  
  
  
是面向行业区域监管机构、集团信息中心量身定制的能大范围快速发现高危Web漏洞及安全事件的硬件监测系统，产品具备扫描快、结果准、取证全的核心特质，能帮助客户快速、全面发现其管辖区域内的安全事件，生成完整通报证据链，方便通报到相关单位以促使其快速整改，帮助监管机构有效履行监管职责。  
  
ZoomEye Pro  
  
  
  
是面向企事业单位研发的一款网络资产扫描与管理系统。采用对全球测绘10余年的ZoomEye同款主动探测引擎，结合被动探测引擎，以及与ZoomEye云地联动的方式，能够全面采集内外网资产并统一管理。基于SeeBug漏洞平台、创宇安全智脑的能力，能够快速更新高威胁漏洞插件并对全部资产进行漏洞影响面分析。具备资产发现能力快速精准、资产指纹信息丰富、资产分类清晰直观、漏洞响应能力强的特点。帮助客户从攻击者视角持续发现内外网资产以及高风险问题，有效降低安全风险。  
  
  
为帮助您快速感知威胁，激活防御体系，守护业务安全！  
  
  
我们建议您订阅**创宇安全智脑-威胁情报订阅服务**，获取更多威胁情报详情以及处置建议。  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/zCyMfA7bc0wICCeibMhfnIV9R86ia6aTy15RIXHnrXLomoWVMX4dTvnUqStziascRfXTtuibsm42lEKS1nW88kDhYQ/640?wx_fmt=png&from=appmsg "")  
  
**点击阅读原文****获取更多信息**  
  
