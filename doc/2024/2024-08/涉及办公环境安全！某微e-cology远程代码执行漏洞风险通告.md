#  涉及办公环境安全！某微e-cology远程代码执行漏洞风险通告   
你信任的  亚信安全   2024-08-20 16:12  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/iczzp36h0nbG74aI4ueVB5OZO5bv9QdAxLic8LribhGibWxk3yn3WDrTfK3waJvxDlibw5wpnemb6EfYzFvH2nuH3lQ/640?wx_fmt=jpeg "")  
  
  
今日，亚信安全CERT监控到某微发布官方安全通告，披露了e-cology远程代码  
执行漏洞。该漏洞允许攻击者通过e-cology-10.0前台获取管理员访问令牌，然后利用JDBC反序列化，实现远程代码执行。  
  
  
**目前厂商官方已发布修复版本。亚信安全CERT建议客户升级安全补丁包至10.69及以上版本。**  
  
  
  
**漏洞编号、类型、等级**  
  
  
  
- 暂无  
  
- 远程代码执行漏洞  
  
- 高危  
  
  
  
  
**漏洞状态**  
  
  
  
<table><tbody style="box-sizing: border-box;"><tr opera-tn-ra-comp="_$.pages:0.layers:0.comps:10.classicTable1:0" style="box-sizing: border-box;"><td colspan="1" rowspan="1" opera-tn-ra-cell="_$.pages:0.layers:0.comps:10.classicTable1:0.td@@0" style="border-width: 1px;border-color: rgb(62, 62, 62);border-style: solid;background-color: rgb(145, 145, 145);box-sizing: border-box;padding: 0px;" width="20.0000%"><section style="margin: 5px 0%;box-sizing: border-box;"><section style="text-align: justify;padding: 0px 5px;font-size: 14px;color: rgb(255, 255, 255);box-sizing: border-box;"><p style="text-align: center;white-space: normal;margin: 0px;padding: 0px;box-sizing: border-box;"><strong style="box-sizing: border-box;">细节</strong></p></section></section></td><td colspan="1" rowspan="1" opera-tn-ra-cell="_$.pages:0.layers:0.comps:10.classicTable1:0.td@@1" style="border-width: 1px;border-color: rgb(62, 62, 62);border-style: solid;background-color: rgb(145, 145, 145);box-sizing: border-box;padding: 0px;" width="20.0000%"><section style="margin: 5px 0%;box-sizing: border-box;"><section style="padding: 0px 5px;font-size: 14px;color: rgb(255, 255, 255);box-sizing: border-box;"><p style="margin: 0px;padding: 0px;box-sizing: border-box;"><strong style="box-sizing: border-box;">PoC</strong></p></section></section></td><td colspan="1" rowspan="1" opera-tn-ra-cell="_$.pages:0.layers:0.comps:10.classicTable1:0.td@@2" style="border-width: 1px;border-color: rgb(62, 62, 62);border-style: solid;background-color: rgb(145, 145, 145);box-sizing: border-box;padding: 0px;" width="20.0000%"><section style="margin: 5px 0%;box-sizing: border-box;"><section style="padding: 0px 5px;font-size: 14px;color: rgb(255, 255, 255);box-sizing: border-box;"><p style="margin: 0px;padding: 0px;box-sizing: border-box;"><strong style="box-sizing: border-box;">EXP</strong></p></section></section></td><td colspan="1" rowspan="1" opera-tn-ra-cell="_$.pages:0.layers:0.comps:10.classicTable1:0.td@@3" style="border-width: 1px;border-color: rgb(62, 62, 62);border-style: solid;background-color: rgb(145, 145, 145);box-sizing: border-box;padding: 0px;" width="20.0000%"><section style="margin: 5px 0%;box-sizing: border-box;"><section style="padding: 0px 5px;font-size: 14px;color: rgb(255, 255, 255);box-sizing: border-box;"><p style="margin: 0px;padding: 0px;box-sizing: border-box;"><strong style="box-sizing: border-box;">在野利用</strong></p></section></section></td><td colspan="1" rowspan="1" opera-tn-ra-cell="_$.pages:0.layers:0.comps:10.classicTable1:0.td@@4" style="border-width: 1px;border-color: rgb(62, 62, 62);border-style: solid;background-color: rgb(145, 145, 145);box-sizing: border-box;padding: 0px;" width="20.0000%"><section style="margin: 5px 0%;box-sizing: border-box;"><section style="padding: 0px 5px;font-size: 14px;color: rgb(255, 255, 255);box-sizing: border-box;"><p style="margin: 0px;padding: 0px;box-sizing: border-box;"><strong style="box-sizing: border-box;">复现情况</strong></p></section></section></td></tr><tr opera-tn-ra-comp="_$.pages:0.layers:0.comps:10.classicTable1:1" style="box-sizing: border-box;"><td colspan="1" rowspan="1" opera-tn-ra-cell="_$.pages:0.layers:0.comps:10.classicTable1:1.td@@0" style="border-width: 1px;border-color: rgb(62, 62, 62);border-style: solid;box-sizing: border-box;padding: 0px;" width="20.0000%"><section style="margin: 5px 0%;box-sizing: border-box;"><section style="padding: 0px 5px;font-size: 14px;color: rgb(62, 62, 62);box-sizing: border-box;"><p style="margin: 0px;padding: 0px;box-sizing: border-box;">已公开</p></section></section></td><td colspan="1" rowspan="1" opera-tn-ra-cell="_$.pages:0.layers:0.comps:10.classicTable1:1.td@@1" style="border-width: 1px;border-color: rgb(62, 62, 62);border-style: solid;box-sizing: border-box;padding: 0px;" width="20.0000%"><section style="margin: 5px 0%;box-sizing: border-box;"><section style="padding: 0px 5px;font-size: 14px;color: rgb(62, 62, 62);box-sizing: border-box;"><p style="margin: 0px;padding: 0px;box-sizing: border-box;">已公开</p></section></section></td><td colspan="1" rowspan="1" opera-tn-ra-cell="_$.pages:0.layers:0.comps:10.classicTable1:1.td@@2" style="border-width: 1px;border-color: rgb(62, 62, 62);border-style: solid;box-sizing: border-box;padding: 0px;" width="20.0000%"><section style="margin: 5px 0%;box-sizing: border-box;"><section style="padding: 0px 5px;font-size: 14px;color: rgb(62, 62, 62);box-sizing: border-box;"><p style="margin: 0px;padding: 0px;box-sizing: border-box;">未公开</p></section></section></td><td colspan="1" rowspan="1" opera-tn-ra-cell="_$.pages:0.layers:0.comps:10.classicTable1:1.td@@3" style="border-width: 1px;border-color: rgb(62, 62, 62);border-style: solid;box-sizing: border-box;padding: 0px;" width="20.0000%"><section style="margin: 5px 0%;box-sizing: border-box;"><section style="padding: 0px 5px;font-size: 14px;color: rgb(62, 62, 62);box-sizing: border-box;"><p style="margin: 0px;padding: 0px;box-sizing: border-box;">未发现</p></section></section></td><td colspan="1" rowspan="1" opera-tn-ra-cell="_$.pages:0.layers:0.comps:10.classicTable1:1.td@@4" style="border-width: 1px;border-color: rgb(62, 62, 62);border-style: solid;box-sizing: border-box;padding: 0px;" width="20.0000%"><section style="margin: 5px 0%;box-sizing: border-box;"><section style="padding: 0px 5px;font-size: 14px;color: rgb(62, 62, 62);box-sizing: border-box;"><p style="margin: 0px;padding: 0px;box-sizing: border-box;">已复现</p></section></section></td></tr></tbody></table>  
  
  
**受影响版本**  
  
  
  
- e-cology-10.0（暂时仅发现该版本)  
  
  
  
  
**产品解决方案**  
  
  
  
目前亚信安全怒狮引擎已新增检测规则，请及时更新TDA、AE产品的特征库到最新版本，更新方式如下：  
  
  
TDA产品在线更新方法：登录系统->系统管理->系统升级->特征码更新；  
  
AE产品在线更新方法：登录系统->管理->更新->特征码->特征码SU。  
  
  
TDA、AE产品离线升级PTN包下载链接如下：  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/iczzp36h0nbG74aI4ueVB5OZO5bv9QdAxYaCW9ZGYBbe1fruiarGENWLspHQfx0rUlGiayRDcfuEfCrfWuibr1pbpA/640?wx_fmt=png "")  
  
（详细下载地址请后台私信获取）  
  
  
**检测方法**  
  
  
  
用sysadmin登录，访问http://oa地址/security/checksec20240815.jsp，可查看检测结果。如果是404或检测结果有【未通过】项，则需要手动升级安全补丁。  
  
  
**修复建议**  
  
  
  
目前，建议受影响的产品尽快升级安全补丁包至10.69及以上版本。  
  
  
**临时措施：**  
  
  
1、建议对sysadmin账号启用IP白名单策略，保障高权限账号泄露带来的安全隐患（攻防演练期间，建议启用）  
  
2、修改/ecology/WEB-INF/securityXML/weaver_security_custom_rules_1.xml，在下方添加如下代码（如果要放行某个网段，则填写IP的前半段即可，如192.168.7. ，则代表192.168.7.*都可以访问)。  
  
  
  
**参考链接**  
  
  
  
- https://www.weaver.com.cn/cs/security/edm20240815_kdielfrovkewpiiuyrtewtw.html  
  
  
  
  
本文发布的补丁下载链接均源自各原厂官方网站。尽管我们努力确保官方资源的安全性，但在互联网环境中，文件下载仍存在潜在风险。为保障您的设备安全与数据隐私，敬请您在点击下载前谨慎核实其安全性和可信度。  
  
  
  
  
了解亚信安全，请点击  
**“阅读原文”**  
  
