#  MOVEit漏洞导致美国900所院校学生信息发生大规模泄露   
 网络安全应急技术国家工程中心   2023-09-27 15:49  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/GoUrACT176m1HFGWIHj2PsyHMFaUM6UeKYf9CRbtN9iaS7xVjSArxAs14VCAyT71j2BQ0nGaopqqjGGnxiaunT4A/640?wx_fmt=jpeg "")  
  
美国非营利教育组织NSC（国家学生信息交换所）近日披露，其MOVEit服务器遭到入侵并导致近900所高等院校的学生个人信息被盗。  
  
NSC为大约3600所北美学院和大学以及2.2万所高中提供教育报告、数据交换、验证和研究服务。  
  
美国国家安全委员会已代表受影响的学校向加州总检察长办公室提交了一份数据泄露通知信，披露攻击者于5月30日获得了对NSC的MOVEit托管文件传输(MFT)服务器的访问权限，并窃取了包含大量个人信息的文件。  
  
根据通知信内容，被盗文件中包含的学生个人身份信息(PII)包括姓名、出生日期、联系信息、社会安全号码、学生ID号码以及一些与学校相关的记录（例如入学记录、学位记录和课程级别数据）。  
  
美国国家安全委员会还公布了受此数据泄露事件影响的教育组织名单。  
  
（https://oag.ca.gov/system/files/Exhibit%20A_6.pdf）  
  
**MOVEit漏洞“交叉泄露”**  
  
2023年5月下旬，Cl0p勒索软件组织利用流行的MOVEit文件传输解决方案中的SQL注入漏洞(CVE-2023-34362)窃取了大量组织的敏感数据，受害者包括大量知名企业、政府（例如多个美国联邦机构和美国能源部）、金融机构、养老金系统以及其他公共和私人实体。  
  
Emsisoft的安全专家Zach Simas透露：“许多MOVEit事件的上游/下游极其复杂，一些组织受到影响，因为他们的供应商的承包商使用了MOVEit，而承包商的分包商也使用了MOVEit。此外，一些组织的数据泄露涉及多个使用MOVEit的供应商。”  
  
“在教育领域尤其如此，一些机构受到涉及国家学生信息交换所、美国教师保险和年金协会-大学退休股票基金的事件的影响（该基金受到供应商PBI事件的影响）以及第三方健康保险提供商和其他金融服务提供商。”  
  
2023年6月下旬，NSC曾向受影响学校通报了MOVEit数据泄露事件，但由于调查仍在进行中，因此没有提供太多细节。  
  
据Databreaches.net的Doe透露，NSC的名字已从Cl0p的泄露网站中删除，这通常表明受害者已支付赎金。  
  
**参考链接：**  
  
https://oag.ca.gov/system/files/Exhibit%20B%20-%20Sample%20Individual%20Notification%20Letter.pdf  
  
  
  
原文来源：GoUpSec  
  
“投稿联系方式：孙中豪 010-82992251   sunzhonghao@cert.org.cn”  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/GoUrACT176n1NvL0JsVSB8lNDX2FCGZjW0HGfDVnFao65ic4fx6Rv4qylYEAbia4AU3V2Zz801UlicBcLeZ6gS6tg/640?wx_fmt=jpeg&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
