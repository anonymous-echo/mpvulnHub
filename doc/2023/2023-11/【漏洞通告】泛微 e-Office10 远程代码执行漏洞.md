#  【漏洞通告】泛微 e-Office10 远程代码执行漏洞   
深瞳漏洞实验室  深信服千里目安全技术中心   2023-11-28 21:27  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/w8NHw6tcQ5wH8SbtvMwKwFrpXTvKN8l5PWx4psAjZ8hiaKztoWSbvBABGlRI1L5FiaHUear9DicoddWwzRmDeaQjw/640?wx_fmt=gif&from=appmsg "")  
  
**漏洞名称：**  
  
泛微 e-Office10 远程代码执行漏洞  
  
**组件名称：**  
  
泛微 e-Office  
  
**影响范围：**  
  
泛微 e-Office < 10.0_20231107  
  
**漏洞类型：**  
  
远程代码执行  
  
**利用条件：**  
  
1、用户认证：否  
  
2、前置条件：未知  
  
3、触发方式：远程  
  
**综合评价：**  
  
<综合评定利用难度>：未知  
  
<综合评定威胁等级>：高危，能造成远程代码执行及敏感信息泄露。  
  
**官方解决方案：**  
  
已发布  
  
  
  
  
  
**漏洞分析**  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/w8NHw6tcQ5wH8SbtvMwKwFrpXTvKN8l5UsbXqKZtsT5v901VqYdGe04tcBqjMoTYJqEKWVdGlqXoEPIvUslLBQ/640?wx_fmt=gif&from=appmsg "")  
  
**组件介绍**  
  
泛微e-Office是一款适合中小企业和机构的办公自动化平台，旨在帮助企业实现信息化办公、流程自动化和协同办公。该平台整合了办公自动化、协同办公、知识管理、移动办公等功能，为企业提供了全方位的办公解决方案。  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/w8NHw6tcQ5wH8SbtvMwKwFrpXTvKN8l5UsbXqKZtsT5v901VqYdGe04tcBqjMoTYJqEKWVdGlqXoEPIvUslLBQ/640?wx_fmt=gif&from=appmsg "")  
  
**漏洞简介**  
  
2023年11月28日，深瞳漏洞实验室监测到一则泛微e-Office组件存在SQL注入漏洞的信息，漏洞威胁等级：高危。  
  
该漏洞是由于泛微e-Office前台存在SQL注入漏洞，**攻击者可利用该漏洞在未授权的情况下，构造恶意数据执行SQL注入攻击，最终获取管理员权限并可进一步导致远程代码执行。**  
  
  
**影响范围**  
  
目前受影响的泛微 e-Office版本：  
  
泛微 e-Office < 10.0_20231107  
  
  
**解决方案**  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/w8NHw6tcQ5wH8SbtvMwKwFrpXTvKN8l5UsbXqKZtsT5v901VqYdGe04tcBqjMoTYJqEKWVdGlqXoEPIvUslLBQ/640?wx_fmt=gif&from=appmsg "")  
  
**官方修复建议**  
  
  
当前官方已发布受影响版本的对应补丁，建议受影响的用户及时更新官方的安全补丁。链接如下：  
  
https://www.weaver.com.cn/cs/securityDownload.asp#  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/w8NHw6tcQ5wH8SbtvMwKwFrpXTvKN8l5UsbXqKZtsT5v901VqYdGe04tcBqjMoTYJqEKWVdGlqXoEPIvUslLBQ/640?wx_fmt=gif&from=appmsg "")  
  
**深信服解决方案**  
  
  
**1.风险资产发现**  
  
支持对泛微 e-Office的主动检测，可**批量检出**业务场景中该事件的**受影响资产**情况，相关产品如下：  
  
**【深信服主机安全检测响应平台CWPP】**已发布资产检测方案。  
  
**【深信服云镜YJ】**已发布资产检测方案。  
  
  
**参考链接**  
  
  
https://www.weaver.com.cn/cs/securityDownload.asp#  
  
  
**时间轴**  
  
  
  
**2023/11/28**  
  
深瞳漏洞实验室监测到泛微 e-Office10 远程代码执行漏洞攻击信息。   
  
  
**2023/11/28**  
  
深瞳漏洞实验室发布漏洞通告。  
  
点击**阅读原文**，及时关注并登录深信服**智安全平台**，可轻松查询漏洞相关解决方案。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/w8NHw6tcQ5wH8SbtvMwKwFrpXTvKN8l5zGQKibzoyjGVeI0ia3dacMEjLocmS6suXagJiaWMibxO1KubvibPtI3bmXA/640?wx_fmt=jpeg&from=appmsg "")  
  
  
