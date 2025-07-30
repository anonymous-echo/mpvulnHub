#  OA漏洞利用工具   
R4gd0ll  WIN哥学安全   2024-03-07 21:27  
  
## 免责声明：  
  
由于传播、利用本公众号所提供的信息而造成的任何直接或者间接的后果及损失，均由使用者本人负责，公众号及作者不为此承担任何责任，一旦造成后果请自行承担！如有侵权烦请告知，我们会立即删除并致歉。谢谢！  
## 介绍  
  
基于Apt-T00ls二次开发工具，I Wanna Get All 安全工具, 严禁一切未授权漏洞扫描攻击  
  
使用工具或文章转发用于其他途径，请备注作者及工具地址来源。  
  
使用工具前建议判断系统指纹框架，部分漏洞为接口探测存活判断是否成功，实际利用情况以执行情况为准。介绍
基于Apt-T00ls二次开发工具，I Wanna Get All 安全工具, 严禁一切未授权漏洞扫描攻击
使用工具或文章转发用于其他途径，请备注作者及工具地址来源。
使用工具前建议判断系统指纹框架，部分漏洞为接口探测存活判断是否成功，实际利用情况以执行情况为准。  
### ATT模块  
```
    1. 用友serial漏洞大部分为接口探测，请ATT根据实际情况进行判断
    2. 部分漏洞为确保准确性，请先进行检测，再进行点击执行利用
    3. 使用ALL进行漏洞探测时，由于多线程等其他原因会产生误报
    4. 文件上传漏洞，上传文件后执行进行上传，并使CMD栏为空，请先检测尝试上传后再利用
    5. 命令执行漏洞利用CMD写入命令后进行执行。
    6. 清屏按钮可清除除URL地址外所有信息
    7. 根据执行结果提示并选择其他模块利用
    8. POC模块目前集成poc情况共近230余个，包含至今HVV、goby纰漏漏洞(因poc集中管理可能出现误报，请配置代理抓包判断)，如下:
       (1).用友NC&反序列化接口----------------------------------fofa:title="YONYOU NC"
       (2).用友GRP--------------------------------------------fofa:app="yonyou-GRP-U8"
       (3).用友NCCloud----------------------------------------fofa:body="nccloud"
       (4).用友tplus------------------------------------------fofa:app="畅捷通-TPlus"
       (5).用友U8C--------------------------------------------fofa:app="用友-U8-Cloud"
       (6).用友ufida------------------------------------------fofa:body="ufida.ico"
       (7).泛微Ecology----------------------------------------fofa:app="泛微-协同办公OA"
       (8).泛微Emobile----------------------------------------fofa:title="移动管理平台-企业管理"
       (9).泛微Eoffice----------------------------------------fofa:app="泛微-EOffice"
       (10).蓝凌OA--------------------------------------------fofa:app="Landray-OA系统"
       (11).蓝凌EIS-------------------------------------------fofa:app="Landray-EIS智慧协同平台"
       (12).万户OA--------------------------------------------fofa:body="/defaultroot/"
       (13).致远A6A8------------------------------------------fofa:app="致远互联-OA"
       (14).致远MServer---------------------------------------fofa:body="/mobile_portal/"
       (15).致远yyoa------------------------------------------fofa:body="yyoa" && app="致远互联-OA"
       (16).通达OA--------------------------------------------fofa:app="TDXK-通达OA"
       (17).帆软组件-------------------------------------------fofa:"Powered by 帆软"
       (18).金蝶Apusic----------------------------------------fofa:header="Apusic"
       (19).金蝶EAS-------------------------------------------fofa:app="Kingdee-EAS"
       (20).金蝶云OA------------------------------------------fofa:app="金蝶云星空-管理中心"
       (21).金和OA--------------------------------------------fofa:app="金和网络-金和OA"
       (22).红帆OA--------------------------------------------fofa:app="红帆-ioffice"
       (23).宏景HCM--------------------------------------------fofa:app="HJSOFT-HCM"
       (24).亿赛通---------------------------------------------fofa:app="亿赛通-电子文档安全管理系统"
       (23).飞企互联-------------------------------------------fofa:app="FE-协作平台"

```  
  
示例1：
用友NC漏洞检测 (选择OA类型 -- 选择漏洞 -- 输入URL -- 检测)  
  
![](https://mmbiz.qpic.cn/mmbiz_png/1mtwZURvGTkK6o0W36joHWu1LYG8RXIVGwC3XSj7nxUpAxTvIKZibTcYN7fZlOfOwPfGHZeTt6f1maEvFKT98Cg/640?wx_fmt=png&from=appmsg "")  
  
用友NC漏洞利用(选择OA类型 -- 选择漏洞 -- 输入URL -- 输入命令 -- 执行)  
  
![](https://mmbiz.qpic.cn/mmbiz_png/1mtwZURvGTkK6o0W36joHWu1LYG8RXIVjTyYDb66eNwzia4ibcibGPaNRaiahEDIxXtGN3Y93nL7INrJyOwWMiaa8jg/640?wx_fmt=png&from=appmsg "")  
  
用友NC文件上传(选择OA类型 -- 选择漏洞 -- 输入URL -- 上传文件 -- 执行)  
  
![](https://mmbiz.qpic.cn/mmbiz_png/1mtwZURvGTkK6o0W36joHWu1LYG8RXIVa0ichylud7xSJVbYyXBTAtcOhcsTFXdfznmEHupdEbY22ibtLWLwZUsg/640?wx_fmt=png&from=appmsg "")  
### MemShell模块  
```
    1. 支持冰蝎3.0、哥斯拉、蚁剑、suo5、cmdecho、neoReGeorg、自定义内存马
    2.  支持输出源码、Base64、hex、gzip格式payload
    3. 用友NC反序列化 集成接口反序列化（测试环境）
    4.  用友U8C反序列化 集接口反序列化（测试环境）
    5. 亿赛通XStream反序列化 集接口反序列化（测试环境）
    6.  用友NC内存马支持bypass脏数据传入，默认为100字节

```  
  
示例2：
(*ActionHandlerSevlet及其他接口均使用CC6NC链注入）  
  
用友NC冰蝎内存马  
  
![](https://mmbiz.qpic.cn/mmbiz_png/1mtwZURvGTkK6o0W36joHWu1LYG8RXIVIkRVUerYW4vsuIWmYEXLL2ensk08PaW7XcRV0PqtKku163m41ibt95Q/640?wx_fmt=png&from=appmsg "")  
  
用友NC哥斯拉内存马注入  
  
![](https://mmbiz.qpic.cn/mmbiz_png/1mtwZURvGTkK6o0W36joHWu1LYG8RXIV6kpGG2HqASnpbFZtSabcrwXiaR8Tic17DNQkiajtTAsEq3ZMqVhCibjicYQ/640?wx_fmt=png&from=appmsg "")  
  
用友NC cmdEcho内存马注入  
  
![](https://mmbiz.qpic.cn/mmbiz_png/1mtwZURvGTkK6o0W36joHWu1LYG8RXIVSxk9LUkia6EIgTotKRAn7U7qh2XY01YegZozykTWg7Mv9gzyibHySr9g/640?wx_fmt=png&from=appmsg "")  
  
用友NC自定义内存马注入(使用蚁剑ClassByte字节码)，输入类名、Base64编码字节码、脏数据(可选)  
  
![](https://mmbiz.qpic.cn/mmbiz_png/1mtwZURvGTkK6o0W36joHWu1LYG8RXIVSxk9LUkia6EIgTotKRAn7U7qh2XY01YegZozykTWg7Mv9gzyibHySr9g/640?wx_fmt=png&from=appmsg "")  
  
其余功能均可实现，不做展示。  
### Sqlmap模块  
  
根据提示输入内容执行，集成调用sqlmap  
  
![](https://mmbiz.qpic.cn/mmbiz_png/1mtwZURvGTkK6o0W36joHWu1LYG8RXIVLotCg3HGDmnOtLL0brZVGxWvP1416v88Aibn0PkIlJDcCVBLYQUwhyg/640?wx_fmt=png&from=appmsg "")  
  
示例5：
泛微CheckServer-Sql注入，检测漏洞存在后，将payload字段下内容保存为req文件，使用sqlmap模块构造参数  
  
![](https://mmbiz.qpic.cn/mmbiz_png/1mtwZURvGTkK6o0W36joHWu1LYG8RXIVZ1xDtWia9Bia1DNZHxLMoqbTkicDkaoePia3CVYwtERp420PaicaSc8RcHQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/1mtwZURvGTkK6o0W36joHWu1LYG8RXIVyzT0k5CYyrRz9W0Vibqicnztlia0cX7QOaH7eCkibJqb8lwOUNjjrbebwg/640?wx_fmt=png&from=appmsg "")  
### Crypt模块  
```
    1. 各类OA加解密
    2.  各类编码解码
    3. Class类反编译、class字节码生成(base64格式、gzip-base64格式)
    4.  class反编译仅文件读取、base64格式(yv66)、gzip-base64格式(H4sI)可反编译

```  
  
示例6
用友NC数据库密码 加解密  
  
![](https://mmbiz.qpic.cn/mmbiz_png/1mtwZURvGTkK6o0W36joHWu1LYG8RXIV2s7wuSn14o8qPic1N4R1ibluRKgDeTneyCAT5RicXtSy7y0bb7TqH2T3g/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/1mtwZURvGTkK6o0W36joHWu1LYG8RXIVCS6RrY7GST9UNZ1Ohg0icb45gQo6wJBYNvTtHUjkeITQLjCib9RQYeSw/640?wx_fmt=png&from=appmsg "")  
### 下载地址  
  
https://github.com/R4gd0ll/I-Wanna-Get-All   
  
Tips:  
  
  
HVV招聘：  
投递到-->https://send2me.cn/BD1nNMFo/RA24cM-ZmOVxkw  
  
**考证咨询：**  
全网最低最优惠报考NISP/CISP/CISSP/PTE/PTS/IRE/IRS  
等证书，后台回复“好友”加V私聊。  
  
[【2024HW】国H招聘早班车启动](https://mp.weixin.qq.com/s?__biz=MzkwODM3NjIxOQ==&mid=2247498213&idx=1&sn=7812c982a6e05f29ed94c19e7b3cbefe&chksm=c0c85811f7bfd107217033770676284a6c5a89adccfe5f61f9c925c2b57b94a86fc01d7514e5&scene=21#wechat_redirect)  
  
  
[攻防演练之防守溯源思路](https://mp.weixin.qq.com/s?__biz=MzkwODM3NjIxOQ==&mid=2247498543&idx=1&sn=50d27ce8e941c860d4043b9f610c1486&chksm=c0c85adbf7bfd3cd1ed40f6872d5e62fdb4132a7dee331d14c0eab1dd7e63da70e32579167bc&scene=21#wechat_redirect)  
  
  
[【漏洞速递】宝塔最新未授权访问漏洞及sql注入](https://mp.weixin.qq.com/s?__biz=MzkwODM3NjIxOQ==&mid=2247497949&idx=1&sn=dd9856b9e5125f92ec9a3281b0f5fcc5&chksm=c0c85929f7bfd03fda87e1a4c288c5cf4270f81af9300e8cd06304d9e60c54133466723c89f7&scene=21#wechat_redirect)  
  
  
[【长篇巨制】6W多字的Windows 应急响应手册发布](https://mp.weixin.qq.com/s?__biz=MzkwODM3NjIxOQ==&mid=2247497751&idx=1&sn=e9ec8352fdda412869b365490044b7c2&chksm=c0c859e3f7bfd0f5af33ea70554e3f97684978b80bf2f06b1cc430ca2f1d36327811a392161a&scene=21#wechat_redirect)  
  
  
[【附靶场】某省信息安全管理与评估第二阶段应急响应](https://mp.weixin.qq.com/s?__biz=MzkwODM3NjIxOQ==&mid=2247496644&idx=1&sn=bdcd7dbdedbb2a491d0168147e2d9d23&chksm=c0c85230f7bfdb26c7d411f864d7a403b8cefb919f51434aff72aa71b915f2975a949f8b7b90&scene=21#wechat_redirect)  
  
  
  
  
