#  【工具分享】I-Wanna-Get-All 主流OA漏洞利用工具   
Mstir  星悦安全   2024-12-02 08:58  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/lSQtsngIibibSOeF8DNKNAC3a6kgvhmWqvoQdibCCk028HCpd5q1pEeFjIhicyia0IcY7f2G9fpqaUm6ATDQuZZ05yw/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
点击上方  
蓝字  
关注我们 并设为  
星标  
## 0x01 工具简介  
  
**集成漏洞系统包括：用友、泛微、蓝凌、万户、致远、通达、帆软、金蝶、金和、红帆、宏景、浪潮、普元、亿赛通、海康威视、飞企互联、大华DSS、jeecg-boot**  
  
**集成memshell功能：用友NC、用友U8C、亿赛通、帆软channel、jeecgboot注入内存马。**  
  
**目前集成385漏洞，包括nday、1day（未公开poc）**  
  
**下载地址在文末!**  
  
****  
**java环境 java version "1.8.0_121" Java(TM) SE Runtime Environment (build 1.8.0_121-b13) Java HotSpot(TM) 64-Bit Server VM (build 25.121-b13, mixed mode)**  
  
**基于Apt-T00ls二次开发工具，I Wanna Get All 安全工具, 严禁一切未授权漏洞扫描攻击**  
  
**使用工具或文章转发用于其他途径，请备注作者及工具地址来源。**  
  
**使用工具前建议判断系统指纹框架，部分漏洞为接口探测存活判断是否成功，实际利用情况以执行情况为准**  
## 0x02 ATT模块介绍  
  
示例1：  
##### 用友NC 漏洞检测 (选择OA类型 -- 选择漏洞 -- 输入URL -- 检测)  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/uicic8KPZnD5cdE5S6hKNVc4w9usKtCM4J9sOdApQ6WO2x2gxnmhiax27Jicuxt3Hoofon6ibiaibP8VNcQOVTcgLVx2Q/640?wx_fmt=png&from=appmsg "")  
  
**用友NC 漏洞利用(选择OA类型 -- 选择漏洞 -- 输入URL -- 输入命令 -- 执行)**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/uicic8KPZnD5cdE5S6hKNVc4w9usKtCM4JhTZxhYjhEiaCH8EsLdrRThpIe0HAa0JlluBSBw4hNcib3b6hiaf14pGRQ/640?wx_fmt=png&from=appmsg "")  
  
**用友NC 文件上传(选择OA类型 -- 选择漏洞 -- 输入URL -- 上传文件 -- 执行)**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/uicic8KPZnD5cdE5S6hKNVc4w9usKtCM4JqYtn78o3n5bMgLblO327fd9T9hh2OfggW3SFxYS0FN1OvuajZWjZUQ/640?wx_fmt=png&from=appmsg "")  
## 0x03 MemShell模块介绍  
  
```
1. 支持冰蝎3.0、哥斯拉、蚁剑、suo5、cmdecho、neoReGeorg、自定义内存马2.  支持输出源码、Base64、hex、gzip格式payload3. 用友NC反序列化 集成接口反序列化（测试环境）4.  用友U8C反序列化 集接口反序列化（测试环境）5. 亿赛通XStream反序列化 集接口反序列化（测试环境）6.  用友NC内存马支持bypass脏数据传入，默认为100字节

```  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/uicic8KPZnD5cdE5S6hKNVc4w9usKtCM4JJhgsq8K1sGTXcNChvjMp4Kkgr9pS979q7ecxP0kUv4FwRL5iah9GSeg/640?wx_fmt=png&from=appmsg "")  
##### 示例2：  
##### (*ActionHandlerSevlet及其他接口均使用CC6NC链注入）  
  
**用友NC冰蝎内存马**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/uicic8KPZnD5cdE5S6hKNVc4w9usKtCM4JvvGNuKOYTNlk3guz5bfYiaaznl6WTDlwcbBsiaAibyCRqhdrnkkE4zgaA/640?wx_fmt=png&from=appmsg "")  
  
**用友NC 哥斯拉内存马注入**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/uicic8KPZnD5cdE5S6hKNVc4w9usKtCM4J2KViboEyOic5I1wdMicZP5ThuppnTLqB77zZ7UHHQZySh6Mm4zTcriaByw/640?wx_fmt=png&from=appmsg "")  
  
**用友NC cmdEcho内存马注入**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/uicic8KPZnD5cdE5S6hKNVc4w9usKtCM4JY8ibYSUwfdHsNxp4XJxVxIkK7d4ibwuVKVWR7k8dOyhY28BVQ8BicFbvA/640?wx_fmt=png&from=appmsg "")  
  
**用友NC 自定义内存马注入(使用蚁剑ClassByte字节码)，输入类名、Base64编码字节码、脏数据(可选)**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/uicic8KPZnD5cdE5S6hKNVc4w9usKtCM4Jv3pxLkwFaDOEC08qkn0I5TLib2TxlABr5byG99WTAbgJrH3Nw0I88ZQ/640?wx_fmt=png&from=appmsg "")  
  
**其余功能均可实现，不做展示。**  
##### 示例3：  
##### 用友U8Cloud 冰蝎内存马注入（其余内存马均可实现注入）  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/uicic8KPZnD5cdE5S6hKNVc4w9usKtCM4JFNrmsKD5DOxPcaKnO76Uibn75xbibgAOyxAYLyQQ9mUJP80usMUQ5OVA/640?wx_fmt=png&from=appmsg "")  
  
**用友U8Cloud cmdEcho内存马注入**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/uicic8KPZnD5cdE5S6hKNVc4w9usKtCM4JWn7em26mJLJP8nLLNMqSYiaGhUqogQy7Yvb8a6WGGVQh9a07xIgOBgQ/640?wx_fmt=png&from=appmsg "")  
##### 示例4：  
##### 冰蝎内存马payload 源码、base64 payload等生成展示(用友NC示例)  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/uicic8KPZnD5cdE5S6hKNVc4w9usKtCM4J07KvNzPYYLGtkeXTd5XGkBKohThpKtHhBbXlJrUEsw8cU1FaHibhUIA/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/uicic8KPZnD5cdE5S6hKNVc4w9usKtCM4JNfA8hlbMnYibV4kq80fxqkI0d78m9MBYxfIm3QUJNdQerEHSRYOBlYw/640?wx_fmt=png&from=appmsg "")  
## 0x04 Sqlmap模块介绍  
  
```
```  
  
**根据提示输入内容执行，集成调用sqlmap**  
##### 示例5：  
##### 泛微CheckServer-Sql注入，检测漏洞存在后，将payload字段下内容保存为req文件，使用sqlmap模块构造参数  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/uicic8KPZnD5cdE5S6hKNVc4w9usKtCM4JialInXdd2rnkL2o03YcGsPAiayKpg0aO6QnF5hzbicGfYiaF77y751fIdg/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/uicic8KPZnD5cdE5S6hKNVc4w9usKtCM4Ju305mY6GvCKWJQI4cUrSlYuzFNWDUrcbaTQfQUabVHeyowb1CKHUOw/640?wx_fmt=png&from=appmsg "")  
## 0x05 Crypt模块介绍  
  
```
1. 各类OA加解密2. 各类编码解码3. Class类反编译、class字节码生成(base64格式、gzip-base64格式)4. Class反编译仅文件读取 base64格式(yv66) gzip-base64格式(H4sI)可反编译
```  
  
##### 示例6  
##### 用友NC数据库密码 加解密  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/uicic8KPZnD5cdE5S6hKNVc4w9usKtCM4JKwLPxpbZqW4Vpf3V0CkajaDSXvDy5IGDZsUcq5cyUTl1MsPBw5b0XQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/uicic8KPZnD5cdE5S6hKNVc4w9usKtCM4J4aLQLAgEgQD71DxXAzwbSvt5XmaozDUial5ibWSsEaf8vbtrcWYGqz4g/640?wx_fmt=png&from=appmsg "")  
##### ‍‍示例7  
##### classbyte字节码解码（class文件导入加解码，base64字节码编码解码）  
  
**恶意类常用加解码方式: Base64-Gzip、Hex-Gzip等**  
‍  
‍  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/uicic8KPZnD5cdE5S6hKNVc4w9usKtCM4JhaaK6O6ds9ZQlRzs4z4eKG7Vbn9eWWUpB1JNo5ISshnBwGKQ0EQQaw/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/uicic8KPZnD5cdE5S6hKNVc4w9usKtCM4JS48Y3cB8VI7N5W1UqhoXBbJTUFsPzYWffF4QKzmbzejDPFx1NsrtSg/640?wx_fmt=png&from=appmsg "")  
## 0x06 TaskList模块介绍  
  
```
```  
  
**保留Apt-T00ls原有功能:杀软识别**  
##### 示例8  
#####   
## 0x07 Command Create模块介绍  
  
```
```  
  
**保留Apt-T00ls原有功能:常用命令创建**  
##### 示例9  
#####   
## 0x08 工具下载地址  
  
```
```  
  
```
https://github.com/R4gd0ll/I-Wanna-Get-All

```  
  
  
**关注公众号发送 241202 获取国内下载地址**  
  
  
  
下方二维  
码添加好友，回复关键词   
**星悦安全**  
进群  
  
![](https://mmbiz.qpic.cn/mmbiz_png/pPVXCo8Wd8CGA5xDtuNnCSVGd0ibW86zZaJ6tr5ib17xnMbupUibq24HQEl4gRoptsVgCBSNnwBEGmSn3a4ftXVzQ/640?wx_fmt=other&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/pPVXCo8Wd8AOzYX7kxefGbGGZg3g1ltkN30q9hceg23PiczgUqMT0EE9w0fLK9uw1eKWwQX9TljXQe1OQeHRZ2Q/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
####   
#### ‍  
  
**免责声明:****文章中涉及的程序(方法)可能带有攻击性，仅供安全研究与教学之用，读者将其信息做其他用途，由读者承担全部法律及连带责任，文章作者和本公众号不承担任何法律及连带责任，望周知！！!**  
  
