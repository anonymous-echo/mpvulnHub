#  【代码审计】某JAVA酒店管理系统多个漏洞（附源码）   
原创 WL  Rot5pider安全团队   2025-05-06 07:31  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/7QRTvkK2qC6nNyjd9QeAUdlJnqcbr4YsiaJBYGWoeEEFUicUo1STkXfMNjmDrdbO9Jf04Q6luKiaYAyjTWMQuofCg/640?wx_fmt=gif "")  
  
  
点击上方蓝字  关注安全知识  
  
  
欢迎加   
技术交流群  
 ，随意聊，禁  
发广告、政治 赌毒  
等，嘿嘿  
  
群已满200，请添加：  
The_movement 备注：  
进群  
  
# 酒店管理系统代码安全审计  
## 一、项目概况  
### 1.1 技术栈  
- 开发语言：Java  
  
- 框架：Spring Boot  
  
- 数据库：MySQL 5.7/8.0  
  
- 构建工具：Maven  
  
### 1.2 环境搭建  
```
# 基础环境准备java -version # 需要JDK1.8+mvn -v        # Maven环境检测mysql --version # 支持5.7或8.0版本# 项目部署流程1. 新建数据库并执行sql.sql脚本（注意设置utf8mb4字符集）2. IDEA导入项目后修改application.yml中的数据库配置3. 执行mvn clean package完成打包
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/OMTnCvx3T1KhUT6lLRms0eic8scTIibJoGmNGicbMticx7iaBAPZicAxibq2XcSibPVYyOciaOicnnibyvDraKRMmfwnnHuAg/640?wx_fmt=png&from=appmsg "")  
## 二、安全漏洞分析  
### 2.1 任意文件读取漏洞（高危）  
  
**影响范围**  
：controller/FileController  
**漏洞原理**  
：未对文件路径参数进行校验，导致目录穿越攻击 controller/FileController 控制器存在任意文件读取漏洞 代码位置：controller/FileController ，传参fileName，获取程序根目录（调试出来的路径），拼接/upload目录，在拼接传入的fileName文件名；先创建一个1.txt文件如下  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/OMTnCvx3T1KhUT6lLRms0eic8scTIibJoGgicIxNd6Cb90CA59ZCpb3Zy7NLCVichB1cOibwTHgDFibnYvJysibaA9Lsw/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/OMTnCvx3T1KhUT6lLRms0eic8scTIibJoGLso2nMvRZ9ubibDvswQjrXK3GWgWrqiaSdJtzxOoUHRu4t4vACG6JUuw/640?wx_fmt=png&from=appmsg "")  
  
**攻击向量**  
：  
```
GET /file?fileName=../../../../etc/passwd HTTP/1.1Host: target.com
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/OMTnCvx3T1KhUT6lLRms0eic8scTIibJoGF3CawiaBGnOa4zzQBtdbtNOerk5kI0jhgTRibjlvfvUtwnI9Qfu0DTEA/640?wx_fmt=png&from=appmsg "")  
  
**修复建议**  
：  
```
// 使用PathMatcher进行安全校验public ResponseEntity<?> readFile(@RequestParam String fileName) {    Path path = Paths.get("upload").resolve(fileName);    if (!Files.exists(path) || !path.startsWith(Paths.get("upload"))) {        return ResponseEntity.badRequest().build();    }    // 文件读取逻辑...}
```  
### 2.2 多处SQL注入漏洞（高危）  
  
**影响范围**  
：NewsController/YonghuController  
**漏洞成因**  
：原始代码直接拼接SQL查询条件  
```
// 原始危险代码示例String sql = "SELECT * FROM news WHERE title = '" + title + "'";
```  
  
controller/NewsController 控制器存在SQL注入漏洞 代码位置：controller/NewsController，对传入参数无任何限制，MPUtil.sort()和MPUtil.between()触发SQL注入  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/OMTnCvx3T1KhUT6lLRms0eic8scTIibJoGR2DcUD3W6RS85VJedqqZZMiaAVjkZDMBRVWWWkaC5YEseahOlMRWHcg/640?wx_fmt=png&from=appmsg "")  
查看MPUtil.sort()和MPUtil.between()函数，无任何过滤器进行限制![](https://mmbiz.qpic.cn/sz_mmbiz_png/OMTnCvx3T1KhUT6lLRms0eic8scTIibJoG0mDYHw41nZNcmoNUkZqrrAuziatrCBuW58bQjLSBuZiajU38Tgj7kRjA/640?wx_fmt=png&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/OMTnCvx3T1KhUT6lLRms0eic8scTIibJoGZbGuVoOoLaOLVkGfnCwDOYvkA4icUp1dQEas2vABDDPnx0fOSriaZ7AA/640?wx_fmt=png&from=appmsg "")  
  
**检测方法**  
：  
1. 使用SqlMap进行自动化检测  
  
1. 手工测试特殊字符（' OR 1=1--）  
  
3.构造poc![](https://mmbiz.qpic.cn/sz_mmbiz_png/OMTnCvx3T1KhUT6lLRms0eic8scTIibJoGYfxMRJA9jfagBECg4G6thibxiaqSp5Pyic6OVydmN0aKm3KrtJYjS0prg/640?wx_fmt=png&from=appmsg "")  
全局搜索“MPUtil.sort(”字符串![](https://mmbiz.qpic.cn/sz_mmbiz_png/OMTnCvx3T1KhUT6lLRms0eic8scTIibJoGnm5pjyaNDo2QaXfuf2Q00Xia6E5icfBic5zwy6iaOyoL4JonmQIvReGnbA/640?wx_fmt=png&from=appmsg "")  
经过测试，用到该方法的功能均存在SQL注入 代码位置： controller/YonghuController![](https://mmbiz.qpic.cn/sz_mmbiz_png/OMTnCvx3T1KhUT6lLRms0eic8scTIibJoGSNfXicWVkYJ9MRzla1bz1JCWuncZm4fBQPNBFCe1zP0Cg00oqK0wd1A/640?wx_fmt=png&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/OMTnCvx3T1KhUT6lLRms0eic8scTIibJoGYn8QVDKDE4lsRcjGu0ASAnKAgsE8Ocdg5QeYvXQJTO1p6UvibU7R0UA/640?wx_fmt=png&from=appmsg "")  
  
**安全编码规范**  
：  
```
// 使用JPA Criteria API构建安全查询CriteriaBuilder cb = entityManager.getCriteriaBuilder();CriteriaQuery<News> cq = cb.createQuery(News.class);Root<News> root = cq.from(News.class);cq.where(cb.equal(root.get("title"), title));List<News> results = entityManager.createQuery(cq).getResultList();
```  
### 2.3 文件上传漏洞（中危）鸡肋  
  
**漏洞原理**  
controller/FileController 控制器存在任意文件上传漏洞 代码位置：controller/FileController，对上传的文件名和文件内容无任何限制，但是该项目没有解析JSP的依赖，无法利用  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/OMTnCvx3T1KhUT6lLRms0eic8scTIibJoGUKGRpckzCkS7L8h8lal5YFDJoorq0HRckFqapkIe8HT4kBJczCMjfw/640?wx_fmt=png&from=appmsg "")  
POC  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/OMTnCvx3T1KhUT6lLRms0eic8scTIibJoGDWumfLoVog42mslMjl1LfsFfkoUA0cBmlL5nFZMVsV3Kj6pN6XyTgA/640?wx_fmt=png&from=appmsg "")  
题外话： Spring Boot 中解析 JSP 文件需要添加相应的依赖和配置，如下： 在 pom.xml 中，你需要添加以下依赖：  
```
    <!-- Spring Boot Starter Web -->    <dependency>        <groupId>org.springframework.boot</groupId>        <artifactId>spring-boot-starter-web</artifactId>    </dependency>    <!-- JSP解析支持 -->    <dependency>        <groupId>org.apache.tomcat.embed</groupId>        <artifactId>tomcat-embed-jasper</artifactId>    </dependency>    <!-- JSP编译器 -->    <dependency>        <groupId>org.apache.jasper</groupId>        <artifactId>jasper</artifactId>    </dependency></dependencies>
```  
  
**防护建议**  
：  
1. 严格限制上传文件类型（MIME类型+后缀名双重校验）  
  
1. 上传文件存储到独立目录  
  
1. 重命名上传文件防止路径遍历  
  
```
// 文件上传安全处理示例@PostMapping("/upload")public String handleFileUpload(@RequestParam("file") MultipartFile file) {    // 校验文件类型    if (!file.getContentType().startsWith("image/")) {        thrownew InvalidFileTypeException();    }    // 生成唯一文件名    String filename = UUID.randomUUID().toString() + getFileExtension(file.getOriginalFilename());    // 存储到安全目录    Path uploadDir = Paths.get("uploads");    Files.copy(file.getInputStream(), uploadDir.resolve(filename));    return"redirect:/";}
```  
## 三、安全加固方案  
### 3.1 输入验证机制  
  
<table><thead><tr><th style="color: rgb(0, 0, 0);font-size: 15px;line-height: 1.5em;letter-spacing: 0em;text-align: left;font-weight: bold;background: rgb(240, 240, 240) left top no-repeat;height: auto;border-style: solid;border-width: 1px;border-color: rgba(204, 204, 204, 0.4);border-radius: 0px;padding: 5px 10px;min-width: 85px;"><section><span leaf="">输入类型</span></section></th><th style="color: rgb(0, 0, 0);font-size: 15px;line-height: 1.5em;letter-spacing: 0em;text-align: left;font-weight: bold;background: rgb(240, 240, 240) left top no-repeat;height: auto;border-style: solid;border-width: 1px;border-color: rgba(204, 204, 204, 0.4);border-radius: 0px;padding: 5px 10px;min-width: 85px;"><section><span leaf="">验证规则</span></section></th><th style="color: rgb(0, 0, 0);font-size: 15px;line-height: 1.5em;letter-spacing: 0em;text-align: left;font-weight: bold;background: rgb(240, 240, 240) left top no-repeat;height: auto;border-style: solid;border-width: 1px;border-color: rgba(204, 204, 204, 0.4);border-radius: 0px;padding: 5px 10px;min-width: 85px;"><section><span leaf="">异常处理</span></section></th></tr></thead><tbody><tr style="color: rgb(0, 0, 0);background-attachment: scroll;background-clip: border-box;background-color: rgb(255, 255, 255);background-image: none;background-origin: padding-box;background-position-x: left;background-position-y: top;background-repeat: no-repeat;background-size: auto;width: auto;height: auto;"><td style="padding-top: 5px;padding-right: 10px;padding-bottom: 5px;padding-left: 10px;min-width: 85px;border-top-style: solid;border-bottom-style: solid;border-left-style: solid;border-right-style: solid;border-top-width: 1px;border-bottom-width: 1px;border-left-width: 1px;border-right-width: 1px;border-top-color: rgba(204, 204, 204, 0.4);border-bottom-color: rgba(204, 204, 204, 0.4);border-left-color: rgba(204, 204, 204, 0.4);border-right-color: rgba(204, 204, 204, 0.4);border-top-left-radius: 0px;border-top-right-radius: 0px;border-bottom-right-radius: 0px;border-bottom-left-radius: 0px;"><section><span leaf="">文件名</span></section></td><td style="padding-top: 5px;padding-right: 10px;padding-bottom: 5px;padding-left: 10px;min-width: 85px;border-top-style: solid;border-bottom-style: solid;border-left-style: solid;border-right-style: solid;border-top-width: 1px;border-bottom-width: 1px;border-left-width: 1px;border-right-width: 1px;border-top-color: rgba(204, 204, 204, 0.4);border-bottom-color: rgba(204, 204, 204, 0.4);border-left-color: rgba(204, 204, 204, 0.4);border-right-color: rgba(204, 204, 204, 0.4);border-top-left-radius: 0px;border-top-right-radius: 0px;border-bottom-right-radius: 0px;border-bottom-left-radius: 0px;"><section><span leaf="">白名单正则匹配 ^[a-zA-Z0-9_-.]+$</span></section></td><td style="padding-top: 5px;padding-right: 10px;padding-bottom: 5px;padding-left: 10px;min-width: 85px;border-top-style: solid;border-bottom-style: solid;border-left-style: solid;border-right-style: solid;border-top-width: 1px;border-bottom-width: 1px;border-left-width: 1px;border-right-width: 1px;border-top-color: rgba(204, 204, 204, 0.4);border-bottom-color: rgba(204, 204, 204, 0.4);border-left-color: rgba(204, 204, 204, 0.4);border-right-color: rgba(204, 204, 204, 0.4);border-top-left-radius: 0px;border-top-right-radius: 0px;border-bottom-right-radius: 0px;border-bottom-left-radius: 0px;"><section><span leaf="">返回400 Bad Request</span></section></td></tr><tr style="color: rgb(0, 0, 0);background-attachment: scroll;background-clip: border-box;background-color: rgb(248, 248, 248);background-image: none;background-origin: padding-box;background-position-x: left;background-position-y: top;background-repeat: no-repeat;background-size: auto;width: auto;height: auto;"><td style="padding-top: 5px;padding-right: 10px;padding-bottom: 5px;padding-left: 10px;min-width: 85px;border-top-style: solid;border-bottom-style: solid;border-left-style: solid;border-right-style: solid;border-top-width: 1px;border-bottom-width: 1px;border-left-width: 1px;border-right-width: 1px;border-top-color: rgba(204, 204, 204, 0.4);border-bottom-color: rgba(204, 204, 204, 0.4);border-left-color: rgba(204, 204, 204, 0.4);border-right-color: rgba(204, 204, 204, 0.4);border-top-left-radius: 0px;border-top-right-radius: 0px;border-bottom-right-radius: 0px;border-bottom-left-radius: 0px;"><section><span leaf="">查询参数</span></section></td><td style="padding-top: 5px;padding-right: 10px;padding-bottom: 5px;padding-left: 10px;min-width: 85px;border-top-style: solid;border-bottom-style: solid;border-left-style: solid;border-right-style: solid;border-top-width: 1px;border-bottom-width: 1px;border-left-width: 1px;border-right-width: 1px;border-top-color: rgba(204, 204, 204, 0.4);border-bottom-color: rgba(204, 204, 204, 0.4);border-left-color: rgba(204, 204, 204, 0.4);border-right-color: rgba(204, 204, 204, 0.4);border-top-left-radius: 0px;border-top-right-radius: 0px;border-bottom-right-radius: 0px;border-bottom-left-radius: 0px;"><section><span leaf="">参数长度限制（&lt;=50字符）</span></section></td><td style="padding-top: 5px;padding-right: 10px;padding-bottom: 5px;padding-left: 10px;min-width: 85px;border-top-style: solid;border-bottom-style: solid;border-left-style: solid;border-right-style: solid;border-top-width: 1px;border-bottom-width: 1px;border-left-width: 1px;border-right-width: 1px;border-top-color: rgba(204, 204, 204, 0.4);border-bottom-color: rgba(204, 204, 204, 0.4);border-left-color: rgba(204, 204, 204, 0.4);border-right-color: rgba(204, 204, 204, 0.4);border-top-left-radius: 0px;border-top-right-radius: 0px;border-bottom-right-radius: 0px;border-bottom-left-radius: 0px;"><section><span leaf="">记录安全日志</span></section></td></tr></tbody></table>  
### 3.2 安全配置基线  
```
# application-security.ymlspring:  servlet:    multipart:      max-file-size: 10MB      max-request-size: 10MB  datasource:    hikari:      connection-test-query: SELECT 1
```  
### 3.3 日志监控体系  
```
// 关键操作日志记录@Aspect@Componentpublicclass SecurityLoggingAspect {    privatefinal Logger logger = LoggerFactory.getLogger(getClass());    @Pointcut("execution(* com.example.controller.*.*(..))")    public void controllerMethods() {}    @AfterReturning(pointcut = "controllerMethods()", returning = "result")    public void logAfter(JoinPoint joinPoint, Object result) {        logger.info("Method {} executed with result {}",                     joinPoint.getSignature(), result);    }}
```  
## 四、代码下载地址  
  
公众号回复【**20250506**  
】  
  
  
  
【限时  
6  
折！华普安全研究星球：以  
原创实战  
为主+SRC/内网渗透核心资源库，助你在漏洞挖掘、SRC挖掘少走90%弯路】当90%的网络安全学习者还在重复刷题、泡论坛找零散资料时，华普安全研究星球已构建起完整的「攻防实战知识生态」：  
  
✅ 原创深度技术文档（独家SRC漏洞报告/代码审计报告）  
  
✅ 实战中使用到的工具分享  
  
✅ 全年更新SRC挖掘、代码审计报告（含最新0day验证思路）  
  
✅ 漏洞挖掘思维导图  
  
✅内部知识库（  
含审计出的0day、1day），进入圈子免费进入  
  
  
【  
实战为王  
】不同于传统课程的纸上谈兵！！  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/OMTnCvx3T1KhUT6lLRms0eic8scTIibJoGQBVaictTrzLs9G2yyia77mBTnW7m4Zx2OQfcbz5b5DbdrradsQNkpHNQ/640?wx_fmt=other&from=appmsg "")  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/OMTnCvx3T1KibZGSTtYYMVNzA35ZxXVRTxJibeicaQ0uttmutBuckibQFCEVicpyhhWXprQVOn4AnAnpDauQiaWTblMQ/640?wx_fmt=png&from=appmsg&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/OMTnCvx3T1KibZGSTtYYMVNzA35ZxXVRT9hvFFPpSupL0Q8d0Yv1F7dYxGZJjcKxHYTyiayhMI3xcVRoQhSs9VTQ/640?wx_fmt=png&from=appmsg&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/OMTnCvx3T1KibZGSTtYYMVNzA35ZxXVRTh0eO1DbG0onZph7o1AMPVU65ZjE5T9QH8XeMU0WNE5HiaUibNTBcQyyg/640?wx_fmt=png&from=appmsg&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/OMTnCvx3T1KibZGSTtYYMVNzA35ZxXVRTpXhxBicMHYsw8hotg4abR2gdaqYkfGPhX8EeNPcibAAs89qcOWl8Sqdw/640?wx_fmt=png&from=appmsg&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/OMTnCvx3T1KibZGSTtYYMVNzA35ZxXVRTJvsQnibaNk5WSuwpkDvkZTIFqN3XyKic4Mg5qI91sjNGQtibJRbEfIxgw/640?wx_fmt=png&from=appmsg&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_jpg/OMTnCvx3T1KibZGSTtYYMVNzA35ZxXVRT7UqeH8ibia1N77Q9iaLtwD9NU7Nt9gicr8sdmDGfQQvibnTDKQYNIJP6tFw/640?wx_fmt=jpeg&from=appmsg&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
  
  
  
**后期我们将持续发布原创代码审计、src等漏洞挖掘文章，后期有些源码、挖掘思路等也会放进圈子哈~**  
  
**有任何问题可后台留言**  
  
  
  
  
往期精选  
  
  
  
围观  
  
[PHP代码审计学习](http://mp.weixin.qq.com/s?__biz=Mzg5OTYxMjk0Mw==&mid=2247484594&idx=1&sn=89c96ed25e1f1d146fa3e67026ae0ca1&chksm=c051ecd2f72665c45d3e8c51b94629319b992f7f459d5677d7ce253eac99fc5e2e8f78684907&scene=21#wechat_redirect)  
  
  
丨更多  
  
热文  
  
[浅谈应急响应](http://mp.weixin.qq.com/s?__biz=Mzg5OTYxMjk0Mw==&mid=2247484589&idx=1&sn=80ff6dbb4471c101a71e203a10354d59&chksm=c051eccdf72665db0530fce6a332bf44392fb0c4d3d61496c9141bb93ece816cbbe97f89d06f&scene=21#wechat_redirect)  
  
  
丨更多  
  
·end·  
  
—如果喜欢，快分享给你的朋友们吧—  
  
我们一起愉快的玩耍吧  
  
  
  
【免责声明】  
  
"Rot5pider安全团队"作为专注于信息安全技术研究的自媒体平台，致力于传播网络安全领域的前沿知识与防御技术。本平台所载文章、工具及案例均用于合法合规的技术研讨与安全防护演练，严禁任何形式的非法入侵、数据窃取等危害网络安全的行为。所有技术文档仅代表作者研究过程中的技术观察，不构成实际操作建议，更不作为任何法律行为的背书。  
  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/OMTnCvx3T1K26bQox3P7WP9dbZ8fiaWVicDTm83Sic86kzBCzlXI5OiazEoc5ZrPHHWsRb80WlZcKRll5xOU2s5JKw/640?wx_fmt=gif&from=appmsg "")  
  
  
  
  
