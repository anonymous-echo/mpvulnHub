#  java代码审计之常见漏洞学习   
原创 Z0安全  Z0安全   2025-05-12 06:24  
  
   
  
# 前言  
  
Java代码审计中常见的一些漏洞学习总结以及一些审计思路。  
# 1. SQL注入：数据库的隐形杀手  
### 成因  
  
未过滤的用户输入直接拼接至SQL语句，导致恶意SQL执行。  
### 高危场景  
- • MyBatis：使用${}  
动态拼接参数（如like '%${title}%'  
）  
  
- • Hibernate：createQuery  
拼接字符串  
  
- • 原生JDBC：字符串拼接SQL语句  
  
### 错误示例  
```
// MyBatis错误示例@Select("SELECT * FROM user WHERE username = '${username}'")User getUserByUsername(String username);// JDBC错误示例String sql = "SELECT * FROM product WHERE price > " + price;Statement stmt = conn.createStatement();ResultSet rs = stmt.executeQuery(sql);
```  
### 审计技巧  
- • 搜索输入拼接符号：全局搜索+  
、concat()  
、${}  
、append()  
  
- • 检查动态排序：MyBatis中是否存在order by ${time}  
  
- • 框架特性：Hibernate的createQuery  
是否使用参数绑定  
  
### 修复方案  
- • 强制使用预编译：MyBatis中优先使用#{}  
，JDBC中使用PreparedStatement  
  
- • 输入校验：对参数进行正则过滤（如仅允许数字）  
  
### 正确示例  
```
// MyBatis正确示例@Select("SELECT * FROM user WHERE username = #{username}")User getUserByUsername(String username);// JDBC正确示例String sql = "SELECT * FROM product WHERE price > ?";PreparedStatement stmt = conn.prepareStatement(sql);stmt.setDouble(1, price);
```  
## 2. XSS：前端漏洞，后端之责  
### 成因  
  
未对用户输入输出进行过滤，导致恶意脚本执行。  
### 高危代码示例  
```
@GetMapping("/search")public String search(@RequestParam String keyword, Model model) {    model.addAttribute("keyword", keyword); // 直接输出未过滤    return "result";}
```  
### 审计技巧  
- • 输入点追踪：搜索request.getParameter()  
、@RequestParam  
  
- • 输出点检查：检查JSP/Thymeleaf模板中是否直接输出变量（如${keyword}  
）  
  
- • 过滤机制：确认是否使用StringEscapeUtils.escapeHtml()  
或全局过滤器  
  
### 修复方案  
- • 全局XSS过滤器：配置web.xml  
过滤所有请求  
  
- • 输出编码：使用StringEscapeUtils.escapeHtml4()  
对输出内容转义  
  
### 过滤器配置示例  
```
<filter>    <filter-name>XSSFilter</filter-name>    <filter-class>com.example.XSSFilter</filter-class></filter><filter-mapping>    <filter-name>XSSFilter</filter-name>    <url-pattern>/*</url-pattern></filter-mapping>
```  
## 3. XXE：XML解析的致命陷阱  
### 成因  
  
允许解析外部实体，导致文件读取、SSRF等风险。  
### 高危接口示例  
```
// 使用DOM4J解析XML（未禁用DTD）SAXReader reader = new SAXReader();Document doc = reader.read(new File("user.xml"));
```  
### 审计技巧  
- • 搜索任务XML解析器：全局搜索DocumentBuilder  
、SAXReader  
  
- • 检查安全配置：确认是否禁用DTD和外部实体  
  
### 修复方案  
- • 禁用外部实体：通过设置FEATURE_SECURE_PROCESSING  
  
- • 使用安全库：如Jackson的XmlMapper  
默认禁用外部实体  
  
### 正确配置示例  
```
DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
```  
## 4. SSRF：内网渗透的跳板  
### 成因  
  
未校验请求URL，攻击者可访问内网资源。  
### 高危代码示例  
```
URL url = new URL(request.getParameter("url"));HttpURLConnection conn = (HttpURLConnection) url.openConnection();
```  
### 审计技巧  
- • 搜索文件网络请求方法：全局搜索URL.openConnection()  
、HttpClient.execute()  
  
- • 协议限制检查：确认是否禁止file://  
、ftp://  
等协议  
  
### 修复方案  
- • 域名/IP白名单：允许仅访问指定域名  
  
### 校验域名示例  
```
if (!url.getHost().endsWith(".example.com")) {    throw new SecurityException("非法域名");}
```  
## 5. 文件操作漏洞：权限失控之痛  
### 成因  
  
未校验文件路径，导致任意文件读写。  
### 高危场景示例  
```
File file = new File("/uploads/" + userInput);InputStream is = new FileInputStream(file);
```  
### 审计技巧  
- • 搜索图片文件IO类：全局搜索FileInputStream  
、FileOutputStream  
  
- • 路径拼接检查：确认是否使用getCanonicalPath()  
规范化路径  
  
### 修复方案  
- • 限制文件目录：仅允许访问固定根目录下的文件  
  
### 安全路径拼接示例  
```
File baseDir = new File("/safe/uploads/");File targetFile = new File(baseDir, userInput);if (!targetFile.getCanonicalPath().startsWith(baseDir.getCanonicalPath())) {    throw new SecurityException("非法路径");}
```  
## 6. 命令执行：系统级的高危操作  
### 成因  
  
用户输入直接拼接至系统命令。  
### 高危代码示例  
```
Process process = Runtime.getRuntime().exec("ping " + userInput);
```  
### 审计技巧  
- • 搜索和命令执行函数：全局搜索Runtime.exec()  
、ProcessBuilder.start()  
  
- • 特殊符号过滤：检查是否过滤&  
、;  
、|  
  
### 修复方案  
- • 参数白名单：仅允许特定参数格式  
  
### 正则过滤示例  
```
if (!Pattern.matches("^((25[0-5]|2[0-4]\\d|[01]?\\d\\d?)\\.){3}(25[0-5]|2[0-4]\\d|[01]?\\d\\d?)$", userInput)) {    throw new SecurityException("非法IP");}
```  
## 7. 反序列化：隐形代码执行  
### 成因  
  
反序列化不可信数据导致恶意代码执行。  
### 高危接口示例  
```
// Fastjson反序列化User user = JSON.parseObject(jsonStr, User.class);
```  
### 审计技巧  
- • 搜索功能反序列化方法：全局搜索ObjectInputStream.readObject()  
、JSON.parseObject()  
  
- • 依赖版本检查：确认Fastjson、XStream是否使用安全版本  
  
### 修复方案  
- • 升级依赖：Fastjson ≥1.2.83，XStream ≥1.4.19  
  
- • 启用安全模式：Fastjson使用Feature.SupportNonPublicField  
  
## 8. 中间件漏洞：被忽视的底层风险  
### 成因  
  
使用存在已知漏洞的中间件版本。  
### 常见漏洞  
- • Apache Shiro：反序列化漏洞（默认密钥）  
  
- • WebLogic：SSRF、反序列化漏洞（CVE-2020-2551）  
  
### 审计技巧  
- • 检查依赖版本：通过pom.xml  
确认中间件版本  
  
- • CVE匹配：比对已知漏洞库（如NVD）  
  
### 修复方案  
- • 更新中间件：Shiro ≥1.8.0，WebLogic ≥12.2.1.4  
  
- • 删除无用组件：移除未使用的Struts2、Log4j 1.x  
  
## 9. 业务逻辑漏洞：越权与越界  
### 成因  
  
未校验用户权限，导致越权访问。  
### 典型案例  
- • 垂直越权：普通用户访问管理员接口  
  
- • 水平越权：用户A查看用户B的数据  
  
### 审计技巧  
- • 参数校验：检查接口是否验证当前用户身份（如userId  
是否属于登录用户）  
  
### 错误示例  
```
@GetMapping("/user/{id}")public User getUser(@PathVariable Long id) {    return userService.findById(id); // 攻击者可传入他人ID}
```  
### 正确示例  
```
@GetMapping("/user/{id}")public User getUser(@PathVariable Long id, HttpSession session) {    Long currentUserId = (Long) session.getAttribute("userId");    if (!currentUserId.equals(id)) {        throw new AccessDeniedException();    }    return userService.findById(id);}
```  
### 修复方案  
- • 强制权限校验：在Service层校验用户身份  
  
- • 使用框架：Spring Security配置角色权限  
  
## 10. 不安全的反序列化：数据背后的毒蛇  
### 成因  
  
反序列化不可信数据导致远程代码执行。  
### 高危场景  
- • HTTP接口反序列化：接收外部JSON/XML数据并反序列化  
  
- • 日志存储反序列化：从文件或数据库加载序列化对象  
  
### 审计技巧  
- • 黑盒测试：发送恶意序列化数据（ysoserial工具）  
  
- • 代码检查：确认反序列化前是否校验数据来源  
  
### 修复方案  
- • 输入白名单：仅允许反序列化已知类  
  
- • 使用JSON：避免Java原生反序列化，改用Jackson/Gson  
  
## 11. 文件包含与路径遍历：目录下的幽灵  
### 成因  
  
未校验文件路径参数，导致包含或读取敏感文件。  
### 高危代码示例  
```
// 文件包含漏洞include(request.getParameter("page")); // 攻击者传入../../etc/passwd
```  
### 审计技巧  
- • 搜索文件包含函数：全局搜索RequestDispatcher.include()  
、include()  
  
- • 路径规范化检查：确认是否使用getCanonicalPath()  
  
### 修复方案  
- • 白名单控制：仅允许包含固定文件  
  
### 白名单校验示例  
```
List<String> allowedPages = Arrays.asList("home.jsp", "profile.jsp");if (!allowedPages.contains(pageParam)) {    throw new SecurityException("非法页面");}
```  
## 12. 防御之道：安全开发全流程  
### 代码层  
- • 使用ESAPI进行输入输出编码  
  
- • 集成静态代码分析工具（SonarQube、Checkstyle）  
  
### 测试层  
- • 使用SAST工具（Checkmarx）扫描代码漏洞  
  
- • 结合DAST工具（Burp Suite）进行渗透测试  
  
### 运维层  
- • 配置WAF规则拦截常见攻击（如SQL注入、XSS）  
  
- • 定期更新中间件和依赖库  
  
**结语**  
：安全是开发的生命线。通过系统化的代码审计、严格的权限校验、及时的依赖更新，开发者能够将风险降至最低。记住：漏洞不会消失，但可以通过严谨的态度将其扼杀在摇篮中！  
  
  
   
  
  
  
