#  JAVA 代码审计第一课：环境搭建与SQL 注入漏洞   
 sec0nd安全   2025-03-11 23:07  
  
很久没有审计了，所以想出一期审计内容，整体内容偏简单，我默认你们会基本的 java 语言，所以就不带你们学习相关的语言基础，废话少说，直接开篇  
  
审计环境  
  
jdk 下载  
  
https://www.oracle.com/technetwork/java/javase/downloads/jdk8-downloads-2133151.html  
  
整体审计文章，都是以 jdk8 为主，当然看文章的基本上都是安全行业，jdk 相信大家都装了，这里就不过多描述。  
  
  
IDEA 下载  
  
http://www.jetbrains.com/idea/  
  
审计的话 还是推荐使用 idea，个人用习惯了，也好用。  
  
现在不知道有没有个人版了，这个我就不过多说了，懂得都懂。  
  
  
Maven下载  
  
https://archive.apache.org/dist/maven/maven-3/3.6.1/  
  
这个必备的，但是安装也是要选版本的，我个人用的是3.6.1，也推荐你们用同版本。因为像之前华夏 erp 审计，有好几个群友下的是新版本的， 导致无法运行。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BAby4Fk1HQbcPTboMkrOyto8IuPrA5MUBXGZ7O8f2uFMseziaLMFiaicYd6HARZEgesUIm5U3GwWIicNbXPOXkYtqA/640?wx_fmt=png "")  
  
                   
      
  
然后就是需要配置环境变量  
```
windows 到你的计算机环境里，添加这一行                  
D:\apache-maven\bin\              
                      
mac 则是在家目录下 .bashrc                  
export PATH=$PATH:/Users/tools/apache-maven-3.6.1/bin
```  
  
  
配之后就 mvn -version  
  
  
phpstudy 安装  
  
xp.cn  
  
这个则包含了继承环境，就不用单独下载 mysql，比较省事。  
  
到这里基本的环境就差不多了。下面就开始第一课的内容。  
  
  
  
SQL 注入  
  
像之前测试网站，我们是通过黑盒的方式，进行测试。  
  
审计代码，则为白盒，我们需要知道有哪些框架，参数是如何拼接的，以及怎么去快速寻找等等。  
  
JDBC  
  
传统的参数拼接  
```
Statement stmt = conn.createStatement();
String sql = "SELECT * FROM users WHERE username = '" + username + "'";
ResultSet rs = stmt.executeQuery(sql);
```  
  
  
如果修复需要使用安全的函数进行，变量用 ？代替，增加PreparedStatement 函数 注：  
order by这种排序的用不了预编译  
```
String sql = "SELECT * FROM users WHERE username = ?";
PreparedStatement pstmt = conn.prepareStatement(sql);
pstmt.setString(1, username);
ResultSet rs = pstmt.executeQuery();
```  
  
  
  
MyBatis  
  
这种用的比较多，我们可以专注 xml 文件里的  
${  
```
<select id="selectUser" resultType="User">
    SELECT * FROM users
    <where>
        <if test="username != null and username != ''">
            username = #{username}  <!-- 安全 -->
            <!-- username = '${username}'  不安全，可能导致 SQL 注入 -->
      
        </if>
    </where>
</select>            
```  
  
  
  
Hibernate  
  
类似jdbc直接查询  
```
String hql = "FROM User WHERE username = '" + username + "'";
Query query = session.createQuery(hql);
List<User> users = query.list();
```  
  
  
修复则通过   
setParameter  
 方法设置参数  
```
String hql = "FROM User WHERE username = :username";
Query query = session.createQuery(hql);
query.setParameter("username", username);
List<User> users = query.list();
```  
  
  
  
  
SQL注入审计  
  
自己简单写了一个登录口的注入，可以从数据层的思路逐步到web层。架构则为mvc。  
  
什么是 mvc，我这里简单说明一下  
  
MVC即模型（Model）、视图（View）、控制器（Controller）。  
  
模型（Model）  
  
模型是用于处理数据逻辑的部分。  
  
所谓数据逻辑，也就是数据的映射以及对数据的增删改查，Bean、DAO（dataaccess object，数据访问对象）等都属于模型部分。  
  
视图（View）  
  
视图负责数据与其它信息的显示，也就是给用户看到的页面。  
  
HTML、JSP等页面都可以作为视图。  
  
控制器（controller）  
  
控制器是模型与视图之间的桥梁，控制着数据与用户的交互。  
  
控制器通常负责从视图读取数据，处理用户输入，并向模型发送数据，也可以从模型中读取数据，再发送给视图，由视图显示。  
  
                 
      
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BAby4Fk1HQbcPTboMkrOyto8IuPrA5MUClop74bd0libo4w9XctDGtKeuNEUH5iaYaVibqTn6uKicw8KW80pucjKCg/640?wx_fmt=png "")  
  
                 
  
因为懒，所以就没有写对应的目录，都放在同一个了。  
  
可以看到有一个 xml 文件，说明系统中存在 mybatis 框架  
  
我们打开看一下内容，发现均适用$进行查询，说明这两个参数是存在注入的。  
      
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BAby4Fk1HQbcPTboMkrOyto8IuPrA5MU1oLpJrPtM5DucbgYbEdYPjOGyiaz8tXFDP4lpHnB9r4ggEwmBYWE2sw/640?wx_fmt=png "")  
  
                 
  
那么怎么寻找上层代码  
  
我们可以单击 （ctrl + 鼠标左键） checkUserLogin 方法，他会跳转对应的方法中  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BAby4Fk1HQbcPTboMkrOyto8IuPrA5MUmBzBDoWlrqZOaRnbfHUSqIjjAI7MQPFHu4gficicJEicZnKRCQv9JWZuQ/640?wx_fmt=png "")  
  
                 
  
然后存在两个参数，这个时候我们接着点击 会有一个提示窗，这个时候就来到 sevice 层  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BAby4Fk1HQbcPTboMkrOyto8IuPrA5MU6CFEWJfm2XBqOTNEjVPzGrrpRCYGHBCmbn4TicgRs1XrZSYZLmjKXGQ/640?wx_fmt=png "")  
  
                 
  
跳转进来后，仍然是查看代码，此时我们要关注 14 行的checkUserLogin 方法  
      
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BAby4Fk1HQbcPTboMkrOyto8IuPrA5MUPyDOxz8wR3VkgxLPz5WlzXbF41g5DaFEoR5WuU07oMcb7gdElfX5cA/640?wx_fmt=png "")  
  
                 
  
接着单击，他会跳转到对应的控制器中，此时整体的流程就走完了，我们只需要查看控制器里的代码即可。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BAby4Fk1HQbcPTboMkrOyto8IuPrA5MU0xEkUDxTExqXCqicY33LeAjAByXrYdfLKianoz0hUfWgRAHvRrbTv75A/640?wx_fmt=png "")  
  
                 
  
因为是靶场 代码比较简单，没有过多的过滤和验证  
  
21 行则是映射的 uri，当我们访问 login 后，就会触发登录代码，然后就会传入 username 和 password 的数据来。  
  
这个时候我们启动项目  
      
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BAby4Fk1HQbcPTboMkrOyto8IuPrA5MUMJyialy1G2rN9vAmf5ia3r9tdSQJDb19zGia9Np2sANtyKzPqutUoBQdw/640?wx_fmt=png "")  
  
                 
  
端口 9090   
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BAby4Fk1HQbcPTboMkrOyto8IuPrA5MUZgFqyjzHZevvcTicguT6ZrcGQC1ZykDibgGCibTJmUgMbcOiamRtWOl65Q/640?wx_fmt=png "")  
  
                 
      
  
访问 login 就可以看到页面。咱们已经从底层审计了，确认是存在注入，那么我们则需要进行复现  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BAby4Fk1HQbcPTboMkrOyto8IuPrA5MUQEIqia4h8INYIUynYHd62qydJOTTE28CwDJCwJD4pXlZ4zt3kFeFIQA/640?wx_fmt=png "")  
  
                 
  
直接略过过程，可以看到，存在注入。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BAby4Fk1HQbcPTboMkrOyto8IuPrA5MU8R3K4tSxtGBHoiaqJaOrial8SicCD8Y6lbR4CUfbNTZm61ETZt2s4DLXA/640?wx_fmt=png "")  
  
                 
  
如果修复的话，直接将$替换为#，就可以修复此漏洞。  
  
  
靶场环境配置  
  
想要本地学习的伙伴，可以后台回复   
day1sql 即可获取源码。  
  
拿到源码后，需要配置一些信息，否则无法运行。  
  
使用idea打开后，点击信任项目  
  
然后配置jdk  
      
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BAby4Fk1HQbcPTboMkrOyto8IuPrA5MUiaib8iaEPGHMCpyczfY5xr0icyfH9oib0zibPuXDMuVtXTicib1ZVJHKoYVnag/640?wx_fmt=png "")  
  
                 
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BAby4Fk1HQbcPTboMkrOyto8IuPrA5MUXHQKQz043T2BAYZZSm1pyY3UnXWM3INbOqbZXmDxFlSKNwicOwP1K3w/640?wx_fmt=png "")  
  
                 
  
然后打开设置，找到maven  
      
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BAby4Fk1HQbcPTboMkrOyto8IuPrA5MU9CwR2hEYYa0iaIQoKqw1TALRg8DxHBGMAYrBfcIbW47DXq10a1YibQgA/640?wx_fmt=png "")  
  
                 
  
选择对应的文件夹，如果下载比较慢，可以修改setting.xml里的源为国内的。  
  
最好是在maven目录下，新建一个  
repository  
 文件夹，用来存在下载的pom依赖包。  
  
然后创建数据库，数据库的配置在application.properties  
      
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BAby4Fk1HQbcPTboMkrOyto8IuPrA5MU140kHLzAV6ic2KA8HkNYfXg6eYBtuWkdBaibhA30jWQjNsZ7xDhbzibiag/640?wx_fmt=png "")  
  
                 
```
CREATE DATABASE test;

USE test;

CREATE TABLE demo (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    pass VARCHAR(255) NOT NULL
);

INSERT INTO demo (name, pass) VALUES ('zhangsan', '123456');
INSERT INTO demo (name, pass) VALUES ('lisi', 'aaabbbccc');
```  
  
  
                 
      
  
