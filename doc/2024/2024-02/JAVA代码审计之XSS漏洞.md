#  JAVA代码审计之XSS漏洞   
原创 goddemon  goddemon的小屋   2024-02-23 22:56  
  
## Part1 漏洞案例demo：  
  
没有java代码审计XSS漏洞拿赏金的案例。  
  
所以将就看看demo吧   
  
漏洞原理：关于XSS漏洞的漏洞原理核心其实没啥好说的，网上一查一大堆。  
### 反射性XSS漏洞  
```
<%@ page language="java" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8"%>

<!DOCTYPE html PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN" "http://www.w3.org/TR/html4/loose.dtd">
<html>
<head>
  <meta http-equiv="Content-Type" content="text/html; charset=UTF-8">
  <title>XSS Vulnerable</title>
</head>
<body>
<form action="index.jsp" method="post">
  Enter your name: <input type="text" name="name"><input type="submit">
</form>

<%

    String str = request.getParameter("m");
    <%=str%>
%>

</body>
</html>



```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/BYtyQicN4iaC5kdD9hPgCX2zanRFAYkiaJbBZ1GMJQJVeIIBOdEB5yG5MdOVpzxeyW9gEw3NPDoS00ic95PXkuNNzw/640?wx_fmt=png&from=appmsg "")  
![](https://mmbiz.qpic.cn/mmbiz_png/BYtyQicN4iaC5kdD9hPgCX2zanRFAYkiaJbv6ql7iaewUIJ3JPSJFP3Y87brJjc23YkfdHJrwYVvrQJdSgyqdUPwqQ/640?wx_fmt=png&from=appmsg "")  
### 存储型XSS漏洞  
  
存储型XSS漏洞和反射XSS漏洞的核心唯一区别就在于，字段入了数据库，然后又将页面取了出来。  
```
// 留言板页面上的表单提交处理代码
@WebServlet("/postComment")
public class CommentServlet extends HttpServlet {
    protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        // 从表单中获取用户输入的评论内容
        String comment = request.getParameter("comment");
        
        // 将评论内容存储到数据库中
        saveCommentToDatabase(comment);
        
        // 重定向回留言板页面
        response.sendRedirect("message_board.jsp");
    }
    
    // 将评论内容存储到数据库中的函数
    private void saveCommentToDatabase(String comment) {
        try {
            // 假设这里使用 JDBC 连接数据库，并执行 SQL 语句将评论内容存储到数据库中
            Connection connection = DriverManager.getConnection("jdbc:mysql://localhost:3306/mydatabase", "username", "password");
            Statement statement = connection.createStatement();
            String sql = "INSERT INTO comments (content) VALUES ('" + comment + "')";
            statement.executeUpdate(sql);
            connection.close();
        } catch (SQLException e) {
            e.printStackTrace();
        }
    }
}


```  
  
message_board.jsp页面  
```
<%@ page language="java" contentType="text/html; charset=UTF-8"
    pageEncoding="UTF-8"%>
<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<title>留言板</title>
</head>
<body>
    <h1>留言板</h1>
    
    <!-- 留言板评论 -->
    <div id="comments">
        <%-- 这里使用 JSP 脚本块来动态生成评论 --%>
        <% 
            // 假设从数据库中获取留言板评论的数据列表
            List<String> comments = getCommentsFromDatabase();
            for (String comment : comments) {
        %>
            <div class="comment">
                <%= comment %>
            </div>
        <% } %>
    </div>
</body>
</html>


```  
  
其实漏洞demo，xss的单独漏洞实在没啥可写的![](https://mmbiz.qpic.cn/mmbiz_png/BYtyQicN4iaC5kdD9hPgCX2zanRFAYkiaJbhPq65VBicicadmso06fP1aSPEQbAJkicV4ElyY0CAN8ibwalia3ic6om44pw/640?wx_fmt=png&from=appmsg "")  
  
### 漏洞组合经典漏洞CS CVE-2022-39197  
  
经典案例CS RCE漏洞   
  
其实这个洞在笔者看来核心不是XSS漏洞。  
  
核心还是反射机制导致的问题
漏洞的具体细节这里就不细跟细写了，给大家简单讲一讲原理：  
  
1.）objectview对象 可以利用反射机制动态的加载classid的类名，且当实例化对象归属于Component的子类或实现类，且类型为string类型以及为public修饰符修饰时，可以进行控制setxxx方法对值进行控制  
```
  <object classid="javax.swing.JLabel">
      <param name="text" value="sample text">
      </object> 

```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/BYtyQicN4iaC5kdD9hPgCX2zanRFAYkiaJb7lY8F3mcdg5Mo0ma3AhNnzBlRRd41QRVLiaSf2gELvQjbtgib9bWmFbQ/640?wx_fmt=png&from=appmsg "")  
如上面这个即反射动态加载javax.swing.JLabel这个类名。  
  
  
2.）apache的batik包中即org.apache.batik.swing.JSVGCanvas对象
满足上面的条件，导致利用set方法可控制uri值及set方法中存在  
  
loadSVGDocument方法可以去引用svg进而去调用loadScript方法，而该loadScript方法中如果类型为application/java-archive时，可引入外部一个jar包，且cs可将该jar包实例化为一个对象，进而导致代码执行。  
  
  
3.)CS的jlabel存在无参数构造方法，可以进行控制setText的值。进而实现我们展示进程名，主机名这些。  
  
  
即完整的链：  
  
  
jlabel中setText控制字段名-->设置字段名为object去引用JSVGCanvas对象调用set方法-->进而控制loadSVGDocument方法-->控制加载svg标签-->svg标签去加载jar包进行实例化，进而代码执行。  
  
  
实际利用脚本：cve-2022-39197 cs利用  
  
https://github.com/its-arun/CVE-2022-39197  
## Part2 进一步分析与思考  
### 漏洞自动化挖掘：  
  
推荐利用fortify
fortify效果：对于XSS漏洞的审计追踪还是较为友好。  
  
匹配思路：  
  
如果一定要使用匹配思路
就经典正则匹配下面的规则，限定为2条，3条规则即可。  
  
```
getParamter
<%=
param.
${
典型jstl语法思路写的
<c:out
<c:if
<c:forEach
ModelAndView
ModelMap
Model
request.getParameter
request.setAttribute

```  
### 漏洞进一步思考：  
  
其实XSS的漏洞本身单独从一个漏洞的角度而要，利用效果其实不会特别好。  
  
但是结合其他漏洞，就可以达到1click实现RCE漏洞的效果，如宝塔rce，小皮面板rce，cs rce，蚁剑反制，goby反制均为如此。  
  
除此之外，还可以达到结合csrf实现蠕虫，同源策略问题实现账户接管漏洞，具体就得看怎么玩了。  
  
##   
## Part3 后言：  
  
最近看到了很多安全圈的瓜，什么不如保安。  
  
自媒体，社群，朋友圈等等铺天盖地的宣传，安全已死的概念。  
  
怎么说呢？  
  
不太爱评论一些东西，但是还是想说  
  
别太焦虑，也没必要焦虑。  
  
  
有那闲工夫不如多学点东西来的有趣，任何行业再不好都有人能扎根，再好也都会有人淘汰。  
  
  
所以淘汰的哪个人为啥应该是你？![](https://mmbiz.qpic.cn/mmbiz_png/BYtyQicN4iaC5kdD9hPgCX2zanRFAYkiaJbsyGs8eskQ5iaARgVPySia6dvX2b6ZibWgCxnicRRcLt5ib59JCTLCmVIXfg/640?wx_fmt=png&from=appmsg "")  
  
  
  
自信从容，虚心进步，慢慢成长，以定入世，以律自洽，自行。  
  
共勉  
  
![](https://mmbiz.qpic.cn/mmbiz_png/BYtyQicN4iaC5kdD9hPgCX2zanRFAYkiaJbXSRHnTaiahpprWBqicKjbibuA7ibtPxdEWr3LpC3AibI38x5ECrOknUgN4A/640?wx_fmt=png&from=appmsg "")  
  
# END  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/BYtyQicN4iaC5kdD9hPgCX2zanRFAYkiaJb0wjoNicfibjYxicOl0xlJZcezLK9y7JT26Kxic9KzJHoewQ0eWAYkJvccg/640?wx_fmt=jpeg&from=appmsg "")  
  
  
  
