#  PHP 静态分析漏洞挖掘：挑战、对策与研究进展综述   
网安探索员  网安探索员   2025-05-12 12:00  
  
原文链接:  
https://forum.butian.net/share/4308  
  
  
  
静态应用安全测试 SAST（Static Application Security Testing）是指基于静态分析技术，在无需实际运行程序的情况下分析代码的语义和行为，找出潜在的漏洞从而保障软件的安全。本文关注过去学术界使用SAST针对PHP应用进行漏洞挖掘的研究，总结了其中遇到的主要挑战和相应的解决方法。  
  
因为最早是在国外读书时的一个作业，有些段落原文用英文写的，读起来可能有点机翻味。  
# 1.过程间污点分析  
  
污点分析旨在检查污点数据在程序中的传播路径，判断是否存在从 source 到sink 且未经 sanitizer 处理的数据流。这里我们将PHP的过程间污点分析（显然过程内的的污点分析不够实用）的实现方法分为两类：自顶向下方法(The Top-Down Approach)与自底向上方法(The Bottom-Up Approach)。本节暂时忽略对面向对象以及动态特性的处理，它们将专门在第2节和第3节讨论。  
## 1.1 自顶向下方法  
  
自顶向下方法从程序的入口点出发，当遇到函数调用时，通过传递参数和全局变量的抽象值，递归地分析其调用的每个函数。这是传统基于格(Lattice Based) 的数据流分析的常用策略。  
  
Pixy[1], [2], [3]是采用此方法的典型代表。它首先通过基于不动点迭代的过程间的到达定义分析（Reaching Definition Analysis）(其源码中也称为Dependency Analysis)，随后检查哪些定义能够最终到达 sink。Pixy 实现了 Sharir 和 Pnueli [4]提出的两种经典上下文敏感 (Context Sensitivity)实现策略：调用串 (call-string) 方法和函数式 (functional) 方法。调用串方法依据调用栈信息（即调用点序列）来区分同一函数的不同调用场景。为应对递归并避免调用链无限增长，通常会为上下文设置一个长度限制  
k  
。下面的代码就展示了当  
k=1  
  
时，Pixy 的污点分析可能出现误报的情况：由于只追踪了最后一个调用点，对  
bar  
  
的两次调用被识别为同一上下文，导致第一次调用返回的污点值也传播给了第二次调用的返回值，从而错误地污染了$x2  
。  
```
<?php
// Pixy 中长度为 1 的调用串会引发一个误报
$y1 = $_GET['x'];
$x1 = foo($y1);
$y2 = 'good';
$x2 = foo($y2);
echo $x2;

function foo($y)
{
    return bar($y);
}

function bar($y) {
    return $y;
}
```  
  
与之相对，函数式方法则依据传入参数和全局变量的抽象值来区分上下文，从而实现更精确的分析。若某次函数调用的抽象值与先前某次调用完全一致，便可直接复用那次调用的分析结果（返回值）。在上面的例子里，由于每次调用  
foo  
  
和  
bar  
时传入的参数和全局变量的抽象值都不同，因此这两个函数均需被分析两次。该方法的主要不足在于，生成的函数摘要（Function Summary）可能较难复用，容易导致上下文数量爆炸式增长。即使参数或全局变量的变化并不影响最终返回值，函数也可能被反复分析。Pixy在实验阶段就曾遇到此问题：在分析 MyBloggie项目时，函数式方法产生了过于复杂的上下文。为缓解该问题，他们转而尝试了长度为1的调用串方法。  
  
TChecker等其他工具也采用了类似的自顶向下过程间污点分析思路[5]。其改进之处包括：当一个调用点可能对应多个目标函数时，采用启发式规则进行选择；忽略那些参数均未被污染的函数调用。目前我们还没有看到函数式方法的一种变体IFDS（Interprocedural Finite Distributive Subset Problem）[6]被用于PHP应用的污点分析。理论上讲，IFDS 相比现有自顶向下方法能够在不降低精度的前提下，带来更高的分析效率。  
## 1.2 自底向上方法  
  
自底向上分析则从程序的叶子函数入手，逐步向上分析，并为每个函数生成可供更广泛重用的摘要信息。尽管为单个函数构建能涵盖所有可能调用场景的摘要成本较高，但一旦生成，这些摘要就非常易于复用[7]，且整个构建过程也易于并行化[8]。  
  
PHPJoern[9]采用了自底向上的过程间污点分析策略。它首先构建代码属性图CPG（Code Property Graph），该图融合了抽象语法树 AST（Abstract Syntax Tree）、控制流图 CFG（Control Flow Graph）、程序依赖图 PDG（Program Dependence Graph） 以及调用图 CG（Call Graph）。其中 PDG 包含了每个过程内部的数据依赖图 DDG（Data Dependence Graph） 和控制依赖图 CDG（Control Dependence Graph）。DDG 由过程内的到达定义分析生成，并且会保守地处理函数调用。在下面的代码示例中，入口函数的DDG 会包含一条从  
$c  
  
到  
$e  
  
的、实际并不存在的数据依赖边。随后，PHPJoern 从 sink 出发，沿着数据依赖边和调用图边进行反向污点分析，从而能够排除掉如  
$c  
  
到  
$e  
  
这样的错误数据流。每个函数的 DDG 可以视为其函数摘要。这种方法的潜在缺点是可能存在一定冗余：即使某些函数从未被实际调用，在构建 CPG 的过程中也仍会被分析。但这与 Joern 的定位有关，它更像是一个基础性的代码分析框架，而非直接面向用户的 SAST 工具。  
```
<?php
function foo($a2,$b2) {
    echo $a2;
    return $b2."suffix";
}

function bar($c2) {
    return "nothing";
}

$a = $_GET['a'];
$b = $_GET['b'];
$c = $_GET['c'];
$d = foo($a, $b);
$e = bar($c);
echo $d;
echo $e;
```  
  
Xie 和 Aiken[10]提出了一种混合分析方法，它融合了自顶向下（用于摘要构建）与自底向上（用于反向污点分析）的元素。Dahse和Holz在 RIPS[11]中扩展了这一思路。下面介绍 RIPS 的实现：  
  
RIPS运用了两种摘要：块摘要和函数摘要。块摘要负责记录其对应基本块内的数据流信息，而函数摘要则由该函数内部所有块摘要组合而成。RIPS 从入口函数开始构建 CFG，在构建每个基本块的同时，也生成对应的块摘要。例如，对于语句  
$a = $_GET['a'];  
，会生成类似如下的块摘要：  
```
{
    Dataflow: {
        $a: ArrayDimFetch($_GET,"a")
    }
    // 摘要其余部分暂略
}
```  
  
当遇到一个对未被分析的函数的调用时（比如$d = foo($a, $b);  
），RIPS 会先为  
foo  
  
函数构建 CFG 和函数摘要，此时并不考虑传入的具体参数值。在分析到foo  
内部的sink  
echo $a2  
时，RIPS 会执行一次过程内的反向污点分析。这里的$a2  
来自于函数参数，需要考虑具体的调用才能知道是否形成了漏洞，因此它将被记录在foo  
的函数摘要中的  
sensitiveParams  
  
属性里。同时，函数摘要中的  
returnValues  
  
属性则会记录返回值的符号值。下面是  
foo  
  
函数摘要的一个示例：  
```
{
    sensitiveParams: [
        $a2
    ],
    returnValues: Concat($b2, "suffix")
}
```  
  
RIPS会忽略掉CFG中循环造成的回边，因此生成函数摘要时不需要不动点迭代，但会造成一定的漏报。Xie 和 Aiken则明确提到了他们使用不动点迭代来生成函数摘要。  
  
foo  
  
的摘要构建完毕后将处理$d = foo($a, $b);  
，RIPS 会利用  
foo  
  
摘要中的  
sensitiveParams  
  
信息，对变量  
$a  
  
发起反向污点追踪。这次追踪能够成功找到污点 source  
$_GET['a']  
，从而确认漏洞的存在。而  
$d  
  
的符号值则可以通过查询  
foo  
  
摘要的  
returnValues  
，并将  
$b  
  
的符号值代入其中的$b2  
  
来获得。之后若再次遇到对  
foo  
  
函数的调用，则能够直接复用已生成的摘要，避免重复的分析。  
  
RIPS 的开源版本相较于其研究论文中描述的实现有所简化，没有显式构建 CFG 和摘要，但其核心分析思路是类似的。  
  
这种混合分析方法虽然整体上以自顶向下方法为主导，但也融入了自底向上的思想，从而在提升摘要的复用率和减少对死代码的冗余分析之间取得了更好的平衡。  
# 2.面向对象  
  
支持 PHP 的面向对象特性对于有效的 PHP 静态分析至关重要。对于过程间分析，必须获取对象类型才能分析出方法调用的目标方法，从而构建完整的调用图。与 Java 等语言不同，PHP 中的对象没有声明类型（虽然PHP 7.4+ 为属性和方法参数/返回类型引入了部分类型声明），这使得像 CHA（Class Hierarchy Analysis）这样简单的方法无法使用。此外，在污点分析和其他数据流分析中需要域敏感性（Field Sensitivity）以提高精度。我们将分别介绍基于指针分析（Pointer Analysis）和变量类型分析 VTA（Variable Type Analysis）来支持 PHP 面向对象特征的方法。  
```
<?php

class Container {
    public $dependency;
}

class Sink {
    private $dataToEcho;

    public function setData($data) {
        $this->dataToEcho = $data;
    }

    public function execute() {
        echo $this->dataToEcho;
    }
}

class FakeSink {
    // This method will not be called.
    public function execute() {
        echo $_GET['y'];
    }
}

function triggerVulnerability($object) {
    $object->execute(); // RIPS-A can't infer the type of $object here.
}

$container = new Container();
$container->dependency = new FakeSink();  // Initially set to a safe object.
$alias = $container;  // Alias.
$alias->dependency = new Sink(); // Now it contains the vulnerable object (Sink).
$userInput = $_GET['x'];
$container->dependency->setData($userInput);
$container->dependency->execute(); // Vuln 1
triggerVulnerability($alias->dependency); // Vuln 2
```  
## 2.1 指针分析  
  
指针分析用于静态计算程序中变量在运行时可能指向的对象集合[12]。Dahse 等人在RIPS的拓展版本（TChecker[5]论文中称为 RIPS-A）中使用指针分析来支持 PHP 的 OOP 分析[13]。该版本的RIPS主要用于检测PHP的反序列化利用链，但也可以用于检测其他污点式漏洞。他们的方法是对上一节中描述的 RIPS 分析方法的拓展。  
  
具体来说，他们在摘要中添加了新的符号  
Object  
、PropertyFetch  
  
和  
PropertyWrite  
  
以实现堆抽象和域敏感。在上面的例子中，入口函数前 4 行的模拟将导致块摘要包含：  
```
{
    Dataflow: {
        $container -> Object1,
        $alias -> Object1
    },
    Object: [
        Object(type: Container, properties: {
            dependency -> Object3
        }),
        Object(type: FakeSink, properties: {}),
        Object(type: Sink, properties: {})
    ]
}
```  
  
和上一节介绍的类似，RIPS在生成方法摘要时并不考虑具体的调用。因此对参数，全局变量或者  
$this  
  
的属性进行访问时并不知道此时的接受者对象（Receiver Object）是哪一个，此时就需要使用到  
PropertyWrite  
  
和  
PropertyFetch  
。比如在创建Sink::setData  
方法摘要时将生成：  
```
{
    PropWrite: [
        PropertyWrite($this, dataToEcho, $data)
    ]
}
```  
  
之后对  
$container->dependency->setData($userInput);  
  
的处理将根据  
PropWrite  
  
缓存将$userInput  
  
写入到  
$container->dependency  
  
指向的对象。类似地，Sink::execute  
  
的方法摘要将使  
PropertyFetch  
来表示对  
$this->dataToEcho  
  
的访问，并将其存储在  
sensitiveParams  
  
属性中。在分析到$container->dependency->execute()  
时将触发反向污点分析，此时将检查  
$container->dependency  
  
对象的  
dataToEcho  
属性是否可由用户控制，从而检测到第一个漏洞。  
  
不过 RIPS-A 仅仅实现了过程内的污点分析。在创建triggerVulnerability  
  
方法摘要时$object->execute();  
  
中  
$object  
  
类型是未知的。因此，Sink::execute  
  
和  
FakeSink::execute  
  
都被认为是潜在的被调用者，导致它们的摘要被合并，造成误报。  
  
RIPS-A 还支持了 PHP 的魔术方法特性，在实现堆抽象后这并不难实现。  
## 2.2 对象类型分析  
  
TChecker[5]使用了一种基于类型而不是基于堆抽象的方式来支持PHP的面向对象。这种方法相对来说更加轻量级。它的分析分为调用图构建和污点分析两个阶段。在调用图构建阶段使用了过程间的对象类型分析[14]来获取对象的类型从而构建精确的调用图。这种方法与指针分析的区别在于没用进行堆抽象，仅仅依靠反向查找new  
关键字来确定对象的类型。理论上讲TChecker能够没有误报处理triggerVulnerability  
中$object->execute();  
的调用边，但会因为没有堆抽象无法正确添加$container->dependency->execute();  
的调用边。反向追踪$container->dependency  
的new  
初始化会将其类型视为FakeSink  
。  
  
此外，TChecker 还使用了一种启发式规则来推断对象属性的类型，以此弥补缺乏完整堆抽象带来的限制。在下面的例子中，TChecker在分析  
$ev = $o->config;  
  
时无法直接通过反向分析追踪到  
$o->config  
  
的初始化位置。因为缺乏堆抽象，TChecker 无法精确跟踪  
$o  
  
指向的具体对象实例，也无法将外部变量  
$o  
  
与类方法（这里是构造函数）内部的  
$this  
  
进行关联，因此它无法直接判断出  
$this->config = new ConfigData();  
  
是对$o->config  
的赋值。为了解决这个问题，TChecker 对于  
$o->config  
  
这种对象属性的访问采用了一种启发式方法：  
- 首先通过反向分析确定父对象  
$o  
  
的类型是  
AppContainer  
- 检查  
AppContainer  
  
类定义，确认：  
- 是否存在  
config  
  
属性  
- 该属性是否在类中（通常在方法如  
__construct  
  
内）通过  
new  
  
表达式进行过赋值。  
若这两个条件都满足，TChecker 便推断  
$o->config  
  
的类型是  
ConfigData  
。  
```
<?php

class ConfigData {
    public $setting = 'default';

    public function getSetting() {
        return $this->setting;
    }
}

class AppContainer {
    // 约束 1: 类 'C' 必须有属性 'p' (这里是 'config')
    public $config;

    public function __construct() {
        // 约束 2: 属性 'C::p' (AppContainer::config) 通过 'new' 实例化赋值
        $this->config = new ConfigData();
    }
}

$o = new AppContainer();

$ev = $o->config;
$value = $ev->getSetting();
echo "配置值: " . $value;
?>
```  
  
TChecker的论文中没有给出它的污点分析部分对于面向对象的处理细节，尤其是如何在没有堆抽象的情况下实现域敏感的污点分析。对其开源工具的测试能够发现其污点分析也仅实现了类型敏感（Type Sensitivity）而没有对象敏感（Object Sensitivity）。某个对象的属性的污点会影响到同一类型其他对象的同一属性。  
# 3.动态特性  
  
在PHP中，动态特性如同Java中的反射机制一样，是静态分析的难点（Hard Language Features）之一，并且在PHP程序中普遍存在。Yama[15]将PHP的动态特性归纳为以下几类：  
- Variable Variables (D1)  
```
$$a = 'hello';
```  
- Dynamic Includes (D2)  
```
include $page . '.php';
```  
- Dynamic PHP Code Execution (D3)  
```
eval($code);
```  
- Variadic Functions (D4)  
```
function sum(...$numbers) { /* ... */ }
```  
- Variable Functions (D5)  
```
$funcName();
call_user_func($funcName);
```  
- Variable Objects/Arrays (D6)  
- Yama原文中未提及Variable Arrays，但其与Variable Objects类似可以归到一类  
```
echo $obj->{$propertyName};
echo $array[$keyName];
```  
- Magic Methods (D7)  
```
echo $obj; // call __toString
```  
  
由于D4相对比较好处理(对参数传递进行更精确的建模)，而D7与面向对象特性的关联性更强，因此本节将重点讨论D1-D3 D5-D6这五类与动态字符串值相关的动态特性。  
  
此外，Al Kassar等人在Testability Tarpits中提出了动态特性的四个级别[16]，用于描述其静态可计算程度：  
- D'1: 动态操作的核心参数是硬编码的常量。  
```
call_user_func_array("Func", $b);
```  
- D'2: 参数是一个表达式，其值可以通过常量传播静态地唯一计算出来  
```
$a = "FuncA";
call_user_func_array($a, $b);
call_user_func_array($a."2", $b);
```  
- D'3: 参数是一个表达式，其值只能部分地静态计算  
```
$v = $row["function_name"]; // ex: from database
call_user_func_array("Func" . $v, $b);
```  
- D'4: 参数是一个表达式，其值无法静态计算  
```
$f = $row["function_name"]; // ex: from database
call_user_func_array($f, $b);
```  
  
过去，已有大量研究致力于处理PHP的动态特性。这些研究方法大致可以分为以下四类：字符串分析、针对MVC框架的启发式规则，使用自然语言处理（NLP）技术辅助以及SAST协作。  
## 3.1 字符串分析  
  
通过静态字符串分析（String Analysis）（这里采用RIPS的叫法，不同研究的叫法不同，但本质上都是常量传播（Constant Propagation）和常量折叠（Constant Folding）的组合）来模拟运行时的字符串行为是处理PHP动态特性最常用的方法。  
  
Pixy在污点分析前使用标准的不动点迭代进行过程间上下文敏感的字符串分析（他们称为Literal Analysis）[1], [2], [3]。他们在D'1 和 D'2 级别上支持了D2和部分的D6动态特性（可变数组）。因为没有采用正则表达式对字符串进行建模，因此无法处理D'3级别的动态特性。为了避免冗余的分析，字符串分析仅会在有需要时启动（比如包含D'2级别的D2），但一旦启动就会对所有的字符串常量进行传播和折叠，带来了一定程度上冗余的分析。  
  
RIPS的字符串分析和它的污点分析一样，是反向on demand的[11]。在碰到需要解析出具体字符串字面量值时，将反向根据此前摘要中的符号值推断出具体值。相比Pixy，RIPS的方法能够避免更多冗余的分析，不过他们的字符串分析仅仅是过程内的。他们对动态特性的支持也更加全面，支持了D1-D3 D5-D6中除了D6的可变属性（因为没有支持面向对象）外的所有动态特性种类，并且对于D2和D5的支持达到了D'3级别，对于能部分精确求解的字符串，将使用正则表达式进行建模（比如Func.*  
），并最终使用正则匹配可能的文件名和函数名。TChecker[5]的做法类似于RIPS，也采用了反向on demand的策略并支持了D'3级别的D2和D5，并且支持了过程间的字符串分析。  
  
Yama支持了所有的动态特性类型并且实验结果中能够处理Testability Tarpits中的所有D'4级别用例[15]。但需要注意的是这些用例都使用$_GET  
作为外部值，并且没有干扰的其他变量或函数。这种情况仅仅需要使用.*  
处理外部值即可解决（例子如下）。鉴于Yama的论文没有太多的阐述这块的细节并且没有开源，其是否能处理其他外部值（例如来自数据库或文件系统，此时难以获取其具体值，建模成.*  
也不合理）并避免真实应用中过多的误报（使用.*  
连接过多调用边或包含过多文件）仍不明确。  
```
<?php
function F($var){
    echo $var;
}

$a = $_GET["p1"];
call_user_func($func, $a);
```  
  
Yama的github仓库称将在论文被接收后开源  
  
需要注意的是，这里说的各工具支持的动态特性类别和级别都仅仅是Soundy的[17]，不代表他们能做到真正的Sound  
## 3.2 启发式规则  
  
PHP的动态特性带来的问题在使用MVC框架的现代PHP应用中得到了放大，这些框架中的一些关键特性常常依赖于复杂的动态特性，当SAST无法处理它们时将导致整个应用都无法正常分析。下面的例子中展示了一个使用CodeIgniter的PHP应用，其中包含了多处静态分析的难点：  
- Controller由CodeIgniter根据Url动态初始化，仅从入口函数开始分析的SAST可能根本无法分析到Controller。即使是逐个分析每个方法的SAST可能也会因为没有模拟实例化Controller对象导致无法正确分析。  
- CodeIgniter对于控制器的实例化：  
https://github.com/bcit-ci/CodeIgniter/blob/3658d731eaabe6117298a105ffb5b9dd59e190ce/system/core/CodeIgniter.php#L468  
，这是一个典型的复杂D'4级别动态特性  
- Controller和Model中的属性$this->load  
,  
$this->input  
由CodeIgniter动态注入，SAST可能难以分析出其具体类型。尽管这是一个D'2级别的动态特性，但非常复杂需要对PHP特性进行精细的建模，目前没有见到开源工具能够正确依靠字符串分析处理它。  
- $this->input  
：  
https://github.com/bcit-ci/CodeIgniter/blob/3658d731eaabe6117298a105ffb5b9dd59e190ce/system/core/CodeIgniter.php#L292  
- $this->load  
：  
https://github.com/bcit-ci/CodeIgniter/blob/3658d731eaabe6117298a105ffb5b9dd59e190ce/system/core/Controller.php#L86  
- load_class  
动态加载：  
https://github.com/bcit-ci/CodeIgniter/blob/3658d731eaabe6117298a105ffb5b9dd59e190ce/system/core/Common.php#L141  
。  
- ProductController::Product_model  
和Product_model::db  
由ProductController  
和Product_model  
动态加载。同样非常复杂的D'2级别动态特性。  
- Loader::model  
:  
  
https://github.com/bcit-ci/CodeIgniter/blob/3658d731eaabe6117298a105ffb5b9dd59e190ce/system/core/Loader.php#L242  
- Loader::database  
:  
  
https://github.com/bcit-ci/CodeIgniter/blob/3658d731eaabe6117298a105ffb5b9dd59e190ce/system/core/Loader.php#L382  
- 视图渲染需要将$data  
中的变量绑定到当前作用域然后动态包含模版文件：  
https://github.com/bcit-ci/CodeIgniter/blob/3658d731eaabe6117298a105ffb5b9dd59e190ce/system/core/Loader.php#L888  
- CodeIgniter的视图渲染相对而言还是比较简单的，一些模版渲染引擎还将包含自己的DSL，更加难以分析。  
```
<?php
class ProductController extends CI_Controller {
    /**
     * @var Product_model The product model instance
     */
    private $Product_model;

    public function __construct() {
        parent::__construct();
        // Load the model in the constructor
        $this->load->model('Product_model');
    }

    public function search() {
        // Get search term from POST request
        $search_term = $this->input->post('search_term');

        // Pass the search term to the model method without sanitization
        $products = $this->Product_model->search_products($search_term);

        // XSS vulnerability - directly passing unsanitized user input to the view
        $data['search_term'] = $search_term; // No escaping or sanitization
        $data['products'] = $products;
        $data['title'] = 'Search Results';

        $this->load->view('products/search_results', $data);
    }
}
```  
```
<?php
class Product_model extends CI_Model {
    public function __construct() {
        parent::__construct();
        $this->load->database();
    }

    public function search_products($search_term) {
        // SQL Injection vulnerability - directly inserting user input into query
        $query = $this->db->query("SELECT * FROM products WHERE name LIKE '%{$search_term}%' OR description LIKE '%{$search_term}%'");

        return $query->result_array();
    }
}
```  
```
<div class="search-results">
    <h1>Search Results</h1>

    <!-- XSS vulnerability - directly outputting unsanitized user input -->
    <h2>Results for: <?php echo $search_term; ?></h2>

    <?php if (empty($products)): ?>
        <p>No products found matching your search.</p>
    <?php else: ?>
        <ul class="product-list">
            <?php foreach ($products as $product): ?>
            <li>
                <h3><?php echo $product['name']; ?></h3>
                <div class="description"><?php echo $product['description']; ?></div>
                <div class="price">Price: $<?php echo $product['price']; ?></div>
            </li>
            <?php endforeach; ?>
        </ul>
    <?php endif; ?>

    <form method="post">
        <input type="text" name="search_term" placeholder="Search products..." />
        <button type="submit">Search</button>
    </form>
</div>
```  
  
Zhao 等人在 VulPathsFinder 中通过解析 PHPDoc 风格的注释来获取对象类型[18]，以此应对 MVC 框架中的对象类型推断难题。在上面的例子中，可以通过@var Product_model  
  
获取  
ProductController::Product_model  
的类型。这种方法在PHP Intelephense这样的VSCode拓展中也有使用，但其有效性直接取决于开发者是否提供了辅助的注释。  
  
Al Kassar在其博士论文中提出了针对特定框架（CodeIgniter和Laravel）使用转换规则的方法来帮助SAST避开复杂的动态特性[19]。以ProductController  
为例，运用转换规则后将变为：  
```
class ProductController extends CI_Controller {
    /**
     * @var Product_model The product model instance
     */
    private $Product_model;

    public function __construct() {
        parent::__construct();
        // Load the model in the constructor
        $this->Product_model = new Product_model();
    }

    public function search() {
        // Get search term from POST request
        $search_term = $_POST['search_term'];

        // Pass the search term to the model method without sanitization
        $products = $this->Product_model->search_products($search_term);

        // XSS vulnerability - directly passing unsanitized user input to the view
        $GLOBALS['search_term'] = $search_term; // No escaping or sanitization
        $GLOBALS['products'] = $products;
        $GLOBALS['title'] = 'Search Results';

        include "products/search_results.php"
    }
}
```  
  
总体而言，这类采用特定规则来处理动态特性的方法相比于复杂的字符串分析开发成本更低。不过它们的通用性较差，往往需要针对特定的框架进行定制，或是依赖于开发者提供的额外信息。  
## 3.3 NLP  
  
Su等人在PAT中结合 NLP（Natural Language Processing）来解决动态特性[20]。PAT 的核心策略包括推断 Inner Source 和 Inner Sink，也就是上面例子中的$this->input->post  
和$this->load->view('products/search_results', $data)  
，从而有效缩短污点分析路径，避免了分析这些包装函数中潜在的复杂动态特性。其工作流程如下：  
- 推断用户自定义sanitizer： PAT 使用 NLP 分析函数名称和注释，根据函数名称、注释等信息识别可能的用户自定义sanitizer，例如CodeIgniter中的xss_clean  
方法。  
- 推断 Inner Source 和 Inner Sink：PAT以saniziter为中心进行推断。从已知的 sanitizer 调用开始在 PDG上执行双向的数据流追踪：反向查找其返回值经常传递给给 sanitizer 的函数（潜在的 Inner Source），并正向查找其参数经常来自 sanitizer 输出的函数（潜在的 Inner Sink）。PAT使用一个称为 sanDegree 的指标来量化这种流的频率，超过阈值的候选者将得到确认。  
- 在缩短路径上进行污点分析：使用 Inner Source 和 Inner Sink 进行污点分析  
Ji 等人在 Artemis 中采用了一种更直接的策略：基于 LLM 直接识别 Inner Source 和 Inner Sink[21]。他们首先提取出第三方库中带有 PHPDoc 注释的公开函数作为候选的source 和 sink。接着，应用 GPT-4o 的few-shot learning对这些候选点进行精确分类。随着 LLM 的快速发展，我们有理由相信基于LLM的方法有更广阔的应用前景。  
## 3.4 SAST合作  
  
Al Kassar等人进行了一个有趣的研究，通过不同SAST工具互补来解决动态特性带来的挑战[22]。他们的工具WHIP能够在将SAST视为黑盒的的情况下，仅仅通过临时修改目标PHP应用源代码来迫使2个不同的SAST工具A和B进行互补合作。  
  
假设A工具支持动态函数调用但没有支持魔术方法，B工具则相反支持魔术方法但没有支持动态函数调用。在下面的代码中，两个工具在初始状态下均无法发现漏洞。  
```
<?php
class MagicProcessor {
    private function internalProcessing($value) {
        return "PROCESSED_" . $value;
    }

    // 工具 A 无法正确追踪数据从这里流出
    public function __call($methodName, $arguments) {
        if ($methodName == 'processData')
            return $this->internalProcessing($arguments[0]);
        else
            die("Called undefined method: " . $methodName);
    }
}

// 函数：使用 call_user_func 进行动态调用
// 工具 B 无法可靠地追踪数据流经这里
function dynamicFormatter($inputData, $formatFunctionName) {
    if (function_exists($formatFunctionName))
        return call_user_func($formatFunctionName, $inputData);
    else
        die("Function $formatFunctionName does not exist");
}

$userInput = $_GET['data'] ?? 'default_value';

// 阶段 1: 数据通过魔术方法处理器
$processor = new MagicProcessor();
// 工具 A 在这里丢失 $userInput 到 $processedResult 的追踪
$processedResult = $processor->processData($userInput); // 调用 __call

// 阶段 2: 处理结果通过动态格式化器
// 工具 B 在这里丢失 $processedResult 到 $finalResult 的追踪
$finalResult = dynamicFormatter($processedResult, 'trim'); // 使用 trim，非净化

echo "Final Output: " . $finalResult;
?>
```  
  
WHIP在所有函数和方法调用后注入临时的echo  
  
fake sink用于探测不同工具的数据流传递情况（监测返回值和参数），此时源代码变为：  
```
// ...
$processedResult = $processor->processData($userInput);
/* WHIP INPUT sink for processData */ echo $userInput;
/* WHIP OUTPUT sink for processData */ echo $processedResult;
// ...
$finalResult = dynamicFormatter($processedResult, 'trim');
/* WHIP INPUT sink for dynamicFormatter */ echo $processedResult;
/* WHIP OUTPUT sink for dynamicFormatter */ echo $finalResult;
// ...
echo "Final Output: " . $finalResult;
```  
  
此时再次运行两个工具:  
- 工具A由于  
__call  
  
数据流中断，在/* WHIP OUTPUT sink for processData */ echo $processedResult;  
处未报告污点。  
- 工具B能处理  
__call  
，在/* WHIP OUTPUT sink for processData */ echo $processedResult;  
处报告污点。  
由此WHIP可以推断出工具A缺失了此数据流，将通过插入条件分支语句缝合数据流：  
```
// ...
$processedResult = $processor->processData($userInput);
/* STITCH_BEGIN: ST1 */
if (round(rand(0,1))) { $processedResult = $userInput; }
/* STITCH_END */
```  
  
此时工具A也将能够检测到$userInput  
到$processedResult  
的数据流。因为增加了新的数据流，WHIP将再次重复以上步骤。第二轮迭代将类似的为工具B缝合$processedResult  
到$finalResult  
的数据流。当没有新的数据流产生时迭代将终止，此时A和B都能够检测到示例中的漏洞。  
  
不过，他们的方法目前还存在一些明显的局限性。首先出于效率上的权衡，WHIP仅仅在方法或函数调用后插入fake sink，没有考虑其他情况的数据流断流。其次WHIP仅仅考虑了函数参数和返回值的数据流，没有考虑方法调用$this  
造成的隐式数据流，不过这一点不难解决。这种方法还可能导致更多的误报，因为其中一个工具的错误数据流也将一起被共享。  
# 4.存储型漏洞  
  
Dahse 和 Holz 在另一个RIPS的拓展版中基于字符串分析支持了涉及持久数据存储（如数据库、session和文件名）的二阶污点漏洞[23]。处理session和文件名比较简单，通过字符串分析对session名和文件名进行建模即可。对数据库的处理则更为复杂，分为以下步骤：  
- Preparation: 解析.sql文件或使用正则搜索CREATE TABLE  
语句获取数据库模式。这是为了了解表结构从而处理  
SELECT *  
  
这样模糊的SQL查询。在下面的例子中将得知  
users  
  
表中依次存在  
id  
,username  
和nickname  
  
列。  
- Writing: 识别  
INSERT  
,  
UPDATE  
,  
REPLACE  
等语句，确定目标表、列和输入值，并检查输入值是否为污点。在例子中将解析UPDATE  
语句，识别出其目标是  
users.nickname  
，并反向进行污点分析追溯到输入$_GET['nickname']  
。  
- Reading: 解析SELECT  
语句，例子中将为查询结果  
$result  
  
创建  
ResourceDB  
  
符号，记录其nickname  
元素对应于users.nickname  
列。此外这一步还会考虑SQL中隐式的Sanitization，比如SELECT * FROM users WHERE nickname = 'guest'  
返回的ResourceDB  
中的nickname  
列会是静态值'guest'  
。  
- Access: 对被污染的ResourceDB  
进行污点分析。  
```
CREATE TABLE users (
  id INT PRIMARY KEY,
  username VARCHAR(50),
  nickname VARCHAR(50)
);
```  
```
<?php // update_nickname.php
// ...
$new_nickname = $_GET['nickname']; // 1. Source: Tainted input with TID
$escaped_nickname = mysqli_real_escape_string($db_conn, $new_nickname);

// 2. Writing: SQL 解析器识别 UPDATE, 目标 users.nickname
//   输入值 $escaped_nickname 含 TID -> users.nickname 标记为 taintable
$sql_update = "UPDATE users SET nickname = '$escaped_nickname' WHERE id = 1";
mysqli_query($db_conn, $sql_update);
?>
```  
```
<?php // display_profile.php
// ...
// 3. Reading: SQL 解析器识别 SELECT users.nickname
//   为 $result 创建 ResourceDB 符号，记录含 users.nickname
$sql_select = "SELECT nickname FROM users WHERE id = 1";
$result = mysqli_query($db_conn, $sql_select);

// 4. Access:
$row = mysqli_fetch_assoc($result);
echo $row['nickname'];
```  
  
然而，现代PHP应用程序和框架往往对原生数据库操作方式进行了封装，例如如下所示：  
```
$username = $_POST['username'];
$nickname = $_POST['nickname']; // 污点源数据

$insertUserData = [
    'username' => $username,
    'nickname' => $nickname
];

// 链式调用写入数据库
QueryMaster::table('users')  // ① 表名参数
           ->data($insertData) // ② 数据参数 (包含列名键)
           ->insert();         // ③ 操作方法
```  
```
$id = $_GET['id'];
$user = QueryMaster::table('users')           // ① 表名参数
                      ->where('id', '=', $id)
                      ->fields(['nickname']) // ② 字段参数 (包含列名)
                      ->select();                  // ③ 操作方法 (假设返回单行)

echo $user['nickname'];
```  
  
因为不同的应用和框架可能存在不同的封装方式，无法统一建模，Su 等人在 Splendor中使用了基于模糊匹配（Fuzzy Matching）的方法来获取一次数据库操作对应的数据库三元组（表名，列名，操作），其中的操作包括读取和写入[24]。其工作流程如下：  
- 与RIPS拓展版类似，分析SQL文件获取数据库模式  
- 锚点 API（Anchor Point API）收集: Splendor 在 CPG 上遍历从 source 到 sink的路径。它发现  
QueryMaster  
  
类的方法，如  
table()  
,  
data()  
,insert()  
,  
fields()  
,  
select()  
  
在这些路径上被频繁地以链式结构调用。基于高频调用和链式结构特征，他们被识别为潜在锚点API集合。  
- 识别数据库写入操作:  
- 收集与解析: SPLENDOR首先分析链式调用，收集令牌  
QueryMaster  
,  
table  
,  
'users'  
,  
data  
,  
$insertData  
,  
insert  
。追踪  
$insertData  
  
发现键  
'nickname'  
和'username'  
。  
- 模糊令牌匹配:  
table('users')  
调用中参数'users'  
能够匹配到表名users  
。insert()  
调用能够识别出写入操作。username  
和nickname  
则能够匹配对应的列名。最终识别出两个数据库操作三元组:  
(users, nickname, write)  
和(users, username, write)  
- Write2Source污点分析：针对(users, nickname, write)  
和(users, username, write)  
进行反向污点分析，最终将users.nickname  
和users.username  
标记为污点  
- 识别数据库读取操作：类似于识别写入操作，例子中能识别出数据库操作三元组：(users, nickname, read)  
- Read2Sink污点分析： 针对  
(users, nickname, read)  
检查  
users.nickname  
  
是否已标记为污染。对select()  
的返回值  
$user  
  
进行污点分析  
# 5.误报去除  
  
静态分析无可避免的会引入误报。本节关注一些减少污点分析误报的工作以及更进一步，能够生成漏洞利用从而进行漏洞验证的工作。  
## 5.1 Sink上下文  
  
污点分析中的一些sanitizer是否有效取决于sink点所处的上下文。一个典型的例子用于过滤XSS漏洞的htmlspecialchars  
。在未使用ENT_QUOTES  
参数时htmlspecialchars  
默认不转义单引号。如果位于HTML标签属性值中的sink点仅被单引号包围则漏洞存在，如果被双引号包围则不存在漏洞，如下面的例子所示：  
```
<?php
$username = htmlspecialchars($_GET['user']);

$output = "<input type='text' name='uname' value='";
$output .= $username;
$output .= "'>";
// unsafe
echo $output;

// safe
echo "<input type='text' name='uname' value=\"" . $username . "\">";
?>
```  
  
为了解决这个问题，RIPS[11]在常规的污点分析结束后将再次使用字符串分析重建出echo  
的参数并使用HTML parser对其进行解析，从而分析出$username  
是否被单引号包裹。之后RIPS将反向回溯污点流检查是否有针对单引号的转义。  
  
RIPS论文中使用术语Context-Sensitive String Analysis来描述这种方法，这里的上下文指的是sink点所处的上下文，很容易与过程间分析中的术语Context-Sensitive混淆。  
## 5.2 自定义Sanitizers  
  
另一个常见的误报原因在于用户自定义的sanitizer，例如使用正则表达式进行对输入进行验证或过滤，我们以验证为例因为它还需要额外考虑控制流：  
```
<?php
// ...
$username = $_GET['user'];

// 只允许字母、数字和下划线
$pattern = '/^[a-zA-Z0-9_]+$/';

if (preg_match($pattern, $username)) {
    $sql = "SELECT * FROM users WHERE username = '" . $username . "'";
    mysqli_query($db_conn, $sql);
}
?>
```  
  
正确处理这个例子需要做到：（1）能够分析正则表达式/^[a-zA-Z0-9_]+$/  
对不同漏洞的影响（2）需要在if  
分支内部考虑preg_match($pattern, $username)  
的影响。这称为控制流敏感（Control Sensitivity）。  
  
这里我们使用Møller和Schwartzbach给出的定义[25]，将考虑分支条件（不一定能精确判断会进入哪个分支，但至少会在分支内部利用此时成立的条件来精化路径上的状态），但在分支汇合的地方仍然合并多个抽象域的做法称为控制流敏感。将在控制流敏感基础上更进一步不合并分支，逐个考虑到达某个程序点的所有路径的方法称为路径敏感（Path Sensitivity）（将在下一节介绍）。不过路径敏感的定义其实很模糊，一些工作将他们仅仅实现控制流敏感的方法也称为路径敏感[15], [21]。  
  
RIPS[11]的方法较为简单。在识别到条件判断中的preg_match  
后会将其中的正则表达式转换为对应的AST，之后检查相应漏洞需要的特殊字符（例如sql注入的'  
,"  
）能否通过该正则，从而在条件为true  
的后续基本块中去除对应漏洞的污点。这种方法比较简单，但没有真正考虑正则的语义，并不是对所有正则都是sound的。  
  
Wassermann和Su使用了另一种基于上下文无关文法（CFG）的字符串分析来处理这种情况[26]。他们的字符串分析起到了污点分析的效果，并且能够生成一个CFG来表示目标程序中可能产生的字符串。具体方法是将SSA（Static Single Assignment）形式的中间表示中的每一个赋值语句以及条件判断翻译成对应的CFG产生式规则。上述例子将产生下面的文法：  
```
// Grammar Productions:

SQLQuery      -> QueryPrefix username QuerySuffix
QueryPrefix   -> "SELECT * FROM users WHERE username = '"
QuerySuffix   -> "'"
username  -> GETuser
GETuser  -> [a-zA-Z0-9_]+

// Taint Annotation:
// GETuser derives from $_GET, which is a direct source.
// The input from the database is indirect.

direct        = { GETuser }
indirect      = { }
```  
  
之后他们将首先考虑最常见的字符型SQL注入和数字型SQL注入的情况。将依次检查上述文法中每个带有污点的非终结符  
X  
（direct  
和indriect  
集合中的）能够推导出的语言是否与指定的正则语言存在交集（使用特定的算法），包括4个检查（检查1，3，4在得到不安全结果时停止，检查2在得到安全结果时停止）：  
- 字符型  
- 1.带有污点的非终结符生成的字符串是否可能带有奇数个未转义引号。如果是的话则可以视为不安全。  
- 2.生成的整个SQL中，是否带有污点的非终结符生成的部分都位于SQL的字符串位置并且其中的引号都会被转义。如果不是的话视为不安全的。这步会把GETuser  
替换成一个终结符tX  
，然后从SQLQuery  
开始推导（另外3个检查都是从GETuser  
开始推导），也就是考虑了sink点所处的上下文。这个检查对应的情况是攻击者可以闭合SQL中原有的引号，此时即使是偶数个引号也是不安全的。  
- 数字型  
- 3.带有污点的非终结符是否仅能衍生出数字字面量，是的话则视为安全的。  
- 4.带有污点的非终结符是否存在能生成类似DROP WHERE  
、--  
这种危险 SQL 语句片段，存在的话则视为不安全。这步是对上一步的补充。  
如果还存在带有污点的非终结符 X 没有确定安全或不安全，接下来还将考虑用户可控输入位于SQL其他位置的情况（比如order by  
注入）。此时将考虑以 X 为根的子文法以及所有包含  
X  
  
的句子形式（sentential forms）是否被标准SQL文法的某些非终结符覆盖（也就是前者能够生成的字符串后者都能生成）。如果是的话则是安全的，因为这说明  
X  
  
生成的可能字符串在其上下文中时，会形成单一的句法结构。尽管判断文法的包含关系是一个不可决策问题，但可以采用近似的处理方法。  
  
Ji等人在针对SSRF漏洞的Artemis中引入了外部的SMT solver来处理这个问题[21]。他们在污点分析后额外对生成的污点路径进行误报检查，提取其中的控制流约束并转换为SMT公式进行求解，判断一个合法的URL是否能够满足这些约束。这种依赖外部求解器的方法与下一节将要介绍的使用符号执行实现利用生成的方法有一定的相似之处，但因为没有实现路径敏感只实现了控制流敏感所以更加轻量级，更多细节放在下一节介绍。  
## 5.3 利用生成  
  
一些工作更进一步，在兼具了前两节的方法的同时还能够生成漏洞利用以便于进一步的动态验证。这通常需要使用符号执行策略来实现路径敏感，因为此时我们需要更加精确的考虑程序真实执行时的路径，而非之前在条件分支交汇处进行合并得到的抽象路径。我们用以下例子来说明如何使用符号执行来做到路径敏感以及利用生成。上一节仅仅实现了控制流敏感的方法会在C造成误报。因为合并条件分支会使得$is_safe  
的抽象域变成true|false  
，导致无论正则是否匹配成功都会进入第2个分支到达sink。  
```
<?php
// ...
$username = $_GET['user'];
$action = $_GET['action'];

// 只允许字母、数字和下划线
$pattern = '/^[a-zA-Z0-9_]+$/';

if (preg_match($pattern, $username))
    $is_safe = true; // A
else
    $is_safe = false; // B

if($is_safe && $action == "show") {
    // C
    $sql = "SELECT * FROM users WHERE username = '" . $username . "'";
    mysqli_query($db_conn, $sql);  // safe
}
else {
    // D
    $output = str_ireplace("script","",$username);
    echo $output; // unsafe
}
?>
```  
  
符号执行中的"符号"表示将未知的用户输入表示为符号值  
GETxxx  
，"执行"则意味着像具体执行一样一次执行完整的一条路径（Lazy Evaluation的情况下），该例子中将得到3条路径需要最终交给外部求解器判断是否可行：  
- A + C，最终状态和收集到的约束条件Cond为  
```
$username = GETuser
$action = GETaction
$pattern = '/^[a-zA-Z0-9_]+$/';
$is_safe = true
$sql = "SELECT * FROM users WHERE username = '". GETuser. "'"

Cond: preg_match($pattern, GETuser) == true && GETaction == "show"
```  
- A + D  
```
$username = GETuser
$action = GETaction
$pattern = '/^[a-zA-Z0-9_]+$/';
$is_safe = true
$output = str_ireplace("script","",GETuser)

Cond: preg_match($pattern, GETuser) == true && GETaction != "show"
```  
- B + D  
```
$username = GETuser
$action = GETaction
$pattern = '/^[a-zA-Z0-9_]+$/';
$is_safe = false
$output = str_ireplace("script","",GETuser)

Cond: preg_match($pattern, GETuser) == false
```  
  
注意这里不会生成B + C路径，因为$is_safe  
为false  
会使得第二个条件判断必然为假，因此该路径肯定不可行。另外3条路径因为在Cond中包含了符号值，需要引入外部求解器才能判断是否可行。  
  
在求解进行前可以先进一步考虑如何生成利用。在A + C中因为符号值  
GETuser  
  
被单引号包裹并且是SQL注入漏洞（使用类似于5.1节中的方法），可以在提前定义好的攻击字典中搜索对应情况的payload，如foo' OR '1'='1  
。结合A + C路径的约束得到如下SMT公式：  
```
(declare-const GETuser String)
(declare-const GETaction String)

(assert
  (and
    ; 1. 路径 A+C 的约束条件: preg_match($pattern, GETuser) == true
    (str.in.re GETuser
      (re.+
        (re.union
          (re.range "a" "z")
          (re.range "A" "Z")
          (re.range "0" "9")
          (str.to.re "_")
        )
      )
    )

    ; 2. 路径 A+C 的约束条件: GETaction == "show"
    (= GETaction "show")

    ; 3. 漏洞利用/Payload 条件
    (= GETuser "foo' OR '1'='1")
  )
)

(check-sat)
; (get-model)
```  
  
因为这里实际上不存在漏洞，SMT solver将返回UNSAT。  
  
A + D和B + D也是类似，以B + D求解<script>alert(1);</script>  
为例：  
```
(declare-const GETuser String)
(declare-const GETaction String)
(declare-const $output String)

(assert
  (not
    (str.in.re GETuser
      (re.+
        (re.union
          (re.range "a" "z")
          (re.range "A" "Z")
          (re.range "0" "9")
          (str.to.re "_")
        )
      )
    )
  )
)

; The most popular z3 solver does not currently support str.replace_all, just an example
(assert (= $output (str.replace_all GETuser "script" "")))
(assert (= $output "<script>alert(1);</script>"))

(check-sat)
(get-model)
```  
  
SMT solver将能够搜索到类似<scrscriptipt>alert(1);</scrscriptipt>  
这样的结果  
  
目前我们只关注了单个请求漏洞的情况。Session, 文件和数据库等持久性存储还将引入更复杂的多请求漏洞。除了第4节提及的二阶漏洞外，来自它们的值也可能出现在约束之中。在下面的例子中，vulnerable_feature.php中的xss漏洞需要满足约束if (!isset($_SESSION['loggedin']) || $_SESSION['loggedin'] !== true || $_SESSION['role'] !== 'admin' || !$from_dashboard)  
，也就是需要先按顺序访问login.php和dashboard.php。但是模块间的请求顺序存在大量可能的组合，而每个模块内部又存在非常多条路径。如果直接穷举模块的组合需要考虑的路径数量会指数级增长，导致路径爆炸的问题。  
```
<?php
// login.php
session_start();

$message = '';
$user = $_POST['username'] ?? '';
$pass = $_POST['password'] ?? '';

// 简化认证
if ($user === 'admin' && $pass === 'password') {
    // Path L1: 登录成功
    $_SESSION['loggedin'] = true;
    $_SESSION['role'] = 'admin';
    header('Location: dashboard.php'); // 重定向到 dashboard
    exit;
} else {
    // Path L2: 登录失败
    $message = 'Invalid credentials';
}
?>
<form method="post" action="login.php">
    Username: <input type="text" name="username"><br>
    Password: <input type="password" name="password"><br>
    <button type="submit">Login</button>
    <?php echo $message; ?>
</form>
```  
```
<?php
// dashboard.php
session_start();

// Path D1: 检查 Session - 必须登录
if (!isset($_SESSION['loggedin']) || $_SESSION['loggedin'] !== true) {
    header('Location: login.php'); // 未登录则重定向回 login
    exit;
}

// Path D2: 检查角色 - 必须是 admin
if ($_SESSION['role'] === 'admin') {
    // Path D2a: Admin 路径 - 设置 from_dashboard 标记
    $_SESSION['from_dashboard'] = true; // 设置标记
    echo "Welcome, Admin!<br>";
    echo '<a href="vulnerable_feature.php?data=default">Access Admin Feature</a>';
} else {
    // Path D2b: 非 Admin 路径
    echo "You do not have access to the admin feature.";
}
?>
```  
```
<?php
// vulnerable_feature.php
session_start();

// Path V1: 检查 Session, 角色 和 from_dashboard 标记
$from_dashboard = $_SESSION['from_dashboard'] ?? false;

if (!isset($_SESSION['loggedin']) || $_SESSION['loggedin'] !== true || $_SESSION['role'] !== 'admin' || !$from_dashboard) {
    echo "Access Denied.";
    exit;
}

// Path V2: 已验证为 Admin 且来自 Dashboard - 处理输入并输出 (存在 XSS Sink)
$userData = $_GET['data'] ?? 'nothing';
echo "Admin Feature Data: " . $userData; // 漏洞点 (Sink) - 未净化 $userData
?>
```  
  
Chainsaw结合了启发式的路径搜索和基于模块间的依赖关系的剪枝来解决这个问题[27]。他们的方法如下：  
- Seed Generation：首先对每个模块中从source到sink的路径依次进行符号执行，并对其中不涉及到其他模块的本地约束（也就是与持久性存储无关的约束）先进行求解，排除一些明显不可利用的漏洞。剩下可能能够利用的漏洞称为seed。  
- 在上面的例子中将首先假设所有Session 条件已经满足，仅仅对$_GET['data']  
求解得到潜在的payload  
data=<script>alert(1)</script>  
- 之后将建立一个称为General Workflow Graph (GWFG)的有向图。其中每个节点代表一个模块，每条边除了表示模块间的导航关系（重定向，表单提交，超链接...）外，还标记了目标模块中的路径数量（记录其对数$log_2N$）。Chainsaw将在GWFG中查找能够通向包含seed的模块的路径。因为此时存在非常多的可能，将使用最短路径算法优先处理条件路径总数较少的模块组合，也就是优先选择路径总数较少的导航序列。  
- 上面的例子将生成如下导航图，其中从login.php到vulnerable_feature.php的最短路径将是login.php -> dashboard.php -> vulnerable_feature.php  
- 如果一个多请求利用中的两个模块间没有任何的导航关系，则会被Chainsaw漏掉  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CSyEGWNz8kvTQS3A0ZWziaZeBOFkiciaibWiaVFWKmqjSh1Y8vMaicO0GeCQrryK1IQ6zMLytSW9cMhT53ic4g1PF6Whw/640?wx_fmt=png&from=appmsg "")  
- 对于每个GWFG中选择出的导航序列，Chainsaw将再构造一个细化的Refined Workflow Graph (RWFG)，其中的每个节点是一个模块中的一条路径，边则仍然表示它们之间的导航关系。每个节点上还带前置条件（Preconditions）和路径摘要（Path Summary）。他们分别代表执行该路径需要满足的约束条件和执行该路径后对全局状态的影响或赋值。一条无法满足其节点前置条件的RWFG边将被去除。剩下的RWFG路径将被逐一送往求解器验证其可行性并生成包含多个HTTP请求的利用。  
- login.php -> dashboard.php -> vulnerable_feature.php对应的RWFG如下。可以看到其中唯一的路径上每个节点的前置条件都由其前驱节点的摘要满足。  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CSyEGWNz8kvTQS3A0ZWziaZeBOFkiciaibWiaDic8Udtjo2mvHCpP0SOErgm3sL1yBVicOiappAEueGydG79vRO52gEoicA/640?wx_fmt=png&from=appmsg "")  
  
Navex则结合了动态的方法来解决这一问题[28]。在类似于Chainsaw的Seed Generation阶段后（已经获得了潜在的payload），他们使用爬虫来生成导航图。符号执行将分别在客户端（针对JS约束）和服务端（通过Xdebug获取执行路径）辅助爬虫最大化代码覆盖率，比如求解出上面例子中的用户名和密码是admin  
和password  
。上面例子将获得如下导航图：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CSyEGWNz8kvTQS3A0ZWziaZeBOFkiciaibWiaiaGRUDlpx9NjDgjXoHlfianuWzTQegibXxwcwcGNMAeib41sdfwguQKeDA/640?wx_fmt=png&from=appmsg "")  
  
此时只需要将login.php -> dashboard.php -> vulnerable_feature.php的请求序列中最后一个请求的data换成之前求解到的payload即可得到整个利用。这种方法和Chainsaw方法的关系类似于静态符号执行和动态符号执行的关系，后者能够获得更好的效率。  
# 6.自动内置函数建模  
  
由于PHP的内置函数通常由C语言编写，针对PHP SAST工具无法直接分析其内部实现。这就要求无论是数据流分析还是符号执行，都必须对这些函数进行建模。不同的分析技术关注函数行为的不同侧面，因此需要采用不同的建模策略。例如，污点分析侧重于追踪数据污染状态的传播，因此其模型需定义清晰的污点传递规则；而字符串分析则要求模型能精确模拟字符串操作函数（如  
substr  
,  
concat  
）对字符串值的具体变换；对于旨在生成漏洞利用的符号执行，则需要将函数的完整语义转化为SMT约束公式，以便进行路径探索和求解。以往PHP SAST的研究大多依赖手工为内置函数构建模型，但手工建模天然存在覆盖范围的局限，导致模型往往不够全面或精确。下面介绍两种自动化建模内置函数的思路。  
## 6.1 C 程序分析  
  
一种自动化建模PHP内置函数的策略是基于C程序分析的方法对其实现进行分析。Li等人[29]提出了一种基于程序合成的方法，在PHP符号执行中自动建模内置函数。其工具XSym将PHP符号执行生成的约束求解任务转换为C程序，该程序集成了相关PHP内置函数的C实现，并利用C符号执行引擎（如KLEE[30]）进行分析。他们指出由于PHP语言的复杂性和动态特性，直接将整个PHP应用转换为对应的C程序是极其困难甚至不可行的。但仅仅转换PHP符号执行过程中产生的约束求解任务到C程序则相对容易。因为PHP是没有类型限定符的弱类型语言，XSym通过一种类型推断算法获取其对应C实现中的类型：  
- 基于操作符和函数签名的初始推断：根据约束中出现的PHP操作符（例如，算术操作符+  
  
的操作数倾向于数字类型，字符串连接符  
.  
  
的操作数和结果为字符串类型）以及PHP内置函数已知的参数和返回值类型签名，对相关变量进行初步的类型推断。  
- 基于比较操作符的推断：分析比较操作符（如==  
），通常假设参与比较的操作数具有相同的类型，这有助于推断出更多变量的类型。  
- 迭代类型传播：将已确定类型的变量放入一个集合，并通过类型约束关系（例如，在比较中被认为类型相同的变量）进行迭代传播，直到没有更多变量的类型可以被推断出来。对于最终仍无法确定类型的变量，会设置一个默认类型（如字符串）。  
此外，为了确保转换后的C程序和原PHP约束的语义等价，他们还将PHP特有的运算符映射到其底层C语言实现的对应函数（例如，PHP中的字符串连接运算符.  
  
映射到PHP解释器内部的  
php_concat()  
函数）。这种方法的一大优势是能够复用相对成熟的C符号执行，无需重新实现符号执行工具。  
  
Jahanshahi和Egele则提出了一个自动识别污点分析PHP内置函数sink点的工具Argus[31]。他们的方法如下：  
- 首先对PHP解释器及其扩展的已编译二进制文件进行反汇编，并利用调试符号和动态链接时解析的库函数地址信息，来识别函数间的直接调用和对外部库函数的调用关系，从而静态地构建出一个初始的函数调用图。  
- 仅靠静态分析难以处理PHP解释器中广泛存在的间接调用（如函数指针、流处理器的动态分派），因此Argus接着运行PHP官方测试套件，并使用uftrace等工具追踪记录运行时函数调用轨迹从而完善调用图。  
- 基于调用图，Argus从已知的底层敏感操作函数VIFs（例如命令执行的execve  
和phar反序列化的php_var_unserialize  
）进行反向可达性分析从而识别出候选sink点。  
- Argus为每个候选sink生成特定的PHP测试代码片段，用精心构造的输入（如phar://...  
）调用该API，并检查执行结果，判断是否为有效sink点。  
类似这种对PHP解释器进行静态分析和动态验证的方法可能也可以推广到其他的数据流分析的内置函数建模中，比如自动化生成污点分析中的sanitizer规则，不过可能需要更加复杂的分析方法。  
## 6.2 具体执行  
  
另一个自动处理PHP内置函数的思路是采用具体执行策略。Yama[15]采用了这种策略，在遇到难以通过纯静态方法精确建模其复杂语义（例如  
parse_str  
）或其返回值严重依赖运行时环境（例如  
get_include_path  
）的内置函数时，Yama会调用其具体执行模块，在受控的环境下实际执行这些函数，以期获得更精确的返回值和副作用信息。不过他们的论文省略了在具体执行前后，静态分析中的符号值与执行所需的具体值之间如何相互转换的机制说明，也没有提供触发具体执行的完整函数列表，需要等待Yama开源才能了解到他们方法的更多细节。  
# 7.Benchmark  
  
目前，关于PHP SAST的研究尚未出现一个统一的Benchmark，许多过去的研究主要依赖在一系列真实应用上的表现作为评估标准。这在一定程度上不利于直接对比这些工作，因为每个研究可能选择了对其工具更有利的应用进行评估（比如他们支持的某种特性在这些应用中出现频率较多）。此外，大部分研究也没有进行消融实验，使得我们很难确定其创新点在评估中的具体贡献。  
  
Nunes等人曾提出了一个基于134个WordPress插件的Benchmark[32]，但他们只公开了插件列表而未提供漏洞细节，这给后续研究基于其工作进行评估带来了困难。同时，仅使用WordPress插件也可能无法覆盖所有PHP应用场景。  
  
Al Kassar等人[16]则总结了122个对PHP SAST而言较难处理的PHP代码模式（称为"Testability Tarpits"），涵盖了内置函数建模、面向对象特性以及动态特性等方面，并通过扫描数千个PHP应用量化了它们对SAST工具的潜在影响。这些Testability Tarpits可以作为一种PHP SAST Benchmark，用于对比不同SAST工具对特定代码模式的支持程度。将这种基于特性的评估与传统的真实应用漏洞挖掘评估相结合，可能能够更全面地体现SAST工具的能力。在较新的研究Yama[15]中，我们已经看到了对Testability Tarpits在实验部分的使用。此外Yama还设计了一个数据集用于评估SAST在数据流分析方面的能力，例如是否实现了流敏感和上下文敏感，不过还没有开源。  
  
  
关注我获取更多......  
  
  
  
  
  
  
  
