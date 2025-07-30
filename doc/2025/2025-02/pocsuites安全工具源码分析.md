#  pocsuites安全工具源码分析   
原创 大白  蚁景网络安全   2025-02-17 09:43  
  
**pocsuite3 是由 知道创宇 404实验室 开发维护的开源远程漏洞测试和概念验证开发框架。为了更好理解其运行逻辑，本文将从源码角度分析该项目的初始化，多线程函数，poc模板等等源码**  
# 项目结构  
  
![IMG_256](https://mmbiz.qpic.cn/mmbiz_jpg/5znJiaZxqldydQmSslgMg5at3lUYlTlib9LUVAw0ibVZy0pFtggoUxhckQyotpenOIiahH3Gu7cOE7LQYdGq5FGtgQ/640?wx_fmt=other&from=appmsg "")  
  
api：对要导入的包重命名，方便后续导入调用
data：存储用户需要使用的文档数据
lib：项目核心代码
modules：存储用户自定义的模块
plugins：存储用户自定义的插件
pocs：存储poc文件
shellcodes：存储生成php，java，python等脚本语言的利用代码，以及反弹shell的利用代码
cli.py：项目的入口
console.py：命令行界面  
  
进入项目入口：/pocsuite3/cli.py  
  
![IMG_257](https://mmbiz.qpic.cn/mmbiz_jpg/5znJiaZxqldydQmSslgMg5at3lUYlTlib9hhP6h1Yr2yALRhibLIx1keOg8MZHZx2gg96ApFGPUU0FicC4SWuEGMbg/640?wx_fmt=other&from=appmsg "")  
 check_environment() #检查当前工作目录是否符合当前系统
set_paths(). #设置后续需要用到的数据，目录信息
banner() #打印命令行页面的横幅  
  
init_options(cmd_line_parser().**dict**) # 命令行参数处理
跟进cmd_line_parser()查看：  
  
![IMG_258](https://mmbiz.qpic.cn/mmbiz_jpg/5znJiaZxqldydQmSslgMg5at3lUYlTlib9pYiajcqWiap76GfakbhJ1iaZNiccPBHMGp6VO5Jv5LB4U87crHdFjOxxEQ/640?wx_fmt=other&from=appmsg "")  
此处注意一个参数-c
target.add_argument("-c", dest="configFile", help="Load options
from a configuration INI file")
可以先在pocsuite.ini配置好参数，通过pocsuite -c pocsuite.ini 运行  
  
![IMG_259](https://mmbiz.qpic.cn/mmbiz_jpg/5znJiaZxqldydQmSslgMg5at3lUYlTlib9LibPzusQAtuqdNrcKaDWRvXuBQpqj6IU1KX5ia3JHNOlNtiaXS4uthUZg/640?wx_fmt=other&from=appmsg "")  
  
双重跟进init_options()，找到命令行存储参数：  
  
![IMG_260](https://mmbiz.qpic.cn/mmbiz_jpg/5znJiaZxqldydQmSslgMg5at3lUYlTlib96XdGLIOb1mWU3xzncN22h7vusdJPn4VmhghUKWCny4upImdicGicicPAA/640?wx_fmt=other&from=appmsg "")  
可见采用了类似字典的形式存储，避免了重复数据
且还有其它四个参数也采用了该形式存储，五个参数贯穿整个项目  
  
conf：存储基本配置信息
kb：存储了目标地址、加载的PoC、运行模式、输出结果、加载的PoC文件地址、多线程信息等
cmd_line_options：是存储命令行输入的参数值
merged_options：存储输入值与默认值合并后的结果
paths：存储数据、插件、poc等目录地址  
  
参数获取处理完后，进入项目初始化，init()函数，一下对部分函数进行注解分析：  
  
def init():  
  
"""  
  
Set attributes into both configuration and knowledge base singletons  
  
based upon command line and configuration file options.  
  
"""  
  
set_verbosity() #日志输出级别设置  
  
_adjust_logging_formatter() #调整日志格式器  
  
_cleanup_options() #将各个配置项格式化，并校验合法性  
  
_basic_option_validation() #校验seebug,zoomeye等api,token的合法性  
  
_create_directory() #检测文件路径是否存在，不存在则创建  
  
_init_kb_comparison()  
  
update()  
  
_set_multiple_targets() #读取目标  
  
_set_user_pocs_path()  
  
_set_pocs_modules() #动态加载poc  
  
_set_plugins() #动态加载插件  
  
_init_targets_plugins()  
  
_init_pocs_plugins()  
  
_set_task_queue() #初始化多线程设置  
  
_init_results_plugins() #初始化输出插件  
# AttribDict类解析  
  
前文也提到过以下五个全局变量，它们均通过创建AttribDict类的实例进行使用，现在我们跟进类详细分析：  
  
![IMG_256](https://mmbiz.qpic.cn/mmbiz_jpg/5znJiaZxqldydQmSslgMg5at3lUYlTlib9YqD7OJguA29Io8hibOVAPg0H4Gb86coNuYwaNlrgjDoYoGV9A3oia84Q/640?wx_fmt=other&from=appmsg "")  
  
AttribDict()类：  
  
![IMG_257](https://mmbiz.qpic.cn/mmbiz_jpg/5znJiaZxqldydQmSslgMg5at3lUYlTlib9YXh8JvwL2Fr36H8akzj31VF0uuY2XTulZ1xPeO92S9qiaLGbt0FPxGQ/640?wx_fmt=other&from=appmsg "")  
  
自定义类，继承自python内建的OrderedDict类，扩展访问方式，简化了对字典键的访问。主要存在三个方法：**getattr**(),**setattr**(),**delattr**()
这三个方法在if判断逻辑均相同：1:以双下划线 __ 开头（例如，Python 的内置属性，如 **dict**）。2:以 OrderedDict_ 开头（因为 OrderedDict
在内部实现中使用的名称）。3:名字存在于 **exclude_keys** 集合中（排除的键）。如果任一条件成立，说明这个属性不应该通过 obj.attr
访问，所以跳过使用自定义的 **getattr**处理，直接调用父类对应的方法访问。例：**getattr**()就调用父类的__getattribute__()访问  
  
如果属性名不满足，则通过字典的方式，添加或者删除AttribDict中  
  
![IMG_258](https://mmbiz.qpic.cn/mmbiz_jpg/5znJiaZxqldydQmSslgMg5at3lUYlTlib9icgtHmxhypUkCwBd1zA5jRic1J3g0kTvg1mpuBYHVD615ibyMrjhqBibHA/640?wx_fmt=other&from=appmsg "")  
# 地址处理代码分析  
  
![IMG_256](https://mmbiz.qpic.cn/mmbiz_jpg/5znJiaZxqldydQmSslgMg5at3lUYlTlib9HKV0yjHj9pIuug15ziawpP6SibrGfchPyAF5oDwqkoy2LiaIFicSEy0qvw/640?wx_fmt=other&from=appmsg "")  
先查看存储初始数据，存在则进行下一步。通过set()创建集合方便去重，再遍历conf.url数据，通过parde_target()进行对url进行分析处理，并且在不为空的情况下调用集合的add()方法添加，完成后再将，用于临时存储的target集合里面的数据，放到kb这种全局变量内。parde_target()函数  
  
![IMG_257](https://mmbiz.qpic.cn/mmbiz_jpg/5znJiaZxqldydQmSslgMg5at3lUYlTlib9j5icNgKZPDnibCx3Vnbd3yr6MlyriaX7KiciaMiaZcuNy0hpsuhicXeKEdyhw/640?wx_fmt=other&from=appmsg "")  
  
接受参数后先if判断，如果是域名，url，ip:端口形式则直接赋值给target
跟进其中一个判断函数：  
  
![IMG_258](https://mmbiz.qpic.cn/mmbiz_jpg/5znJiaZxqldydQmSslgMg5at3lUYlTlib9okFp1mqxd2xmxAOju3QnWcJ1icaORklhrMHf2EUek4dB1A6f6I3ic1jA/640?wx_fmt=other&from=appmsg "")  
  
跟进：  
  
![IMG_259](https://mmbiz.qpic.cn/mmbiz_jpg/5znJiaZxqldydQmSslgMg5at3lUYlTlib9TA2xhRXUKsXnYh8g4RnuRdgDbhiaM8v3mdIBRLrzibZpJgsfcGXLOycA/640?wx_fmt=other&from=appmsg "")  
可见是通过正则进行判断。接着再判断如果为http://ipv6形式，则启动ipv6配置，并进行赋值target，依旧是正则判断。  
  
再判断如果为ipv4则调用python内置ip_address解析赋值，该方法自动区分ipv4或者ipv6并最后返回对应的对象。再通过else判断，对纯ipv6地址，或者ipv6网络进行解析赋值。  
# 动态poc加载  
  
![IMG_256](https://mmbiz.qpic.cn/mmbiz_jpg/5znJiaZxqldydQmSslgMg5at3lUYlTlib9jiaLVrib8AicneXFrGzPkSqibZMWdZiagA96jr2ibRvOlIXFz7wXNA4lYEicA/640?wx_fmt=other&from=appmsg "")  
Step1：从pocs目录加载
先通过os.listdir读取对应目录，返回一个含有poc的py文件的列表。再通过filter()函数过滤__init__.之类文件，不过此时filter()函数返回的是一个迭代器，所以又通过list()函数将数据处理成列表再赋值。（lambda x: x not in ['**init**.py',
'**init**.pyc']：这个匿名函数会检查每个文件名 x 是否不等于
'**init**.py' 或 '**init**.pyc'。）  
  
再从含有类似thinkphp_poc.py的文件名中，通过x变量循环读取，并通过splitex()函数将其分为"thinkphp_poc",".py"格式的键值队元组。再次通过dict()字典函数，将x元组的第一个元素作为字典的键，第二个元素作为字典的值。  
  
如果poc是目录，则使用 os.walk() 递归遍历该目录下的所有文件，过滤出 .py
或 .yaml 文件，并将其完整路径添加到 _pocs 列表中。  
  
Step2：遍历加载 PoC 文件内容并检查，并对加载失败的poc进行日志记录。  
  
Step3：最后从 Seebug 网站加载 PoC。  
  
poc模版
跟据目录找到现存poc：pocsuite3/pocs，thinkphp_rce为例  
  
![IMG_257](https://mmbiz.qpic.cn/mmbiz_jpg/5znJiaZxqldydQmSslgMg5at3lUYlTlib9QkOqO0y7KE8XPCvO6J9S8IXOWyjMgeUuhTGjwTR9lYzkDsdD8qgjsg/640?wx_fmt=other&from=appmsg "")  
  
所有模版均是继承自父类POCBase，跟进：  
  
![IMG_258](https://mmbiz.qpic.cn/mmbiz_jpg/5znJiaZxqldydQmSslgMg5at3lUYlTlib9HPJFKtIADlKWXUDleP19ibvSrHNZY8YIEoiauFTRFib3u11tNV3lOLWAQ/640?wx_fmt=other&from=appmsg "")  
父类在初始化时便设置了一系列可能用到的属性，例如自定义headers，目标url，端口等等。这里关注execute()函数  
  
![IMG_259](https://mmbiz.qpic.cn/mmbiz_jpg/5znJiaZxqldydQmSslgMg5at3lUYlTlib9wvW2wQhpktPnxWmYibkyq5Tx8eeRlc8KlyiaLC2ibGecO5yXucRQdJdAQ/640?wx_fmt=other&from=appmsg "")  
self.url处采用if判断：如果为http协议则采用parse_target_url()解析，else采用build_url()解析：mode值默认为verify。随后调用_execute()根据mode值执行。  
  
![IMG_260](https://mmbiz.qpic.cn/mmbiz_jpg/5znJiaZxqldydQmSslgMg5at3lUYlTlib9pziakUkSumBLC80VlGPwFkbGl5sNrQk57E5ib1S5UMRnyGZPTWACaVWA/640?wx_fmt=other&from=appmsg "")  
 _shell()，_attack()，_verify()均需自定义重写。回到例thinkphp_rce例子：_verify()函数如下：  
  
![IMG_261](https://mmbiz.qpic.cn/mmbiz_jpg/5znJiaZxqldydQmSslgMg5at3lUYlTlib9cnXyicEzTxwYZOUaciaIwF8O3yH3CpMvAUp5T1oibRsic2QVXAXRU3g7fw/640?wx_fmt=other&from=appmsg "")  
调用了_check()函数进行检验：  
  
![IMG_262](https://mmbiz.qpic.cn/mmbiz_jpg/5znJiaZxqldydQmSslgMg5at3lUYlTlib9ovmPQkmUDJibnwxektiauOrrBZtnmKKrLEZC2wjlDHEaPicoribDHboOYg/640?wx_fmt=other&from=appmsg "")  
  
通过request.post()发送设置好payload的请求，根据返回包关键字判断是否成功。（flag自定义）
返回的结果在_verify()函数又会调用parse_output()转化为json格式输出。  
  
动态核心load_file_to_module()
继续分析_set_pocs_modules()  
  
![IMG_263](https://mmbiz.qpic.cn/mmbiz_jpg/5znJiaZxqldydQmSslgMg5at3lUYlTlib9Wwjyyc9icMFffExEHo0ibRGPicXEw9PAZvic32U0OlHV4z0UOPkPjKEVMg/640?wx_fmt=other&from=appmsg "")  
将读取文件切割为文件名和后缀名，根据后缀名重构路径file_pth，if判断file_path构建成功则进入红框代码处。  
  
![IMG_264](https://mmbiz.qpic.cn/mmbiz_jpg/5znJiaZxqldydQmSslgMg5at3lUYlTlib9GyvKbB7xOgWpK6mlibS9HKicCicOvaad2VRcZ6rWvTSiaAYKMibNMTFEzQg/640?wx_fmt=other&from=appmsg "")  
  
通过get_filename()从file_path路径提取文件名，由于wuth.ext=False，则不提取文件名后缀，提取后拼接在pocs_后并赋值给module，例如：pocs_thinkphp_rce。随后三行代码涉及到python中动态模块加载知识：  
  
spec = importlib.util.spec_from_file_location(module_name, file_path,
loader=PocLoader(module_name, file_path))  
  
#创建模块规格，采用自定义加载器类加载模块，loader:加载器对象，负责如何从文件加载模块  
  
mod = importlib.util.module_from_spec(spec)#根据规格创建模块对象  
  
spec.loader.exec_module(mod) #执行模块代码，确保为完整可用的模块  
  
动态模块注解：  
  
模块是包含 Python 代码的文件，可以通过 import
语句加载并使用。通常，当你使用 import 语句导入一个模块时，Python
会根据模块的名称查找相应的文件（如 .py 文件），并将其加载到内存中。  
  
然而，在一些特殊的情况下，比如动态加载模块或运行时创建模块，我们需要用到
importlib 模块。importlib
提供了一些工具，可以帮助我们在运行时加载模块，而不是在编写代码时静态地导入。  
  
例如：importlib.util.spec_from_file_location  
  
spec（模块加载规格）描述了如何加载一个模块。它定义了如何找到模块代码，如何加载它，以及加载时需要的一些元数据。类似于说明书，它告诉
Python 模块在哪里、叫什么名字、以及如何加载它。  
  
接着看看是如何调用loader加载器的exec_module()函数进行加载的：  
  
![IMG_265](https://mmbiz.qpic.cn/mmbiz_jpg/5znJiaZxqldydQmSslgMg5at3lUYlTlib94ibIttfvXwkCicHrLOAToKSrZyiaBM4h7d36EPPAgZS7a0MWoOU6jmk6w/640?wx_fmt=other&from=appmsg "")  
  
filename接受poc绝对路径，poc_code接受poc文件内容。随后调用check_requires()检查代码运行中需要的包，通过__import__函数导入。compile()为python内置函数，将源代码字符串poc_code编译为字节码，'exec'这是一个编译模式，表示代码将作为一段可执行的代码被执行。常见的编译模式有
'eval'（用于单个表达式）和 'exec'（用于整个代码块）
之后再调用exec()函数执行字节码对象obj当中的代码，并绑定到module.__dict__上，这样就可以通过module.函数()直接调用poc_code当中的函数。  
# 多线程与输出加载  
  
跟进：_set_task_queue()  
  
![IMG_256](https://mmbiz.qpic.cn/mmbiz_jpg/5znJiaZxqldydQmSslgMg5at3lUYlTlib9mDgYibkX5BYbsoBketWLLSAlbE8aw0UibL6jo5ql0ykWPMT9tO3TzgibQ/640?wx_fmt=other&from=appmsg "")  
if判断，poc模版与目标ip均不为空情况下，遍历出poc_module与target。并将它们组成元组，加入kb.task_queue中，确保数据在线程安全传输。  
  
start()函数  
  
![IMG_257](https://mmbiz.qpic.cn/mmbiz_jpg/5znJiaZxqldydQmSslgMg5at3lUYlTlib9UO5aAgc1bPuWFLsYPh9MowibxfjK05fJmA4qCzydicPYNn2FsuLWs83A/640?wx_fmt=other&from=appmsg "")  
  
调用runtime_check()检查poc是否加载成功：  
  
![IMG_258](https://mmbiz.qpic.cn/mmbiz_jpg/5znJiaZxqldydQmSslgMg5at3lUYlTlib9Y1DQ2YYdPZYU4VfGNhVFqePSsXqtTraYc0OSr6klyMaen84A8af8sw/640?wx_fmt=other&from=appmsg "")  
  
再调用python标准库中的queue.Queue类的qsize()方法，获取先前kb.task_queue队列的任务数量。run_threads()函数
随后进入start()函数核心：run_threads(conf.threads, task_run)：该函数传入线程数conf.threads()，与多线程执行函数task_run()。  
  
![IMG_259](https://mmbiz.qpic.cn/mmbiz_jpg/5znJiaZxqldydQmSslgMg5at3lUYlTlib9pqCLWAPUax0QYGjycwSzDaXVjEpjeUmicFcbjFtCjKh3w3VqLwbVIicg/640?wx_fmt=other&from=appmsg "")  
这个函数的目的是启动多个线程并执行给定的函数
thread_function。num_threads: 需要启动的线程数量。thread_function: 要在线程中运行的目标函数。args: 传递给 thread_function 的参数，默认为空元组。forward_exception: 控制是否在捕获异常后继续传播异常，默认值为 True。start_msg: 控制是否输出启动线程的消息，默认值为 True。  
  
先threads = []创建空列表，用来存储后续的线程实例  
  
随后进行线程数检查，如果大于1，则是多线程，并在线程数超过max时发出告警提示，线程不大于1，则直接执行函数  
  
![IMG_260](https://mmbiz.qpic.cn/mmbiz_jpg/5znJiaZxqldydQmSslgMg5at3lUYlTlib9NuB7cLmZsjxFP7y05EicHLUFT19lJHjml6frDUdkfDcv6kIm2asqlUA/640?wx_fmt=other&from=appmsg "")  
检查完为多线程则进行下一步：循环创建线程，并启动  
  
![IMG_261](https://mmbiz.qpic.cn/mmbiz_jpg/5znJiaZxqldydQmSslgMg5at3lUYlTlib9gOgoF4iaFSBOia0Blrf1cK2T8cYfelxXDYKB8qE4D1I50I7b2XmVX2jA/640?wx_fmt=other&from=appmsg "")  
根据num_threads数量循环创建，并调用setDaemon(TRUE)将所有线程设置为守护线程。（守护线程：后台运行，随主线程终止而终止)  
  
![IMG_262](https://mmbiz.qpic.cn/mmbiz_jpg/5znJiaZxqldydQmSslgMg5at3lUYlTlib987pdK7PRnJoxpRX9fBE4vWoOrHoibuyp9qs817KOtN89zJsLvLriaDIw/640?wx_fmt=other&from=appmsg "")  
  
随后再调用python标准库函数isAlive()进行循环检查，直到所有线程完成才跳出循环。(python3建议使用is_Alive()函数)。  
  
![IMG_263](https://mmbiz.qpic.cn/mmbiz_jpg/5znJiaZxqldydQmSslgMg5at3lUYlTlib9cm2wtEEcq9hQxJKGenVBaUia83kFZnblBqJfXxMSweFZF5N3M7QLPZQ/640?wx_fmt=other&from=appmsg "")  
执行完run_threads()函数后，finally代码再执行task_done()，跟进该函数，内部存在三个函数：  
  
![IMG_264](https://mmbiz.qpic.cn/mmbiz_jpg/5znJiaZxqldydQmSslgMg5at3lUYlTlib9mbcF7rxO9bR4QiaamqvM0lQXLcsXW3Lu9HiaOtMgO61SSuiahYMf1gib3g/640?wx_fmt=other&from=appmsg "")  
  
show_task_result()：会取出poc执行结果，然后格式化输出  
  
![IMG_265](https://mmbiz.qpic.cn/mmbiz_jpg/5znJiaZxqldydQmSslgMg5at3lUYlTlib9YBxWlqU0HEicDAMNrMichFOp2usAiawvup1QicPJlKjAZd3nlMFJmSHW1w/640?wx_fmt=other&from=appmsg "")  
  
result_plugins_start():该函数负责调用file_record.py中的start()函数  
  
![IMG_266](https://mmbiz.qpic.cn/mmbiz_jpg/5znJiaZxqldydQmSslgMg5at3lUYlTlib9Nsic4yW8mJsDGZCLGmOmCUXfwzOSGlA0icicibAvZykuVysJ6tsNEpC4qw/640?wx_fmt=other&from=appmsg "")  
  
![IMG_267](https://mmbiz.qpic.cn/mmbiz_jpg/5znJiaZxqldydQmSslgMg5at3lUYlTlib9Jxkva0iapE3wia0Ns8v7RIicTsEL20UybF00YQcuJibu6G22JjABHu5gDw/640?wx_fmt=other&from=appmsg "")  
  
result_compare_handle():显示来自各个搜索引擎的对比数据  
  
![IMG_268](https://mmbiz.qpic.cn/mmbiz_jpg/5znJiaZxqldydQmSslgMg5at3lUYlTlib9TRNRl3ic6sRlgAiaJlu76Az2UBka04qp0Aa81SXRlzoNNBaibtGDZCM1Q/640?wx_fmt=other&from=appmsg "")  
先前已经分析了start(0函数核心在于run_threads(conf.threads,
task_run)，我们接着跟进分析多线程执行函数：task_run()  
  
**多线程执行函数：**  
  
task_run():  
  
![IMG_256](https://mmbiz.qpic.cn/mmbiz_jpg/5znJiaZxqldydQmSslgMg5at3lUYlTlib9VjROCIWjia0ictMckJEWcobfK42yYLibTib8M1M92yAzgBpXzxzRxFAt1A/640?wx_fmt=other&from=appmsg "")  
  
先确认task_queue不为空，并且thread_continue为真，随后从task_queue获取目标ip与poc模版  
  
（之前通过task_queue.put((target,poc_module))存储进去的）  
  
随后调用python标准库copy模块中的deepcpy，进行深拷贝操作，复制poc模版，防止原始poc模块被修改。  
  
poc_name获取poc模块名称方便日志打印。  
  
随后处理用户自定义参数，检查是否尝试修改白名单内容，并校验是否存在必选参数未设置。  
  
![IMG_257](https://mmbiz.qpic.cn/mmbiz_jpg/5znJiaZxqldydQmSslgMg5at3lUYlTlib9CpRAsDicQn5Zn1Micw22bDPUC10za5Io3mRicHhgLbnVA3UFEFo8Juib7w/640?wx_fmt=other&from=appmsg "")  
  
随后进入核心代码块，根据传参调用excute()函数：  
  
![IMG_258](https://mmbiz.qpic.cn/mmbiz_jpg/5znJiaZxqldydQmSslgMg5at3lUYlTlib9YJYUicTyDrpwp7gOyuZABm8BYINEIf2pVb5k3WiaNIia1fA3iaEZJLIDlA/640?wx_fmt=other&from=appmsg "")  
  
后续则是根据测试成功或者失败，对结果进行处理输出  
  
![IMG_259](https://mmbiz.qpic.cn/mmbiz_jpg/5znJiaZxqldydQmSslgMg5at3lUYlTlib9KjW4cZyc8bn7tJCQUw1hxYxYIazk1KicdQNicyksEVbib8emV2yCY4nkw/640?wx_fmt=other&from=appmsg "")  
  
综合文章分析，pocsuite3项目被我分成如下执行流程：![](https://mmbiz.qpic.cn/mmbiz_jpg/5znJiaZxqldydQmSslgMg5at3lUYlTlib9asLUPpdajauw5oRhIDSDcI2GXnTpPluOicQp9ibPHzgafjVX2cDHt8ZA/640?wx_fmt=other&from=appmsg "")  
  
  
在clip.py中调用main()函数，整个项目则开始执行，进行环境检查，参数获取后，则进入核心代码：在main()函数中调用init()与start()函数，最后则是我上文刚分析过的数据处理与输出格式化。  
  
[](https://mp.weixin.qq.com/s?__biz=MzkxNTIwNTkyNg==&mid=2247549615&idx=1&sn=5de0fec4a85adc4c45c6864eec2c5c56&scene=21#wechat_redirect)  
  
  
