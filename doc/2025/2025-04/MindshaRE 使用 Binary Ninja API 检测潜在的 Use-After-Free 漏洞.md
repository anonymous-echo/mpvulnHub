#  MindshaRE: 使用 Binary Ninja API 检测潜在的 Use-After-Free 漏洞   
Reno Robert  securitainment   2025-04-12 05:37  
  
> 【翻译】MindshaRE Using Binary Ninja API to Detect Potential Use-After-Free Vulnerabilities  
  
  
Use-after-free（释放后使用）是一种内存破坏漏洞，当程序在内存被释放回分配器后仍然引用该内存时发生。静态检测这类漏洞具有挑战性。过去已有多种方法尝试解决这个问题，例如 Josselin Feist 的   
GUEB[1]  
 和 Sean Heelan 关于   
使用静态分析发现 use-after-free 漏洞[2]  
 的研究。  
  
本文探讨了如何使用 Binary Ninja 的中级中间语言（Medium Level Intermediate Language, MLIL）通过追踪特定内存分配与其他内存区域之间的交互来建立数据流图。基于该数据流图，我们进一步在跨函数的上下文不敏感可达性分析中使用它，以识别二进制文件中的潜在 Use-After-Free (UAF) 漏洞。与其它静态代码分析方法一样，该方法也存在分类错误。在承认静态代码分析固有的分类错误的同时，我们强调了一些可能也适用于建模其他类型漏洞的基元。  
  
对于对 Binary Ninja API 感兴趣的读者，可以参考我们之前的   
博客文章[3]  
，该文章全面解释了如何使用 Binary Ninja 中间语言（ILs）和静态单赋值（Static Single Assignment, SSA）形式。  
## 构建内存分配的数据流图  
  
在此上下文中，数据指的是与特定内存分配相关联的指针，这是跟踪和分析的主题。数据流信息被可视化为一个图，其中：  
- 节点表示不同的内存区域。  
  
- 边表示在这些区域之间建立关系或交互的指针存储操作。  
  
在本实现中，使用了四种不同类型的节点来构建数据流图，每种节点都有特定的用途：  
  
跟踪分配节点（红色）：  
 表示感兴趣的内存分配，并作为跟踪图中交互的焦点。  
  
函数栈帧节点（绿色）：  
 表示在过程间分析期间访问的各个函数的栈帧。  
  
动态内存节点（蓝色）：  
 表示无法绑定到特定源的静态单赋值（SSA）变量。这些可能包括动态分配的内存或传递给函数的参数，我们在函数范围内缺乏对这些参数的洞察。  
  
全局内存节点（黑色）：  
 不全面跟踪跨函数的全局变量。然而，这些节点有助于分析单个函数内的交互。  
  
图中的边表示指针存储操作，在内存分配之间建立连接。源节点对应于被写入的内存，目标节点表示被存储的指针值。边属性捕获了从分配基地址的偏移量。"write" 属性表示从分配（源节点）基地址的偏移量，指针被写入该位置；"points" 属性表示分配（目标节点）内的偏移量，写入的指针值指向该位置。对于每个唯一的 "write" 或 "points" 属性值，都会创建新的边。对栈内存的写操作使用 Binary Ninja 表示的栈基地址的绝对值表示，因此在大多数架构中会有负偏移量。当 "write" 或 "points" 属性为 0 时，表示分配的基地址。在未解析的内存加载操作期间也会创建额外的边，假设相关的内存存储发生在函数范围之外。这种图形表示有助于理解内存区域如何交互。下面是在分析   
OpenSLP[4]  
 时生成的示例图的一部分，可以更清楚地理解上述细节：  
  
查看完整尺寸  
  
![](https://mmbiz.qpic.cn/mmbiz_png/hoiaQy7WhTCMOrJ5glbHvfqL39ib8UoWC67EOapxCm1MDeOyLr5GpHPib3sbnhaFicwzSrUiaYz8JOcDYEZLCxu6IpA/640?wx_fmt=png&from=appmsg "")  
  
图 1 - 数据图片段  
## 映射 SSA 变量、图节点和边之间的关系  
  
现在我们已经了解了图结构，让我们探讨 SSA 变量如何映射到数据流图中的节点。在我们的自动化分析中，第一个要跟踪的 SSA 变量是分配给分配器调用（如 malloc()  
 或 calloc()  
）返回值的变量。此外，可以开发一个 Binary Ninja GUI 界面，使用户能够标记任意变量进行跟踪并将其包含在进一步的分析中。一旦我们确定了感兴趣的 SSA 变量，就可以利用定义 - 使用链来遍历其在函数内的所有使用。Binary Ninja 提供了 get_ssa_var_definition()  
 和 get_ssa_var_uses()  
 API 来分别检索变量的定义位置及其使用。考虑以下 C 代码及其在 Binary Ninja 中的 MLIL SSA 表示：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/hoiaQy7WhTCMOrJ5glbHvfqL39ib8UoWC61rlC3JDNep19ICccBa4L4k7EV5AQduXRUIaVGDpNGT82Vt8Jy2KjRA/640?wx_fmt=png&from=appmsg "")  
  
在这里，malloc()  
 调用的返回值被写入 SSA 变量 rax#1  
，并且可以使用 get_ssa_var_uses()  
 API 获取 rax#1  
 在函数中的进一步使用：  
```
>>> current_function.get_llil_at(here).mlil.ssa_form<MediumLevelILCallSsa: rax#1, mem#1 = 0x1050(0x10) @ mem#0>>>> current_function.get_low_level_il_at(here).mlil.ssa_form.vars_written[<SSAVariable: rax version 1>]>>> ssa_var = current_function.get_low_level_il_at(here).mlil.ssa_form.vars_written[0]>>> current_function.mlil.ssa_form.get_ssa_var_definition(ssa_var)<MediumLevelILCallSsa: rax#1, mem#1 = 0x1050(0x10) @ mem#0>>>> current_function.mlil.ssa_form.get_ssa_var_uses(ssa_var)[<MediumLevelILSetVarSsa: var_10#1 = rax#1>]
```  
  
一个变量指向一个节点，在此上下文中，rax#1  
 指向跟踪分配节点（红色）。当 rax#1  
 被赋值给 var_10#1  
 时，该信息会传播到 var_10#1  
 以及后续的任何赋值。当变量赋值涉及指针运算时，除了节点信息外，还会存储偏移量信息。在本例中，偏移量为 0，因为所有变量都指向跟踪分配节点的基地址。  
```
{'rax#1_0x11f0': {'node': 'ALLOC', 'offset': 0, 'vartype': 'ALLOC'}, 'rax_1#2_0x11f0': {'node': 'ALLOC', 'offset': 0, 'vartype': 'ALLOC'}, 'var_10#1_0x11f0': {'node': 'ALLOC', 'offset': 0, 'vartype': 'ALLOC'}}
```  
  
函数栈中的 ptr  
 变量由 SSA 变量 var_10#1  
 表示，该变量存储了指向已分配内存的指针。该变量的偏移量可以被提取并表示为图中的一条边。本质上，构建了两个数据结构：一个将 SSA 变量映射到节点的字典，以及一个连接不同内存区域（表示为节点）的图。由于 SSA 变量与其特定函数相关联，因此在过程间分析期间可以跨函数唯一地识别它们。  
```
>>> current_function.get_llil_at(here).mlil.ssa_form<MediumLevelILSetVarSsa: var_10#1 = rax#1>>>> current_function.get_llil_at(here).mlil.ssa_form.operation<MediumLevelILOperation.MLIL_SET_VAR_SSA: 108>>>> current_function.get_llil_at(here).mlil.ssa_form.dest<SSAVariable: var_10 version 1>>>> current_function.get_llil_at(here).mlil.ssa_form.dest.var<var int64_t var_10>>>> current_function.get_llil_at(here).mlil.ssa_form.dest.var.source_type<VariableSourceType.StackVariableSourceType: 0>>>> current_function.get_llil_at(here).mlil.ssa_form.dest.var.storage-16
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/hoiaQy7WhTCMOrJ5glbHvfqL39ib8UoWC6vibV59OYwmncvrfnAvQc6ltws2q0M8wgEibDSoLXfIwXJV4EOF6wU9Vw/640?wx_fmt=png&from=appmsg "")  
  
图 2 - 跟踪分配节点（红色）与栈帧节点（绿色）之间的连接  
  
以下代码片段展示了如何创建跟踪分配节点（红色节点）以及初始化 SSA 变量字典，该字典包含有关 SSA 变量及其引用节点的信息：  
```
    def trace(self):            . . .            # Create a data node for the allocation that's being tracked. Associate a node to a node type.            self.data_graph.add_node(config.MEMALLOC, nodetype = config.MEMALLOC, color = "red")            # Associate the variable holding address of allocated memory to a node as well an offset. For a newly            # allocated memory the variable points to offset 0.            self.setvar(destvar, config.MEMALLOC, 0, config.MEMALLOC)    def setvar(self, destvar, srcnode, srcoffset, srcvartype):        srcvarinfo = dict(node = srcnode, offset = srcoffset, vartype = srcvartype)        destvarindex = self.get_var_index(destvar)        self.vars[destvarindex] = srcvarinfo
```  
  
让我们通过另一个代码示例及其 MLIL（Medium Level Intermediate Language）翻译来理解如何创建动态内存节点（蓝色节点）。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/hoiaQy7WhTCMOrJ5glbHvfqL39ib8UoWC6LMgAwHwr5F4eIPcwTIMh5iae7XZaVyfwqSZRkiaukvrDsjNicnsiajYlJg/640?wx_fmt=png&from=appmsg "")  
  
在函数作用域内，我们无法确定recptr  
指针具体指向的位置。当recptr->link  
被初始化为malloc()  
调用的返回值时，会创建一个动态内存节点，并与跟踪分配节点建立边连接。这对应于 MLIL 指令0000118a [rax_1#2 + 8].q = rdx#1 @ mem#1 -> mem#2  
（MLIL_STORE_SSA），其中边属性包含偏移量信息。变量rax_1#2  
可以通过 SSA（Static Single Assignment）使用 - 定义链追溯到arg1#0  
。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/hoiaQy7WhTCMOrJ5glbHvfqL39ib8UoWC6cC3v5wPJ5lEX53Jl4q56uaTgiaLX7ic1YJZAv8kcvvYxtyb20ycT8gWA/640?wx_fmt=png&from=appmsg "")  
  
图 3 - 跟踪分配节点（红色）与动态内存节点（蓝色）之间的连接  
  
本质上，当遇到内存存储操作如MLIL_SET_VAR_SSA  
、MLIL_STORE_SSA  
或MLIL_STORE_STRUCT_SSA  
时，都会在图中创建边。在 Binary Ninja 的 MLIL SSA 形式中，MLIL_SET_VAR_SSA  
并不严格属于内存存储操作，因为栈写入会被转换为 SSA 变量。然而，这些变量仍然保留偏移量信息，可用于构建数据流图。  
## 将内存加载操作转换为图边  
  
如前所述，内存存储操作被转换为图边，而来自函数作用域外的内存加载操作也会被表示为图边。考虑以下示例：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/hoiaQy7WhTCMOrJ5glbHvfqL39ib8UoWC6H8ndZHgXljt2heHs9ZLBv1BB3GCoTCw5Q7Mud2zOC8fah8R6z9fNnw/640?wx_fmt=png&from=appmsg "")  
  
在函数作用域内，我们无法确定recptr  
的具体信息。然而，当malloc()  
返回的指针被写入recptr_new->link  
时，可以通过 SSA 使用 - 定义链将该内存追溯到传递的参数，即recptr (arg1#0)  
。内存加载操作recptr->link  
被翻译为 MLIL SSA 表示中的0000117d rax_1#2 = [rax#1 + 8].q @ mem#0  
。该加载操作表示为arg1#0  
和rax_1#2  
之间的边。这里的基本假设是：如果内存被加载，那么它必须事先被初始化。内存存储、赋值和加载操作构成了数据流图的基本构建块。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/hoiaQy7WhTCMOrJ5glbHvfqL39ib8UoWC6YNI2nJKLgJCU89F9B7VLEvyeDia3DyKqAI2VfTIDmQHmPeYhtJARRSw/640?wx_fmt=png&from=appmsg "")  
  
图 4. 由内存存储和加载操作构建的数据流图  
## 遍历数据流图以传播信息  
  
现在我们已经理解了变量如何被初始化为图中节点的映射，以及内存访问如何被转换为边，接下来的问题是：在遍历 SSA 定义 - 使用链中的指令时，这些信息是如何传播的？答案在于我们之前初始化的 SSA 变量字典和图。  
  
-- 直接变量赋值是直观的。源变量的值被赋给目标变量。考虑表达式rax#0 = rbx#0  
，这里rax#0  
被赋值为 SSA 变量字典中rbx#0  
的值。  
```
{'rax#0_0x11f0': {'node': 'ALLOC', 'offset': 0, 'vartype': 'ALLOC'}, 'rbx#0_0x11f0': {'node': 'ALLOC', 'offset': 0, 'vartype': 'ALLOC'}}
```  
  
-- 对于涉及指针运算的变量赋值，除了节点信息外，还会存储偏移量信息。以表达式rax#0 = rbx#0 + 0x10  
为例，这里rax#0  
被赋值为源变量rbx#0  
所指向的节点，并持有到该节点的偏移量值 0x10。  
  
-- 对于涉及指针运算的变量赋值，源变量的节点信息会直接赋给目标变量，这与直接赋值的情况相同。然而，在这种情况下，偏移量信息会被更新以反映指针运算操作。以表达式rax#0 = rbx#0 + 0x10  
为例，这里rax#0  
被赋值为源变量rbx#0  
所指向的节点，但偏移量值被设置为 16。  
```
{'rax#0_0x11f0': {'node': 'ALLOC', 'offset': 16, 'vartype': 'ALLOC'}, 'rbx#0_0x11f0': {'node': 'ALLOC', 'offset': 0, 'vartype': 'ALLOC'}}
```  
  
-- 对于从内存加载数据的变量赋值操作，如rax_1#2 = [rax#1 + 8].q  
，需要遍历图的边来获取源变量指向的目标节点。具体来说，首先从 SSA（Static Single Assignment）变量字典中获取rax#1  
（基变量）关联的节点和偏移量。然后，将 SSA 变量字典中获取的"offset"与加载指令中的偏移量相加，计算出最终偏移量。在获得节点和计算出的偏移量后，通过遍历该节点的所有边，找到"write"偏移量与计算偏移量相等的边。将该边的目标节点和"points"偏移量赋值给rax_1#2  
。本质上，我们将内存加载操作解析为节点和偏移量值，这些值可用于更新 SSA 变量字典。以下是演示该过程的代码片段：  
```
        # When loading from stack, fetch the stack offset and get the associated edge.        if expr.src.value.type == RegisterValueType.StackFrameOffset:            offset = expr.src.value.value            node = hex(self.function.start)            edge = self.get_edge(node, offset)            if edge isNone:                srcvarinfo = self.visit(expr.src)                edge = self.get_edge(srcvarinfo["node"], srcvarinfo["offset"])        # Otherwise resolve the variable and fetch the edge info.        else:            basevar, basevar_expr, offset = self.get_basevar_offset(expr.src)            srcvarinfo = self.visit(basevar_expr)            edge = self.get_edge(srcvarinfo["node"], srcvarinfo["offset"] + offset). . .    def get_edge(self, node, offset):        # Given a node and an offset, search through all edges for finding an edge with matching offset. An edge is        # created for every memory write. Since multiple writes are possible to the same memory location, multiple        # edges may be created. If any of the destination points to allocated memory, then prioritize that edge.        all_edges = []        # Assume multiple writes to same memory location, creating multiple edges        for edge in self.data_graph.edges(node, data=True):            src, dest, attr = edge            if attr["write_offset"] == offset:                all_edges.append(edge)        if len(all_edges) == 0:            returnNone        else:            return self.choose_edge(all_edges)
```  
  
被调用函数（Callees）会在调用函数的 def-use 链中的所有指令处理完毕后被访问。只有当传递给被调用函数的参数在 SSA（Static Single Assignment）变量字典中存在映射时，才会对该被调用函数进行进一步分析。递归调用通过监控调用栈中是否重复调用同一函数来处理，并在达到预定义的迭代次数后终止分析。  
  
当栈内存作为参数传递时，如果传递的栈偏移量小于相应函数栈帧节点（绿色）关联的任何边的write  
偏移量值，也会对该被调用函数进行分析。这种考虑确保了即使结构体元素在函数内初始化，且结构体基址被传递给被调用函数（栈向下增长并使用负偏移量），分析也能正确处理这种情况。  
  
一旦调用函数和被调用函数的 SSA def-use 链中的指令都被遍历完毕，数据流图的生成即被视为完成，所有变量信息都已完全填充，可供进一步分析。  
## 记录与跟踪分配相关的指令  
  
在完成 SSA 变量映射并生成数据流图后，会重新访问指令。所有依赖于跟踪分配节点（Tracked Allocation Node）的内存加载、内存存储或调用指令都会被记录，同时记录静态生成的调用栈。这些指令被视为"使用"（Use）。此外，涉及释放函数（deallocator functions）的调用指令也会被记录，并被视为"释放"（Free）。以下是处理MLIL_STORE_SSA  
指令的示例代码片段：  
```
    def visit_MLIL_STORE_SSA(self, expr):        if expr in self.visited:            return. . .        # An allocated memory is written to. Log this info irrespective of the source.        if self.is_allocmem(expr.dest):            self.store_in_alloc(expr)            return    def is_allocmem(self, expr):        # Check if any of the variable points to allocated memory using the type info        # associated with the SSA variable.        for var in expr.vars_read:            varindex = self.get_var_index(var)            if varindex in self.vars and self.vars[varindex]["vartype"] == config.MEMALLOC:                returnTrue    def store_in_alloc(self, expr):        self.log_message("Write to allocated memory %s @ 0x%x" % (expr, expr.address), logging.INFO)        config.stacktrace[-1][1] = expr.address        stacktrace = copy.deepcopy(config.stacktrace)        key = self.generate_index(stacktrace, expr.address)        self.log_blks[key] = [config.WRITE, expr, stacktrace]        self.visited[expr] = 0
```  
## 通过调用栈进行跨过程分析以检测 Use-After-Free 漏洞  
  
完成日志记录后，检测潜在的 use-after-free 漏洞涉及分析所有被分类为"Free"的基本块，并验证是否存在通向被分类为"Use"的基本块的路径。如果存在这样的路径，则将其标记为潜在的 use-after-free 情况。由于 double-free 漏洞与 use-after-free 相关，分析还会检查是否存在从一个"Free"块到另一个"Free"块的路径。如果检测到这样的路径，则将其标记并记录为潜在的 double-free 情况。  
  
在前向数据流分析中，导致"Free"的调用栈和导致"Use"的调用栈中至少存在一个共同函数。例如，考虑这样一个场景：函数 A 分配内存，将其传递给函数 B 使用，函数 B 又将其传播到函数 C，在函数 C 中内存被释放。在 B 中使用分配的指令具有从 A 到 B 的调用栈，而函数 C 的调用栈包括从 A 到 B 和从 B 到 C。这两个调用栈中最后一个共同函数是 B。  
  
此处进行的分析不是上下文敏感的，仅关注可达性。因此，分析不会直接识别 C 中释放内存的基本块与 B 中使用内存的指令之间的路径，而是检查最后一个共同函数内的路径，即在 B 中调用函数 C 的基本块与 B 中使用内存的基本块之间的路径。这种方法允许进行跨过程分析，同时将路径查找限制在最后一个共同函数内，提高了效率和范围控制。否则，可能需要将多个函数内联到单个图中以执行可达性分析。  
  
此外，循环需要特别注意以最小化误报。在循环中，后向边可以将释放后的基本块连接到分配前的基本块。因此，在分配后但释放前执行的指令在图中仍然可能显示为可达的，可能被误识别为 use-after-free。为了缓解这种情况，在控制流图中移除了调用分配器函数的基本块的所有入边。这有效地断开了在循环中原本显示为可达的语句，减少了误报结果。  
## 自动检测分配器和释放器调用  
  
虽然理想情况下应使用特定于程序的分配器和释放器包装器作为此分析的输入，但手动识别它们可能具有挑战性。一个更简单的起点是输入标准函数如malloc()  
、realloc()  
和free()  
，检查结果，并根据结果逐步完善分析。通过交叉引用malloc()  
等分配器函数并利用 def-use 链，我们可以确定分配器函数返回的指针是否随后由调用者返回。如果是，则调用者可能是分配器的包装器。对于查找释放器函数，方法类似于  
Sean Heelan[5]  
提到的"函数别名"。Binary Ninja 的数据流分析可用于验证调用者的任何函数参数是否直接传递给free()  
等释放器。这可以通过检查参数的值类型是否为RegisterValueType.EntryValue  
来识别。如果满足此条件，则表明可能是释放器函数的包装器。  
  
使用包含最少分配器详细信息的 JSON 文件，在 OpenSLP 中识别了许多涉及分配和释放数据结构的函数。这些发现的函数可以纳入 JSON 文件以进行进一步分析。目前，"arg"键在实现中没有意义。  
```
{ "allocators":[  {   "alloc":{"func":"malloc", "arg": "arg0"},   "dealloc":{"func":["free", "realloc"], "arg":["arg0", "arg0"]}  },  {   "alloc":{"func":"realloc", "arg": "arg0"},   "dealloc":{"func":["free"], "arg":"arg0"}  },  {   "alloc":{"func":"calloc", "arg": "arg0"},   "dealloc":{"func":["free"], "arg":"arg0"}  } ]}
```  
```
$ time python3 analyze_allocators.py --find_deallocators --check_type_size --allocator_funcs demo.json --logname analysis.log slpd.bndb$ cat analysis.log | grep -i allocator | sort -uPotential allocator wrapper function memdup @ 0xf1d0Potential allocator wrapper function SLPBufferAlloc @ 0xf210Potential allocator wrapper function SLPDatabaseEntryCreate @ 0x11000Potential allocator wrapper function SLPDatabaseOpen @ 0x110e0Potential allocator wrapper function SLPDSocketAlloc @ 0x7ab0Potential allocator wrapper function SLPDSocketCreateBoundDatagram @ 0x7d40Potential allocator wrapper function SLPDSocketCreateConnected @ 0x8040Potential allocator wrapper function SLPDSocketCreateDatagram @ 0x7b50Potential allocator wrapper function SLPDSocketCreateListen @ 0x7f20Potential allocator wrapper function SLPMessageAlloc @ 0xf470Potential allocator wrapper function value_new @ 0x13860Potential allocator wrapper function var_new @ 0x138b0Potential deallocator wrapper function SLPAttrFree @ 0x13a80Potential deallocator wrapper function SLPAttrIteratorFree @ 0x15290Potential deallocator wrapper function SLPBufferFree @ 0xf2e0Potential deallocator wrapper function SLPBufferRealloc @ 0xf240Potential deallocator wrapper function SLPDatabaseClose @ 0x11140Potential deallocator wrapper function SLPDatabaseEntryDestroy @ 0x11040Potential deallocator wrapper function SLPDDatabaseAttrRqstEnd @ 0x8980Potential deallocator wrapper function SLPDDatabaseSrvRqstEnd @ 0x8690Potential deallocator wrapper function SLPDDatabaseSrvTypeRqstEnd @ 0x8810Potential deallocator wrapper function SLPDSocketFree @ 0x7ae0Potential deallocator wrapper function SLPMessageFree @ 0xf4c0Potential deallocator wrapper function value_free @ 0x138a0Potential deallocator wrapper function var_free @ 0x13970
```  
  
由于我们执行的是前向数据流分析（forward data flow analysis），这涉及到访问调用分配器（allocator）的函数以及这些函数的被调用者（callees），识别这些包装函数（wrappers）使我们能够调整分析的起点。简而言之，与其在SLPMessageAlloc()  
内部开始分析（在那里前向数据流分析的范围有限，因为它只调用了calloc()  
而没有进一步的交互），我们可以专注于分析所有调用SLPMessageAlloc()  
的函数。这种方法扩大了分析范围，并提供了更好的数据流洞察。  
```
0000f470  int64_t SLPMessageAlloc()   0 @ 0000f47e  return calloc(nmemb: 0xb8, size: 1) __tailcall
```  
## 分析历史真实漏洞  
  
为了理解该工具的工作原理，让我们在一些已知存在漏洞的程序上进行测试。由于  
GUEB[6]  
已经提供了已识别漏洞的列表，我选择将它们作为示例。  
## CVE-2015-5221: JasPer JPEG-2000  
  
在 mif_process_cmpt()  
 函数中存在一个 use-after-free/double-free 漏洞，如   
RedHat Bugzilla[7]  
 所示。  
```
static int mif_process_cmpt(mif_hdr_t *hdr, char *buf){        jas_tvparser_t *tvp;. . .        if (!(tvp = jas_tvparser_create(buf))) {                goto error;        }. . .        jas_tvparser_destroy(tvp);       // free here        if (!cmpt->sampperx || !cmpt->samppery) {                goto error;        }        if (mif_hdr_addcmpt(hdr, hdr->numcmpts, cmpt)) {                goto error;        }        return0;error:        if (cmpt) {                mif_cmpt_destroy(cmpt);        }        if (tvp) {                jas_tvparser_destroy(tvp);   // another free here        }        return-1;}
```  
  
通过追踪内存分配和释放 API，即jas_tvparser_create()  
和jas_tvparser_destroy()  
，我们观察到了以下结果：  
```
$ python3 analyze_allocators.py --check_type_size --allocator_funcs jas_allocator_functions.json --logname analysis.log mif_cod.o.bndbBuilding data graph for reference @ 0x2daAllocation @ 0x2da in mif_hdr_getFunction jas_tvparser_gettag() call made using allocated memory @ 0x2feAllocation freed @ 0x320Function jas_tvparser_next() call made using allocated memory @ 0x2eeBuilding data graph for reference @ 0x398Allocation @ 0x398 in mif_hdr_getFunction jas_tvparser_next() call made using allocated memory @ 0x3b3Allocation freed @ 0x678Function jas_tvparser_gettag() call made using allocated memory @ 0x3c3Function jas_tvparser_getval() call made using allocated memory @ 0x448Function jas_tvparser_getval() call made using allocated memory @ 0x470. . .Allocation freed @ 0x6c9[$$$] Potential Double Free @ 0x6c9 mem#58 = jas_tvparser_destroy(rdi_28#35) @ mem#57 in function mif_hdr_get || Free @ 0x678 in mif_hdr_get || Allocation @ 0x398 in mif_hdr_get
```  
  
在本例中，mif_process_cmpt()  
 函数被内联到 mif_hdr_get()  
 中，因此分析结果也相应地显示出来。  
## CVE-2016-3177: Giflib  
  
这里展示的是 gifcolor 中的一个双重释放（Double-Free）漏洞 -   
#83 Use-after-free / Double-Free in gifcolor[8]  
```
    /* Open stdout for the output file: */    if ((GifFile = EGifOpenFileHandle(1, &ErrorCode)) == NULL) {        PrintGifError(ErrorCode);        exit(EXIT_FAILURE);    }. . .    if (EGifCloseFile(GifFile, &ErrorCode) == GIF_ERROR)   // free here    {        PrintGifError(ErrorCode);        if (GifFile != NULL) {            EGifCloseFile(GifFile, NULL);    // free here        }        exit(EXIT_FAILURE);    }
```  
  
在本例中，使用的内存分配和释放 API 分别是EGifOpenFileHandle()  
和EGifCloseFile()  
，分析结果如下：  
```
$ python3 analyze_allocators.py --find_deallocators --check_type_size --allocator_funcs giflib.json --logname analysis.log gifcolor.o.bndbStarting analysis using giflib.jsonBuilding data graph for reference @ 0x246Allocation @ 0x246 in mainFunction EGifPutScreenDesc() call made using allocated memory @ 0x33bFunction EGifPutImageDesc() call made using allocated memory @ 0x360Function QuitGifError() call made using allocated memory @ 0x621Read from allocated memory [r12_1#4 + 0x2c].d @ mem#25 @ 0x36f. . .Function EGifPutLine() call made using allocated memory @ 0x55eAllocation freed @ 0x5b9Allocation freed @ 0x636[*] Exploring function call QuitGifError @ 0x621Allocation freed @ 0x16Potential deallocator wrapper function QuitGifError @ 0x0Read from allocated memory [arg1#0 + 0x60].d @ mem#0 @ 0x9[$$$] Potential Double Free @ 0x636 mem#44 = EGifCloseFile(rdi_15#25, 0) @ mem#43 in function main || Free @ 0x5b9 in main || Allocation @ 0x246 in main
```  
## GNOME-Nettool  
  
这是一个在 get_nic_information()  
 函数中发现的 Use-After-Free（释放后使用）漏洞 -   
Bug 753184[9]  
。在本分析中，我们追踪了 g_malloc0()  
 和 free()  
 这对内存分配/释放函数：  
```
$ python3 analyze_allocators.py --find_deallocators --check_type_size --allocator_funcs gnome-nettool.json --logname analysis.log gnome-nettool.bndbBuilding data graph for reference @ 0x12a2eAllocation @ 0x12a2e in info_get_nic_informationWrite to allocated memory [rbp_6#8].q = rax_35#49 @ mem#52 -> mem#53 @ 0x12a43Write to allocated memory [rbp_6#8 + 8].q = rax_36#50 @ mem#54 -> mem#55 @ 0x12a53Write to allocated memory [rbp_6#8 + 0x10].q = rax_37#51 @ mem#56 -> mem#57 @ 0x12a68. . .Allocation freed @ 0x12b46Write to allocated memory [rbp_6#8 + 0x10].q = rax_57#75 @ mem#91 -> mem#92 @ 0x12ca8[$$$] Potential UAF @ 0x12ca8 [rbp_6#8 + 0x10].q = rax_57#75 @ mem#91 -> mem#92 in function info_get_nic_information || Free @ 0x12b46 in info_get_nic_information || Allocation @ 0x12a2e in info_get_nic_information
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/hoiaQy7WhTCMOrJ5glbHvfqL39ib8UoWC6ATFJHF6CSvcJpUltrjicmeCQhzUVDqicLAx6eoyCibAcuEl7uicPmSIX6Q/640?wx_fmt=png&from=appmsg "")  
  
图 5. get_nic_information 函数中的 UAF（Use-After-Free）漏洞  
## CVE-2015-5177: OpenSLP  
  
这个在SLPDProcessMessage()  
函数中发现的 double-free（双重释放）问题   
#1251064[10]  
 展示了与前几个漏洞不同的场景。之前的案例涉及在同一函数内的内存分配、释放和使用。然而，在这个 double-free 案例中，我们观察到了跨函数分析的有效性。这突显了如何检测跨越多个函数的漏洞，为复杂代码路径提供了更广泛的分析范围。  
```
$ python3 analyze_allocators.py --find_deallocators --check_type_size --allocator_funcs slp.json --filter_function SLPDProcessMessage --logname analysis.log slpd.bndb. . .Building data graph for reference @ 0xa605Allocation @ 0xa605 in SLPDProcessMessageRead from allocated memory [rax_2#5 + 0x18].q @ mem#4 @ 0xa4d7Write to allocated memory [rax_2#5 + 0x28].q = rdx_1#2 @ mem#5 -> mem#6 @ 0xa4e9Function SLPDLogMessage() call made using allocated memory @ 0xa5cf. . .[$$$] Potential Double Free @ 0xa674 mem#3 = SLPMessageFree(rdi_11#1) @ mem#2 in function SLPDProcessMessage || Free @ 0xcbc9 in SLPDKnownDAAdd || Allocation @ 0xa536 in SLPDProcessMessage[$$$] Potential Double Free @ 0xa674 mem#25 = SLPMessageFree(rdi_1#19) @ mem#24 in function SLPDProcessMessage || Free @ 0xcaca in SLPDKnownDAAdd || Allocation @ 0xa536 in SLPDProcessMessage
```  
  
在SLPDProcessMessage()  
函数中，由SLPMessageAlloc()  
和SLPBufferAlloc()  
分配的内存指针会在消息 ID 设置为SLP_FUNCT_DAADVERT  
时传递给ProcessDAAdvert()  
函数。在ProcessDAAdvert()  
函数内部，这些指针会进一步传递给SLPDKnownDAAdd()  
函数。如果SLPDKnownDAAdd()  
函数中发生错误，则会使用SLPMessageFree()  
和SLPBufferFree()  
释放缓冲区，并返回一个非零错误码给SLPDProcessMessage()  
。随后，当SLPDProcessMessage()  
检测到非零错误码时，它会尝试再次释放相同的缓冲区，从而导致双重释放（Double-Free）的情况。该问题的上游修复可以在这里找到 -   
修复 SLPDKnownDAAdd() 失败时的双重释放问题[11]  
：  
```
int SLPDProcessMessage(struct sockaddr_in* peerinfo,                       SLPBuffer recvbuf,                       SLPBuffer* sendbuf). . .        /* Allocate the message descriptor */        message = SLPMessageAlloc();        if (message)        {            /* Parse the message and fill out the message descriptor */            errorcode = SLPMessageParseBuffer(peerinfo,recvbuf, message);            if (errorcode == 0)            {                /* Process messages based on type */                switch (message->header.functionid)                {. . .                case SLP_FUNCT_DAADVERT:                    errorcode = ProcessDAAdvert(message,                                                recvbuf,                                                sendbuf,                                                errorcode);. . .            if (header.functionid == SLP_FUNCT_SRVREG ||                header.functionid == SLP_FUNCT_DAADVERT )            {                /* TRICKY: If this is a reg or daadvert message we do not                * free the message descriptor or duplicated recvbuf                * because they are being kept in the database!                *                */                if (errorcode == 0)                {                    goto FINISHED;                }                /* TRICKY: If there is an error we need to free the                 * duplicated recvbuf,                 */                SLPBufferFree(recvbuf);            }            SLPMessageFree(message);. . .}int ProcessDAAdvert(SLPMessage message,                    SLPBuffer recvbuf,                    SLPBuffer* sendbuf,                    int errorcode){. . .    if (errorcode == 0);#endif    {        /* Only process if errorcode is not set */        if (message->body.daadvert.errorcode == SLP_ERROR_OK)        {            errorcode = SLPDKnownDAAdd(message,recvbuf);        }    }. . .int SLPDKnownDAAdd(SLPMessage msg, SLPBuffer buf)/* Adds a DA to the known DA list if it is new, removes it if DA is going  *//* down or adjusts entry if DA changed.                                    *//*                                                                         *//* msg     (IN) DAAdvert Message descriptor                                *//*                                                                         *//* buf     (IN) The DAAdvert message buffer                                *//*                                                                         *//* returns  Zero on success, Non-zero on error                             */. . .    CLEANUP:    /* If we are here, we need to cleanup the message descriptor and the  */    /* message buffer because they were not added to the database and not */    /* cleaning them up would result in a memory leak                     */    /* We also need to make sure the Database handle is closed.           */    SLPMessageFree(msg);    SLPBufferFree(buf);    if (dh) SLPDatabaseClose(dh);    return result;
```  
  
有趣的是，尽管SLPDKnownDAAdd()  
在代码中只释放了一次指针，但由于SLPMessageFree()  
却报告了两个双重释放（double-free）问题。这种差异是因为编译器为了优化目的，为同一个goto  
语句的目标生成了多个基本块（basic blocks），从而导致多个结果被报告。我们的实现没有跟踪通过SLPBufferAlloc()  
分配的缓冲区，因为这些指针是通过全局内存跨函数传递的，这目前不在我们的跟踪范围内。  
  
目前的日志记录非常原始。每个被分类为潜在 UAF（Use-After-Free）条件的指令都是单独记录的。通过按基本块或函数对指令进行分组，可以显著提高可读性。  
## 结论  
  
希望您喜欢这次通过数据流分析和图可达性使用 Binary Ninja 查找 use-after-free 漏洞的探索。该项目的源代码可以在这里找到 -   
uafninja[12]  
。  
## 致谢与参考文献  
- Trail of Bits[18]  
关于 Binary Ninja 的各种博客文章  
  
- Josh Watson 使用 Binary Ninja 的各种项目。访问者类（visitor class）的实现基于  
emilator[19]  
  
- Jordan 提供的所有  
代码片段[20]  
以及 Binary Ninja slack 社区回答的各种问题  
  
- Josselin Feist 开发的  
GUEB[21]  
静态分析器  
  
- Sean Heelan 关于  
使用静态分析查找 use-after-free 漏洞[22]  
的工作。  
  
## 参考资料  
  
[1]   
GUEB: https://github.com/montyly/gueb  
  
[2]   
使用静态分析发现 use-after-free 漏洞: https://sean.heelan.io/2009/11/30/finding-bugs-with-static-analysis/  
  
[3]   
博客文章: https://www.zerodayinitiative.com/blog/2022/2/14/static-taint-analysis-using-binary-ninja-a-case-study-of-mysql-cluster-vulnerabilities  
  
[4]   
OpenSLP: http://www.openslp.org/  
  
[5]   
Sean Heelan: https://sean.heelan.io/2009/11/30/finding-bugs-with-static-analysis/  
  
[6]   
GUEB: https://github.com/montyly/gueb?tab=readme-ov-file%22%20%5Cl%20%22vulnerabilities-found-by-gueb  
  
[7]   
RedHat Bugzilla: https://bugzilla.redhat.com/show_bug.cgi?id=1255710  
  
[8]   
#83 Use-after-free / Double-Free in gifcolor: https://sourceforge.net/p/giflib/bugs/83/  
  
[9]   
Bug 753184: https://bugzilla.gnome.org/show_bug.cgi?id=753184  
  
[10]   
#1251064: https://bugzilla.redhat.com/show_bug.cgi?id=1251064  
  
[11]   
修复 SLPDKnownDAAdd() 失败时的双重释放问题: https://sourceforge.net/p/openslp/mercurial/ci/2bc15d0494f886d9c4fe342d23bc160605aea51d/  
  
[12]   
uafninja: https://github.com/thezdi/binaryninja/  
  
[13]   
@RenoRobertr: https://x.com/renorobertr  
  
[14]   
Twitter: https://www.twitter.com/thezdi  
  
[15]   
Mastodon: https://infosec.exchange/@thezdi  
  
[16]   
LinkedIn: https://www.linkedin.com/company/zerodayinitiative  
  
[17]   
Bluesky: https://bsky.app/profile/thezdi.bsky.social  
  
[18]   
Trail of Bits: https://blog.trailofbits.com/categories/binary-ninja/  
  
[19]   
emilator: https://github.com/joshwatson/emilator  
  
[20]   
代码片段: https://gist.github.com/psifertex/6fbc7532f536775194edd26290892ef7  
  
[21]   
GUEB: https://github.com/montyly/gueb  
  
[22]   
使用静态分析查找 use-after-free 漏洞: https://sean.heelan.io/2009/11/30/finding-bugs-with-static-analysis/  
  
  
