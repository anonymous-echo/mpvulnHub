#  如何利用SCA静态代码分析工具快速发现漏洞   
原创 unr4v31  山石网科安全技术研究院   2023-11-24 10:59  
  
Static Code Analysis（SCA）静态代码分析技术，可以帮助开发人员快速扫描代码中存在的问题，对于开源软件安全研究也是一种非常高效的手段。本文介绍如何使用静态代码分析工具，在大型开源项目中快速发现漏洞。  
# 静态代码分析细节  
  
静态代码分析，简单来说就是扫描源码，根据源码执行流程等方面构建抽象语法树，通过中间语言进行语义和行为分析，以此来判断代码中是否存在缺陷或漏洞。  
  
对于开源项目漏洞挖掘，一般流程如下：  
1. 选择一个合适的挖掘目标。  
  
1. 源码审计过程。这一步骤可以使用工具来提高审计效率。  
  
1. 编译调试目标，验证漏洞是否真实存在，编写漏洞验证代码。  
  
1. 必要时可以针对目标部分代码进行模糊测试。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Gw8FuwXLJnSev93fZx2icYLnutRdEAFPORSjEaTaLPKBDdBoia6cGFrQLj4ZMiaia3yQBMW7DcUsnV5wsac06utHIQ/640?wx_fmt=png&from=appmsg "")  
  
目前已经存在多种针对于不同语言的SCA工具，例如：  
- C/CPP [1]：Clang、Cppcheck、Klocwork、CppDepend  
  
- Python：Pylint、Mypy  
  
- Javascript：ESLint、JSLint  
  
- CodeQL  
  
对于C/CPP程序来说，Cppcheck [2] 操作最简单，编译好后，只需要一条命令即可扫描出代码中存在的问题：  
```
./cppcheck source/test.c --xml 2> my_check.xml

```  
  
可以通过cppcheck-htmlreport工具将xml结果转为HTML文本，易于扫描结果的筛选和查看：  
```
htmlreport/cppcheck-htmlreport --file=my_check.xml --report-dir=my_check_html
firefox my_check_html/index.html

```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Gw8FuwXLJnSev93fZx2icYLnutRdEAFPOgEHAUOjDmv9y1qESBFhRmLljG76DlmGT5hfyjxo2XnE4Usr48KmHeg/640?wx_fmt=png&from=appmsg "")  
  
以CVE-2022-31615来看看Cppcheck的效果如何。此漏洞是Nvidia Open GPU Kernel Source源码中的一处空指针引用漏洞。Cppcheck扫描到的问题代码如下：  
```
void NV_API_CALL nv_acpi_methods_uninit(void){
    struct acpi_device *device = NULL;
    ...
#if defined(NV_ACPI_BUS_GET_DEVICE_PRESENT)
    acpi_bus_get_device(nvif_parent_gpu_handle, &device);  // device could remain NULL

    nv_uninstall_notifier(device->driver_data, nv_acpi_event);  // device dereference
#endif

    device->driver_data = NULL;  // device dereference
    nvif_parent_gpu_handle = NULL;

    return;
}

```  
  
从以上代码中可以观察到，device指针初始化为NULL，acpi_bus_get_device函数可能会不会改变device的值，但是在nv_uninstall_notifier函数与device->driver_data位置，向device取指针成员，毫无疑问这里存在空指针引用漏洞。  
  
再用Cppcheck尝试一些更大的开源项目，比如Linux kernel。扫描到的一个空指针引用问题（绝大多数内核中的空指针引用会导致内核崩溃宕机）：  
```
int attr_punch_hole(struct ntfs_inode *ni, u64 vbo, u64 bytes, u32 *frame_size){
    ...
  struct ATTRIB *attr = NULL, *attr_b;
    ...
    attr_b = ni_find_attr(ni, NULL, &le_b, ATTR_DATA, NULL, 0, NULL, &mi_b);
  if (!attr_b)
    return -ENOENT;

  if (!attr_b->non_res) {
    u32 data_size = le32_to_cpu(attr->res.data_size);  // Dereference attr which is NULL
    ...
}

```  
  
通过分析这段代码，可以发现整个函数中，并没有判断attr是否为空指针，而在le32_to_cpu函数中直接引用了attr->res.data_size，即存在空指针引用漏洞。  
# 总结  
  
从以上两个例子，可以总结一个结论：即便是Linux kernel这种级别的开源项目，也会存在这种非常低级的漏洞，并且这种低级漏洞可以直接通过Cppcheck扫描到，所以掌握多个SCA工具在一定程度上可以提高漏洞挖掘效率。  
  
对于静态代码分析得到的结果，最难过程的莫过于理清程序逻辑，触发漏洞位置，编写漏洞验证代码。小型开源项目由于代码量比较少，不太需要担心这个问题。但如果像Linux kernel这种量级的项目，查找调用路径就显得比较复杂了，这里提出三种漏洞验证思路：  
1. 可以使用CodeQL来分析调用路径编写PoC。通过CodeQL对路径进行约束查找，或者通过污点传播路径进行查找，虽然CodeQL学习成本较高，但掌握以后也是一件利器。  
  
1. 或者针对于可能存在漏洞的位置进行Fuzz。静态代码分析与Fuzz最为不同的点在于，Fuzz会直接得到崩溃样本与输入，可以根据输入样本进行微调进行利用。Fuzz的缺点就是需要根据模块设计和编写Fuzzer，有时候并不能精准的对想要的某一功能进行模糊测试。而静态代码分析得到的结果还需要分析输入和调用路径，比较耗费精力和时间。静态代码分析和模糊测试结合，不能说是雪中送炭，但是有好过没有。  
  
1. 最后一种方法就是去搜索开源项目的一些测试项目，像Linux kernel这种功能模块非常多的项目，会有一些单独的模块测试项目，一般测试会覆盖所有模块功能，那么就可以分析测试用例来得到触发漏洞路径的输入，更方便编写PoC。  
  
# References  
  
[1] https://www.incredibuild.com/blog/top-9-c-static-code-analysis-tools  
  
[2] https://github.com/danmar/cppcheck  
  
[3] https://www.cyberark.com/resources/threat-research-blog/nvme-new-vulnerabilities-made-easy  
  
