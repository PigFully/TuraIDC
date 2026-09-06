<?php

declare(strict_types=1);

namespace App\Support\Waf;

use Illuminate\Http\Request;

/**
 * 入站请求规则匹配引擎。
 *
 * 参照异次元发卡（acg-faka）`Kernel\Waf\Firewall::check()` 的思路：把请求的各个
 * 部位（查询串 / 路径 / 请求体 / Cookie / UA）拼成待检字符串，逐条过正则规则库，
 * 命中即返回，交由中间件决定拦截或仅记录。
 *
 * 与参照实现的两处关键差异：
 *
 * 1. **绝不二次 urldecode。** acg-faka 早期版本对已解码的输入再 `urldecode` 一次，
 *    导致用户字面输入的 `%20`/`%2B`/`%25` 被改写，卡密、查单密码等字段整体失真
 *    （其仓库 issue #833）。PHP/Laravel 在解析请求时已完成解码，`$request->query()`
 *    与 `$request->post()` 拿到的就是解码后的值，这里只做 `http_build_query` 重新
 *    拼接用于匹配，不再解码。
 *
 * 2. **只读不改。** 本类不修改请求内容，纯匹配。输入净化由 RichHtmlSanitizer /
 *    TextSanitizer 在各自的语义位置负责，职责不混。
 */
class Firewall
{
    /** 单条规则匹配上限，超长字符串截断后再匹配，避免正则回溯放大成 DoS。 */
    private const MAX_SCAN_LENGTH = 20000;

    /**
     * 规则库由外部注入，本类不读 config()。
     *
     * 这样做的原因：直接在类内调用 `config()` 会把引擎与框架启动状态绑死，
     * 既无法在不启动应用的情况下单测，也无法在别处（如 CLI 校验工具）复用。
     * 容器绑定见 AppServiceProvider，中间件拿到的实例已注入 config('waf.rules')。
     *
     * @var array<string, list<array{name?: string, pattern?: string}>>
     */
    private array $rules;

    /**
     * @param  array<string, list<array{name?: string, pattern?: string}>>|null  $rules
     *                                                                                   传 null 时回退到 config('waf.rules')，便于容器解析与手工构造两种用法共存。
     */
    public function __construct(?array $rules = null)
    {
        $this->rules = $rules ?? (array) (function_exists('config') ? config('waf.rules', []) : []);
    }

    /**
     * 检查请求，返回命中的规则；未命中返回 null。
     *
     * @return array{group: string, name: string}|null
     */
    public function inspect(Request $request): ?array
    {
        $rules = $this->rules;

        foreach ($this->targets($request) as $group => $subject) {
            if ($subject === '' || ! isset($rules[$group])) {
                continue;
            }

            $hit = $this->matchGroup((array) $rules[$group], $subject);
            if ($hit !== null) {
                return ['group' => $group, 'name' => $hit];
            }
        }

        return null;
    }

    /**
     * 组装各检测部位的待检字符串。
     *
     * 顺序即检测优先级：路径与查询串成本最低且最常命中，放在前面短路。
     *
     * @return array<string, string>
     */
    private function targets(Request $request): array
    {
        return [
            'path' => rawurldecode($request->getPathInfo()),
            'query' => $this->flatten($request->query()),
            'body' => $this->flatten($this->bodyInput($request)),
            'cookie' => $this->flatten($request->cookies->all()),
            'ua' => (string) $request->userAgent(),
        ];
    }

    /**
     * 取请求体输入。
     *
     * 文件上传不参与匹配：二进制内容命中正则纯属偶然，且会带来巨大的匹配开销。
     *
     * @return array<array-key, mixed>
     */
    private function bodyInput(Request $request): array
    {
        // JSON 请求体也要检测：现代前端大多以 application/json 提交。
        // json()->all() 在报文非法时返回空数组，无需再做类型判断。
        if ($request->isJson()) {
            return $request->json()->all();
        }

        return $request->post();
    }

    /**
     * 把任意层级的输入摊平成一个可匹配的字符串。
     *
     * 用 `key=value` 拼接而非仅取值：部分攻击载荷藏在参数名里（例如
     * `?a[eval(...)]=1`），只看值会漏。
     *
     * @param  array<array-key, mixed>  $input
     */
    private function flatten(array $input): string
    {
        if ($input === []) {
            return '';
        }

        $parts = [];
        $this->walk($input, $parts);

        $joined = implode('&', $parts);

        return strlen($joined) > self::MAX_SCAN_LENGTH
            ? substr($joined, 0, self::MAX_SCAN_LENGTH)
            : $joined;
    }

    /**
     * 递归摊平嵌套数组。
     *
     * @param  array<array-key, mixed>  $input
     * @param  list<string>  $parts
     */
    private function walk(array $input, array &$parts, string $prefix = '', int $depth = 0): void
    {
        // 深度上限防御畸形深层嵌套构造的栈耗尽。
        if ($depth > 12) {
            return;
        }

        foreach ($input as $key => $value) {
            $name = $prefix === '' ? (string) $key : $prefix.'.'.$key;

            if (is_array($value)) {
                $this->walk($value, $parts, $name, $depth + 1);

                continue;
            }

            if (is_scalar($value) || $value === null) {
                $parts[] = $name.'='.(string) $value;
            }

            // 对象 / 资源等非标量不参与匹配。
        }
    }

    /**
     * 在一组规则内匹配，返回命中的规则名。
     *
     * @param  list<array{name?: string, pattern?: string}>  $rules
     */
    private function matchGroup(array $rules, string $subject): ?string
    {
        foreach ($rules as $rule) {
            $pattern = (string) ($rule['pattern'] ?? '');
            if ($pattern === '') {
                continue;
            }

            // 规则以 # 为分隔符、i 忽略大小写、u 支持 UTF-8。
            // 用 @ 抑制畸形正则的告警：一条规则写错不应让整个站点 500，
            // preg_match 返回 false 时视为未命中并继续下一条。
            if (@preg_match('#'.$pattern.'#iu', $subject) === 1) {
                return (string) ($rule['name'] ?? 'unnamed');
            }
        }

        return null;
    }
}
