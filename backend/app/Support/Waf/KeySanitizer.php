<?php

declare(strict_types=1);

namespace App\Support\Waf;

/**
 * 请求「键名」净化器 —— 中和数组键里的注入字符。
 *
 * 由来：异次元发卡（acg-faka）3.6.3 修复的一个 P0——其 WAF 历来只清洗数组的
 * **值**、不清洗**键**，攻击者遂把 PHP 代码/HTML 藏进键名，经配置写入器逃逸单引号
 * 造成配置文件 RCE，或经后台表格 innerHTML 渲染造成存储型 XSS。
 *
 * TuraIdc 现状（已逐条核过，2026-08-28）：该 P0 的三条利用路径在本项目**均不成立**——
 * 配置存数据库而非 PHP 文件（全项目零 `var_export`）、`.env` 写入用白名单约束键名、
 * 前端业务代码零 `innerHTML`/`v-html`、键名走查询构建器参数绑定。
 *
 * 那为什么还要做？因为当前的安全性依赖「下游恰好都安全」这一**隐式前提**：
 * 一旦将来有人加了导出 PHP 配置的功能、或某个后台表格用了 v-html，这个洞就会凭空
 * 出现，而没有任何机制会提醒他。本类把该前提变成显式的、全局生效的一层兜底。
 *
 * ⚠ 本类只处理**键名**，绝不改写**值**。原因见 WebApplicationFirewall 的类注释：
 * 全局改写值会打断支付回调验签、损坏密码与密钥、破坏 Markdown 正文。
 */
final class KeySanitizer
{
    /**
     * 需要剔除的字符：
     * - `\x00-\x1F\x7F` 控制字符（含换行，可用于伪造配置行 / 日志注入）
     * - `<` `>` `"` HTML 逃逸
     * - `'` `\` PHP/SQL 字符串逃逸
     *
     * 合法键名（参数名、配置键、SKU 规格名等人类可读标识）不含这些字符，
     * 因此本操作对正常请求是**恒等变换**——这正是它能安全地全局生效的前提。
     */
    private const FORBIDDEN = '/[\x00-\x1F\x7F<>"\'\\\\]/u';

    /** 递归深度上限，防御畸形深层嵌套。与 Firewall::walk 同口径。 */
    private const MAX_DEPTH = 12;

    /**
     * 递归净化数组的所有键名，值原样保留。
     *
     * @param  array<array-key, mixed>  $input
     * @return array<array-key, mixed>
     */
    public function sanitize(array $input, int $depth = 0): array
    {
        if ($depth > self::MAX_DEPTH) {
            return $input;
        }

        $result = [];

        foreach ($input as $key => $value) {
            $cleanKey = $this->cleanKey($key);

            $result[$cleanKey] = is_array($value)
                ? $this->sanitize($value, $depth + 1)
                : $value;
        }

        return $result;
    }

    /**
     * 是否存在需要净化的键（用于告警判断，不产生副本）。
     *
     * @param  array<array-key, mixed>  $input
     */
    public function hasDirtyKey(array $input, int $depth = 0): bool
    {
        if ($depth > self::MAX_DEPTH) {
            return false;
        }

        foreach ($input as $key => $value) {
            if (is_string($key) && $this->cleanKey($key) !== $key) {
                return true;
            }

            if (is_array($value) && $this->hasDirtyKey($value, $depth + 1)) {
                return true;
            }
        }

        return false;
    }

    /**
     * 净化单个键。整数键（数组索引）原样返回，不做任何处理。
     */
    private function cleanKey(mixed $key): string|int
    {
        if (! is_string($key)) {
            // 整数索引保持整数类型：转成字符串会把 list 变成 map，破坏 json_encode 的形态。
            return is_int($key) ? $key : (string) $key;
        }

        return (string) preg_replace(self::FORBIDDEN, '', $key);
    }
}
