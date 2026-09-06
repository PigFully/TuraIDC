<?php

declare(strict_types=1);

namespace App\Support;

/**
 * SQL LIKE 通配符转义。
 *
 * 用户输入拼进 LIKE 模式时，`%`/`_` 是通配符、`\` 是转义字符：不转义则用户
 * 可注入通配符造成全表扫描（性能）与跨字段枚举探测（信息泄露）。本类把
 * 「先转义再包边界」收口为单点，此前 31 个文件的 LIKE 搜索各自手拼
 * `%{$keyword}%`，无一转义。
 *
 * 前提：MySQL 默认（未开 NO_BACKSLASH_ESCAPES）下 LIKE 的转义字符是 `\`，
 * 与本项目的 MySQL 5.7.44 / 8.x 兼容基线一致。
 */
final class SqlLike
{
    /**
     * 转义值中的 LIKE 通配符与转义符，返回可直接作为 LIKE 模式主体的字符串。
     *
     * 反斜杠必须最先替换，否则会把刚写入的转义符再转义掉。
     */
    public static function escape(string $value): string
    {
        return str_replace(['\\', '%', '_'], ['\\\\', '\\%', '\\_'], $value);
    }

    /** `%value%`：包含匹配。 */
    public static function contains(string $value): string
    {
        return '%'.self::escape($value).'%';
    }

    /** `value%`：前缀匹配。 */
    public static function startsWith(string $value): string
    {
        return self::escape($value).'%';
    }

    /** `%value`：后缀匹配。 */
    public static function endsWith(string $value): string
    {
        return '%'.self::escape($value);
    }
}
