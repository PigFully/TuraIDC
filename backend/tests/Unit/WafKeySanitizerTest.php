<?php

declare(strict_types=1);

namespace Tests\Unit;

use App\Support\Waf\KeySanitizer;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * 键名净化器行为约束。
 *
 * 对应 acg-faka 3.6.3 修复的 P0（WAF 只清值不清键，键名成为 RCE/XSS 载体）。
 * 本测试的两条主线：
 *   1. 危险字符必须被剔除；
 *   2. **合法数据必须原样通过**——这条比第 1 条更重要：键名净化是全局生效的，
 *      一旦它改写了正常请求，影响面是整站。
 */
final class WafKeySanitizerTest extends TestCase
{
    private KeySanitizer $sanitizer;

    protected function setUp(): void
    {
        parent::setUp();
        $this->sanitizer = new KeySanitizer;
    }

    // ---------- 危险键名必须被中和 ----------

    public function test_strips_php_string_escape_characters_from_key(): void
    {
        $result = $this->sanitizer->sanitize(["key'; system('id'); //" => 'v']);

        self::assertArrayNotHasKey("key'; system('id'); //", $result);
        self::assertSame(['key; system(id); //' => 'v'], $result);
    }

    public function test_strips_html_characters_from_key(): void
    {
        $result = $this->sanitizer->sanitize(['<script>alert(1)</script>' => 'v']);

        self::assertSame(['scriptalert(1)/script' => 'v'], $result);
    }

    public function test_strips_backslash_from_key(): void
    {
        $result = $this->sanitizer->sanitize(['a\\\\b' => 'v']);

        self::assertSame(['ab' => 'v'], $result);
    }

    public function test_strips_control_characters_and_newlines_from_key(): void
    {
        $result = $this->sanitizer->sanitize(["evil\nINJECTED=1\x00" => 'v']);

        self::assertSame(['evilINJECTED=1' => 'v'], $result);
    }

    public function test_sanitizes_nested_array_keys(): void
    {
        $result = $this->sanitizer->sanitize([
            'outer' => ['in<ner' => ['deep"est' => 'v']],
        ]);

        self::assertSame(['outer' => ['inner' => ['deepest' => 'v']]], $result);
    }

    // ---------- 值绝不能被改动 ----------

    public function test_never_modifies_values(): void
    {
        $value = "<script>alert(1)</script> ' \\ \n %2B";

        $result = $this->sanitizer->sanitize(['note' => $value]);

        self::assertSame($value, $result['note'], '键名净化器改写了值');
    }

    public function test_preserves_non_string_values(): void
    {
        $result = $this->sanitizer->sanitize([
            'int' => 42,
            'float' => 1.5,
            'bool' => true,
            'null' => null,
        ]);

        self::assertSame(42, $result['int']);
        self::assertSame(1.5, $result['float']);
        self::assertTrue($result['bool']);
        self::assertNull($result['null']);
    }

    // ---------- 合法数据必须恒等（最关键） ----------

    /**
     * @param  array<array-key, mixed>  $input
     */
    #[DataProvider('legitimateInputProvider')]
    public function test_is_identity_transform_for_legitimate_input(array $input): void
    {
        self::assertSame(
            $input,
            $this->sanitizer->sanitize($input),
            '合法输入被改写：'.json_encode($input, JSON_UNESCAPED_UNICODE)
        );
        self::assertFalse($this->sanitizer->hasDirtyKey($input));
    }

    /**
     * @return iterable<string, array{array<array-key, mixed>}>
     */
    public static function legitimateInputProvider(): iterable
    {
        yield '普通参数' => [['page' => 1, 'per_page' => 20, 'keyword' => '云服务器']];
        yield '配置键' => [['site_name' => 'X', 'smtp_port' => 465, 'alipay_private_key' => 'MIIE...']];
        yield '点号分隔键' => [['home_hero.slides' => '[]', 'a.b.c' => 1]];
        yield '中划线下划线' => [['order-no' => 'X', 'user_id' => 2]];
        yield '中文键' => [['规格' => '4C8G', '机房' => '香港']];
        yield '整数索引列表' => [[0 => 'a', 1 => 'b', 2 => 'c']];
        yield '嵌套结构' => [['filter' => ['status' => ['active', 'pending']]]];
        // 支付回调的典型参数名——键名净化对它们必须是 no-op，否则验签会挂
        yield '支付宝回调参数名' => [[
            'out_trade_no' => 'TU202608280001',
            'trade_no' => '2026082822001',
            'trade_status' => 'TRADE_SUCCESS',
            'total_amount' => '99.00',
            'sign_type' => 'RSA2',
            'sign' => 'abc+/=def',
        ]];
    }

    public function test_integer_keys_keep_integer_type(): void
    {
        // 整数键若被转成字符串，json_encode 会把 list 变成 object，破坏 API 契约。
        $result = $this->sanitizer->sanitize([0 => 'a', 1 => 'b']);

        self::assertSame([0 => 'a', 1 => 'b'], $result);
        self::assertSame('["a","b"]', json_encode($result));
    }

    // ---------- 健壮性 ----------

    public function test_deeply_nested_input_terminates(): void
    {
        $deep = 'x';
        for ($i = 0; $i < 40; $i++) {
            $deep = ['k' => $deep];
        }

        // 只要不栈溢出即通过。
        $this->sanitizer->sanitize($deep);
        self::assertTrue(true);
    }

    public function test_empty_array_is_returned_as_is(): void
    {
        self::assertSame([], $this->sanitizer->sanitize([]));
        self::assertFalse($this->sanitizer->hasDirtyKey([]));
    }
}
