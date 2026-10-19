# dsh-verify

[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Platform: Windows x64](https://img.shields.io/badge/platform-Windows%20x64-lightgrey.svg)](#限制)
[![Node](https://img.shields.io/badge/node-%E2%89%A520-brightgreen.svg)](package.json)

[English](README.md) | 中文

agent 编译没报错，就跟你说「改好了」。它其实不知道改没改对——你也不知道，除非自己从头再跑一遍。

这几个插件让它能查清楚，并且把查的过程留成你能核对的东西。

```
agent:  「配置解析器修好了，编译干净。」

你:     verify_run(cmd: "build/app.exe")

        exit 0xC0000005   ACCESS_VIOLATION
        #0  parse_json    src/config.c:12    ← 它刚改的那一行
        #1  load_config   src/config.c:22
        #2  main          src/main.c:34

agent:  「……它崩了，我再看。」
```

## 安装

```powershell
dsh plugin --profile "$env:DSH_PROFILE" add @alexzeng666/dsh-verify
```

Windows x64。一个包，十二个工具。四个子包是它的依赖——单独装会让工具重复注册。

## 十二个工具

| | |
|---|---|
| **跑** | `verify_run` —— 退出码、stdout/stderr，崩了直接给调用栈 |
| **断言** | `verify_assert_exit` · `verify_assert_stdout` · `verify_assert_file` · `verify_assert_json` · `verify_assert_screenshot` |
| **汇总** | `verify_report` —— 把运行历史收成一页报告 |
| **限制** | `verify_limit` —— CPU / 内存 / 时长上限，超了把整个 Job 杀掉 |
| **归因** | `verify_attribution` —— 说清它为什么死：退出码语义、事件日志、minidump 调用栈 |
| **观察** | `verify_trace` —— 它调了哪些 API、传了什么参数 |
| **造假** | `verify_hook` —— 改掉某个 API 的返回值（12 项白名单） |
| **拨时间** | `verify_timeshift` —— 把目标进程的时间拨快、拨慢、拨到未来 |

## 证据，不是说法

每次验证都写进工作区的 `.verify/`：

```
.verify/
  fragments.jsonl     一行一个 JSON，一次验证一条
  timeline.jsonl      started / exited / killed / crashed / attached / shifted
  V-001.stdout.log
  V-001.stderr.log
  V-001.dmp           崩了才有
```

`verify_report` 就是把这些读回来。于是「验过了」变成一件下周还能翻出来查的事，而不是一句你得信的话。

## 为什么不直接自己跑命令

可以。编译退出 0 或 1 的时候，自己跑就够了。

不够用是在这几种情况：

- **程序崩了。** shell 只给你 `exit code 1`；这个给你崩在哪一帧、哪一行源码。
- **命令卡死或者吃满机器。** 你拿到的是上限和一次干净的终止，不是卡住的会话。
- **结论是「输出里有 X」。** 这是一句断言，断言得有记录。

## 限制

- **只支持 Windows x64。** 没有 32 位，没有别的平台。
- **native helper 是预编译的**，装的时候不需要编译器。自己编译要 cmake + mingw-w64，
  见 [native/README.md](native/README.md)。
- **`verify_hook` 只覆盖固定的 12 个 API。** 白名单之外一律报「不支持」，不会假装 hook 上了。
- **追踪 JIT 运行时要把 API 收窄。** `verify_trace` 走内联 hook，在 node/V8 里 hook
  `QueryPerformanceCounter` 会以 `STATUS_BREAKPOINT` 把目标打死。传 `apis` 把它排除掉，
  其余 API 在那边都是安全的。
- **这些工具仍然得 agent 主动调。** 系统提示会催它，但没有强制力。工具能保证的是：
  它一旦真去验了，那个结果是实的。

## 包

| 包 | 提供 |
|---|---|
| `dsh-verify` | 跑、断言、汇总 —— 收网包 |
| `dsh-quota` | `verify_limit` |
| `dsh-crashlab` | `verify_attribution` |
| `dsh-probe` | `verify_trace`、`verify_hook` |
| `dsh-timelab` | `verify_timeshift` |
| `dsh-verify-contract` | 共享类型，不发布 |

每个包都能单独装。它们之间只通过
[`packages/dsh-verify-contract/src/index.d.ts`](packages/dsh-verify-contract/src/index.d.ts)
这一个类型契约耦合。

## 许可

MIT，见 [LICENSE](LICENSE)。内置的 MinHook 是 BSD-2-Clause，见
[native/third_party/minhook/LICENSE.txt](native/third_party/minhook/LICENSE.txt)。
