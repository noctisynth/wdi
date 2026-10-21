# wdi

`wdi` 是一个基于 [`dll-syringe`](https://crates.io/crates/dll-syringe) 的 Windows DLL 注入器命令行工具，
支持**注入 / 卸载 / 列举进程 / 启动并注入（挂起注入）**，并额外提供**反射式加载（reflective loading）**。
反射式加载参考了 [`injectum`](https://github.com/0x536b796ec3b578/injectum) 的注入思路和
[`rspe` / `rust-pe`](https://github.com/Thoxy67/rust-pe) 的 PE 内存映射实现。

## 环境要求

- Windows（`dll-syringe` 仅支持 Windows）
- Rust **nightly** 工具链

> `dll-syringe` 使用了若干 nightly 才有的特性（如 `linked_list_cursors`），
> 因此本项目通过 `rust-toolchain.toml` 固定使用 nightly。
> 使用 `rustup toolchain install nightly` 安装即可。

## 构建

```powershell
cargo build --release
# 产物： .\target\release\wdi.exe
```

## 命令

```
wdi <COMMAND>

Commands:
  inject  把 DLL 注入到正在运行的进程
  eject   从正在运行的进程中卸载 DLL
  list    列出正在运行的进程
  spawn   启动一个进程并注入 DLL（默认挂起注入）
```

选择目标进程有两种方式（二选一，不能同时使用）：

- `-p, --pid <PID>` 通过进程 ID
- `-n, --name <NAME>` 通过进程名（大小写不敏感，支持子串匹配）
  - 若匹配到多个进程，默认报错并列出候选；加 `--first` 取第一个

### 列举进程

```powershell
wdi list
wdi list -f chrome        # 只看名字包含 chrome 的进程
wdi list --paths          # 额外显示完整可执行文件路径
```

### 注入

```powershell
wdi inject C:\path\to\payload.dll --pid 1234
wdi inject C:\path\to\payload.dll --name notepad
wdi inject C:\path\to\payload.dll --name notepad --first
wdi inject C:\path\to\payload.dll --pid 1234 --if-missing   # 已加载则不重复注入
wdi inject C:\path\to\payload.dll --pid 1234 --reflective   # 反射式加载
```

### 反射式加载（reflective）

加 `--reflective` 后，`wdi` 不会调用目标进程的 `LoadLibrary`，而是在目标进程中手动完成 PE 映射：

- 写入 PE 头和所有节
- 应用基址重定位
- 解析普通导入表；尽可能提前解析延迟导入表，无法提前解析的保留原有的延迟加载 thunk
- 初始化安全 Cookie（`/GS`）
- 注册 Control Flow Guard 有效调用目标（`SetProcessValidCallTargets`）
- 运行 TLS 回调
- 在 x64 下注册异常处理表（`.pdata` / `RtlAddFunctionTable`）
- 用一段临时引导代码以 `DLL_PROCESS_ATTACH` 调用 DLL 入口点

```powershell
wdi inject C:\path\to\payload.dll --pid 1234 --reflective
wdi spawn notepad.exe --dll C:\path\to\payload.dll --reflective
```

反射式加载的限制：

- **只支持同架构**：`wdi` 与目标进程必须同为 64 位或同为 32 位。
  跨架构请使用默认的经典注入（不加 `--reflective`）。
- **模块不可见**：反射加载的 DLL 不会出现在目标的 PEB 模块列表中，
  因此 `wdi list` 看不到它，`wdi eject` 也无法卸载它。
  `--if-missing` 同样只能检测常规加载的模块，无法判断是否已经反射加载过同一 DLL。
- **导入库基址需一致**：导入地址在注入器进程中解析，因此被导入的 DLL 必须在
  `wdi` 和目标进程中映射到相同基址。系统 DLL 通常满足这一点；
  自定义依赖 DLL 若不满足会直接报错，请改用经典注入。
- **静态 TLS**：使用静态 `thread_local!` / `__declspec(thread)` 数据的 DLL
  在反射加载后可能无法正常工作（会给出 warning）。
  纯回调形式的 TLS 会被执行。
- **CFG**：会尝试通过 `SetProcessValidCallTargets` 注册 Control Flow Guard 的有效调用目标；
  如果系统上无法解析该 API，会给出 warning，启用 `/guard:cf` 的 DLL 可能无法正常工作。
- **不保证所有 DLL 都能加载**：依赖 Windows 加载器内部状态的特殊 DLL（部分系统 DLL）
  可能在 `DllMain` 中返回 `FALSE`。反射加载主要面向普通 payload DLL。
- **仅原生 DLL**：不支持 .NET 程序集。

### 卸载

`DLL` 参数既可传完整路径，也可只传文件名（如 `payload.dll`）：

```powershell
wdi eject C:\path\to\payload.dll --pid 1234
wdi eject payload.dll --name notepad --first
```

### 启动并注入（spawn）

默认先以**挂起**方式创建进程，注入后再恢复运行，这样 DLL 会早于目标自身的代码加载。
可执行文件可以是完整路径，也可以是 `PATH` 中的名字（如 `notepad.exe`）。

```powershell
# 挂起注入，注入后 wdi 立即返回
wdi spawn notepad.exe --dll C:\path\to\payload.dll

# 传参（可重复 -a/--arg）
wdi spawn C:\game\game.exe --dll mod.dll -a "--windowed" -a "-dx11"

# 等待进程退出并打印退出码
wdi spawn app.exe --dll payload.dll --wait

# 先正常运行再注入（不挂起）
wdi spawn app.exe --dll payload.dll --unsuspended

# 反射式加载
wdi spawn app.exe --dll payload.dll --reflective
```

## 注意事项

- **位数必须一致**：注入器、目标进程、DLL 三者需要同为 64 位或同为 32 位。
  64 位注入器向 32 位进程注入需要 `dll-syringe` 的 `into-x86-from-x64` 特性（默认已启用）。
- **权限**：打开/注入进程需要相应权限。注入更高完整性级别（例如以管理员运行）的进程时，
  需要以管理员身份运行 `wdi`，否则会出现 "inaccessible target process" 之类的错误。
- 部分打包应用（如 Win11 上的商店版记事本/画图）受保护，无法注入。

## 项目结构

```
src/
  main.rs              程序入口
  cli.rs               clap 命令行定义
  target.rs            目标进程解析与模块查找
  util.rs              通用小工具（文件校验、PATH 解析、对齐输出）
  reflective/
    mod.rs             反射式加载入口（远程内存、导入基址检查、执行引导代码）
    pe.rs              PE 解析、节映射、重定位、导入、TLS、安全 Cookie
    shim.rs            目标进程内调用入口点的 x86/x64 引导代码
  commands/
    inject.rs          inject 子命令
    eject.rs           eject 子命令
    list.rs            list 子命令
    spawn.rs           spawn 子命令（CreateProcessW 挂起注入）
```
