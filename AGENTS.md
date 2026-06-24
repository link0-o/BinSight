# BinSight AI Production Red Lines

This file is mandatory project context for any AI coding agent working in this repository.

## Hard Gate Before Code Changes

Do not modify source code, build files, CI files, rules, knowledge files, or documentation until you have read this entire file.

Before any implementation work, the agent must treat these constraints as active project instructions:

- The Industrial Component First Rule is mandatory.
- These rules apply to every code change, refactor, new component, parser, scanner, RAG feature, LLM client, report format, build integration, and external dependency decision.
- If a requested change conflicts with these rules, stop and explain the conflict before editing files.
- If a custom implementation is used, explicitly mark it as `Temporary / Prototype / Educational Implementation` in the relevant design documentation and explain why an industrial component was not used.
- Do not hide required runtime behavior behind undocumented CLI tool dependencies.

## 工业组件优先法则 / Industrial Component First Rule

在任何实现决策中，如果存在成熟、稳定、跨平台、可维护的工业级开源组件，BinSight 必须优先采用该组件，除非满足以下任一条件：

- 该组件无法满足核心功能需求。
- 该组件无法满足 Windows、Linux 或 CI 的跨平台/部署约束。
- 引入该组件会显著增加系统复杂度或运行时依赖负担。
- 自研实现具有明确的教学或研究价值，并且不影响产品边界。

For any implementation decision, if there is a mature, stable, cross-platform, maintainable industry-grade open-source component, BinSight must prefer that component unless one of these exceptions applies:

- The component cannot satisfy the core functional requirement.
- The component cannot satisfy Windows, Linux, or CI deployment constraints.
- The component would significantly increase system complexity or runtime dependency burden.
- A custom implementation has explicit educational or research value and does not change the product boundary.

若存在多个可选方案，优先级如下：

```text
工业标准库 > 轻量成熟库 > 自研实现
industry-standard library > lightweight mature library > custom implementation
```

必须遵守：

- 不得为了“控制实现细节”重复造轮子。
- 不得在存在可嵌入库时，把 CLI 工具作为必需系统依赖。
- 优先选择可嵌入组件，而不是外部进程依赖。
- 优先选择跨平台行为统一的实现。

Mandatory rules:

- Do not reinvent a wheel only to control implementation details.
- Do not make CLI tools required system dependencies when an embeddable library can provide the same evidence.
- Prefer embeddable components over external process dependencies.
- Prefer implementations with unified cross-platform behavior.

所有非工业实现必须在设计文档中明确标注为：

```text
Temporary / Prototype / Educational Implementation
```

Every non-industrial implementation must be explicitly marked in design documentation as:

```text
Temporary / Prototype / Educational Implementation
```

## Current Parser Policy

LIEF is the preferred production direction for PE/ELF parsing because it is an embeddable, cross-platform binary analysis library.

The current built-in PE parser and string extractor are classified as:

```text
Temporary / Prototype / Educational Implementation
```

They exist only to keep BinSight runnable in offline or dependency-restricted environments and to provide a small fallback path when optional parser dependencies are unavailable. They must not become the long-term production parser if LIEF or another mature embeddable component satisfies the same requirement.

`objdump`, `llvm-objdump`, `readelf`, and similar external tools are optional enrichment tools only. They must not be required for the core scan path when an embeddable component can provide the same evidence.

## Required Reasoning Before Adding Components

Before introducing or changing an implementation, the agent must check and briefly record:

- Which mature library/tool could solve this problem?
- Why is the selected approach compatible with Windows, Linux, and CI?
- Is any CLI tool dependency optional or required?
- If custom code is used, which exception justifies it?
- Where is the `Temporary / Prototype / Educational Implementation` label documented?

If these questions cannot be answered, do not implement the change yet.
