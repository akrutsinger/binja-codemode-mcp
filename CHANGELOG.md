# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed

- `define_type()` returns the names it defined rather than a bool, and both mutation methods let the
  type parser's own diagnostic through instead of answering a bare False
- Function names resolve through Binary Ninja's index rather than a scan of `bv.functions`, which
  was linear in the size of the binary on every call
- A traceback no longer repeats the exception line under a header of its own, or opens on the
  executor's own frame
- The status-bar indicator's timer stops once the indicator is in place, rather than polling twice a
  second for the rest of the session
- Workspace files are per binary, under `codemode_mcp/workspace/<binary>-<digest>/`. Shared across
  binaries they were both misleading and unsafe: the `execute` tool description advertised a
  previous binary's notes as this one's context - a report on some firmware presented while
  analysing a game - and two sessions each writing `analysis.md` clobbered one another. The
  directory is named for the binary and suffixed with a digest of its full path, so two files of the
  same name do not share one and the folder can still be found by hand. Keyed on path rather than
  contents, so moving a binary presents an empty workspace rather than costing a hash of the whole
  file at every startup. Skills stay shared, being code meant to work on any binary, which is the
  distinction: the workspace holds results about the binary in front of you. Files already in the
  old shared location are left alone and named once in the log at startup, since which binary each
  belongs to is not recoverable and guessing would file them under the wrong one
- `checkpoint()`'s summary line says that checkpoints last only as long as the server runs. The undo
  stack they index into lives in the database and survives a restart, but the names do not, so a
  name from before one is forgotten rather than stale and `rollback()` answers False. On the summary
  line because that is what the model is shown: the API reference renders a method's first docstring
  line and its return shape and drops everything between, so a caveat in the body reaches whoever
  opens `plugin/api.py` and nobody else
- `get_all_xrefs()`'s summary line says it is about one address rather than a whole function. Asked
  for a function's entry point it reports what jumps or calls there, and `xrefs_from` covers that
  single address rather than the body, so it reads as "this function calls nothing" when it means
  "nothing is referenced from this one instruction": on `sub_1001399` of the test binary, which has
  two callees, it answers `xrefs_from: 0`. `binja.function(f).callees` is the function-level answer
- `workspace` and `skills` are their own names in the execution namespace rather than eight
  delegating methods on `binja`: `binja.write_file(name, content)` is now `workspace.write(name,
content)`, `binja.save_skill(...)` is `skills.save(...)`, and so on. The delegations were the same
  pattern as the `bv` passthroughs removed above - a rename of an existing Python API - and they
  narrowed it, leaving `WorkspaceManager.clear()` and `SkillsManager.get_code()` implemented but
  unreachable. Both are now callable
- The execution namespace and the tool description are built from one mapping of name to object, so
  a name the model is told about is by construction a name it can call. `BinjaAPI` no longer takes
  the workspace or the skills manager, and the reference renderer no longer hardcodes the `binja.`
  prefix
- There is one MCP tool, `execute`. `checkpoint` and `rollback` were separate tools; they are now
  `binja.checkpoint(name)` and `binja.rollback(name)`, callable from the code the model is already
  writing, alongside a new `binja.list_checkpoints()`. A code-mode server that also ships bespoke
  tools for individual operations is arguing with itself
- The plugin now speaks MCP directly over Streamable HTTP at `http://127.0.0.1:42069/mcp`, so there
  is no bridge process. Clients register the URL and a bearer token instead of a path to a script,
  which means the configuration no longer depends on how the plugin was installed. The plugin's own
  REST API (`/execute`, `/checkpoint`, `/rollback`, `/status`, `/tools`, `/skills`, `/files`,
  `/checkpoints`) is gone with it: there is one endpoint, and it speaks the protocol the client
  already speaks
- JSON-RPC handling gained what the bridge never had: protocol version negotiation, the specified
  error codes, notifications answered with `202` rather than a response, and a handler crash
  reported as `-32603` instead of taking the connection down
- Requests carrying a non-localhost `Origin` are refused, the DNS-rebinding guard the MCP spec asks
  of local servers. Clients send no `Origin` at all, so only a browser sees this
- The API reference the LLM reads is now generated from `BinjaAPI` by introspection and delivered in
  the `execute` tool description, where it is always in context. Previously it was hand-written in
  `stubs.py` and offered as an MCP resource that most clients never read. Adding a method to
  `BinjaAPI` now advertises it automatically, and signatures cannot drift from the code
- Output is now capped on a token budget (`max_output_tokens`, default 6,000) rather than
  `max_output_bytes` (100,000, roughly 25,000 tokens). An over-budget result says what the whole
  result would have cost and how to narrow it, instead of just "(output truncated)"
- `print()` no longer stamps `[0.0s]` on every line, which taxed every printed row

### Added

- `binja.delete_checkpoint(name)` - forget a checkpoint without undoing anything. `rollback()`
  discards the checkpoints taken after the one it returns to and keeps the rest, so a session that
  guards several batches accumulated names it would never use again, with no way to remove one.
  Every name is listed in the `execute` tool description on each call, which is what made forgetting
  them worth a method rather than a shrug
- `binja.function(name_or_addr)` - the real `Function` object rather than a rendered dict, for the
  work the methods do not cover. `_resolve_function()` was the most useful thing in the file and was
  reachable only indirectly, through whichever wrapper happened to accept a name or an address
- `search_api()` and `describe()` now look at 31 Binary Ninja types rather than 6. The old list
  covered what the wrapper methods themselves used; this one covers what the model reaches for when
  it leaves the wrapper - `Variable`, `DataVariable`, `Section`, `Segment`, the IL function and
  instruction classes, `SymbolType` and `SymbolBinding`, tags, and the binary readers. The catalogue
  is 2,112 members and takes 3 ms to build, and none of it is in the tool description, so the reach
  is free in context. A type missing from the running version is skipped rather than raising
- `binja.checkpoint(name)`, `binja.rollback(name)` and `binja.list_checkpoints()` - checkpointing
  from inside executed code, so a script can take one before mutating and roll itself back.
  Checkpoints exist for the one thing Binary Ninja's own undo API cannot express: spanning several
  `execute` calls, which a `with` block cannot do
- The tool description now points at `bv.undoable_transaction()` for atomicity inside a single call,
  and says the rest of the undo API is reachable through `search_api("undo")`. Wrapping every
  `execute` in a transaction was considered and rejected: it would discard the work of a long
  analysis that happened to raise at the end, so the model opts in instead
- `scripts/generate_docs.py` rewrites the README's API section from `plugin/api.py`, and
  `scripts/check_api.py` fails when a public method lacks a docstring summary or a documented return
  shape, or (with `--check`) when that README section is stale. Both run under Binary Ninja's Python
  and print the tool description's token cost, so growth stays visible
- The value of a trailing bare expression is returned alongside anything printed, so a result no
  longer has to be wrapped in `print()`
- `bv` and `bn` are now in scope for executed code, alongside `binja` - the raw `BinaryView` and the
  `binaryninja` module. The wrapper methods are a convenience layer, not a limit
- `search_api(query)` and `describe(name)` - Find and read Binary Ninja's own API by keyword,
  introspected from the installed module rather than a checked-in list, so they describe whichever
  version is running and never need regenerating. Together with `bv` they make a missing wrapper
  method something the model can route around instead of a dead end
- `list_methods()` - Re-emit the API reference from inside the execution namespace, for when the
  tool description reaches the model truncated
- `search_decompiled()` - Search for patterns in HLIL decompiled code with regex support
- `get_control_flow_graph()` - Export CFG structure with nodes and edges for graph analysis
- `get_all_xrefs()` - Unified view of all code/data cross-references to/from an address
- `find_xref_chains()` - BFS-based call chain discovery between two functions
- `patch_bytes()` - Patch bytes at address with original/patched byte tracking
- `nop_range()` - NOP out instruction ranges
- `assemble_at()` - Assemble instructions and patch in-place

### Removed

- `cleanup_status_indicator()`, which had no caller, and `Config.log_executions`, which had no
  reader
- `bridge/`, which held nothing but a stale `__pycache__` from the bridge that went away when the
  plugin started speaking MCP itself
- `decompile()`'s `// Variables:` block, which was 41% of the method's output and repeated what
  the body already says. HLIL declares each variable inline with its type at first assignment, so
  `uint32_t var_c_1` appeared in the listing and again on the line that assigns it, and most of
  what the listing named was compiler temporaries - `eax_3`, `cond:0`, `__saved_esi`,
  `var_c_1` through `var_c_14`. The parameter types worth having are on the signature line, which
  stays. Over the 96 functions of the test binary the output drops 41%, about 13,600 tokens.
  `binja.function(f).vars` still has the whole set for the rare case that wants it
- A further 14 of `BinjaAPI`'s 26 methods, taking the tool description from ~2,300 tokens to
  ~1,742 and leaving 12. The criterion narrows: "filters server-side" was never true here, because
  the code runs in Binary Ninja's own process and a comprehension over `bv` costs no round trip.
  What is left is what only a wrapper can do - state that outlives a call, introspection of the
  running API, and a few idioms that are easy to get wrong. What went:
  - Comprehensions over `bv` the model writes as readily as it calls: `list_functions`,
    `list_strings`, `get_basic_blocks`, `get_binary_status`, `find_bytes`, `search_decompiled`,
    `get_control_flow_graph`, `find_xref_chains`. Each was verified against the obvious one-liner
    and returned identical results
  - `analyze_functions_batch`, which paginated a list already in memory. Pagination pays for a round
    trip, and there is no round trip to pay for
  - `get_function_calls`, which was wrong: it matched any HLIL instruction having a `dest` with a
    `constant`, so `HLIL_JUMP` counted as a call. It disagreed with `f.callees` on 38 of the 96
    functions in the test binary and invented `sub_<addr>` names for targets that were not functions
  - `nop_range`, which hand-rolled a NOP byte per architecture: `0x90` for x86 and `0x00` for ARM
    and for everything else, which is not a NOP anywhere. Binary Ninja's own `bv.convert_to_nop()`
    is instruction-aware and correct, and `search_api("nop")` finds it
  - `assemble_at`, which never worked. It read `arch.assemble()` as returning `(bytes, error)` when
    it returns `bytes`, so the tuple unpack consumed the instruction itself: a two-byte instruction
    bound `assembled_bytes` to an int, and any other length raised on the unpack
  - `patch_bytes` and `retype_variable`, thin enough over `bv.write()` and `var.type` to be worth
    less than the space they took in every tool description

- 28 of `BinjaAPI`'s 61 methods, taking the tool description from ~2,833 tokens to ~2,222. Binary
  Ninja is already a Python API, so a wrapper only earns its place where it encodes an idiom that is
  hard to guess (`decompile()` knows about `f.hlil.root.lines`), renders something awkward as JSON,
  or filters server-side. What went:
  - Passthroughs a single `bv` call already does: `list_imports`, `list_exports`, `list_segments`,
    `list_data_items`, `function_at`, `get_comment`, `get_function_comment`, `get_type`,
    `read_bytes`, `read_string`, `get_data_var_at`, `get_string_at`, `get_xrefs_to`,
    `get_data_xrefs_to`, `get_data_xrefs_from`. Two of them (`get_string_at`, `get_data_var_at`) had
    the same name as the `bv` method they wrapped
  - `list_classes` and `list_namespaces`, which described one thing and returned another:
    `list_namespaces` was annotated `list[str]` and returned `NameSpace` objects
  - `bulk_rename` and `batch_set_types`, which were Python loops over the single-item methods. In
    process a loop is already one round trip, so they saved nothing, and `batch_set_types` made the
    model learn a `{type, target, signature}` dialect to avoid writing the Python it knows
  - The mutation wrappers `rename_function`, `rename_data`, `rename_variable`, `set_comment`,
    `delete_comment`, `set_function_comment` and `delete_function_comment`, replaced by
    `binja.function("main").name = "x"`. Rollback still covers these, because Binary Ninja commits
    every mutation as its own undo entry however it was made
  - `find_functions_calling_unsafe` and `get_function_complexity`. Canned analyses are what the
    model should be writing, and `binja.save_skill()` is where a good one belongs
- The four MCP resources (`binja://api-reference`, `status`, `skills`, `files`). Three restated
  what `binja.get_binary_status()`, `binja.list_skills()` and `binja.list_files()` already return,
  and the fourth restated the `execute` tool description that `binja.list_methods()` re-emits from
  inside the namespace. Most clients never read resources, and three ways to ask one question is two
  too many
- `plugin/state.py` entirely, along with the `enable_state_tracking` config option and the
  `state_summary` parameter threaded through the tool description. Ninety lines of `StateTracker`, a
  `Checkpoint` dataclass and a `record_change()` call in twelve mutation methods have become a
  `dict[str, int]` on `BinjaAPI` and three methods of a few lines each. Binary Ninja's own undo
  system was doing the work already; the tracker was a second set of books that could only ever
  disagree with it, and did: mutations made through `bv` directly never called `record_change()`, so
  the "N change(s)" line it produced undercounted by design. That line is gone, and the header lists
  checkpoint names the same way it already lists skills
- `bridge/mcp_bridge.py`, and with it `BINJA_MCP_URL`, `BINJA_MCP_KEY` and `BINJA_MCP_LOG_LEVEL`.
  The bridge existed to translate stdio to HTTP because MCP had no HTTP transport when the plugin
  was written; it has had one since protocol 2025-03-26. Clients that still speak only stdio can
  front the server with `mcp-remote` (see the README)
- The placeholder `execute` tool the bridge advertised when Binary Ninja was not running. With no
  bridge process there is nothing to answer when the server is down, which is the honest signal
- The AST validator that rejected imports of `os`, `sys` and friends, and the "safe builtins"
  allowlist. Neither was a security boundary: `exec()` with a globals dict that has no
  `__builtins__` key gets the real builtins module injected by CPython, so `open()` and every import
  already worked, and the AST check was syntax-only (`getattr(f, "__globals__")` walked straight
  past it). The code runs in Binary Ninja's process with its privileges; localhost binding and the
  API key are the boundary, and the docs now say so

### Fixed

- A `Function` passed to any `func` argument resolved to `None`, so the call answered as though no
  such function existed - although `binja.function()` hands one back and the guide says to use it
- Only one window had the status indicator. Binary Ninja opens more than one main window in a
  single process and the indicator was one widget, so it moved between them rather than appearing
  in each
- A client hanging up mid-request printed a full traceback into Binary Ninja's log window, for what
  is a connection ending rather than a failure
- `get_all_xrefs()` never reported the code references leaving an address, so `xrefs_from` was
  data-only and a call site looked like it called nothing
- `define_type()` answered True for C that declared no type at all, `int x;` and a bare comment
  among them
- `search_api()` could not find a class or an enum, dead-ending the lookup the guide recommends
  exactly where a wrong enum member is a silent empty result
- A result JSON could not hold - a dict keyed by anything but a string, or a cycle - failed the whole
  call as a protocol error, discarding everything it had printed
- A request declaring more body than it sent parked a handler thread for the life of the process, a
  chunked body was answered with a parse error, and a non-string `code` was reported as a server bug
  rather than a bad argument
- `workspace.write(".")` raised where every other rejected name answers False, and `clear()` deleted
  and counted the dotfiles `list()` hides
- The manual install instructions copied `plugin/` alone, which cannot import the `config.py` beside
  it, and the Usage step named a menu that does not exist
- One MCP client blocked every other one, indefinitely. The server used a single-threaded
  `HTTPServer` with `protocol_version = "HTTP/1.1"`, so `serve_forever()` stayed inside the first
  connection's keep-alive loop until that client disconnected - and an MCP client holds its
  connection open for the whole session. The port accepted connections and answered none of them.
  This was invisible for as long as the only client was the bridge, which connected per request; it
  appeared the moment a real client did. Connections are now served on their own threads, and the
  guarantee the single thread was really providing - that two scripts never mutate the BinaryView at
  once - is enforced where it belongs, by a lock around `execute` alone
- The execution timeout stopped nothing. `thread.join(timeout=...)` returns when the wait expires,
  not when the thread does, so a script that ran past the limit was reported as timed out and then
  carried on running - still printing, still mutating the BinaryView, and now overlapping every
  later call. That is exactly what the server's single-threaded design exists to prevent, so the
  guarantee stated in `server.py` was not true. A timed-out thread is now stopped through
  `sys.monitoring`, by arming line and jump events on the executed code objects and nothing else, so
  the `KeyboardInterrupt` can only surface between statements the model wrote. Events are armed only
  after a timeout, so ordinary execution carries no tracing cost, and a runaway stops in about 10ms.
  On interpreters without `sys.monitoring` (Binary Ninja 4.0 predates it) the fallback raises
  asynchronously instead, which works but lands wherever the thread happens to be - usually inside a
  Binary Ninja destructor, where Python discards the exception and the C free it was part of never
  runs. A thread that will not stop either way is remembered, and later requests are refused rather
  than run beside it until it finishes
- A runaway execution thread could hold up Binary Ninja's own shutdown, because the interpreter
  waits to join a non-daemon thread. The execution thread is now a daemon
- `WorkspaceManager.list()` and `SkillsManager.list()` had annotations that could not be read. The
  method is named `list`, so under PEP 649's lazy evaluation the `list[dict]` return annotation
  resolved to the method itself and raised `TypeError`. Latent until something introspected those
  classes, which the namespace split does
- `describe()` no longer refuses a bare name that sits on more than one type. Widening the discovery
  roots took the share of ambiguous bare names from 6% to 29%, so a third of lookups would have cost
  a round trip to learn a qualification the caller usually did not care about. Ties now break
  towards the earliest entry in the roots list, which is ordered by how central the type is, and the
  result carries `also_defined_on` naming the types that lost, so the choice is visible rather than
  silent
- `describe()` now answers for a class or an enum, not only for a member of one. `search_api()`
  routinely returns a method whose parameter is a type - `define_user_symbol(sym: CoreSymbol)` - and
  every route to that type's constructor was closed: `describe("Symbol")`, `describe("bn.Symbol")`
  and `describe("Symbol.__init__")` all raised, while the error told the caller to use
  `search_api()`, which had already found the name. So the one question the discovery layer exists
  to answer - how do I build one of these - was the one it could not. A class now answers with its
  constructor signature, and an enum with its members, since an enum's `__init__` is `int`'s and
  says nothing while a wrong member is a silent empty result rather than an error
- `rollback()` reverted nothing, and reported success, when the changes it was undoing were made in
  the same `execute` call as the checkpoint. Binary Ninja holds a mutation made outside an explicit
  transaction in an anonymous one and commits it at its own pace, so `undo_entries` had not grown
  yet: the depth arithmetic came out at zero and the loop ran no iterations. The shape that failed
  is the obvious one - checkpoint, try something, roll back if it went wrong, all in one script.
  Depth is now measured after committing pending actions, which is safe inside a `with
bv.undoable_transaction():` since that still reverts its own block on an exception
- `rollback()` also waits for analysis before returning, so an undone function signature reads back
  as the old one. The undo itself was always correct; the result was only invisible, for the same
  reason setting a signature appeared to do nothing
- Checkpoint and rollback never worked. `StateTracker` read the undo stack through
  `bv.undoable_actions()`, which is not a `BinaryView` method; `create_checkpoint()` swallowed the
  `AttributeError` and recorded a depth of 0 while reporting success, and `rollback()` swallowed the
  same error and reported "checkpoint not found". Checkpoints now record the depth of
  `bv.file.undo_entries`, and nothing hides a failure to read it. Binary Ninja commits every API
  mutation as its own undo entry, so a rollback reverts changes made through `bv` directly as well
  as those made through `binja`. A checkpoint recorded deeper than the current stack rolls back to
  nothing rather than undoing work that predates it
- Every `func` argument resolved to the wrong function wherever two functions share a basic block.
  `_resolve_function()` asked `get_functions_containing()`, which answers with any function covering
  the address, so an address that is one function's own entry point could return a different
  function that merely overlaps it - on the test binary, `binja.decompile( 0x100140c)` returned
  `sub_1001399`. Resolution now asks `get_function_at()` first and falls back to
  `get_functions_containing()`, so an entry point resolves to its own function and an address in the
  middle of one still resolves to a container
- `set_function_signature()` reported success for a change that had not happened yet. Assigning a
  function's type queues reanalysis rather than applying it, so the method returned True and the
  very next read returned the old signature - the model saw a working call produce no effect and
  concluded the method was broken. It now waits for the analysis, so True means the signature is in
  effect. Variable types, renames and comments were never affected; function signatures alone are
  deferred, and the guidance now says so for the `binja.function(...).type = ...` path that no
  method covers
- `set_function_signature()` now correctly validates parsed types with explicit None check
- `find_bytes()` and `list_strings()` now default their optional arguments, matching how they have
  always been documented. `find_bytes(b"\x90")` and `list_strings()` previously raised `TypeError`
- `get_all_xrefs()` documented its result keys as `to`/`from`; they are `xrefs_to`/`xrefs_from`
- `analyze_functions_batch()` returns a `next_offset` key that was undocumented
- Functions defined by executed code could not see variables that code had assigned, raising
  `NameError`. Globals and locals were separate dicts, so a function body resolving a global never
  found names bound at the top level of the submitted script
- The status widget's headless guard caught only `ImportError`, but `binaryninjaui` raises
  `UIPluginInHeadlessError`, so importing the plugin outside the GUI crashed

## [0.1.3] - 2026-01-08

### Added

- Status indicator for MCP server running state

### Fixed

- Plugin not running properly in headless mode

## [0.1.2] - 2025-12-18

### Added

- This changelog

### Changed

- Cleaned up the README and included community plugin installation information

### Fixed

- Fix `mcp_bridge.py` variables to initialize before use

## [0.1.1] - 2025-12-09

### Fixed

- Update `plugin.json` with correct key name so Vector35's `generate_plugininfo.py -v plugin.json` succeeds

## [0.1.0] - 2025-12-02

### Added

- Initial release
