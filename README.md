# Ghidra Patch Manager

A Ghidra 12.x extension for managing fixed-length byte patches as first-class, toggleable patch records.

## Features

- Dockable **Patch Manager** window.
- Create a patch from the current Ghidra location.
- The manager stores the original bytes and replacement bytes.
- Enable/disable patches with a checkbox, button, Space, or **Enable All / Disable All**.
- Double-click a patch to jump to its address in the Listing.
- **Capture Existing...** imports a change you already made with Ghidra's normal byte/instruction patch UI by comparing current bytes against Ghidra's imported original bytes.
- Automatically clears affected code units and invokes Ghidra's normal `DisassembleCommand` after byte changes, eliminating the manual undefine/re-disassemble workflow.
- Patch state is persisted inside the Ghidra program database.
- Export/import patch sets as simple Java-Properties text files suitable for version control.
- Conflict detection: a patch is only toggled when the current bytes exactly match either its stored original or patched bytes.
- Fixed-length, non-overlapping patches keep toggling deterministic.

## Building

Requires **Ghidra 12.1.x** and **JDK 21**. The project follows the same Gradle extension-build mechanism used by current Ghidra extensions.

Set `GHIDRA_INSTALL_DIR` and run:

```bash
./build.sh
```

or:

```bash
GHIDRA_INSTALL_DIR=/path/to/ghidra_12.1.4_PUBLIC ./gradlew buildExtension
```

The resulting extension zip is placed in `dist/` by Ghidra's extension build system.

## Installing

In Ghidra:

`File -> Install Extensions... -> + -> select the generated zip`

Restart Ghidra, then open:

`Window -> Patch Manager`

## How automatic re-disassembly works

When a patch touches an existing instruction, the plugin first expands the patch range to include any instruction containing the first or last patched byte. It clears those code units and writes the new bytes in one program transaction. After the transaction commits, it invokes `DisassembleCommand` on the affected range with flow following and code analysis enabled.

Undefined executable bytes are also offered to the disassembler, but the operation remains restricted to the patch range instead of triggering a whole-program disassembly.

The plugin intentionally does not silently overwrite a location whose current bytes are neither the stored original bytes nor the stored patched bytes. This protects manual edits and overlapping patch experiments.

## Notes

This is source-complete but should be built against the exact Ghidra version you intend to use. The build environment available while this project was generated did not contain a local Ghidra installation, so the final Ghidra extension zip could not be compiled here.


## 1.0.3 Changes
- Optimize build to exclude unneeded files
- Add icons to buttons

## 1.0.2 changes

- Enabled-column checkboxes are now handled as explicit mouse toggle targets instead of JTable Boolean cell editors.
- Prevents stale/repeated checkbox submissions and duplicate Patch Conflict dialogs.
- Prevents double-clicking the checkbox from also navigating.
- Keeps patch editing locked until automatic background re-disassembly finishes.
- Coalesces redundant program-change refreshes.
- Honors “Apply patch immediately” when editing a disabled patch without changing its definition.
- Tightens validation of stored patch definitions.
