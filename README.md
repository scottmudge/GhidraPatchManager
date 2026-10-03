# Ghidra Patch Manager

A Ghidra 12.x extension for managing fixed-length byte patches as first-class, toggleable patch records.

[![Build Ghidra Patch Manager Extension](https://github.com/scottmudge/GhidraPatchManager/actions/workflows/gradle.yml/badge.svg)](https://github.com/scottmudge/GhidraPatchManager/actions/workflows/gradle.yml)

#### Patch Manager UI:
<img width="779" height="353" alt="image" src="https://github.com/user-attachments/assets/8bad4c06-7832-4b98-97e7-8da505a80a8e" />

#### Patched bytes highlighting and automatic original disassembly comments:
<img width="586" height="176" alt="image" src="https://github.com/user-attachments/assets/1c83ddee-353f-4b84-8955-eeb316ed7d09" />

## Features

- Dockable **Patch Manager** window.
- Create a patch from the current Ghidra location.
- The manager stores the original bytes and replacement bytes.
- Enable/disable patches with a checkbox, button, Space, or **Enable All / Disable All**.
- Double-click a patch to jump to its address in the Listing.
- **Patch Info** opens a read-only, copy-friendly detail window containing the patch name/state, address and end address, RVA, file offset(s), length, address space, image base, source file, memory block, and current bytes.
- Patch Info byte fields can be viewed as hexadecimal, Base64, ASCII, UTF-8, UTF-16LE/BE, Windows-1252, ISO-8859-1, or any charset exposed by the Java runtime.
- **Capture Existing...** imports a change you already made with Ghidra's normal byte/instruction patch UI by comparing current bytes against Ghidra's imported original bytes.
- Automatically clears affected code units and invokes Ghidra's normal `DisassembleCommand` after byte changes, eliminating the manual undefine/re-disassemble workflow.
- **Patch highlighting:** managed patch instructions are highlighted in the CodeBrowser with state-specific colors. Enabled patches use brownish-orange; disabled patches use purplish-lavender. The colors automatically switch between darker variants for dark themes and lighter variants for light themes. Highlighting is enabled by default and can be disabled with **Edit -> Tool Options -> Ghidra Patch Manager -> Highlight Patch Locations**.
- Patch highlighting is **address/instruction based**, not UI-line based. After a patch is toggled and re-disassembled, the current instruction containing the patch bytes is resolved again. All managed patches are re-resolved when any patch changes so instruction-boundary shifts do not leave stale highlighting behind.
- The same state-colored patch ranges are registered with Ghidra's `MarkerService`, which also makes their locations available in marker-capable connected views such as the Bytes viewer. Ghidra 12.1.x does not expose the CodeBrowser's marker-backed background model for individual byte cells, so this does not replace the Bytes viewer's own cell renderer.
- Patch state is persisted inside the Ghidra program database.
- Export/import patch sets as simple Java-Properties text files suitable for version control.
- **Original disassembly comments:** the **Show Orig** toggle controls whether every enabled patch gets a managed **PRE comment** above the current instruction containing the patch. The original-disassembly setting under **Edit -> Tool Options -> Ghidra Patch Manager** is named **Show Original Disassembly Comments by Default**, is disabled by default, and supplies the initial state of the **Show Orig** button when the tool starts.
- Original-disassembly comments use a distinct gold/yellow background and are automatically removed when the patch is disabled or deleted. Unrelated user PRE comments are preserved.
- **Delete Patch:** the confirmation dialog includes a **Restore original bytes before deleting** checkbox, enabled by default. When enabled, any selected enabled patches are reverted to their stored original bytes, the affected code units are cleared, and the restored ranges are automatically re-disassembled before deletion completes. Managed original-disassembly comments are removed as part of the same deletion operation.
- **Patch names in comments:** **Show Patch Names in Comments** is enabled by default. Custom patch names are appended to the first line of the managed original-disassembly comment as ` - Patch: <patch name>`. If original-disassembly comments are disabled, the extension instead adds a standalone `Patch: <patch name>` PRE comment for enabled patches. The generated default name `Patch @ <address>` is never added.
- Conflict detection: a patch is only toggled when the current bytes exactly match either its stored original or patched bytes.
- Fixed-length, non-overlapping patches keep toggling deterministic.

## Hotkeys

Actions are registered as normal Ghidra Docking actions, so their default keybindings appear in Ghidra's **Edit -> Tool Options -> Key Bindings** and can be changed there. The defaults use `Ctrl+Alt+Shift` to reduce collisions with ordinary CodeBrowser navigation and editing shortcuts. There should be no other default Ghidra key bindings using the below defaults.

| Action | Default | Scope |
|---|---|---|
| Show Patch Manager | `Ctrl+Alt+Shift + P`  &nbsp; &nbsp; &nbsp; | Global |
| Add Patch | `Ctrl+Alt+Shift + A` | CodeBrowser/program location |
| Capture Existing Patch | `Ctrl+Alt+Shift + C` | CodeBrowser/program location |
| Toggle Patch At Location | `Ctrl+Alt+Shift + T` | CodeBrowser, only when patch exists at current location |
| Patch Info At Location | `Ctrl+Alt+Shift + I` | CodeBrowser, only when patch exists at current location |
| Edit Patch | `Ctrl+Alt+Shift + E` | Patch Manager selection |
| Delete Patch | `Ctrl+Alt+Shift + D` | Patch Manager selection |
| Show Orginal Dissassembly | `Ctrl+Alt+Shift + O` | CodeBrowser |
| Enable All Patches | `Ctrl+Alt+Shift + Y` | Patch Manager |
| Disable All Patches | `Ctrl+Alt+Shift + N` | Patch Manager |
| Patch Info | `Ctrl+Alt+Shift + U` | Patch Manager selection |
| Save Patch Set | `Ctrl+Alt+Shift + S` | Patch Manager |
| Load Patch Set | `Ctrl+Alt+Shift + L` | Patch Manager |
| Refresh Patch Manager | `Ctrl+Alt+Shift + R` | Patch Manager |

The **Toggle Patch At Location** and **Patch Info At Location** actions deliberately do nothing when the current CodeBrowser location is not inside a managed patch. This includes patches where the cursor is in the middle of the patch, not only exactly at its start address.

The manager's **Edit Patch**, **Delete Patch**, **Enable All**, **Disable All**, and **Patch Info** actions are context-sensitive because they operate on the Patch Manager provider rather than arbitrary CodeBrowser locations. Ghidra's Key Bindings configuration can be used to assign different combinations when desired.

## Original disassembly comments

The **Show Original Disassembly Comments by Default** option is disabled by default under `Edit -> Tool Options -> Ghidra Patch Manager`. It controls only the initial state of the **Show Orig** button when the tool starts; changing this setting does not change the button during the current session. When an enabled patch has captured original disassembly, the extension stores it as a managed `PRE` comment anchored to the instruction that currently contains the patch start. `PRE` comments appear above the instruction, so the annotation does not depend on patched/original instruction line counts matching.

The **Show Patch Names in Comments** option is also enabled by default. For a patch with a custom name, the managed block begins with `[Original disassembly @ ...] - Patch: <patch name>`. When original-disassembly comments are disabled, the same option produces a standalone `Patch: <patch name>` PRE comment instead. The automatically generated `Patch @ <address>` name is treated as the default and is not written into comments.

The managed comment is tagged with the patch address, allowing Patch Manager to remove or refresh only its own block while retaining unrelated user-authored PRE comment text at the same instruction. The original-disassembly marker uses a separate gold/yellow background.

For legacy enabled patches that predate this feature, the extension performs a one-time background migration when the program is activated. It temporarily writes the stored original bytes, re-disassembles the local affected ranges, records the original instruction text, restores the patched bytes, re-disassembles, and then adds the managed comments. Patch operations remain unavailable while that migration is in progress.

## Building

Requires **Ghidra 12.1.x** and **JDK 25**. The project follows the same Gradle extension-build mechanism used by current Ghidra extensions.

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

When a patch touches an existing instruction, the plugin expands the patch range only to include the complete instruction containing the first and last patched bytes. It clears those code units and writes the new bytes in one program transaction. After the transaction commits, it invokes `DisassembleCommand` with that affected range as both its start set and its restricted set, so every newly undefined address in the range can seed disassembly without touching unrelated following instructions.

This is important when a patch changes instruction boundaries or instruction count. The plugin deliberately does not clear an arbitrary look-ahead region: Ghidra's `clearCodeUnits` operates on complete code units, so a look-ahead range can otherwise undefine an unaffected instruction merely because the range intersects it.

Undefined executable bytes are offered to the disassembler as additional start points, but the operation remains restricted to the patch range instead of triggering a whole-program disassembly.

The plugin intentionally does not silently overwrite a location whose current bytes are neither the stored original bytes nor the stored patched bytes. This protects manual edits and overlapping patch experiments.

## Notes

The extension should be built against the Ghidra version you intend to use. The project is currently written for **Ghidra 12.1.x / JDK 25**. The highlighting implementation uses Ghidra's public `MarkerService`, `ToolOptions`/`OptionsChangeListener`, and theme-listener APIs rather than private CodeBrowser line-number state.

---

## 1.3.4 Changes

- Renamed **Show Original Disassembly Comments** to **Show Original Disassembly Comments by Default** and changed its default to disabled.
- Added the **Show Orig** toggle button next to **Delete**, with `Ctrl+Alt+Shift + O` keybinding.
- The Tool Option now controls only the initial **Show Orig** state at tool startup; the button controls the live original-disassembly comment visibility for the current session.

## 1.3.3 Changes

- Added optional patch-name comments, enabled by default.
- Custom names are appended to the first line of the original-disassembly block.
- When original-disassembly comments are disabled, custom names are shown as standalone `Patch: <name>` PRE comments.
- Default `Patch @ <address>` names are never added.
- Renaming an enabled patch now immediately refreshes managed comment text.

## 1.3.2 Changes

- Delete Patch can optionally restore original bytes before removing the patch definition (enabled by default).
- Restored code is automatically cleared and re-disassembled after deletion.
- Managed original-disassembly comments are removed during deletion.

## 1.3.1 Changes

- Fixed automatic patch re-disassembly overreach when a patch changes instruction length or instruction count.
- The code-clear range is now limited to the complete instruction units actually intersecting the patch instead of using an executable 16-byte look-ahead.
- Re-disassembly seeds the affected range directly so newly undefined bytes such as a trailing NOP after a shortened branch are still decoded automatically.

## 1.3.0 Changes

- Added optional original-disassembly PRE comments, enabled by default.
- Added automatic migration for already-enabled patches that lack captured original disassembly.
- Persisted captured original disassembly in program state and patch-set exports/imports.

## 1.2.1 Changes

- Patches can now be edited while enabled or disabled; manual disabling is no longer required.
- Enabled-patch byte changes use a single disable/update/re-enable transaction according to the editor's **Apply patch immediately** setting, followed by one automatic re-disassembly pass.
- Patch state is revalidated after the editor closes to avoid overwriting an intervening external change.
- Patch Info byte fields have a slightly larger default display area.

## 1.2.0 Changes

- Added optional state-colored patch highlighting in the CodeBrowser.
- Enabled patches use brownish-orange; disabled patches use purplish-lavender.
- Colors automatically adapt for Ghidra light/dark themes.
- Highlight ranges are recalculated after re-disassembly and refreshed for all managed patches after a toggle.
- Added the **Highlight Patch Locations** Tool Option, enabled by default.
- Added state-colored MarkerService ranges for connected marker-capable views such as the Bytes viewer.

## 1.1.0 Changes

- Added the **Patch Info** read-only dialog with individually selectable/copyable fields for address, RVA, file offsets, source file, memory block, byte lengths, and other patch metadata.
- Added selectable byte rendering for hexadecimal, Base64, ASCII, UTF-8, UTF-16, and the Java runtime's available character sets.
- Added Ghidra DockingAction keybindings for Patch Manager actions.
- Added context-aware CodeBrowser hotkeys for Add, Capture Existing, Toggle-at-location, and Patch Info-at-location.

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
