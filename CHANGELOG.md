# Changelog

## 1.3.0
- Added optional (enabled by default) original-disassembly PRE comments for enabled patches.
- Original disassembly is captured from the unpatched instruction stream and shown above the affected instruction, even when the patch changes instruction boundaries or instruction count.
- Managed original-disassembly comments are removed automatically when a patch is disabled or deleted, while unrelated PRE comments are preserved.
- Existing enabled patches are migrated automatically on program activation by temporarily restoring their original bytes, capturing and re-disassembling the original instruction stream, then restoring the patched bytes.
- Added a gold/yellow background marker for original-disassembly comments; it follows the current instruction containing the patch address.
- Added **Show Original Disassembly Comments** under **Edit -> Tool Options -> Ghidra Patch Manager**.
- Original disassembly is persisted in program patch data and exported/imported patch sets; old patch data remains compatible because the new property is optional.

## 1.2.1
- Better patch editing, allowing editing of patches regardless of enabled/disabled status.

## 1.2.0
- Added optional patch-location highlighting in the CodeBrowser, enabled by default.
- Enabled patches use a brownish-orange background; disabled patches use a purplish-lavender background.
- Highlight colors automatically adapt between Ghidra light and dark themes for foreground readability.
- Highlighting is resolved from current instruction/address ranges after re-disassembly instead of storing UI line numbers.
- Rebuilds highlighting for all managed patches after a patch toggle so instruction-boundary changes are reflected consistently.
- Patch locations are also exposed through Ghidra MarkerService so the state-colored locations are available in connected marker-capable views such as the Bytes viewer.
- Added the **Highlight Patch Locations** option under **Edit -> Tool Options -> Ghidra Patch Manager**.

## 1.1.0
- Added a read-only **Patch Info** window with individually copyable metadata fields.
- Added file offset/RVA reporting, imported source-file information, memory-block information, and live current-byte display.
- Added selectable byte renderings for hexadecimal, Base64, ASCII, UTF-8, UTF-16, and available Java charsets.
- Added normal Ghidra DockingAction keybindings for Patch Manager actions.
- Added context-sensitive CodeBrowser hotkeys for Add, Capture Existing, Toggle-at-location, and Patch Info-at-location.

## 1.0.3
- Optimize build to exclude unneeded files
- Add icons to buttons

## 1.0.2

- Fixed Enabled-column checkbox toggling by removing JTable's live Boolean cell editor path.
- Checkbox clicks now derive the desired state from the patch's actual current bytes.
- Prevented duplicate Patch Conflict dialogs caused by stale checkbox submissions and table refreshes.
- Double-clicking the Enabled checkbox no longer also navigates to the patch.
- Kept patch operations busy until automatic background re-disassembly completes.
- Prevented stale global busy state when the active program changes during re-disassembly.
- Coalesced redundant domain-object refresh requests.
- Fixed the Edit Patch edge case where “Apply patch immediately” could be ignored when name and bytes were unchanged.
- Tightened validation of stored patch definitions.

## 1.0.1

- Corrected ComponentProviderAdapter package for Ghidra 12.1.x.
