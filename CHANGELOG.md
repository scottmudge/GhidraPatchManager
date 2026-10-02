# Changelog

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
