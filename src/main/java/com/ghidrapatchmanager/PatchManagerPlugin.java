package com.ghidrapatchmanager;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.StringReader;
import java.io.StringWriter;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Comparator;
import java.util.List;
import java.util.Objects;
import java.util.Properties;
import java.util.concurrent.atomic.AtomicBoolean;

import javax.swing.JFileChooser;
import javax.swing.JOptionPane;

import docking.ActionContext;
import docking.action.DockingAction;
import docking.action.KeyBindingData;
import docking.action.MenuData;
import ghidra.app.CorePluginPackage;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.context.ProgramLocationSupplierContext;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.framework.cmd.BackgroundCommand;
import ghidra.framework.model.DomainObjectChangedEvent;
import ghidra.framework.model.DomainObjectListener;
import ghidra.framework.options.Options;
import ghidra.framework.options.OptionsChangeListener;
import ghidra.framework.options.ToolOptions;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.database.mem.AddressSourceInfo;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.CommentType;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.util.ProgramLocation;
import ghidra.util.HelpLocation;
import ghidra.util.Msg;
import ghidra.util.task.TaskMonitor;

@PluginInfo(
    status = PluginStatus.RELEASED,
    packageName = CorePluginPackage.NAME,
    category = PluginCategoryNames.CODE_VIEWER,
    shortDescription = "Interactive binary patch manager",
    description = "Tracks byte patches, preserves original bytes, toggles patches, and automatically re-disassembles affected code."
)
public class PatchManagerPlugin extends ProgramPlugin implements DomainObjectListener {
    private static final String OPTION_PATH = "Ghidra Patch Manager";
    private static final String OPTION_DATA = "Patch Set";
    private static final String FORMAT = "GhidraPatchManager";
    private static final int FORMAT_VERSION = 1;
    private static final int HOTKEY_MODIFIERS = java.awt.event.InputEvent.CTRL_DOWN_MASK | java.awt.event.InputEvent.ALT_DOWN_MASK;
    private static final int HOTKEY_SHIFT_MODIFIERS = HOTKEY_MODIFIERS | java.awt.event.InputEvent.SHIFT_DOWN_MASK;
    private static final String ORIGINAL_DISASSEMBLY_OPTION = "Show Original Disassembly Comments";
    private static final String ORIGINAL_COMMENT_PREFIX = "[Original disassembly @ ";
    private static final String ORIGINAL_COMMENT_SUFFIX = "]";
    private static final String ORIGINAL_COMMENT_END_PREFIX = "[/Original disassembly @ ";

    private final AtomicBoolean refreshPending = new AtomicBoolean();
    private final List<DockingAction> registeredActions = new ArrayList<>();

    private PatchManagerProvider provider;
    private DockingAction showAction;
    private PatchInfoDialog patchInfoDialog;
    private Program activeProgram;
    private List<Patch> patches = new ArrayList<>();
    private boolean busy;
    private boolean internalChange;
    private PatchHighlightManager highlightManager;
    private ToolOptions patchToolOptions;
    private boolean originalDisassemblyReconcilePending;

    private final OptionsChangeListener patchToolOptionsListener = new OptionsChangeListener() {
        @Override
        public void optionsChanged(ToolOptions options, String optionName, Object oldValue, Object newValue) {
            if (options == patchToolOptions && ORIGINAL_DISASSEMBLY_OPTION.equals(optionName)) {
                requestOriginalDisassemblyReconcile();
            }
        }
    };

    public PatchManagerPlugin(PluginTool tool) {
        super(tool);
    }

    @Override
    protected void init() {
        super.init();
        provider = new PatchManagerProvider(tool, this);
        patchToolOptions = tool.getOptions(OPTION_PATH);
        patchToolOptions.registerOption(ORIGINAL_DISASSEMBLY_OPTION, Boolean.TRUE, null,
                "Show a gold-highlighted PRE comment containing the original disassembly for enabled patches.");
        patchToolOptions.addOptionsChangeListener(patchToolOptionsListener);
        highlightManager = new PatchHighlightManager(this, tool);
        tool.addComponentProvider(provider, false);
        patchInfoDialog = new PatchInfoDialog(this);

        showAction = new DockingAction("Patch Manager: Show Patch Manager", getName()) {
            @Override
            public void actionPerformed(ActionContext context) {
                showPatchManager();
            }
        };
        showAction.setPopupMenuData(new MenuData(new String[] { "Window", "Patch Manager" }));
        showAction.setDescription("Open the Patch Manager window");
        showAction.setKeyBindingData(new KeyBindingData(java.awt.event.KeyEvent.VK_P, HOTKEY_SHIFT_MODIFIERS));
        tool.addAction(showAction);
        registeredActions.add(showAction);

        registerGlobalAction("Patch Manager: Add Patch", "Create a patch at the current CodeBrowser location",
                java.awt.event.KeyEvent.VK_A, context -> addPatchFromUi(), true,
                this::hasUsableProgramLocation);
        registerGlobalAction("Patch Manager: Capture Existing Patch", "Capture existing modified bytes at the current CodeBrowser location",
                java.awt.event.KeyEvent.VK_C, context -> captureCurrentChanges(),  true,
                this::hasUsableProgramLocation);
        registerGlobalAction("Patch Manager: Toggle Patch At Location", "Toggle the managed patch containing the current CodeBrowser location",
                java.awt.event.KeyEvent.VK_T, context -> togglePatchForContext(context),  true,
                context -> patchForContext(context) != null && canEditPatches() &&
                    isToggleState(patchForContext(context).getState(this)));
        registerGlobalAction("Patch Manager: Patch Info At Location", "Show Patch Info for the managed patch containing the current CodeBrowser location",
                java.awt.event.KeyEvent.VK_I, context -> showPatchInfo(patchForContext(context)),  true,
                context -> patchForContext(context) != null && activeProgram != null);

        registerManagerAction("Patch Manager: Edit Patch", "Edit the selected patch",
                java.awt.event.KeyEvent.VK_E, this::editSelectedPatch, true,
                () -> provider.getSelectedPatch() != null && selectedPatchIsEditable());
        registerManagerAction("Patch Manager: Delete Patch", "Delete the selected patch or patches",
                java.awt.event.KeyEvent.VK_D, this::deleteSelectedPatches, true,
                () -> provider.getSelectedModelRows().length > 0 && canEditPatches());
        registerManagerAction("Patch Manager: Enable All Patches", "Enable all managed patches",
                java.awt.event.KeyEvent.VK_Y, this::enableAllWithHotkey, true,
                () -> canEditPatches());
        registerManagerAction("Patch Manager: Disable All Patches", "Disable all managed patches",
                java.awt.event.KeyEvent.VK_N, this::disableAllWithHotkey, true,
                () -> canEditPatches());
        registerManagerAction("Patch Manager: Save Patch Set", "Save the managed patch set to a file",
                java.awt.event.KeyEvent.VK_S, this::exportPatchSet, true,
                () -> activeProgram != null);
        registerManagerAction("Patch Manager: Load Patch Set", "Load a managed patch set from a file",
                java.awt.event.KeyEvent.VK_L, this::importPatchSet, true,
                () -> canEditPatches());
        registerManagerAction("Patch Manager: Refresh Patch Manager", "Refresh patch states from the current program",
                java.awt.event.KeyEvent.VK_R, this::refreshProvider, true,
                () -> activeProgram != null);
        registerManagerAction("Patch Manager: Patch Info", "Show details for the selected patch",
                java.awt.event.KeyEvent.VK_U, this::showPatchInfoForSelectedPatch, true,
                () -> provider.getSelectedPatch() != null && activeProgram != null);

        provider.getComponent().setName("Ghidra Patch Manager");
        provider.setHelpLocation(new HelpLocation(getName(), "Patch_Manager"));
    }

    private void registerGlobalAction(String name, String description, int keyCode,
            java.util.function.Consumer<ActionContext> performer, boolean shifted,
            java.util.function.Predicate<ActionContext> enabled) {
        DockingAction action = new DockingAction(name, getName()) {
            @Override
            public void actionPerformed(ActionContext context) {
                performer.accept(context);
            }

            @Override
            public boolean isEnabledForContext(ActionContext context) {
                return enabled.test(context);
            }
        };
        action.setDescription(description);
        action.setKeyBindingData(new KeyBindingData(keyCode, shifted ? HOTKEY_SHIFT_MODIFIERS : HOTKEY_MODIFIERS));
        tool.addAction(action);
        registeredActions.add(action);
    }

    private void registerManagerAction(String name, String description, int keyCode,
            Runnable performer, boolean shifted, java.util.function.BooleanSupplier enabled) {
        DockingAction action = new DockingAction(name, getName()) {
            @Override
            public void actionPerformed(ActionContext context) {
                performer.run();
            }

            @Override
            public boolean isEnabledForContext(ActionContext context) {
                return context != null && context.getComponentProvider() == provider && enabled.getAsBoolean();
            }
        };
        action.setDescription(description);
        action.setKeyBindingData(new KeyBindingData(keyCode, shifted ? HOTKEY_SHIFT_MODIFIERS : HOTKEY_MODIFIERS));
        tool.addAction(action);
        registeredActions.add(action);
    }

    void notifyContextChanged() {
        tool.contextChanged(provider);
    }

    private void showPatchManager() {
        provider.setVisible(true);
        tool.toFront(provider);
        provider.getComponent().requestFocusInWindow();
    }

    private void enableAllWithHotkey() {
        setAllPatchesEnabled(true);
    }

    private void disableAllWithHotkey() {
        setAllPatchesEnabled(false);
    }

    @Override
    protected void dispose() {
        originalDisassemblyReconcilePending = false;
        if (patchToolOptions != null) {
            patchToolOptions.removeOptionsChangeListener(patchToolOptionsListener);
            patchToolOptions = null;
        }
        if (activeProgram != null) {
            activeProgram.removeListener(this);
        }
        if (highlightManager != null) {
            highlightManager.dispose();
            highlightManager = null;
        }
        for (DockingAction action : registeredActions) {
            tool.removeAction(action);
        }
        registeredActions.clear();
        if (patchInfoDialog != null) {
            patchInfoDialog.close();
            patchInfoDialog = null;
        }
        if (provider != null) {
            tool.removeComponentProvider(provider);
            provider = null;
        }
        super.dispose();
    }

    @Override
    protected void programActivated(Program program) {
        super.programActivated(program);
        activeProgram = program;
        program.addListener(this);
        loadFromProgram(program);
        if (highlightManager != null) {
            highlightManager.programActivated(program);
        }
        refreshProvider();
        clearPatchInfoOnProgramSwitch();
        requestOriginalDisassemblyReconcile();
    }

    @Override
    protected void programDeactivated(Program program) {
        if (highlightManager != null) {
            highlightManager.programDeactivated(program);
        }
        if (program != null) {
            program.removeListener(this);
        }
        if (activeProgram == program) {
            activeProgram = null;
        }
        clearPatchInfoOnProgramSwitch();
        super.programDeactivated(program);
        refreshProvider();
    }

    @Override
    protected void locationChanged(ProgramLocation location) {
        super.locationChanged(location);
        if (provider != null && provider.isVisible() && activeProgram != null && provider.getSelectedPatch() == null) {
            provider.setStatus("Current address: " + location);
        }
        tool.contextChanged(null);
    }

    private void clearPatchInfoOnProgramSwitch() {
        if (patchInfoDialog != null) {
            patchInfoDialog.clearPatch();
        }
    }

    @Override
    public void domainObjectChanged(DomainObjectChangedEvent ev) {
        if (internalChange || provider == null || busy) {
            return;
        }
        if (!refreshPending.compareAndSet(false, true)) {
            return;
        }
        javax.swing.SwingUtilities.invokeLater(() -> {
            refreshPending.set(false);
            if (provider != null && !busy) {
                refreshProvider();
            }
        });
    }

    @Override
    public Program getCurrentProgram() {
        return activeProgram;
    }

    boolean isOriginalDisassemblyCommentsEnabled() {
        return patchToolOptions == null || patchToolOptions.getBoolean(ORIGINAL_DISASSEMBLY_OPTION, true);
    }

    boolean hasOriginalDisassembly(Patch patch) {
        return patch != null && patch.originalDisassembly != null && !patch.originalDisassembly.isBlank();
    }

    boolean canEditPatches() {
        return activeProgram != null && !busy;
    }

    Address getSuggestedPatchAddress() {
        if (getProgramLocation() != null) {
            return getProgramLocation().getByteAddress();
        }
        return activeProgram != null ? activeProgram.getImageBase() : null;
    }

    private boolean hasUsableProgramLocation(ActionContext context) {
        if (context instanceof ProgramLocationSupplierContext locationContext && locationContext.getLocation() != null) {
            return canEditPatches() && locationContext.getLocation().getByteAddress() != null;
        }
        return false;
    }

    private ProgramLocation getContextLocation(ActionContext context) {
        if (context instanceof ProgramLocationSupplierContext locationContext) {
            return locationContext.getLocation();
        }
        return null;
    }

    private Patch patchForContext(ActionContext context) {
        ProgramLocation location = getContextLocation(context);
        if (location == null) {
            return null;
        }
        return findPatchAt(location.getByteAddress());
    }

    private Patch findPatchAt(Address address) {
        if (address == null) {
            return null;
        }
        for (Patch patch : patches) {
            if (patch.address.getAddressSpace().equals(address.getAddressSpace())
                    && patch.address.compareTo(address) <= 0
                    && patch.getEndAddress().compareTo(address) >= 0) {
                return patch;
            }
        }
        return null;
    }

    private static boolean isToggleState(PatchState state) {
        return state == PatchState.ENABLED || state == PatchState.DISABLED;
    }

    private void togglePatchForContext(ActionContext context) {
        Patch patch = patchForContext(context);
        if (patch == null || !canEditPatches()) {
            return;
        }
        togglePatch(patch);
    }

    private void togglePatch(Patch patch) {
        PatchState state = patch.getState(this);
        if (state == PatchState.ENABLED) {
            setPatchEnabled(patch, false);
        }
        else if (state == PatchState.DISABLED) {
            setPatchEnabled(patch, true);
        }
        else {
            showConflict(patch, state);
        }
    }

    void showPatchInfoForSelectedPatch() {
        if (provider == null) {
            return;
        }
        showPatchInfo(provider.getSelectedPatch());
    }

    void showPatchInfo(Patch patch) {
        if (patch == null || activeProgram == null || patchInfoDialog == null) {
            return;
        }
        patchInfoDialog.setPatch(patch);
        if (!patchInfoDialog.isVisible()) {
            tool.showDialog(patchInfoDialog);
        }
        patchInfoDialog.toFront();
    }

    byte[] readSuggestedOriginalBytes() {
        Address address = getSuggestedPatchAddress();
        if (address == null || activeProgram == null) {
            return new byte[] { 0 };
        }
        try {
            if (currentSelection != null && !currentSelection.isEmpty()
                    && currentSelection.getNumAddressRanges() == 1
                    && currentSelection.getFirstRange().getMinAddress().equals(address)) {
                long length = currentSelection.getFirstRange().getLength();
                if (length > 0 && length <= 1024 * 1024) {
                    return readBytes(address, (int) length);
                }
            }
            Instruction instruction = activeProgram.getListing().getInstructionContaining(address);
            if (instruction != null && instruction.getMinAddress().equals(address)) {
                return readBytes(address, instruction.getLength());
            }
            return readBytes(address, 1);
        }
        catch (Exception e) {
            return new byte[] { 0 };
        }
    }

    byte[] readBytes(Address address, int length) throws MemoryAccessException {
        if (activeProgram == null || address == null || length <= 0) {
            throw new MemoryAccessException("Invalid memory read request");
        }
        byte[] bytes = new byte[length];
        int count = activeProgram.getMemory().getBytes(address, bytes);
        if (count != length) {
            throw new MemoryAccessException("Only " + count + " bytes were readable");
        }
        return bytes;
    }


    void addPatchFromUi() {
        if (!canEditPatches()) {
            return;
        }
        PatchEditorDialog.Result result = PatchEditorDialog.show(this, provider.getComponent(), null);
        if (result == null) {
            return;
        }

        Patch patch = new Patch(result.name(), result.address(), result.originalBytes(), result.patchedBytes());
        if (!validateNewPatch(patch, null)) {
            return;
        }

        // The dialog captures the original bytes immediately before the patch is made.
        // Refuse to create a patch if the bytes have changed since the dialog was built.
        try {
            byte[] now = readBytes(patch.address, patch.originalBytes.length);
            if (!Arrays.equals(now, patch.originalBytes)) {
                showError("The bytes at " + patch.address + " changed while the patch dialog was open.\n\n"
                        + "Original expected:\n" + HexUtil.format(patch.originalBytes) + "\n\n"
                        + "Current:\n" + HexUtil.format(now), "Patch Conflict");
                return;
            }
        }
        catch (Exception e) {
            showError("Unable to validate the patch location: " + e.getMessage(), "Patch Error");
            return;
        }

        if (!result.enabled()) {
            patches.add(patch);
            saveToProgram();
            refreshProvider();
            provider.selectPatch(patch);
            return;
        }

        setPatchesEnabled(List.of(patch), true, true);
        if (!patches.contains(patch)) {
            return;
        }
        provider.selectPatch(patch);
    }

    void captureCurrentChanges() {
        if (!canEditPatches() || activeProgram == null) {
            return;
        }
        AddressRange range = null;
        if (currentSelection != null && !currentSelection.isEmpty()) {
            if (currentSelection.getNumAddressRanges() != 1) {
                showError("Select one contiguous address range.", "Capture Existing Patch");
                return;
            }
            range = currentSelection.getFirstRange();
        }
        else {
            Address start = getSuggestedPatchAddress();
            if (start == null) {
                return;
            }
            String value = JOptionPane.showInputDialog(provider.getComponent(),
                    "Number of bytes to capture (default 8):", "8");
            if (value == null) {
                return;
            }
            try {
                int length = Integer.parseInt(value.trim());
                if (length <= 0 || length > 1024 * 1024) {
                    throw new NumberFormatException();
                }
                Address end = start.add(length - 1L);
                range = new AddressSet(start, end).getFirstRange();
            }
            catch (RuntimeException e) {
                showError("Invalid length.", "Capture Existing Patch");
                return;
            }
        }

        long rangeLength = range.getLength();
        if (rangeLength <= 0 || rangeLength > 1024 * 1024) {
            showError("Capture range must be between 1 byte and 1 MiB.", "Capture Existing Patch");
            return;
        }
        int length = (int) rangeLength;
        byte[] current = new byte[length];
        byte[] original = new byte[length];
        try {
            activeProgram.getMemory().getBytes(range.getMinAddress(), current);
            for (int i = 0; i < length; i++) {
                Address a = range.getMinAddress().add(i);
                AddressSourceInfo info = activeProgram.getMemory().getAddressSourceInfo(a);
                if (info == null) {
                    showError("No original-file byte information is available at " + a + ".\n"
                            + "Use Add Patch... for memory that is not backed by an imported file.",
                            "Capture Existing Patch");
                    return;
                }
                try {
                    original[i] = info.getOriginalValue();
                }
                catch (IOException e) {
                    showError("Unable to read the original byte at " + a + ": " + e.getMessage(),
                            "Capture Existing Patch");
                    return;
                }
            }
        }
        catch (Exception e) {
            showError("Unable to read the selected bytes: " + e.getMessage(), "Capture Existing Patch");
            return;
        }

        if (Arrays.equals(original, current)) {
            showInfo("The selected range does not contain any bytes changed from the imported original file.",
                    "Capture Existing Patch");
            return;
        }

        String name = JOptionPane.showInputDialog(provider.getComponent(),
                "Patch name:", "Captured @ " + range.getMinAddress());
        if (name == null) {
            return;
        }
        name = name.trim();
        if (name.isEmpty()) {
            showError("Patch name cannot be empty.", "Capture Existing Patch");
            return;
        }

        Patch patch = new Patch(name, range.getMinAddress(), original, current);
        if (!validateNewPatch(patch, null)) {
            return;
        }
        patches.add(patch);
        saveToProgram();
        refreshProvider();
        provider.selectPatch(patch);
        requestOriginalDisassemblyReconcile();
        provider.setStatus("Captured existing patch at " + patch.address);
    }

    void editSelectedPatch() {
        if (!canEditPatches() || provider.getSelectedPatch() == null) {
            return;
        }

        Patch patch = provider.getSelectedPatch();
        PatchState stateBeforeDialog = patch.getState(this);
        if (!isToggleState(stateBeforeDialog)) {
            showConflict(patch, stateBeforeDialog);
            return;
        }

        PatchEditorDialog.Result result = PatchEditorDialog.show(this, provider.getComponent(), patch);
        if (result == null) {
            return;
        }

        // Refuse to overwrite an intervening external change made while the editor was open.
        PatchState stateAfterDialog = patch.getState(this);
        if (stateAfterDialog != stateBeforeDialog) {
            showConflict(patch, stateAfterDialog);
            return;
        }

        if (!result.address().equals(patch.address)) {
            showError("Editing the address of an existing patch is not supported. Delete and recreate it instead.",
                    "Edit Patch");
            return;
        }
        if (!Arrays.equals(result.originalBytes(), patch.originalBytes)) {
            showError("The original bytes of an existing patch are immutable.", "Edit Patch");
            return;
        }

        boolean bytesChanged = !Arrays.equals(result.patchedBytes(), patch.patchedBytes);
        boolean nameChanged = !result.name().equals(patch.name);
        boolean definitionChanged = bytesChanged || nameChanged;
        boolean enabledBefore = stateBeforeDialog == PatchState.ENABLED;
        boolean enabledAfter = result.enabled();

        // Nothing changed, including enabled state.
        if (!definitionChanged && enabledBefore == enabledAfter) {
            return;
        }

        Patch replacement = new Patch(result.name(), patch.address, patch.originalBytes, result.patchedBytes());
        if (!validateNewPatch(replacement, patch)) {
            return;
        }

        // Editing an enabled patch with changed bytes must not use two independent asynchronous
        // toggles. Perform the logical disable -> update -> optional re-enable in one transaction,
        // then re-disassemble once against the final byte state.
        if (enabledBefore && bytesChanged) {
            editEnabledPatch(patch, replacement, enabledAfter);
            return;
        }

        patch.name = replacement.name;
        patch.patchedBytes = replacement.patchedBytes;
        saveToProgram();
        refreshProvider();
        provider.selectPatch(patch);

        if (enabledBefore != enabledAfter) {
            setPatchEnabled(patch, enabledAfter);
        }
        else {
            provider.setStatus("Updated patch '" + patch.name + "'.");
        }
    }

    private void editEnabledPatch(Patch patch, Patch replacement, boolean enabledAfter) {
        if (!canEditPatches() || activeProgram == null) {
            return;
        }

        PatchState state = patch.getState(this);
        if (state != PatchState.ENABLED) {
            showConflict(patch, state);
            return;
        }

        Program program = activeProgram;
        boolean committed = false;
        boolean bytesRestored = false;
        String oldName = patch.name;
        byte[] oldPatchedBytes = patch.patchedBytes.clone();
        ReassemblyRange reassemblyRange = prepareReassembly(patch.address, patch.getEndAddress());

        busy = true;
        internalChange = true;
        int tx = program.startTransaction("Edit Ghidra patch");
        try {
            removeOriginalDisassemblyComment(program, patch);
            if (reassemblyRange != null) {
                program.getListing().clearCodeUnits(
                    reassemblyRange.start(),
                    reassemblyRange.end(),
                    false,
                    TaskMonitor.DUMMY
                );
            }

            // Put the original bytes back before changing the stored patch definition.
            program.getMemory().setBytes(patch.address, patch.originalBytes);
            bytesRestored = true;

            patch.name = replacement.name;
            patch.patchedBytes = replacement.patchedBytes;

            if (enabledAfter) {
                program.getMemory().setBytes(patch.address, patch.patchedBytes);
            }
            committed = true;
        }
        catch (Exception e) {
            patch.name = oldName;
            patch.patchedBytes = oldPatchedBytes;
            if (bytesRestored) {
                try {
                    program.getMemory().setBytes(patch.address, oldPatchedBytes);
                }
                catch (Exception restoreError) {
                    Msg.error(this, "Unable to restore the original patched bytes after edit failure", restoreError);
                }
            }
            showError("Unable to edit enabled patch '" + patch.name + "': " + e.getMessage(), "Edit Patch");
        }
        finally {
            program.endTransaction(tx, committed);
            internalChange = false;
        }

        if (!committed) {
            busy = false;
            refreshProvider();
            provider.selectPatch(patch);
            return;
        }

        try {
            saveToProgram();
        }
        catch (RuntimeException e) {
            Msg.error(this, "Unable to persist edited patch state", e);
        }
        refreshProvider();
        provider.selectPatch(patch);

        if (reassemblyRange == null) {
            busy = false;
            provider.setStatus((enabledAfter ? "Updated and enabled " : "Updated and disabled ")
                    + "patch '" + patch.name + "'.");
            return;
        }

        Program programAtSchedule = program;
        tool.executeBackgroundCommand(new BackgroundCommand<Program>(
                "Re-disassemble edited Ghidra patch", true, false, false) {
            @Override
            public boolean applyTo(Program program, TaskMonitor monitor) {
                boolean success = true;
                try {
                    if (monitor.isCancelled()) {
                        return false;
                    }
                    DisassembleCommand command = createReassemblyCommand(reassemblyRange);
                    success = command.applyTo(program, monitor);
                    return success;
                }
                catch (RuntimeException e) {
                    success = false;
                    Msg.error(PatchManagerPlugin.this,
                            "Automatic patch re-disassembly after edit failed", e);
                    return false;
                }
                finally {
                    boolean finalSuccess = success;
                    javax.swing.SwingUtilities.invokeLater(() ->
                            finishPatchEditReassembly(programAtSchedule, enabledAfter, finalSuccess));
                }
            }
        }, programAtSchedule);
    }

    private void finishPatchEditReassembly(Program program, boolean enabled, boolean success) {
        boolean pending = originalDisassemblyReconcilePending;
        busy = false;
        if (activeProgram != program) {
            refreshProvider();
            if (pending) {
                requestOriginalDisassemblyReconcile();
            }
            return;
        }
        refreshProvider();
        requestOriginalDisassemblyReconcile();
        if (success) {
            Patch selected = provider.getSelectedPatch();
            String name = selected == null ? "" : " '" + selected.name + "'";
            provider.setStatus((enabled ? "Updated and enabled patch" : "Updated and disabled patch")
                    + name + ".");
        }
        else {
            provider.setStatus("Patch edit applied, but automatic re-disassembly did not complete.");
        }
    }

    void togglePatchAtModelRow(int modelRow) {
        if (!canEditPatches() || provider == null) {
            return;
        }
        Patch patch = provider.getModel().getPatch(modelRow);
        if (patch == null) {
            return;
        }
        PatchState state = patch.getState(this);
        if (state == PatchState.ENABLED) {
            setPatchEnabled(patch, false);
        }
        else if (state == PatchState.DISABLED) {
            setPatchEnabled(patch, true);
        }
        else {
            showConflict(patch, state);
        }
    }

    void toggleSelectedPatch() {
        Patch patch = provider.getSelectedPatch();
        if (patch == null || !canEditPatches()) {
            return;
        }
        PatchState state = patch.getState(this);
        if (state == PatchState.ENABLED) {
            setPatchEnabled(patch, false);
        }
        else if (state == PatchState.DISABLED) {
            setPatchEnabled(patch, true);
        }
        else {
            showConflict(patch, state);
        }
    }

    void setPatchEnabled(Patch patch, boolean enabled) {
        if (!canEditPatches() || patch == null) {
            return;
        }
        setPatchesEnabled(List.of(patch), enabled, true);
    }

    void setAllPatchesEnabled(boolean enabled) {
        if (!canEditPatches()) {
            return;
        }
        List<Patch> targets = new ArrayList<>();
        for (Patch patch : patches) {
            PatchState state = patch.getState(this);
            if (state == PatchState.CONFLICT || state == PatchState.MISSING) {
                showConflict(patch, state);
                return;
            }
            if (enabled && state == PatchState.DISABLED) {
                targets.add(patch);
            }
            if (!enabled && state == PatchState.ENABLED) {
                targets.add(patch);
            }
        }
        setPatchesEnabled(targets, enabled, true);
    }

    private void setPatchesEnabled(List<Patch> targets, boolean enabled, boolean addToSet) {
        if (targets.isEmpty()) {
            return;
        }
        if (activeProgram == null) {
            return;
        }
        if (busy) {
            return;
        }

        // Preflight every patch before taking the program transaction. No partial toggles.
        for (Patch patch : targets) {
            PatchState state = patch.getState(this);
            PatchState required = enabled ? PatchState.DISABLED : PatchState.ENABLED;
            if (state != required) {
                showError("Cannot " + (enabled ? "enable" : "disable") + " patch '" + patch.name
                        + "' because its current state is " + state + ".", "Patch Conflict");
                return;
            }
            if (!validateNewPatchBytes(patch)) {
                return;
            }
        }

        busy = true;
        internalChange = true;
        boolean committed = false;
        List<ReassemblyRange> reassemblyRanges = new ArrayList<>();
        Program program = activeProgram;
        int tx = program.startTransaction((enabled ? "Enable " : "Disable ") + " Ghidra patches");
        try {
            if (enabled && isOriginalDisassemblyCommentsEnabled()) {
                for (Patch patch : targets) {
                    if (!hasOriginalDisassembly(patch)) {
                        String captured = captureOriginalDisassembly(program, patch);
                        if (captured != null) {
                            patch.originalDisassembly = captured;
                        }
                    }
                }
            }
            for (Patch patch : targets) {
                if (!enabled) {
                    removeOriginalDisassemblyComment(program, patch);
                }
                ReassemblyRange range = prepareReassembly(program, patch.address, patch.getEndAddress());
                if (range != null) {
                    reassemblyRanges.add(range);
                    program.getListing().clearCodeUnits(range.start(), range.end(), false,
                            TaskMonitor.DUMMY);
                }
                byte[] bytes = enabled ? patch.patchedBytes : patch.originalBytes;
                program.getMemory().setBytes(patch.address, bytes);
            }
            committed = true;
        }
        catch (Exception e) {
            showError("Patch transaction failed: " + e.getMessage(), "Patch Error");
        }
        finally {
            activeProgram.endTransaction(tx, committed);
            internalChange = false;
        }

        if (!committed) {
            busy = false;
            provider.refreshTable();
            return;
        }

        if (addToSet) {
            for (Patch patch : targets) {
                if (!patches.contains(patch)) {
                    patches.add(patch);
                }
            }
            try {
                saveToProgram();
            }
            catch (RuntimeException e) {
                // The byte transaction has already committed. Keep the in-memory patch set
                // usable and report that persistence failed rather than leaving the plugin
                // permanently busy.
                Msg.error(this, "Unable to persist Patch Manager state", e);
            }
        }

        // Disassembly is deliberately performed after the byte transaction commits. Keep the
        // plugin busy until the background re-disassembly has actually completed; otherwise a
        // fast second click can race the first DisassembleCommand and observe a transient state.
        List<ReassemblyRange> mergedRanges = mergeRanges(reassemblyRanges);
        if (mergedRanges.isEmpty()) {
            busy = false;
            refreshProvider();
            provider.setStatus((enabled ? "Enabled " : "Disabled ") + targets.size() + " patch"
                    + (targets.size() == 1 ? "" : "es") + ".");
            return;
        }

        Program programAtSchedule = program;
        tool.executeBackgroundCommand(new BackgroundCommand<Program>(
                "Re-disassemble Ghidra patches", true, false, false) {
            @Override
            public boolean applyTo(Program program, TaskMonitor monitor) {
                boolean success = true;
                try {
                    for (ReassemblyRange range : mergedRanges) {
                        if (monitor.isCancelled()) {
                            success = false;
                            return false;
                        }
                        DisassembleCommand command = createReassemblyCommand(range);
                        if (!command.applyTo(program, monitor)) {
                            success = false;
                        }
                    }
                    return success;
                }
                catch (RuntimeException e) {
                    success = false;
                    Msg.error(PatchManagerPlugin.this,
                            "Automatic patch re-disassembly failed", e);
                    return false;
                }
                finally {
                    boolean finalSuccess = success;
                    javax.swing.SwingUtilities.invokeLater(() ->
                            finishReassembly(programAtSchedule, enabled, targets.size(), finalSuccess));
                }
            }
        }, programAtSchedule);
    }

    private void finishReassembly(Program program, boolean enabled, int count, boolean success) {
        // The command may finish after the user switches programs.  'busy' is plugin-global,
        // so it must still be cleared even though the completed command belongs to the old
        // program. Refresh whichever program is currently active.
        boolean pending = originalDisassemblyReconcilePending;
        busy = false;
        if (activeProgram != program) {
            refreshProvider();
            if (pending) {
                requestOriginalDisassemblyReconcile();
            }
            return;
        }
        refreshProvider();
        requestOriginalDisassemblyReconcile();
        if (success) {
            provider.setStatus((enabled ? "Enabled " : "Disabled ") + count + " patch"
                    + (count == 1 ? "" : "es") + ".");
        }
        else {
            provider.setStatus("Patch byte change applied, but automatic re-disassembly did not complete.");
        }
    }

    private List<ReassemblyRange> mergeRanges(List<ReassemblyRange> ranges) {
        if (ranges.isEmpty()) {
            return List.of();
        }
        List<ReassemblyRange> sorted = new ArrayList<>(ranges);
        sorted.sort(Comparator.comparing(ReassemblyRange::start));
        List<ReassemblyRange> merged = new ArrayList<>();
        ReassemblyRange current = sorted.get(0);
        for (int i = 1; i < sorted.size(); i++) {
            ReassemblyRange next = sorted.get(i);
            if (current.end().getAddressSpace().equals(next.start().getAddressSpace())
                    && current.end().compareTo(next.start()) >= 0) {
                Address end = current.end().compareTo(next.end()) >= 0 ? current.end() : next.end();
                current = new ReassemblyRange(current.start(), end);
            }
            else {
                merged.add(current);
                current = next;
            }
        }
        merged.add(current);
        return merged;
    }

    private boolean validateNewPatch(Patch patch, Patch ignore) {
        try {
            // This framework intentionally keeps patches fixed-length and non-overlapping. That
            // makes the enabled/disabled transition unambiguous even when several patches exist.
            if (patch.originalBytes.length != patch.patchedBytes.length || patch.originalBytes.length == 0) {
                showError("Patch byte arrays must be non-empty and the same length.", "Invalid Patch");
                return false;
            }
            if (activeProgram.getMemory().getBlock(patch.address) == null
                    || activeProgram.getMemory().getBytes(patch.address, new byte[patch.originalBytes.length])
                        != patch.originalBytes.length) {
                showError("The patch does not fit entirely inside initialized program memory.", "Invalid Patch");
                return false;
            }
            if (Arrays.equals(patch.originalBytes, patch.patchedBytes)) {
                showError("Original and patched bytes are identical.", "Invalid Patch");
                return false;
            }
            for (Patch existing : patches) {
                if (existing == ignore) {
                    continue;
                }
                if (overlap(patch, existing)) {
                    showError("Patch overlaps existing patch '" + existing.name + "' at " + existing.address + ".",
                            "Overlapping Patch");
                    return false;
                }
            }
        }
        catch (RuntimeException | MemoryAccessException e) {
            showError("Invalid patch address/range: " + e.getMessage(), "Invalid Patch");
            return false;
        }
        return true;
    }

    private boolean validateNewPatchBytes(Patch patch) {
        try {
            PatchState state = patch.getState(this);
            if (state == PatchState.CONFLICT || state == PatchState.MISSING) {
                showConflict(patch, state);
                return false;
            }
            return true;
        }
        catch (Exception e) {
            showError("Unable to validate patch '" + patch.name + "': " + e.getMessage(), "Patch Error");
            return false;
        }
    }

    private boolean overlap(Patch a, Patch b) {
        if (!a.address.getAddressSpace().equals(b.address.getAddressSpace())) {
            return false;
        }
        return a.address.compareTo(b.getEndAddress()) <= 0 && b.address.compareTo(a.getEndAddress()) <= 0;
    }

    private void requestOriginalDisassemblyReconcile() {
        if (activeProgram == null) {
            if (highlightManager != null) {
                highlightManager.refresh();
            }
            return;
        }
        if (busy) {
            originalDisassemblyReconcilePending = true;
            return;
        }
        originalDisassemblyReconcilePending = false;

        if (!isOriginalDisassemblyCommentsEnabled()) {
            removeAllOriginalDisassemblyComments(activeProgram);
            if (highlightManager != null) {
                highlightManager.refresh();
            }
            return;
        }

        List<Patch> missing = new ArrayList<>();
        for (Patch patch : patches) {
            if (patch.getState(this) == PatchState.ENABLED && !hasOriginalDisassembly(patch)) {
                missing.add(patch);
            }
        }
        if (!missing.isEmpty()) {
            startOriginalDisassemblyMigration(activeProgram, missing, new ArrayList<>(patches));
            return;
        }
        applyOriginalDisassemblyComments(activeProgram);
    }

    private void applyOriginalDisassemblyComments(Program program) {
        if (program == null || program != activeProgram || !isOriginalDisassemblyCommentsEnabled()) {
            return;
        }
        int tx = program.startTransaction("Update original patch comments");
        try {
            for (Patch patch : patches) {
                if (patch.getState(this) == PatchState.ENABLED && hasOriginalDisassembly(patch)) {
                    setOriginalDisassemblyComment(program, patch);
                }
                else {
                    removeOriginalDisassemblyComment(program, patch);
                }
            }
            writePatchProperties(program);
            program.endTransaction(tx, true);
        }
        catch (RuntimeException e) {
            program.endTransaction(tx, false);
            Msg.error(this, "Unable to update original disassembly comments", e);
        }
        if (highlightManager != null) {
            highlightManager.refresh();
        }
    }

    private void removeAllOriginalDisassemblyComments(Program program) {
        if (program == null) {
            return;
        }
        int tx = program.startTransaction("Remove original patch comments");
        try {
            for (Patch patch : patches) {
                removeOriginalDisassemblyComment(program, patch);
            }
            program.endTransaction(tx, true);
        }
        catch (RuntimeException e) {
            program.endTransaction(tx, false);
            Msg.error(this, "Unable to remove original disassembly comments", e);
        }
    }

    private String captureOriginalDisassembly(Program program, Patch patch) {
        if (program == null || patch == null) {
            return null;
        }
        try {
            Address end = patch.address.add(patch.originalBytes.length - 1L);
            Listing listing = program.getListing();
            Instruction current = listing.getInstructionContaining(patch.address);
            if (current == null) {
                current = listing.getInstructionAt(patch.address);
            }
            if (current == null) {
                return null;
            }

            List<String> lines = new ArrayList<>();
            while (current != null
                    && current.getMinAddress().getAddressSpace().equals(patch.address.getAddressSpace())
                    && current.getMinAddress().compareTo(end) <= 0) {
                lines.add("    " + current.getMinAddress() + "  " + current);
                if (current.getMaxAddress().compareTo(end) >= 0) {
                    break;
                }
                Instruction next = listing.getInstructionAfter(current.getMaxAddress());
                if (next == null) {
                    break;
                }
                current = next;
            }
            return lines.isEmpty() ? null : String.join("\n", lines);
        }
        catch (RuntimeException e) {
            return null;
        }
    }

    private boolean setOriginalDisassemblyComment(Program program, Patch patch) {
        if (program == null || patch == null || !hasOriginalDisassembly(patch)) {
            return false;
        }
        CodeUnit codeUnit = getOriginalCommentCodeUnit(program, patch);
        if (codeUnit == null) {
            return false;
        }

        String existing = codeUnit.getComment(CommentType.PRE);
        String managed = buildOriginalDisassemblyComment(patch);
        String replacement = removeManagedOriginalComment(existing, patch);
        if (replacement == null || replacement.isBlank()) {
            replacement = managed;
        }
        else {
            replacement = replacement + "\n\n" + managed;
        }
        if (Objects.equals(existing, replacement)) {
            return false;
        }
        codeUnit.setComment(CommentType.PRE, replacement);
        return true;
    }

    private boolean removeOriginalDisassemblyComment(Program program, Patch patch) {
        if (program == null || patch == null) {
            return false;
        }
        CodeUnit codeUnit = getOriginalCommentCodeUnit(program, patch);
        if (codeUnit == null) {
            return false;
        }
        String existing = codeUnit.getComment(CommentType.PRE);
        if (existing == null) {
            return false;
        }
        String replacement = removeManagedOriginalComment(existing, patch);
        if (Objects.equals(existing, replacement)) {
            return false;
        }
        codeUnit.setComment(CommentType.PRE, replacement == null || replacement.isBlank() ? null : replacement);
        return true;
    }

    private CodeUnit getOriginalCommentCodeUnit(Program program, Patch patch) {
        Listing listing = program.getListing();
        Instruction instruction = listing.getInstructionContaining(patch.address);
        if (instruction != null) {
            return instruction;
        }
        return listing.getCodeUnitAt(patch.address);
    }

    private static String buildOriginalDisassemblyComment(Patch patch) {
        return originalCommentStart(patch) + "\n" + patch.originalDisassembly
                + "\n" + originalCommentEnd(patch);
    }

    private static String originalCommentStart(Patch patch) {
        return ORIGINAL_COMMENT_PREFIX + patch.address + ORIGINAL_COMMENT_SUFFIX;
    }

    private static String originalCommentEnd(Patch patch) {
        return ORIGINAL_COMMENT_END_PREFIX + patch.address + ORIGINAL_COMMENT_SUFFIX;
    }

    private static String removeManagedOriginalComment(String comment, Patch patch) {
        if (comment == null || comment.isEmpty()) {
            return comment;
        }
        String start = originalCommentStart(patch);
        String end = originalCommentEnd(patch);
        String[] lines = comment.split("\n", -1);
        List<String> kept = new ArrayList<>();
        boolean removing = false;
        boolean found = false;
        for (String line : lines) {
            if (!removing && line.equals(start)) {
                removing = true;
                found = true;
                continue;
            }
            if (removing) {
                if (line.equals(end)) {
                    removing = false;
                }
                continue;
            }
            kept.add(line);
        }
        if (!found || removing) {
            return comment;
        }
        while (!kept.isEmpty() && kept.get(0).isBlank()) {
            kept.remove(0);
        }
        while (!kept.isEmpty() && kept.get(kept.size() - 1).isBlank()) {
            kept.remove(kept.size() - 1);
        }
        return String.join("\n", kept);
    }

    private void startOriginalDisassemblyMigration(Program program, List<Patch> missing, List<Patch> patchSnapshot) {
        if (program == null || missing.isEmpty()) {
            return;
        }
        busy = true;
        internalChange = true;
        tool.executeBackgroundCommand(new BackgroundCommand<Program>(
                "Capture original patch disassembly", true, false, false) {
            @Override
            public boolean applyTo(Program targetProgram, TaskMonitor monitor) {
                boolean success = true;
                boolean originalsWritten = false;
                List<ReassemblyRange> ranges = new ArrayList<>();
                try {
                    for (Patch patch : missing) {
                        if (monitor.isCancelled()) {
                            return false;
                        }
                        ReassemblyRange range = prepareReassembly(targetProgram, patch.address, patch.getEndAddress());
                        if (range != null) {
                            ranges.add(range);
                        }
                    }
                    List<ReassemblyRange> merged = mergeRanges(ranges);

                    int tx = targetProgram.startTransaction("Temporarily restore original patches");
                    try {
                        for (Patch patch : missing) {
                            removeOriginalDisassemblyComment(targetProgram, patch);
                        }
                        for (ReassemblyRange range : merged) {
                            targetProgram.getListing().clearCodeUnits(range.start(), range.end(), false,
                                    TaskMonitor.DUMMY);
                        }
                        for (Patch patch : missing) {
                            targetProgram.getMemory().setBytes(patch.address, patch.originalBytes);
                        }
                        originalsWritten = true;
                        targetProgram.endTransaction(tx, true);
                    }
                    catch (Exception e) {
                        targetProgram.endTransaction(tx, false);
                        throw new RuntimeException(e);
                    }

                    for (ReassemblyRange range : merged) {
                        if (monitor.isCancelled()) {
                            return false;
                        }
                        DisassembleCommand command = createReassemblyCommand(range);
                        if (!command.applyTo(targetProgram, monitor)) {
                            success = false;
                        }
                    }

                    int captured = 0;
                    for (Patch patch : missing) {
                        String value = captureOriginalDisassembly(targetProgram, patch);
                        if (value != null) {
                            patch.originalDisassembly = value;
                            captured++;
                        }
                    }

                    int tx2 = targetProgram.startTransaction("Restore enabled patches after capture");
                    try {
                        for (ReassemblyRange range : merged) {
                            targetProgram.getListing().clearCodeUnits(range.start(), range.end(), false,
                                    TaskMonitor.DUMMY);
                        }
                        for (Patch patch : missing) {
                            targetProgram.getMemory().setBytes(patch.address, patch.patchedBytes);
                        }
                        targetProgram.endTransaction(tx2, true);
                    }
                    catch (Exception e) {
                        targetProgram.endTransaction(tx2, false);
                        throw new RuntimeException(e);
                    }

                    for (ReassemblyRange range : merged) {
                        if (monitor.isCancelled()) {
                            return false;
                        }
                        DisassembleCommand command = createReassemblyCommand(range);
                        if (!command.applyTo(targetProgram, monitor)) {
                            success = false;
                        }
                    }

                    int tx3 = targetProgram.startTransaction("Store original patch disassembly");
                    try {
                        for (Patch patch : patchSnapshot) {
                            if (isOriginalDisassemblyCommentsEnabled()
                                    && patch.getState(targetProgram) == PatchState.ENABLED
                                    && hasOriginalDisassembly(patch)) {
                                setOriginalDisassemblyComment(targetProgram, patch);
                            }
                            else {
                                removeOriginalDisassemblyComment(targetProgram, patch);
                            }
                        }
                        writePatchProperties(targetProgram, patchSnapshot);
                        targetProgram.endTransaction(tx3, true);
                    }
                    catch (Exception e) {
                        targetProgram.endTransaction(tx3, false);
                        throw new RuntimeException(e);
                    }

                    final int capturedFinal = captured;
                    final boolean successFinal = success;
                    javax.swing.SwingUtilities.invokeLater(() ->
                            finishOriginalDisassemblyMigration(program, successFinal, capturedFinal, missing.size()));
                    return success;
                }
                catch (RuntimeException e) {
                    success = false;
                    Msg.error(PatchManagerPlugin.this,
                            "Unable to capture original disassembly for existing patches", e);
                    javax.swing.SwingUtilities.invokeLater(() ->
                            finishOriginalDisassemblyMigration(program, false, 0, missing.size()));
                    return false;
                }
                finally {
                    if (!success && originalsWritten) {
                        restorePatchedBytesAfterMigration(targetProgram, missing, ranges);
                    }
                }
            }
        }, program);
    }

    private void restorePatchedBytesAfterMigration(Program program, List<Patch> missing,
            List<ReassemblyRange> ranges) {
        try {
            int tx = program.startTransaction("Restore patches after original disassembly capture failure");
            try {
                for (ReassemblyRange range : mergeRanges(ranges)) {
                    program.getListing().clearCodeUnits(range.start(), range.end(), false, TaskMonitor.DUMMY);
                }
                for (Patch patch : missing) {
                    program.getMemory().setBytes(patch.address, patch.patchedBytes);
                }
                program.endTransaction(tx, true);
            }
            catch (Exception e) {
                program.endTransaction(tx, false);
                throw new RuntimeException(e);
            }
            for (ReassemblyRange range : mergeRanges(ranges)) {
                DisassembleCommand command = createReassemblyCommand(range);
                command.applyTo(program, TaskMonitor.DUMMY);
            }
        }
        catch (RuntimeException e) {
            Msg.error(this, "Unable to restore enabled patch bytes after migration failure", e);
        }
    }

    private void finishOriginalDisassemblyMigration(Program program, boolean success, int captured, int total) {
        if (activeProgram == program) {
            refreshProvider();
            if (success && captured == total) {
                provider.setStatus("Captured original disassembly for " + total + " enabled patch"
                        + (total == 1 ? "" : "es") + ".");
            }
            else if (captured > 0) {
                provider.setStatus("Captured original disassembly for " + captured + " of " + total + " patches.");
            }
            else {
                provider.setStatus("Original disassembly capture did not complete.");
            }
        }
        boolean pending = originalDisassemblyReconcilePending;
        busy = false;
        originalDisassemblyReconcilePending = false;
        if (activeProgram != program) {
            if (pending) {
                requestOriginalDisassemblyReconcile();
            }
            else if (highlightManager != null) {
                highlightManager.refresh();
            }
            return;
        }
        if (pending) {
            requestOriginalDisassemblyReconcile();
        }
        else if (highlightManager != null) {
            highlightManager.refresh();
        }
    }

    /**
     * Re-disassemble every currently undefined start point in the affected range, while still
     * restricting the operation to that same range. Using the range as the start set is important
     * for patches that turn a conditional branch into an unconditional branch and leave a valid
     * instruction (for example a NOP) immediately after the patched instruction; a single start
     * address would otherwise have no flow path into that fall-through byte.
     */
    private static DisassembleCommand createReassemblyCommand(ReassemblyRange range) {
        AddressSet rangeSet = new AddressSet(range.start(), range.end());
        DisassembleCommand command = new DisassembleCommand(rangeSet, rangeSet, true);
        command.enableCodeAnalysis(true);
        return command;
    }

    private ReassemblyRange prepareReassembly(Address address, Address end) {
        return prepareReassembly(activeProgram, address, end);
    }

    private ReassemblyRange prepareReassembly(Program program, Address address, Address end) {
        if (program == null || address == null || end == null) {
            return null;
        }
        Listing listing = program.getListing();
        Instruction first = listing.getInstructionContaining(address);
        Instruction last = listing.getInstructionContaining(end);
        if (first == null && last == null) {
            // If the user is patching undefined executable bytes, give Ghidra a chance to decode
            // them as well. This is still restricted to a small local range rather than the
            // whole program.
            if (!program.getMemory().getExecuteSet().contains(address)) {
                return null;
            }
        }
        Address start = first != null ? first.getMinAddress() : address;
        Address finish = last != null ? last.getMaxAddress() : end;

        // Only clear code units that actually intersect the patch (expanded to the complete
        // containing instruction boundaries). Do not extend the clear range into otherwise-valid
        // following instructions: a fixed-length patch can change instruction boundaries, and
        // clearing an arbitrary look-ahead region would destroy unaffected disassembly. The
        // subsequent DisassembleCommand is still restricted to this affected range.
        return new ReassemblyRange(start, finish);
    }


    void deleteSelectedPatches() {
        int[] rows = provider.getSelectedModelRows();
        if (rows.length == 0 || !canEditPatches()) {
            return;
        }

        javax.swing.JCheckBox restoreOriginals =
                new javax.swing.JCheckBox("Restore original bytes before deleting", true);
        javax.swing.JPanel confirmation = new javax.swing.JPanel(new java.awt.BorderLayout(0, 8));
        confirmation.add(new javax.swing.JLabel(
                "Delete " + rows.length + " patch" + (rows.length == 1 ? "" : "es")
                        + " from Patch Manager?"), java.awt.BorderLayout.NORTH);
        confirmation.add(restoreOriginals, java.awt.BorderLayout.SOUTH);

        int answer = JOptionPane.showConfirmDialog(provider.getComponent(),
                confirmation, "Delete Patches", JOptionPane.OK_CANCEL_OPTION, JOptionPane.WARNING_MESSAGE);
        if (answer != JOptionPane.OK_OPTION) {
            return;
        }

        List<Patch> remove = new ArrayList<>();
        for (int row : rows) {
            Patch p = provider.getModel().getPatch(row);
            if (p != null) {
                remove.add(p);
            }
        }
        if (remove.isEmpty() || !canEditPatches()) {
            return;
        }

        Program program = activeProgram;
        boolean restore = restoreOriginals.isSelected();
        List<Patch> enabledToRestore = new ArrayList<>();
        List<ReassemblyRange> reassemblyRanges = new ArrayList<>();

        if (restore) {
            // Do not silently overwrite unexpected bytes merely because the user chose the
            // restore option. Disabled patches already have their original bytes present, while
            // conflicts/missing patches must be resolved explicitly by the user.
            for (Patch patch : remove) {
                PatchState state = patch.getState(program);
                if (state == PatchState.CONFLICT || state == PatchState.MISSING) {
                    showConflict(patch, state);
                    return;
                }
                if (state == PatchState.ENABLED) {
                    enabledToRestore.add(patch);
                    ReassemblyRange range = prepareReassembly(program, patch.address, patch.getEndAddress());
                    if (range != null) {
                        reassemblyRanges.add(range);
                    }
                }
            }
        }

        busy = true;
        internalChange = true;
        boolean committed = false;
        int tx = program.startTransaction(restore
                ? "Restore and delete Ghidra patches"
                : "Delete Ghidra patches");
        try {
            // Clear only the code units intersected by each enabled patch while their current
            // (possibly differently-sized) instructions still exist.  This is essential when
            // restoring an original instruction whose size differs from the patched decoding.
            if (restore) {
                for (ReassemblyRange range : mergeRanges(reassemblyRanges)) {
                    program.getListing().clearCodeUnits(range.start(), range.end(), false,
                            TaskMonitor.DUMMY);
                }
                for (Patch patch : enabledToRestore) {
                    program.getMemory().setBytes(patch.address, patch.originalBytes);
                }
            }

            // Remove managed PRE comment blocks in the same transaction as the deletion.
            for (Patch patch : remove) {
                removeOriginalDisassemblyComment(program, patch);
            }
            committed = true;
        }
        catch (Exception e) {
            showError("Unable to delete selected patches: " + e.getMessage(), "Delete Patches");
        }
        finally {
            program.endTransaction(tx, committed);
            internalChange = false;
        }

        if (!committed) {
            busy = false;
            refreshProvider();
            return;
        }

        patches.removeAll(remove);
        try {
            saveToProgram();
        }
        catch (RuntimeException e) {
            Msg.error(this, "Unable to persist Patch Manager state after deleting patches", e);
        }
        refreshProvider();

        List<ReassemblyRange> mergedRanges = mergeRanges(reassemblyRanges);
        if (!restore || mergedRanges.isEmpty()) {
            busy = false;
            requestOriginalDisassemblyReconcile();
            return;
        }

        Program programAtSchedule = program;
        tool.executeBackgroundCommand(new BackgroundCommand<Program>(
                "Re-disassemble restored Ghidra patches", true, false, false) {
            @Override
            public boolean applyTo(Program targetProgram, TaskMonitor monitor) {
                boolean success = true;
                try {
                    for (ReassemblyRange range : mergedRanges) {
                        if (monitor.isCancelled()) {
                            success = false;
                            return false;
                        }
                        DisassembleCommand command = createReassemblyCommand(range);
                        if (!command.applyTo(targetProgram, monitor)) {
                            success = false;
                        }
                    }
                    return success;
                }
                catch (RuntimeException e) {
                    success = false;
                    Msg.error(PatchManagerPlugin.this,
                            "Automatic re-disassembly after restoring deleted patches failed", e);
                    return false;
                }
                finally {
                    boolean finalSuccess = success;
                    javax.swing.SwingUtilities.invokeLater(() ->
                            finishDeletedPatchReassembly(programAtSchedule, finalSuccess, remove.size()));
                }
            }
        }, programAtSchedule);
    }

    private void finishDeletedPatchReassembly(Program program, boolean success, int count) {
        busy = false;
        if (activeProgram != program) {
            refreshProvider();
            return;
        }
        refreshProvider();
        requestOriginalDisassemblyReconcile();
        if (success) {
            provider.setStatus("Deleted " + count + " patch" + (count == 1 ? "" : "es")
                    + " and restored original bytes.");
        }
        else {
            provider.setStatus("Deleted " + count
                    + " patch" + (count == 1 ? "" : "es")
                    + "; original bytes restored, but automatic re-disassembly did not complete.");
        }
    }

    void jumpToSelectedPatch() {
        Patch patch = provider.getSelectedPatch();
        if (patch == null || activeProgram == null) {
            return;
        }
        goTo(patch.address);
    }

    boolean selectedPatchIsEditable() {
        Patch patch = provider.getSelectedPatch();
        if (patch == null) {
            return false;
        }
        PatchState state = patch.getState(this);
        return state == PatchState.ENABLED || state == PatchState.DISABLED;
    }

    void refreshProvider() {
        if (provider == null) {
            return;
        }
        if (activeProgram == null) {
            provider.setPatches(List.of());
            provider.setStatus("No program");
            if (patchInfoDialog != null) {
                patchInfoDialog.clearPatch();
            }
            tool.contextChanged(null);
            return;
        }
        provider.setPatches(patches);
        if (highlightManager != null) {
            highlightManager.refresh();
        }
        provider.setStatus(patches.size() + " patch" + (patches.size() == 1 ? "" : "es")
                + " in " + activeProgram.getName());
        if (patchInfoDialog != null && patchInfoDialog.isVisible()) {
            patchInfoDialog.refresh();
        }
        tool.contextChanged(null);
    }

    private void loadFromProgram(Program program) {
        patches = new ArrayList<>();
        Options options = program.getOptions(OPTION_PATH);
        String encoded = options.getString(OPTION_DATA, "");
        if (encoded == null || encoded.isBlank()) {
            return;
        }
        try {
            Properties props = new Properties();
            props.load(new StringReader(encoded));
            String format = props.getProperty("format", "");
            int version = Integer.parseInt(props.getProperty("version", "0"));
            if (!FORMAT.equals(format) || version != FORMAT_VERSION) {
                Msg.warn(this, "Ignoring unsupported Patch Manager data in " + program.getName());
                return;
            }
            int count = Integer.parseInt(props.getProperty("count", "0"));
            for (int i = 0; i < count; i++) {
                String addressText = props.getProperty("patch." + i + ".address");
                String nameEncoded = props.getProperty("patch." + i + ".name");
                String originalText = props.getProperty("patch." + i + ".original");
                String patchedText = props.getProperty("patch." + i + ".patched");
                String originalDisassemblyEncoded = props.getProperty("patch." + i + ".originalDisassembly");
                if (addressText == null || nameEncoded == null || originalText == null || patchedText == null) {
                    continue;
                }
                Address address = program.getAddressFactory().getAddress(addressText);
                if (address == null) {
                    continue;
                }
                String name = new String(Base64.getDecoder().decode(nameEncoded), StandardCharsets.UTF_8);
                byte[] original = HexUtil.parse(originalText);
                byte[] patched = HexUtil.parse(patchedText);
                Patch patch = new Patch(name, address, original, patched);
                if (originalDisassemblyEncoded != null && !originalDisassemblyEncoded.isBlank()) {
                    try {
                        patch.originalDisassembly = new String(
                                Base64.getDecoder().decode(originalDisassemblyEncoded), StandardCharsets.UTF_8);
                    }
                    catch (IllegalArgumentException e) {
                        Msg.warn(this, "Ignoring invalid stored original disassembly for patch '" + name + "'.");
                    }
                }
                if (validateStoredPatch(program, patch)) {
                    patches.add(patch);
                }
            }
            patches.sort(Comparator.comparing(p -> p.address));
        }
        catch (Exception e) {
            Msg.showError(this, null, "Patch Manager", "Unable to load stored patch definitions: " + e.getMessage());
        }
    }

    private boolean validateStoredPatch(Program program, Patch patch) {
        if (patch.address == null || patch.originalBytes.length == 0
                || patch.originalBytes.length != patch.patchedBytes.length
                || Arrays.equals(patch.originalBytes, patch.patchedBytes)) {
            return false;
        }
        try {
            byte[] current = new byte[patch.originalBytes.length];
            return program.getMemory().getBytes(patch.address, current) == current.length
                    && program.getMemory().getBlock(patch.address) != null;
        }
        catch (Exception e) {
            return false;
        }
    }

    private void saveToProgram() {
        if (activeProgram == null) {
            return;
        }
        int tx = activeProgram.startTransaction("Save Patch Manager state");
        try {
            writePatchProperties(activeProgram);
            activeProgram.endTransaction(tx, true);
        }
        catch (RuntimeException e) {
            activeProgram.endTransaction(tx, false);
            throw e;
        }
    }


    void exportPatchSet() {
        if (activeProgram == null) {
            return;
        }
        JFileChooser chooser = new JFileChooser();
        chooser.setDialogTitle("Save Patch Set");
        chooser.setSelectedFile(new File(activeProgram.getName() + ".ghidrapatches"));
        if (chooser.showSaveDialog(provider.getComponent()) != JFileChooser.APPROVE_OPTION) {
            return;
        }
        Properties props = buildPatchProperties();
        File file = chooser.getSelectedFile();
        try (FileOutputStream out = new FileOutputStream(file)) {
            props.store(out, "Ghidra Patch Manager patch set");
            provider.setStatus("Saved patch set: " + file);
        }
        catch (IOException e) {
            showError("Unable to save patch set: " + e.getMessage(), "Save Patch Set");
        }
    }

    void importPatchSet() {
        if (!canEditPatches()) {
            return;
        }
        JFileChooser chooser = new JFileChooser();
        chooser.setDialogTitle("Load Patch Set");
        if (chooser.showOpenDialog(provider.getComponent()) != JFileChooser.APPROVE_OPTION) {
            return;
        }
        for (Patch existing : patches) {
            PatchState state = existing.getState(this);
            if (state == PatchState.ENABLED) {
                showError("Disable all currently managed patches before loading another patch set.\n\n"
                        + "This prevents old enabled bytes from being left behind after the definitions are replaced.",
                        "Load Patch Set");
                return;
            }
        }

        Properties props = new Properties();
        try (FileInputStream in = new FileInputStream(chooser.getSelectedFile())) {
            props.load(in);
            String expectedSha = props.getProperty("executable_sha256", "").trim();
            String actualSha = activeProgram.getExecutableSHA256();
            if (!expectedSha.isEmpty() && !expectedSha.equalsIgnoreCase(actualSha)) {
                showError("The patch set was created for a different original executable.\n\n"
                        + "Patch-set SHA-256: " + expectedSha + "\n"
                        + "Current program SHA-256: " + actualSha,
                        "Wrong Binary");
                return;
            }
            List<Patch> imported = parsePatchProperties(props);
            if (!validateImportedSet(imported)) {
                return;
            }
            patches = imported;
            saveToProgram();
            refreshProvider();
            requestOriginalDisassemblyReconcile();
            provider.setStatus("Loaded " + patches.size() + " patch" + (patches.size() == 1 ? "" : "es"));
        }
        catch (Exception e) {
            showError("Unable to load patch set: " + e.getMessage(), "Load Patch Set");
        }
    }

    private void writePatchProperties(Program program) {
        writePatchProperties(program, patches);
    }

    private void writePatchProperties(Program program, List<Patch> sourcePatches) {
        Properties props = buildPatchProperties(program, sourcePatches);
        try (StringWriter sw = new StringWriter()) {
            props.store(sw, "Ghidra Patch Manager patch definitions");
            program.getOptions(OPTION_PATH).setString(OPTION_DATA, sw.toString());
        }
        catch (IOException e) {
            throw new IllegalStateException("Unable to serialize patch state", e);
        }
    }

    private Properties buildPatchProperties() {
        return buildPatchProperties(activeProgram, patches);
    }

    private Properties buildPatchProperties(Program program, List<Patch> sourcePatches) {
        Properties props = new Properties();
        props.setProperty("format", FORMAT);
        props.setProperty("version", Integer.toString(FORMAT_VERSION));
        props.setProperty("program", program == null ? "" : program.getName());
        props.setProperty("executable_sha256", program == null ? "" : program.getExecutableSHA256());
        props.setProperty("count", Integer.toString(sourcePatches.size()));
        for (int i = 0; i < sourcePatches.size(); i++) {
            Patch p = sourcePatches.get(i);
            props.setProperty("patch." + i + ".name", Base64.getEncoder().encodeToString(p.name.getBytes(StandardCharsets.UTF_8)));
            props.setProperty("patch." + i + ".address", p.address.toString());
            props.setProperty("patch." + i + ".original", HexUtil.format(p.originalBytes));
            props.setProperty("patch." + i + ".patched", HexUtil.format(p.patchedBytes));
            if (hasOriginalDisassembly(p)) {
                props.setProperty("patch." + i + ".originalDisassembly",
                        Base64.getEncoder().encodeToString(p.originalDisassembly.getBytes(StandardCharsets.UTF_8)));
            }
        }
        return props;
    }

    private List<Patch> parsePatchProperties(Properties props) {
        if (!FORMAT.equals(props.getProperty("format", ""))) {
            throw new IllegalArgumentException("Not a Ghidra Patch Manager file.");
        }
        int version = Integer.parseInt(props.getProperty("version", "0"));
        if (version != FORMAT_VERSION) {
            throw new IllegalArgumentException("Unsupported patch-set version: " + version);
        }
        int count = Integer.parseInt(props.getProperty("count", "0"));
        List<Patch> imported = new ArrayList<>();
        for (int i = 0; i < count; i++) {
            String name = new String(Base64.getDecoder().decode(required(props, "patch." + i + ".name")), StandardCharsets.UTF_8);
            Address address = activeProgram.getAddressFactory().getAddress(required(props, "patch." + i + ".address"));
            if (address == null) {
                throw new IllegalArgumentException("Invalid address for patch " + i);
            }
            Patch p = new Patch(name, address,
                    HexUtil.parse(required(props, "patch." + i + ".original")),
                    HexUtil.parse(required(props, "patch." + i + ".patched")));
            String originalDisassemblyEncoded = props.getProperty("patch." + i + ".originalDisassembly", "");
            if (!originalDisassemblyEncoded.isBlank()) {
                try {
                    p.originalDisassembly = new String(Base64.getDecoder().decode(originalDisassemblyEncoded),
                            StandardCharsets.UTF_8);
                }
                catch (IllegalArgumentException e) {
                    throw new IllegalArgumentException("Invalid original disassembly for imported patch " + i, e);
                }
            }
            imported.add(p);
        }
        return imported;
    }

    private boolean validateImportedSet(List<Patch> imported) {
        for (int i = 0; i < imported.size(); i++) {
            Patch p = imported.get(i);
            if (!validatePatchDefinitionForImport(p)) {
                return false;
            }
            for (int j = i + 1; j < imported.size(); j++) {
                if (overlap(p, imported.get(j))) {
                    showError("Imported patches overlap: '" + p.name + "' and '" + imported.get(j).name + "'.",
                            "Load Patch Set");
                    return false;
                }
            }
            PatchState state = p.getState(this);
            if (state == PatchState.CONFLICT || state == PatchState.MISSING) {
                showError("Imported patch '" + p.name + "' does not match either its original or patched bytes at "
                        + p.address + ". Current state: " + state,
                        "Load Patch Set");
                return false;
            }
        }
        return true;
    }

    private boolean validatePatchDefinitionForImport(Patch patch) {
        try {
            if (patch.originalBytes.length == 0 || patch.originalBytes.length != patch.patchedBytes.length) {
                showError("Patch '" + patch.name + "' has invalid byte lengths.", "Load Patch Set");
                return false;
            }
            if (Arrays.equals(patch.originalBytes, patch.patchedBytes)) {
                showError("Patch '" + patch.name + "' has identical original and patched bytes.", "Load Patch Set");
                return false;
            }
            byte[] current = new byte[patch.originalBytes.length];
            if (activeProgram.getMemory().getBytes(patch.address, current) != current.length) {
                showError("Patch '" + patch.name + "' does not fit in initialized memory.", "Load Patch Set");
                return false;
            }
            return true;
        }
        catch (Exception e) {
            showError("Invalid imported patch '" + patch.name + "': " + e.getMessage(), "Load Patch Set");
            return false;
        }
    }

    private String required(Properties props, String key) {
        String value = props.getProperty(key);
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException("Missing property: " + key);
        }
        return value;
    }

    private void showConflict(Patch patch, PatchState state) {
        String current = "<unavailable>";
        try {
            current = HexUtil.format(readBytes(patch.address, patch.patchedBytes.length));
        }
        catch (Exception ignored) {
        }
        showError("Patch '" + patch.name + "' at " + patch.address + " is in state " + state + ".\n\n"
                + "Original: " + HexUtil.format(patch.originalBytes) + "\n"
                + "Patched:  " + HexUtil.format(patch.patchedBytes) + "\n"
                + "Current:  " + current + "\n\n"
                + "The manager will not overwrite an unexpected byte sequence.",
                "Patch Conflict");
    }

    private void showInfo(String message, String title) {
        JOptionPane.showMessageDialog(provider.getComponent(), message, title, JOptionPane.INFORMATION_MESSAGE);
    }

    private void showError(String message, String title) {
        JOptionPane.showMessageDialog(provider.getComponent(), message, title, JOptionPane.ERROR_MESSAGE);
    }

    List<Patch> getPatchesSnapshot() {
        return new ArrayList<>(patches);
    }

    void refreshProviderFromProgramChange() {
        if (!busy) {
            refreshProvider();
        }
    }

    private record ReassemblyRange(Address start, Address end) {
    }
}
