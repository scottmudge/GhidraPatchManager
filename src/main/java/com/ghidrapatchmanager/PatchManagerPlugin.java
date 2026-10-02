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
import java.util.Properties;

import javax.swing.JFileChooser;
import javax.swing.JOptionPane;

import docking.action.DockingAction;
import docking.action.MenuData;
import ghidra.framework.plugintool.ComponentProviderAdapter;
import docking.ActionContext;
import ghidra.app.CorePluginPackage;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.framework.model.DomainObjectChangedEvent;
import ghidra.framework.model.DomainObjectListener;
import ghidra.framework.options.Options;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.database.mem.AddressSourceInfo;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramLocation;
import ghidra.util.HelpLocation;
import ghidra.util.Msg;
import ghidra.util.task.TaskMonitor;
import ghidra.program.model.mem.MemoryAccessException;

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

    private PatchManagerProvider provider;
    private DockingAction showAction;
    private Program activeProgram;
    private List<Patch> patches = new ArrayList<>();
    private boolean busy;
    private boolean internalChange;

    public PatchManagerPlugin(PluginTool tool) {
        super(tool);
    }

    @Override
    protected void init() {
        super.init();
        provider = new PatchManagerProvider(tool, this);
        tool.addComponentProvider(provider, false);

        showAction = new DockingAction("Show Patch Manager", getName()) {
            @Override
            public void actionPerformed(ActionContext context) {
                provider.setVisible(true);
                tool.toFront(provider);
                provider.getComponent().requestFocusInWindow();
            }
        };
        showAction.setPopupMenuData(new MenuData(new String[] { "Window", "Patch Manager" }));
        showAction.setDescription("Open the Patch Manager window");
        tool.addAction(showAction);

        provider.getComponent().setName("Ghidra Patch Manager");
        provider.setHelpLocation(new HelpLocation(getName(), "Patch_Manager"));
    }

    @Override
    protected void dispose() {
        if (activeProgram != null) {
            activeProgram.removeListener(this);
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
        refreshProvider();
    }

    @Override
    protected void programDeactivated(Program program) {
        if (program != null) {
            program.removeListener(this);
        }
        if (activeProgram == program) {
            activeProgram = null;
        }
        super.programDeactivated(program);
        refreshProvider();
    }

    @Override
    protected void locationChanged(ProgramLocation location) {
        super.locationChanged(location);
        if (provider != null && provider.isVisible() && activeProgram != null && provider.getSelectedPatch() == null) {
            provider.setStatus("Current address: " + location);
        }
    }

    @Override
    public void domainObjectChanged(DomainObjectChangedEvent ev) {
        if (internalChange || provider == null || busy) {
            return;
        }
        javax.swing.SwingUtilities.invokeLater(this::refreshProvider);
    }

    @Override
    public Program getCurrentProgram() {
        return activeProgram;
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

    byte[] readSuggestedOriginalBytes() {
        Address address = getSuggestedPatchAddress();
        if (address == null || activeProgram == null) {
            return new byte[] { 0 };
        }
        try {
            // A contiguous Listing selection is a convenient default patch length.
            if (currentSelection != null && !currentSelection.isEmpty()
                    && currentSelection.getNumAddressRanges() == 1
                    && currentSelection.getFirstRange().getMinAddress().equals(address)) {
                long length = currentSelection.getFirstRange().getLength();
                if (length > 0 && length <= 1024 * 1024) {
                    return readBytes(address, (int) length);
                }
            }

            // When the cursor is at the beginning of an instruction, default to the whole
            // instruction rather than an arbitrary one-byte patch.
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
        provider.setStatus("Captured existing patch at " + patch.address);
    }

    void editSelectedPatch() {
        if (!canEditPatches() || provider.getSelectedPatch() == null) {
            return;
        }
        Patch patch = provider.getSelectedPatch();
        PatchState state = patch.getState(this);
        if (state != PatchState.DISABLED) {
            showInfo("Disable this patch before editing it.\n\nCurrent state: " + state, "Edit Patch");
            return;
        }

        PatchEditorDialog.Result result = PatchEditorDialog.show(this, provider.getComponent(), patch);
        if (result == null) {
            return;
        }
        if (Arrays.equals(result.patchedBytes(), patch.patchedBytes) && result.name().equals(patch.name)) {
            return;
        }
        if (result.address().equals(patch.address) && !Arrays.equals(result.originalBytes(), patch.originalBytes)) {
            showError("The original bytes of an existing patch are immutable.", "Edit Patch");
            return;
        }
        Patch replacement = new Patch(result.name(), patch.address, patch.originalBytes, result.patchedBytes());
        if (!validateNewPatch(replacement, patch)) {
            return;
        }
        patch.name = replacement.name;
        patch.patchedBytes = replacement.patchedBytes;
        saveToProgram();
        refreshProvider();
        provider.selectPatch(patch);
        if (result.enabled()) {
            setPatchEnabled(patch, true);
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
        provider.refreshTable();
        internalChange = true;
        boolean committed = false;
        List<ReassemblyRange> reassemblyRanges = new ArrayList<>();
        int tx = activeProgram.startTransaction((enabled ? "Enable " : "Disable ") + " Ghidra patches");
        try {
            for (Patch patch : targets) {
                ReassemblyRange range = prepareReassembly(patch.address, patch.getEndAddress());
                if (range != null) {
                    reassemblyRanges.add(range);
                    activeProgram.getListing().clearCodeUnits(range.start(), range.end(), false,
                            TaskMonitor.DUMMY);
                }
                byte[] bytes = enabled ? patch.patchedBytes : patch.originalBytes;
                activeProgram.getMemory().setBytes(patch.address, bytes);
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
            saveToProgram();
        }

        // Disassembly is deliberately performed after the byte transaction commits. This mirrors
        // Ghidra's own edit-bytes workflow: clear code units, write bytes, then invoke the normal
        // DisassembleCommand so references, flow and decompiler consumers see the new code.
        for (ReassemblyRange range : mergeRanges(reassemblyRanges)) {
            DisassembleCommand command = new DisassembleCommand(range.start(),
                    new AddressSet(range.start(), range.end()), true);
            command.enableCodeAnalysis(true);
            tool.executeBackgroundCommand(command, activeProgram);
        }

        busy = false;
        refreshProvider();
        provider.setStatus((enabled ? "Enabled " : "Disabled ") + targets.size() + " patch"
                + (targets.size() == 1 ? "" : "es") + ".");
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

    private ReassemblyRange prepareReassembly(Address address, Address end) {
        Listing listing = activeProgram.getListing();
        Instruction first = listing.getInstructionContaining(address);
        Instruction last = listing.getInstructionContaining(end);
        if (first == null && last == null) {
            // If the user is patching undefined executable bytes, give Ghidra a chance to decode
            // them as well. This is still restricted to a small local range rather than the
            // whole program.
            if (!activeProgram.getMemory().getExecuteSet().contains(address)) {
                return null;
            }
        }
        Address start = first != null ? first.getMinAddress() : address;
        Address finish = last != null ? last.getMaxAddress() : end;

        // x86 instructions are variable-length (up to 15 bytes). A byte patch can change an
        // instruction's decoded length, so include a small executable look-ahead region. This
        // lets the normal disassembler resynchronise and recreate immediately following code.
        try {
            MemoryBlock block = activeProgram.getMemory().getBlock(finish);
            if (block != null && activeProgram.getMemory().getExecuteSet().contains(finish)) {
                Address lookAhead = finish.add(16);
                if (lookAhead.compareTo(block.getEnd()) > 0) {
                    lookAhead = block.getEnd();
                }
                finish = lookAhead;
            }
        }
        catch (RuntimeException ignored) {
            // Keep the conservative original end if an address-space boundary is encountered.
        }
        return new ReassemblyRange(start, finish);
    }

    void deleteSelectedPatches() {
        int[] rows = provider.getSelectedModelRows();
        if (rows.length == 0 || !canEditPatches()) {
            return;
        }
        int answer = JOptionPane.showConfirmDialog(provider.getComponent(),
                "Delete " + rows.length + " patch" + (rows.length == 1 ? "" : "es") + " from Patch Manager?\n\n"
                        + "This does not restore bytes. Disable a patch first if you want the program reverted.",
                "Delete Patches", JOptionPane.OK_CANCEL_OPTION, JOptionPane.WARNING_MESSAGE);
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
        patches.removeAll(remove);
        saveToProgram();
        refreshProvider();
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
            return;
        }
        provider.setPatches(patches);
        provider.setStatus(patches.size() + " patch" + (patches.size() == 1 ? "" : "es")
                + " in " + activeProgram.getName());
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
                || patch.originalBytes.length != patch.patchedBytes.length) {
            return false;
        }
        try {
            byte[] current = new byte[patch.originalBytes.length];
            return program.getMemory().getBytes(patch.address, current) == current.length;
        }
        catch (Exception e) {
            return false;
        }
    }

    private void saveToProgram() {
        if (activeProgram == null) {
            return;
        }
        Properties props = new Properties();
        props.setProperty("format", FORMAT);
        props.setProperty("version", Integer.toString(FORMAT_VERSION));
        props.setProperty("count", Integer.toString(patches.size()));
        for (int i = 0; i < patches.size(); i++) {
            Patch p = patches.get(i);
            props.setProperty("patch." + i + ".name", Base64.getEncoder().encodeToString(p.name.getBytes(StandardCharsets.UTF_8)));
            props.setProperty("patch." + i + ".address", p.address.toString());
            props.setProperty("patch." + i + ".original", HexUtil.format(p.originalBytes));
            props.setProperty("patch." + i + ".patched", HexUtil.format(p.patchedBytes));
        }
        try (StringWriter sw = new StringWriter()) {
            props.store(sw, "Ghidra Patch Manager patch definitions");
            Options options = activeProgram.getOptions(OPTION_PATH);
            int tx = activeProgram.startTransaction("Save Patch Manager state");
            try {
                options.setString(OPTION_DATA, sw.toString());
                activeProgram.endTransaction(tx, true);
            }
            catch (RuntimeException e) {
                activeProgram.endTransaction(tx, false);
                throw e;
            }
        }
        catch (IOException e) {
            Msg.error(this, "Unable to serialize patch state", e);
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
            provider.setStatus("Loaded " + patches.size() + " patch" + (patches.size() == 1 ? "" : "es"));
        }
        catch (Exception e) {
            showError("Unable to load patch set: " + e.getMessage(), "Load Patch Set");
        }
    }

    private Properties buildPatchProperties() {
        Properties props = new Properties();
        props.setProperty("format", FORMAT);
        props.setProperty("version", Integer.toString(FORMAT_VERSION));
        props.setProperty("program", activeProgram == null ? "" : activeProgram.getName());
        props.setProperty("executable_sha256", activeProgram == null ? "" : activeProgram.getExecutableSHA256());
        props.setProperty("count", Integer.toString(patches.size()));
        for (int i = 0; i < patches.size(); i++) {
            Patch p = patches.get(i);
            props.setProperty("patch." + i + ".name", Base64.getEncoder().encodeToString(p.name.getBytes(StandardCharsets.UTF_8)));
            props.setProperty("patch." + i + ".address", p.address.toString());
            props.setProperty("patch." + i + ".original", HexUtil.format(p.originalBytes));
            props.setProperty("patch." + i + ".patched", HexUtil.format(p.patchedBytes));
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

    void refreshProviderFromProgramChange() {
        if (!busy) {
            refreshProvider();
        }
    }

    private record ReassemblyRange(Address start, Address end) {
    }
}
