package com.ghidrapatchmanager;

import java.awt.Color;
import java.util.List;

import javax.swing.SwingUtilities;
import javax.swing.Timer;

import generic.theme.Gui;
import generic.theme.ThemeEvent;
import generic.theme.ThemeListener;
import ghidra.app.services.MarkerService;
import ghidra.app.services.MarkerSet;
import ghidra.framework.options.ToolOptions;
import ghidra.framework.options.OptionsChangeListener;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;

/**
 * Manages the visual representation of Patch Manager records in Ghidra's marker-backed views.
 *
 * <p>The CodeBrowser uses {@link MarkerService}'s address-based background model, so the
 * highlighter never stores UI row/line numbers.  After patch bytes are changed and Ghidra has
 * re-disassembled the affected code, this class resolves each patch to the instructions that
 * currently contain its byte range.  That makes highlighting follow changed instruction
 * boundaries automatically.</p>
 */
final class PatchHighlightManager {
    static final String OPTION_NAME = "Highlight Patch Locations";
    private static final String OPTIONS_CATEGORY = "Ghidra Patch Manager";
    private static final String ENABLED_MARKER_NAME = "Ghidra Patch Manager - Enabled";
    private static final String DISABLED_MARKER_NAME = "Ghidra Patch Manager - Disabled";
    private static final String MARKER_DESCRIPTION = "Managed binary patch state";

    // Dark-theme colors keep the light foreground used by CodeBrowser readable.
    private static final Color DARK_ENABLED = new Color(109, 67, 30);
    private static final Color DARK_DISABLED = new Color(78, 66, 99);

    // Light-theme colors keep the dark CodeBrowser foreground readable.
    private static final Color LIGHT_ENABLED = new Color(242, 202, 151);
    private static final Color LIGHT_DISABLED = new Color(221, 210, 235);

    private final PatchManagerPlugin plugin;
    private final PluginTool tool;
    private final MarkerService markerService;
    private final ToolOptions toolOptions;
    private final Timer refreshTimer;

    private final OptionsChangeListener optionsListener = new OptionsChangeListener() {
        @Override
        public void optionsChanged(ToolOptions options, String optionName, Object oldValue, Object newValue) {
            if (options == toolOptions && OPTION_NAME.equals(optionName)) {
                scheduleRefresh();
            }
        }
    };

    private final ThemeListener themeListener = new ThemeListener() {
        @Override
        public void themeChanged(ThemeEvent event) {
            scheduleRefresh();
        }
    };

    private Program activeProgram;
    private MarkerSet enabledMarkerSet;
    private MarkerSet disabledMarkerSet;
    private boolean disposed;

    PatchHighlightManager(PatchManagerPlugin plugin, PluginTool tool) {
        this.plugin = plugin;
        this.tool = tool;
        this.markerService = tool.getService(MarkerService.class);
        this.toolOptions = tool.getOptions(OPTIONS_CATEGORY);
        this.toolOptions.registerOption(OPTION_NAME, Boolean.TRUE, null,
            "Highlight managed patch instructions in the CodeBrowser and mark their locations in connected marker-capable views.");
        this.toolOptions.addOptionsChangeListener(optionsListener);
        Gui.addThemeListener(themeListener);

        this.refreshTimer = new Timer(100, event -> refreshNow());
        this.refreshTimer.setRepeats(false);
    }

    void dispose() {
        disposed = true;
        refreshTimer.stop();
        toolOptions.removeOptionsChangeListener(optionsListener);
        Gui.removeThemeListener(themeListener);
        clearMarkers();
    }

    void programActivated(Program program) {
        activeProgram = program;
        scheduleRefresh();
    }

    void programDeactivated(Program program) {
        if (activeProgram == program) {
            activeProgram = null;
        }
        if (program != null) {
            removeMarkers(program);
        }
    }

    void refresh() {
        scheduleRefresh();
    }

    private void scheduleRefresh() {
        if (disposed) {
            return;
        }
        if (SwingUtilities.isEventDispatchThread()) {
            refreshTimer.restart();
        }
        else {
            SwingUtilities.invokeLater(refreshTimer::restart);
        }
    }

    private void refreshNow() {
        if (disposed) {
            return;
        }
        Program program = activeProgram;
        if (program == null || markerService == null || !isHighlightEnabled()) {
            clearMarkers();
            return;
        }

        removeMarkers(program);

        List<Patch> patches = plugin.getPatchesSnapshot();
        if (patches.isEmpty()) {
            return;
        }

        try {
            enabledMarkerSet = markerService.createAreaMarker(
                ENABLED_MARKER_NAME,
                MARKER_DESCRIPTION + " (enabled)",
                program,
                MarkerService.HIGHLIGHT_PRIORITY - 1,
                true,
                true,
                true,
                enabledColor());

            disabledMarkerSet = markerService.createAreaMarker(
                DISABLED_MARKER_NAME,
                MARKER_DESCRIPTION + " (disabled)",
                program,
                MarkerService.HIGHLIGHT_PRIORITY - 1,
                true,
                true,
                true,
                disabledColor());

            for (Patch patch : patches) {
                AddressSet highlightRange = getCurrentInstructionRange(program, patch);
                if (highlightRange.isEmpty()) {
                    continue;
                }

                PatchState state = patch.getState(plugin);
                if (state == PatchState.ENABLED) {
                    enabledMarkerSet.add(highlightRange);
                }
                else if (state == PatchState.DISABLED) {
                    disabledMarkerSet.add(highlightRange);
                }
            }
        }
        catch (RuntimeException e) {
            clearMarkers();
        }
    }

    /**
     * Resolve the current patch bytes to the current instruction boundaries.  This method is
     * intentionally evaluated after re-disassembly, not before it.
     */
    private AddressSet getCurrentInstructionRange(Program program, Patch patch) {
        Listing listing = program.getListing();
        Instruction first = listing.getInstructionContaining(patch.address);
        Instruction last = listing.getInstructionContaining(patch.getEndAddress());

        if (first != null && last != null
                && sameAddressSpace(first.getMinAddress(), last.getMaxAddress())) {
            return new AddressSet(first.getMinAddress(), last.getMaxAddress());
        }

        // A patch can temporarily live in undefined executable bytes.  In that case there is no
        // Instruction to anchor the marker to, so retain an address-precise byte-range marker.
        if (first != null) {
            return new AddressSet(first.getMinAddress(), patch.getEndAddress());
        }
        if (last != null) {
            return new AddressSet(patch.address, last.getMaxAddress());
        }
        return new AddressSet(patch.address, patch.getEndAddress());
    }

    private static boolean sameAddressSpace(ghidra.program.model.address.Address a,
            ghidra.program.model.address.Address b) {
        AddressSpace as = a.getAddressSpace();
        return as.equals(b.getAddressSpace());
    }

    private boolean isHighlightEnabled() {
        return toolOptions.getBoolean(OPTION_NAME, true);
    }

    private Color enabledColor() {
        return Gui.isDarkTheme() ? DARK_ENABLED : LIGHT_ENABLED;
    }

    private Color disabledColor() {
        return Gui.isDarkTheme() ? DARK_DISABLED : LIGHT_DISABLED;
    }

    private void clearMarkers() {
        Program program = activeProgram;
        if (program != null) {
            removeMarkers(program);
        }
        else {
            enabledMarkerSet = null;
            disabledMarkerSet = null;
        }
    }

    private void removeMarkers(Program program) {
        if (markerService == null) {
            enabledMarkerSet = null;
            disabledMarkerSet = null;
            return;
        }
        if (enabledMarkerSet != null) {
            markerService.removeMarker(enabledMarkerSet, program);
            enabledMarkerSet = null;
        }
        if (disabledMarkerSet != null) {
            markerService.removeMarker(disabledMarkerSet, program);
            disabledMarkerSet = null;
        }
    }
}
