package com.ghidrapatchmanager;

import java.awt.BorderLayout;
import java.awt.Dimension;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.awt.Font;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Base64;

import javax.swing.BorderFactory;
import javax.swing.JComboBox;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;
import javax.swing.JTextField;
import javax.swing.SwingUtilities;

import docking.DialogComponentProvider;
import ghidra.program.database.mem.AddressSourceInfo;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;

/** Displays a read-only, copy-friendly view of all useful details for one managed patch. */
final class PatchInfoDialog extends DialogComponentProvider {
    private static final String HEX = "Hexadecimal";
    private static final String BASE64 = "Base64";

    private final PatchManagerPlugin plugin;
    private final JComboBox<String> encodingCombo;
    private final JTextField nameField = createField();
    private final JTextField stateField = createField();
    private final JTextField addressField = createField();
    private final JTextField endAddressField = createField();
    private final JTextField rvaField = createField();
    private final JTextField endRvaField = createField();
    private final JTextField fileOffsetField = createField();
    private final JTextField endFileOffsetField = createField();
    private final JTextField lengthField = createField();
    private final JTextField addressSpaceField = createField();
    private final JTextField imageBaseField = createField();
    private final JTextField sourceFileField = createField();
    private final JTextField memoryBlockField = createField();
    private final JTextArea originalArea = createByteArea();
    private final JTextArea patchedArea = createByteArea();
    private final JTextArea currentArea = createByteArea();

    private Patch patch;

    PatchInfoDialog(PatchManagerPlugin plugin) {
        super("Patch Info", false);
        this.plugin = plugin;

        encodingCombo = new JComboBox<>(buildEncodingNames());
        encodingCombo.setToolTipText("Choose how the original, patched, and current bytes are displayed.");
        encodingCombo.addActionListener(e -> refreshByteAreas());

        JPanel main = new JPanel(new BorderLayout(8, 8));
        main.setBorder(BorderFactory.createEmptyBorder(8, 8, 8, 8));
        main.add(buildMetadataPanel(), BorderLayout.NORTH);
        main.add(buildBytesPanel(), BorderLayout.CENTER);
        addWorkPanel(main);
        addDismissButton();
        setDefaultSize(820, 650);
        setMinimumSize(new Dimension(650, 480));
        setFocusComponent(nameField);
        clearPatch();
    }

    void setPatch(Patch patch) {
        this.patch = patch;
        refreshFields();
    }

    void clearPatch() {
        patch = null;
        refreshFields();
    }

    void refresh() {
        refreshFields();
    }

    private JPanel buildMetadataPanel() {
        JPanel panel = new JPanel(new GridBagLayout());
        panel.setBorder(BorderFactory.createTitledBorder("Patch Details"));
        int row = 0;
        row = addMetadataRow(panel, row, "Name", nameField);
        row = addMetadataRow(panel, row, "State", stateField);
        row = addMetadataRow(panel, row, "Address", addressField);
        row = addMetadataRow(panel, row, "End Address", endAddressField);
        row = addMetadataRow(panel, row, "RVA", rvaField);
        row = addMetadataRow(panel, row, "End RVA", endRvaField);
        row = addMetadataRow(panel, row, "File Offset", fileOffsetField);
        row = addMetadataRow(panel, row, "End File Offset", endFileOffsetField);
        row = addMetadataRow(panel, row, "Length", lengthField);
        row = addMetadataRow(panel, row, "Address Space", addressSpaceField);
        row = addMetadataRow(panel, row, "Image Base", imageBaseField);
        row = addMetadataRow(panel, row, "Source File", sourceFileField);
        addMetadataRow(panel, row, "Memory Block", memoryBlockField);
        return panel;
    }

    private JPanel buildBytesPanel() {
        JPanel panel = new JPanel(new GridBagLayout());
        panel.setBorder(BorderFactory.createTitledBorder("Bytes"));

        GridBagConstraints label = new GridBagConstraints();
        label.gridx = 0;
        label.gridy = 0;
        label.anchor = GridBagConstraints.LINE_END;
        label.insets = new Insets(3, 4, 3, 8);
        panel.add(new JLabel("Display encoding:"), label);

        GridBagConstraints combo = new GridBagConstraints();
        combo.gridx = 1;
        combo.gridy = 0;
        combo.gridwidth = 2;
        combo.anchor = GridBagConstraints.LINE_START;
        combo.fill = GridBagConstraints.HORIZONTAL;
        combo.weightx = 1.0;
        combo.insets = new Insets(3, 4, 3, 4);
        panel.add(encodingCombo, combo);

        int row = 1;
        row = addByteRow(panel, row, "Original Bytes", originalArea);
        row = addByteRow(panel, row, "Patched Bytes", patchedArea);
        addByteRow(panel, row, "Current Bytes", currentArea);
        return panel;
    }

    private static int addMetadataRow(JPanel panel, int row, String labelText, JTextField field) {
        GridBagConstraints label = new GridBagConstraints();
        label.gridx = 0;
        label.gridy = row;
        label.anchor = GridBagConstraints.LINE_END;
        label.insets = new Insets(2, 4, 2, 8);
        panel.add(new JLabel(labelText + ":"), label);

        GridBagConstraints fieldConstraints = new GridBagConstraints();
        fieldConstraints.gridx = 1;
        fieldConstraints.gridy = row;
        fieldConstraints.weightx = 1.0;
        fieldConstraints.fill = GridBagConstraints.HORIZONTAL;
        fieldConstraints.insets = new Insets(2, 4, 2, 4);
        panel.add(field, fieldConstraints);
        return row + 1;
    }

    private static int addByteRow(JPanel panel, int row, String labelText, JTextArea area) {
        GridBagConstraints label = new GridBagConstraints();
        label.gridx = 0;
        label.gridy = row;
        label.anchor = GridBagConstraints.FIRST_LINE_END;
        label.insets = new Insets(4, 4, 4, 8);
        panel.add(new JLabel(labelText + ":"), label);

        JScrollPane scroll = new JScrollPane(area);
        scroll.setPreferredSize(new Dimension(500, 105));
        GridBagConstraints content = new GridBagConstraints();
        content.gridx = 1;
        content.gridy = row;
        content.gridwidth = 2;
        content.weightx = 1.0;
        content.weighty = 1.0;
        content.fill = GridBagConstraints.BOTH;
        content.insets = new Insets(4, 4, 4, 4);
        panel.add(scroll, content);
        return row + 1;
    }

    private void refreshFields() {
        boolean present = patch != null && plugin.getCurrentProgram() != null;
        if (!present) {
            setField(nameField, "<no patch selected>");
            setField(stateField, "");
            setField(addressField, "");
            setField(endAddressField, "");
            setField(rvaField, "");
            setField(endRvaField, "");
            setField(fileOffsetField, "");
            setField(endFileOffsetField, "");
            setField(lengthField, "");
            setField(addressSpaceField, "");
            setField(imageBaseField, "");
            setField(sourceFileField, "");
            setField(memoryBlockField, "");
            originalArea.setText("");
            patchedArea.setText("");
            currentArea.setText("");
            return;
        }

        Program program = plugin.getCurrentProgram();
        Address end = patch.getEndAddress();
        AddressSourceInfo startInfo = program.getMemory().getAddressSourceInfo(patch.address);
        AddressSourceInfo endInfo = program.getMemory().getAddressSourceInfo(end);
        MemoryBlock block = program.getMemory().getBlock(patch.address);

        setField(nameField, patch.name);
        setField(stateField, patch.getState(plugin).toString());
        setField(addressField, patch.address.toString());
        setField(endAddressField, end.toString());
        setField(rvaField, formatRva(program, patch.address));
        setField(endRvaField, formatRva(program, end));
        setField(fileOffsetField, formatFileOffset(startInfo));
        setField(endFileOffsetField, formatFileOffset(endInfo));
        setField(lengthField, patch.patchedBytes.length + " byte" + (patch.patchedBytes.length == 1 ? "" : "s"));
        setField(addressSpaceField, patch.address.getAddressSpace().getName());
        setField(imageBaseField, program.getImageBase().toString());
        setField(sourceFileField, startInfo == null || startInfo.getFileName() == null ? "<none>" : startInfo.getFileName());
        setField(memoryBlockField, block == null ? "<none>" : block.getName());

        refreshByteAreas();
        SwingUtilities.invokeLater(nameField::requestFocusInWindow);
    }

    private void refreshByteAreas() {
        if (patch == null || plugin.getCurrentProgram() == null) {
            originalArea.setText("");
            patchedArea.setText("");
            currentArea.setText("");
            return;
        }

        byte[] current;
        try {
            current = plugin.readBytes(patch.address, patch.patchedBytes.length);
        }
        catch (Exception e) {
            current = null;
        }
        originalArea.setText(formatBytes(patch.originalBytes));
        patchedArea.setText(formatBytes(patch.patchedBytes));
        currentArea.setText(current == null ? "<unavailable>" : formatBytes(current));
        originalArea.setCaretPosition(0);
        patchedArea.setCaretPosition(0);
        currentArea.setCaretPosition(0);
    }

    private String formatBytes(byte[] bytes) {
        String selected = (String) encodingCombo.getSelectedItem();
        if (HEX.equals(selected)) {
            return HexUtil.format(bytes);
        }
        if (BASE64.equals(selected)) {
            return Base64.getEncoder().encodeToString(bytes);
        }
        Charset charset;
        try {
            charset = Charset.forName(selected);
        }
        catch (Exception e) {
            charset = StandardCharsets.UTF_8;
        }
        return new String(bytes, charset);
    }

    private static String formatFileOffset(AddressSourceInfo info) {
        if (info == null || info.getFileOffset() < 0) {
            return "<none>";
        }
        return String.format("0x%X (%d)", info.getFileOffset(), info.getFileOffset());
    }

    private static String formatRva(Program program, Address address) {
        Address base = program.getImageBase();
        if (base == null || !base.getAddressSpace().equals(address.getAddressSpace())) {
            return "<n/a>";
        }
        long rva = address.subtract(base);
        if (rva < 0) {
            return String.format("-0x%X", -rva);
        }
        return String.format("0x%X", rva);
    }

    private static String[] buildEncodingNames() {
        Map<String, String> values = new LinkedHashMap<>();
        values.put(HEX, null);
        values.put(BASE64, null);
        values.put("ASCII", StandardCharsets.US_ASCII.name());
        values.put("UTF-8", StandardCharsets.UTF_8.name());
        values.put("UTF-16LE", StandardCharsets.UTF_16LE.name());
        values.put("UTF-16BE", StandardCharsets.UTF_16BE.name());
        values.put("ISO-8859-1", StandardCharsets.ISO_8859_1.name());
        try {
            values.put("windows-1252", Charset.forName("windows-1252").name());
        }
        catch (Exception ignored) {
        }
        for (String name : Charset.availableCharsets().keySet()) {
            values.putIfAbsent(name, name);
        }
        return values.keySet().toArray(String[]::new);
    }

    private static JTextField createField() {
        JTextField field = new JTextField();
        field.setEditable(false);
        field.setFocusable(true);
        return field;
    }

    private static JTextArea createByteArea() {
        JTextArea area = new JTextArea(6, 40);
        area.setEditable(false);
        area.setLineWrap(false);
        area.setWrapStyleWord(false);
        area.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        area.setFocusable(true);
        return area;
    }

    private static void setField(JTextField field, String value) {
        field.setText(value == null ? "" : value);
        field.setCaretPosition(0);
    }
}
