package com.ghidrapatchmanager;

import java.awt.BorderLayout;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;

import javax.swing.BorderFactory;
import javax.swing.JCheckBox;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JComponent;
import javax.swing.JPanel;
import javax.swing.JTextField;

import ghidra.program.model.address.Address;

final class PatchEditorDialog {
    record Result(String name, Address address, byte[] originalBytes, byte[] patchedBytes, boolean enabled) {
    }

    private PatchEditorDialog() {
    }

    static Result show(PatchManagerPlugin plugin, JComponent parent, Patch existing) {
        if (plugin.getCurrentProgram() == null) {
            return null;
        }

        Address defaultAddress = existing != null ? existing.address : plugin.getSuggestedPatchAddress();
        if (defaultAddress == null) {
            JOptionPane.showMessageDialog(parent, "No current program address is available.",
                    "Patch Manager", JOptionPane.WARNING_MESSAGE);
            return null;
        }

        JTextField nameField = new JTextField(existing != null ? existing.name
                : "Patch @ " + defaultAddress, 36);
        JTextField addressField = new JTextField(defaultAddress.toString(), 20);
        JTextField originalField = new JTextField(
                HexUtil.format(existing != null ? existing.originalBytes : plugin.readSuggestedOriginalBytes()), 36);
        JTextField patchedField = new JTextField(
                HexUtil.format(existing != null ? existing.patchedBytes : plugin.readSuggestedOriginalBytes()), 36);
        JCheckBox enabledBox = new JCheckBox("Apply patch immediately", existing == null ||
                existing.getState(plugin) == PatchState.ENABLED);

        addressField.setToolTipText("Ghidra address, e.g. 140001234");
        originalField.setEditable(existing == null);
        originalField.setToolTipText(existing == null
                ? "Enter the original bytes to patch; the field is prefilled from the current Listing location."
                : "Original bytes captured when this patch was created; they cannot be edited.");
        patchedField.setToolTipText("Replacement bytes. Must be exactly the same length as the original bytes.");

        JPanel form = new JPanel(new GridBagLayout());
        form.setBorder(BorderFactory.createEmptyBorder(6, 6, 6, 6));
        addRow(form, 0, "Name:", nameField);
        addRow(form, 1, "Address:", addressField);
        addRow(form, 2, "Original:", originalField);
        addRow(form, 3, "Patched:", patchedField);
        GridBagConstraints c = new GridBagConstraints();
        c.gridx = 1;
        c.gridy = 4;
        c.anchor = GridBagConstraints.WEST;
        c.insets = new Insets(5, 4, 4, 4);
        form.add(enabledBox, c);

        JPanel wrapper = new JPanel(new BorderLayout());
        wrapper.add(form, BorderLayout.CENTER);

        while (true) {
            int answer = JOptionPane.showConfirmDialog(parent, wrapper,
                    existing == null ? "Add Patch" : "Edit Patch",
                    JOptionPane.OK_CANCEL_OPTION, JOptionPane.PLAIN_MESSAGE);
            if (answer != JOptionPane.OK_OPTION) {
                return null;
            }

            String name = nameField.getText().trim();
            if (name.isEmpty()) {
                JOptionPane.showMessageDialog(parent, "Patch name cannot be empty.",
                        "Invalid Patch", JOptionPane.WARNING_MESSAGE);
                continue;
            }

            Address address = plugin.getCurrentProgram().getAddressFactory().getAddress(addressField.getText().trim());
            if (address == null) {
                JOptionPane.showMessageDialog(parent, "Invalid Ghidra address.",
                        "Invalid Patch", JOptionPane.WARNING_MESSAGE);
                continue;
            }

            byte[] original;
            try {
                original = existing != null ? existing.originalBytes.clone()
                        : HexUtil.parse(originalField.getText());
            }
            catch (IllegalArgumentException e) {
                JOptionPane.showMessageDialog(parent, e.getMessage(),
                        "Invalid Original Bytes", JOptionPane.WARNING_MESSAGE);
                continue;
            }

            byte[] patched;
            try {
                patched = HexUtil.parse(patchedField.getText());
            }
            catch (IllegalArgumentException e) {
                JOptionPane.showMessageDialog(parent, e.getMessage(),
                        "Invalid Patched Bytes", JOptionPane.WARNING_MESSAGE);
                continue;
            }

            if (original.length != patched.length) {
                JOptionPane.showMessageDialog(parent,
                        "Original and patched byte strings must be the same length.",
                        "Invalid Patch", JOptionPane.WARNING_MESSAGE);
                continue;
            }
            if (original.length == 0) {
                JOptionPane.showMessageDialog(parent, "A patch must contain at least one byte.",
                        "Invalid Patch", JOptionPane.WARNING_MESSAGE);
                continue;
            }

            if (existing == null) {
                try {
                    byte[] actualOriginal = plugin.readBytes(address, original.length);
                    if (!java.util.Arrays.equals(actualOriginal, original)) {
                        JOptionPane.showMessageDialog(parent,
                                "The Original field does not match the bytes currently present at " + address + ".\n\n"
                                        + "Current:\n" + HexUtil.format(actualOriginal) + "\n\n"
                                        + "Expected:\n" + HexUtil.format(original),
                                "Patch Conflict", JOptionPane.WARNING_MESSAGE);
                        continue;
                    }
                    original = actualOriginal;
                }
                catch (Exception e) {
                    JOptionPane.showMessageDialog(parent,
                            "Unable to read the original bytes at " + address + ": " + e.getMessage(),
                            "Invalid Patch", JOptionPane.ERROR_MESSAGE);
                    continue;
                }
            }
            else if (!address.equals(existing.address)) {
                JOptionPane.showMessageDialog(parent,
                        "Editing the address of an existing patch is not supported. Delete and recreate it instead.",
                        "Patch Manager", JOptionPane.WARNING_MESSAGE);
                continue;
            }

            if (patched.length != original.length) {
                continue;
            }

            return new Result(name, address, original, patched, enabledBox.isSelected());
        }
    }

    private static void addRow(JPanel panel, int row, String label, JTextField field) {
        GridBagConstraints l = new GridBagConstraints();
        l.gridx = 0;
        l.gridy = row;
        l.anchor = GridBagConstraints.LINE_END;
        l.insets = new Insets(4, 4, 4, 8);
        panel.add(new JLabel(label), l);

        GridBagConstraints f = new GridBagConstraints();
        f.gridx = 1;
        f.gridy = row;
        f.weightx = 1;
        f.fill = GridBagConstraints.HORIZONTAL;
        f.insets = new Insets(4, 4, 4, 4);
        panel.add(field, f);
    }
}
