package com.ghidrapatchmanager;

import java.awt.BorderLayout;
import java.awt.Dimension;
import java.awt.FlowLayout;
import java.awt.event.ActionEvent;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.awt.event.KeyEvent;
import java.util.List;

import javax.swing.BorderFactory;
import javax.swing.JButton;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTable;
import javax.swing.ListSelectionModel;
import javax.swing.KeyStroke;
import javax.swing.SwingUtilities;
import javax.swing.table.TableColumnModel;

import ghidra.framework.plugintool.ComponentProviderAdapter;
import ghidra.framework.plugintool.PluginTool;

final class PatchManagerProvider extends ComponentProviderAdapter {
    static final String TITLE = "Patch Manager";

    private final PatchManagerPlugin plugin;
    private final JPanel mainPanel = new JPanel(new BorderLayout(6, 6));
    private final PatchTableModel model;
    private final JTable table;
    private final JLabel statusLabel = new JLabel("No program");
    private final JButton editButton = new JButton("Edit...");
    private final JButton toggleButton = new JButton("Toggle");
    private final JButton deleteButton = new JButton("Delete");
    private final JButton captureButton = new JButton("Capture Existing...");

    PatchManagerProvider(PluginTool tool, PatchManagerPlugin plugin) {
        super(tool, TITLE, plugin.getName());
        this.plugin = plugin;
        this.model = new PatchTableModel(plugin);
        this.table = new JTable(model);

        buildUi();
    }

    private void buildUi() {
        JPanel buttons = new JPanel(new FlowLayout(FlowLayout.LEADING, 4, 2));
        JButton addButton = new JButton("Add Patch...");
        JButton enableAllButton = new JButton("Enable All");
        JButton disableAllButton = new JButton("Disable All");
        JButton saveButton = new JButton("Save Patch Set...");
        JButton loadButton = new JButton("Load Patch Set...");
        JButton refreshButton = new JButton("Refresh");

        addButton.addActionListener(e -> plugin.addPatchFromUi());
        captureButton.addActionListener(e -> plugin.captureCurrentChanges());
        editButton.addActionListener(e -> plugin.editSelectedPatch());
        toggleButton.addActionListener(e -> plugin.toggleSelectedPatch());
        deleteButton.addActionListener(e -> plugin.deleteSelectedPatches());
        enableAllButton.addActionListener(e -> plugin.setAllPatchesEnabled(true));
        disableAllButton.addActionListener(e -> plugin.setAllPatchesEnabled(false));
        saveButton.addActionListener(e -> plugin.exportPatchSet());
        loadButton.addActionListener(e -> plugin.importPatchSet());
        refreshButton.addActionListener(e -> plugin.refreshProvider());

        buttons.add(addButton);
        buttons.add(captureButton);
        buttons.add(editButton);
        buttons.add(toggleButton);
        buttons.add(deleteButton);
        buttons.add(enableAllButton);
        buttons.add(disableAllButton);
        buttons.add(saveButton);
        buttons.add(loadButton);
        buttons.add(refreshButton);

        table.setSelectionMode(ListSelectionModel.MULTIPLE_INTERVAL_SELECTION);
        table.setAutoCreateRowSorter(true);
        table.setFillsViewportHeight(true);
        table.setRowHeight(Math.max(22, table.getRowHeight()));
        table.setShowGrid(true);
        table.setIntercellSpacing(new Dimension(1, 1));
        table.setAutoResizeMode(JTable.AUTO_RESIZE_LAST_COLUMN);
        table.getInputMap().put(KeyStroke.getKeyStroke(KeyEvent.VK_SPACE, 0), "toggle-patch");
        table.getActionMap().put("toggle-patch", new javax.swing.AbstractAction() {
            @Override
            public void actionPerformed(ActionEvent e) {
                plugin.toggleSelectedPatch();
            }
        });

        TableColumnModel columns = table.getColumnModel();
        columns.getColumn(PatchTableModel.ENABLED_COL).setPreferredWidth(58);
        columns.getColumn(PatchTableModel.ENABLED_COL).setMaxWidth(70);
        columns.getColumn(PatchTableModel.ADDRESS_COL).setPreferredWidth(120);
        columns.getColumn(PatchTableModel.ORIGINAL_COL).setPreferredWidth(190);
        columns.getColumn(PatchTableModel.PATCHED_COL).setPreferredWidth(190);
        columns.getColumn(PatchTableModel.STATE_COL).setPreferredWidth(85);
        columns.getColumn(PatchTableModel.STATE_COL).setMaxWidth(100);

        table.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseClicked(MouseEvent e) {
                if (e.getClickCount() == 2 && SwingUtilities.isLeftMouseButton(e)) {
                    plugin.jumpToSelectedPatch();
                }
            }
        });
        table.getSelectionModel().addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting()) {
                updateButtons();
            }
        });

        JPanel bottom = new JPanel(new BorderLayout());
        bottom.setBorder(BorderFactory.createEmptyBorder(2, 4, 2, 4));
        bottom.add(statusLabel, BorderLayout.WEST);

        mainPanel.setBorder(BorderFactory.createEmptyBorder(4, 4, 4, 4));
        mainPanel.add(buttons, BorderLayout.NORTH);
        mainPanel.add(new JScrollPane(table), BorderLayout.CENTER);
        mainPanel.add(bottom, BorderLayout.SOUTH);
        updateButtons();
    }

    @Override
    public javax.swing.JComponent getComponent() {
        return mainPanel;
    }

    void setPatches(List<Patch> patches) {
        model.setPatches(patches);
        updateButtons();
    }

    void refreshTable() {
        model.refresh();
        updateButtons();
    }

    JTable getTable() {
        return table;
    }

    PatchTableModel getModel() {
        return model;
    }

    int[] getSelectedModelRows() {
        int[] viewRows = table.getSelectedRows();
        for (int i = 0; i < viewRows.length; i++) {
            viewRows[i] = table.convertRowIndexToModel(viewRows[i]);
        }
        return viewRows;
    }

    Patch getSelectedPatch() {
        int row = table.getSelectedRow();
        if (row < 0) {
            return null;
        }
        return model.getPatch(table.convertRowIndexToModel(row));
    }

    void selectPatch(Patch patch) {
        for (int row = 0; row < model.getRowCount(); row++) {
            if (model.getPatch(row) == patch) {
                int viewRow = table.convertRowIndexToView(row);
                if (viewRow >= 0) {
                    table.getSelectionModel().setSelectionInterval(viewRow, viewRow);
                    table.scrollRectToVisible(table.getCellRect(viewRow, 0, true));
                }
                break;
            }
        }
    }

    void setStatus(String text) {
        statusLabel.setText(text == null ? "" : text);
    }

    private void updateButtons() {
        boolean hasSelection = table.getSelectedRowCount() > 0;
        boolean one = table.getSelectedRowCount() == 1;
        boolean busy = !plugin.canEditPatches();
        editButton.setEnabled(one && !busy && plugin.selectedPatchIsEditable());
        toggleButton.setEnabled(one && !busy && plugin.selectedPatchIsEditable());
        deleteButton.setEnabled(hasSelection && !busy);
    }

}
