package com.ghidrapatchmanager;

import java.awt.BorderLayout;
import java.awt.Dimension;
import java.awt.event.ActionEvent;
import java.awt.event.ComponentAdapter;
import java.awt.event.ComponentEvent;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.awt.event.KeyEvent;
import java.util.ArrayList;
import java.util.List;

import javax.swing.AbstractButton;
import javax.swing.BorderFactory;
import javax.swing.Box;
import javax.swing.JButton;
import javax.swing.JToggleButton;
import javax.swing.Icon;
import javax.swing.JLabel;
import javax.swing.JMenuItem;
import javax.swing.JPanel;
import javax.swing.JPopupMenu;
import javax.swing.JScrollPane;
import javax.swing.JTable;
import javax.swing.ListSelectionModel;
import javax.swing.KeyStroke;
import javax.swing.SwingUtilities;
import javax.swing.table.TableColumnModel;
import javax.swing.event.TableColumnModelEvent;
import javax.swing.event.TableColumnModelListener;

import generic.theme.GIcon;
import resources.Icons;
import resources.ResourceManager;

import ghidra.framework.plugintool.ComponentProviderAdapter;
import ghidra.framework.plugintool.PluginTool;

final class PatchManagerProvider extends ComponentProviderAdapter {
    static final String TITLE = "Patch Manager";

    private static final int ICON_SIZE = 16;
    private static final int BUTTON_GAP = 4;

    private static final int ENABLED_WIDTH = 64;
    private static final int ADDRESS_WIDTH = 120;
    private static final int STATE_WIDTH = 90;
    private static final int FLEXIBLE_MIN_WIDTH = 90;

    private final PatchManagerPlugin plugin;
    private final JPanel mainPanel = new JPanel(new BorderLayout(6, 6));
    private final PatchTableModel model;
    private final JTable table;
    private final JScrollPane scrollPane;
    private final JLabel statusLabel = new JLabel("No program");

    private final JButton addButton = new JButton("Add Patch...");
    private final JButton editButton = new JButton("Edit...");
    private final JButton toggleButton = new JButton("Toggle");
    private final JButton infoButton = new JButton("Patch Info");
    private final JButton deleteButton = new JButton("Delete");
    private final JToggleButton showOriginalButton = new JToggleButton("Show Orig");
    private final JButton captureButton = new JButton("Capture Existing...");
    private final JButton enableAllButton = new JButton("Enable All");
    private final JButton disableAllButton = new JButton("Disable All");
    private final JButton saveButton = new JButton("Save Patch Set...");
    private final JButton loadButton = new JButton("Load Patch Set...");
    private final JButton refreshButton = new JButton("Refresh");

    private final JPanel buttonBar = new JPanel(new BorderLayout());
    private final JPanel buttonStrip = new JPanel();
    private final JButton overflowButton = new JButton("\u22ee");
    private final List<AbstractButton> actionButtons = List.of(
        addButton, captureButton, editButton, toggleButton, infoButton, deleteButton, showOriginalButton,
        enableAllButton, disableAllButton, saveButton, loadButton, refreshButton
    );
    private List<AbstractButton> visibleButtons = new ArrayList<>();
    private boolean updatingOverflow;

    private boolean layingOutColumns;
    private boolean userResizedColumns;

    private final boolean showOriginalDisassemblyComments_initial;

    PatchManagerProvider(PluginTool tool, PatchManagerPlugin plugin, boolean showOriginalDisassemblyComments) {
        super(tool, TITLE, plugin.getName());
        this.plugin = plugin;
        this.model = new PatchTableModel(plugin);
        this.table = new JTable(model);
        this.scrollPane = new JScrollPane(table);
        this.showOriginalDisassemblyComments_initial = showOriginalDisassemblyComments;

        buildUi();
    }

    private static Icon sizedIcon(Icon icon) {
        return ResourceManager.getScaledIcon(icon, ICON_SIZE, ICON_SIZE);
    }

    private static void equalizeHeights(JToggleButton toggleButton, JButton... buttons) {
        int maxHeight = toggleButton.getPreferredSize().height;
        for (JButton b : buttons) {
            maxHeight = Math.max(maxHeight, b.getPreferredSize().height);
        }
        for (JButton b : buttons) {
            Dimension d = b.getPreferredSize();
            b.setPreferredSize(new Dimension(d.width, maxHeight));
        }
        Dimension tb_d = toggleButton.getPreferredSize();
        toggleButton.setPreferredSize(new Dimension(tb_d.width, maxHeight));
    }

    private void buildUi() {
        configureButtons();
        configureButtonBar();
        configureTable();
        mainPanel.setBorder(BorderFactory.createEmptyBorder(4, 4, 4, 4));
        mainPanel.add(buttonBar, BorderLayout.NORTH);
        mainPanel.add(scrollPane, BorderLayout.CENTER);
        mainPanel.add(statusLabelPanel(), BorderLayout.SOUTH);

        SwingUtilities.invokeLater(this::relayoutColumns);
        SwingUtilities.invokeLater(this::updateButtonOverflow);
        updateButtons();
    }

    private void configureButtons() {
        addButton.setIcon(sizedIcon(Icons.ADD_ICON));
        addButton.setIconTextGap(4);
        addButton.setToolTipText("Create a new patch (Ctrl+Alt+Shift + A)");

        captureButton.setIcon(sizedIcon(Icons.COPY_ICON));
        captureButton.setIconTextGap(4);
        captureButton.setToolTipText("Capture existing modifications in the current program (Ctrl+Alt+Shift + C)");

        editButton.setIcon(sizedIcon(new GIcon("icon.properties")));
        editButton.setIconTextGap(4);
        editButton.setToolTipText("Edit the selected patch (Ctrl+Alt+Shift + E)");

        toggleButton.setIcon(sizedIcon(new GIcon("icon.run")));
        toggleButton.setIconTextGap(4);
        toggleButton.setToolTipText("Toggle the selected patch (Ctrl+Alt+Shift + T)");

        infoButton.setIconTextGap(4);
        infoButton.setToolTipText("Show detailed information for the selected patch (Ctrl+Alt+Shift + U)");

        deleteButton.setIcon(sizedIcon(Icons.DELETE_ICON));
        deleteButton.setIconTextGap(4);
        deleteButton.setToolTipText("Delete the selected patch or patches (Ctrl+Alt+Shift + D)");

        showOriginalButton.setIcon(sizedIcon(new GIcon("icon.filter.options.contains")));
        showOriginalButton.setIconTextGap(4);
        showOriginalButton.setToolTipText(
                "Show or hide original-disassembly comments (Ctrl+Alt+Shift + O)");
        showOriginalButton.setSelected(this.showOriginalDisassemblyComments_initial);

        enableAllButton.setIcon(sizedIcon(new GIcon("icon.plugin.bundlemanager.enable")));
        enableAllButton.setIconTextGap(4);
        enableAllButton.setToolTipText("Enable all patches (Ctrl+Alt+Shift + Y)");

        disableAllButton.setIcon(sizedIcon(new GIcon("icon.plugin.bundlemanager.disable")));
        disableAllButton.setIconTextGap(4);
        disableAllButton.setToolTipText("Disable all patches (Ctrl+Alt+Shift + N)");

        saveButton.setIcon(sizedIcon(Icons.SAVE_AS_ICON));
        saveButton.setIconTextGap(4);
        saveButton.setToolTipText("Save the patch set to a file (Ctrl+Alt+Shift + S)");

        loadButton.setIcon(sizedIcon(Icons.OPEN_FOLDER_ICON));
        loadButton.setIconTextGap(4);
        loadButton.setToolTipText("Load a patch set from a file (Ctrl+Alt+Shift + L)");

        refreshButton.setIcon(sizedIcon(Icons.REFRESH_ICON));
        refreshButton.setIconTextGap(4);
        refreshButton.setToolTipText("Refresh patch states (Ctrl+Alt+Shift + R)");

        equalizeHeights(
            showOriginalButton, addButton, captureButton, editButton, toggleButton, infoButton, deleteButton,
            enableAllButton, disableAllButton, saveButton, loadButton, refreshButton
        );

        addButton.addActionListener(e -> plugin.addPatchFromUi());
        captureButton.addActionListener(e -> plugin.captureCurrentChanges());
        editButton.addActionListener(e -> plugin.editSelectedPatch());
        toggleButton.addActionListener(e -> plugin.toggleSelectedPatch());
        infoButton.addActionListener(e -> plugin.showPatchInfoForSelectedPatch());
        deleteButton.addActionListener(e -> plugin.deleteSelectedPatches());
        showOriginalButton.addActionListener(e ->
                plugin.setOriginalDisassemblyCommentsVisible(showOriginalButton.isSelected()));
        enableAllButton.addActionListener(e -> plugin.setAllPatchesEnabled(true));
        disableAllButton.addActionListener(e -> plugin.setAllPatchesEnabled(false));
        saveButton.addActionListener(e -> plugin.exportPatchSet());
        loadButton.addActionListener(e -> plugin.importPatchSet());
        refreshButton.addActionListener(e -> plugin.refreshProvider());

        overflowButton.setFocusable(false);
        overflowButton.setToolTipText("More Patch Manager actions");
        overflowButton.setMargin(new java.awt.Insets(2, 7, 2, 7));
        overflowButton.addActionListener(e -> showOverflowMenu());
    }

    private void configureButtonBar() {
        buttonStrip.setLayout(new javax.swing.BoxLayout(buttonStrip, javax.swing.BoxLayout.X_AXIS));
        buttonStrip.setBorder(BorderFactory.createEmptyBorder(2, 0, 2, BUTTON_GAP));
        buttonBar.add(buttonStrip, BorderLayout.CENTER);
        buttonBar.add(overflowButton, BorderLayout.EAST);
        overflowButton.setVisible(false);

        buttonBar.addComponentListener(new ComponentAdapter() {
            @Override
            public void componentResized(ComponentEvent e) {
                SwingUtilities.invokeLater(PatchManagerProvider.this::updateButtonOverflow);
            }
        });
    }

    private void updateButtonOverflow() {
        if (updatingOverflow) {
            return;
        }

        int availableWidth = buttonBar.getWidth();
        if (availableWidth <= 0) {
            return;
        }

        updatingOverflow = true;
        try {
            int totalWidth = totalButtonWidth(actionButtons);
            boolean needOverflow = totalWidth > availableWidth;
            int budget = needOverflow
                ? Math.max(0, availableWidth - overflowButton.getPreferredSize().width - BUTTON_GAP)
                : availableWidth;

            List<AbstractButton> nextVisible = new ArrayList<>();
            int used = 0;
            for (AbstractButton button : actionButtons) {
                int width = button.getPreferredSize().width;
                int candidate = nextVisible.isEmpty() ? width : used + BUTTON_GAP + width;
                if (candidate > budget) {
                    break;
                }
                nextVisible.add(button);
                used = candidate;
            }

            if (nextVisible.size() == actionButtons.size()) {
                needOverflow = false;
            }

            if (!nextVisible.equals(visibleButtons)) {
                visibleButtons = nextVisible;
                buttonStrip.removeAll();
                for (int i = 0; i < visibleButtons.size(); i++) {
                    if (i != 0) {
                        buttonStrip.add(Box.createHorizontalStrut(BUTTON_GAP));
                    }
                    buttonStrip.add(visibleButtons.get(i));
                }
                buttonStrip.revalidate();
                buttonStrip.repaint();
            }

            overflowButton.setVisible(needOverflow && visibleButtons.size() < actionButtons.size());
            buttonBar.revalidate();
            buttonBar.repaint();
        }
        finally {
            updatingOverflow = false;
        }
    }

    private static int totalButtonWidth(List<? extends AbstractButton> buttons) {
        int total = 0;
        for (int i = 0; i < buttons.size(); i++) {
            if (i != 0) {
                total += BUTTON_GAP;
            }
            total += buttons.get(i).getPreferredSize().width;
        }
        return total;
    }

    private void showOverflowMenu() {
        if (visibleButtons.size() == actionButtons.size()) {
            return;
        }

        JPopupMenu menu = new JPopupMenu();
        for (AbstractButton button : actionButtons) {
            if (visibleButtons.contains(button)) {
                continue;
            }

            JMenuItem item = new JMenuItem(button.getText(), button.getIcon());
            item.setEnabled(button.isEnabled());
            if (button.getToolTipText() != null) {
                item.setToolTipText(button.getToolTipText());
            }
            item.addActionListener(e -> button.doClick());
            menu.add(item);
        }

        menu.show(overflowButton, 0, overflowButton.getHeight());
    }


    private void configureTable() {
        table.setSelectionMode(ListSelectionModel.MULTIPLE_INTERVAL_SELECTION);
        table.setAutoCreateRowSorter(true);
        table.setFillsViewportHeight(true);
        table.setRowHeight(Math.max(22, table.getRowHeight()));
        table.setShowGrid(true);
        table.setIntercellSpacing(new Dimension(1, 1));
        table.setAutoResizeMode(JTable.AUTO_RESIZE_OFF);

        table.getInputMap().put(KeyStroke.getKeyStroke(KeyEvent.VK_SPACE, 0), "toggle-patch");
        table.getActionMap().put("toggle-patch", new javax.swing.AbstractAction() {
            @Override
            public void actionPerformed(ActionEvent e) {
                plugin.toggleSelectedPatch();
            }
        });

        table.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseClicked(MouseEvent e) {
                if (!SwingUtilities.isLeftMouseButton(e)) {
                    return;
                }

                int viewRow = table.rowAtPoint(e.getPoint());
                int viewColumn = table.columnAtPoint(e.getPoint());
                if (viewRow < 0 || viewColumn < 0) {
                    return;
                }

                if (table.convertColumnIndexToModel(viewColumn) == PatchTableModel.ENABLED_COL) {
                    if (e.getClickCount() == 1) {
                        table.getSelectionModel().setSelectionInterval(viewRow, viewRow);
                        plugin.togglePatchAtModelRow(table.convertRowIndexToModel(viewRow));
                    }
                    return;
                }

                if (e.getClickCount() == 2) {
                    table.getSelectionModel().setSelectionInterval(viewRow, viewRow);
                    plugin.jumpToSelectedPatch();
                }
            }
        });
        table.getSelectionModel().addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting()) {
                updateButtons();
            }
        });

        table.getColumnModel().addColumnModelListener(new TableColumnModelListener() {
            @Override
            public void columnAdded(TableColumnModelEvent e) {
            }

            @Override
            public void columnRemoved(TableColumnModelEvent e) {
            }

            @Override
            public void columnMoved(TableColumnModelEvent e) {
                if (!layingOutColumns) {
                    userResizedColumns = true;
                }
            }

            @Override
            public void columnMarginChanged(javax.swing.event.ChangeEvent e) {
                if (!layingOutColumns) {
                    userResizedColumns = true;
                }
            }

            @Override
            public void columnSelectionChanged(javax.swing.event.ListSelectionEvent e) {
            }
        });

        scrollPane.getViewport().addComponentListener(new ComponentAdapter() {
            @Override
            public void componentResized(ComponentEvent e) {
                if (!userResizedColumns) {
                    SwingUtilities.invokeLater(PatchManagerProvider.this::relayoutColumns);
                }
            }
        });
    }

    private void relayoutColumns() {
        if (userResizedColumns || layingOutColumns) {
            return;
        }

        int viewportWidth = scrollPane.getViewport().getWidth();
        if (viewportWidth <= 0) {
            return;
        }

        TableColumnModel columns = table.getColumnModel();
        int fixedWidth = ENABLED_WIDTH + ADDRESS_WIDTH + STATE_WIDTH;
        int flexibleWidth = viewportWidth - fixedWidth;
        int eachFlexible = Math.max(FLEXIBLE_MIN_WIDTH, flexibleWidth / 3);

        layingOutColumns = true;
        try {
            setColumnWidth(columns, PatchTableModel.ENABLED_COL, ENABLED_WIDTH);
            setColumnWidth(columns, PatchTableModel.ADDRESS_COL, ADDRESS_WIDTH);
            setColumnWidth(columns, PatchTableModel.STATE_COL, STATE_WIDTH);
            setColumnWidth(columns, PatchTableModel.NAME_COL, eachFlexible);
            setColumnWidth(columns, PatchTableModel.ORIGINAL_COL, eachFlexible);
            setColumnWidth(columns, PatchTableModel.PATCHED_COL,
                Math.max(FLEXIBLE_MIN_WIDTH, flexibleWidth - eachFlexible * 2));
            table.revalidate();
            table.repaint();
        }
        finally {
            layingOutColumns = false;
        }
    }

    private static void setColumnWidth(TableColumnModel columns, int modelIndex, int width) {
        var column = findColumnByModelIndex(columns, modelIndex);
        if (column != null) {
            column.setPreferredWidth(width);
            column.setWidth(width);
        }
    }

    private static javax.swing.table.TableColumn findColumnByModelIndex(TableColumnModel columns,
            int modelIndex) {
        for (int i = 0; i < columns.getColumnCount(); i++) {
            javax.swing.table.TableColumn column = columns.getColumn(i);
            if (column.getModelIndex() == modelIndex) {
                return column;
            }
        }
        return null;
    }

    void setShowOriginalDisassemblyCommentsButtonState(boolean selected) {
        if (showOriginalButton.isSelected() != selected) {
            showOriginalButton.setSelected(selected);
        }
    }

    private JPanel statusLabelPanel() {
        JPanel bottom = new JPanel(new BorderLayout());
        bottom.setBorder(BorderFactory.createEmptyBorder(2, 4, 2, 4));
        bottom.add(statusLabel, BorderLayout.WEST);
        return bottom;
    }

    @Override
    public javax.swing.JComponent getComponent() {
        return mainPanel;
    }

    void setPatches(List<Patch> patches) {
        // Refreshing the model fires a data-change event, which clears JTable selection.
        // Preserve the currently selected Patch object when it still exists in the refreshed
        // model so asynchronous program/comment refreshes cannot unexpectedly deselect it.
        Patch selectedPatch = getSelectedPatch();
        model.setPatches(patches);
        if (selectedPatch != null && patches.contains(selectedPatch)) {
            selectPatch(selectedPatch);
        }
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

    void focusTable() {
        table.requestFocusInWindow();
    }

    void setStatus(String text) {
        statusLabel.setText(text == null ? "" : text);
    }

    private void updateButtons() {
        boolean hasSelection = table.getSelectedRowCount() > 0;
        boolean one = table.getSelectedRowCount() == 1;
        boolean busy = !plugin.canEditPatches();
        boolean hasPatch = one && getSelectedPatch() != null;
        editButton.setEnabled(hasPatch && !busy && plugin.selectedPatchIsEditable());
        toggleButton.setEnabled(hasPatch && !busy && plugin.selectedPatchIsEditable());
        infoButton.setEnabled(hasPatch && !busy);
        deleteButton.setEnabled(hasSelection && !busy);
        showOriginalButton.setEnabled(!busy && plugin.getCurrentProgram() != null);
        plugin.notifyContextChanged();
    }
}
