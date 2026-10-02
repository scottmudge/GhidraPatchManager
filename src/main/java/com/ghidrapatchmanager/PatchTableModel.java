package com.ghidrapatchmanager;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;

import javax.swing.table.AbstractTableModel;

final class PatchTableModel extends AbstractTableModel {
    static final int ENABLED_COL = 0;
    static final int NAME_COL = 1;
    static final int ADDRESS_COL = 2;
    static final int ORIGINAL_COL = 3;
    static final int PATCHED_COL = 4;
    static final int STATE_COL = 5;
    static final int COLUMN_COUNT = 6;

    private static final String[] COLUMNS = {
        "Enabled", "Name", "Address", "Original Bytes", "Patched Bytes", "State"
    };

    private final PatchManagerPlugin plugin;
    private final List<Patch> patches = new ArrayList<>();

    PatchTableModel(PatchManagerPlugin plugin) {
        this.plugin = plugin;
    }

    void setPatches(List<Patch> source) {
        patches.clear();
        patches.addAll(source);
        patches.sort(Comparator.comparing(p -> p.address, Comparator.nullsLast(Comparator.naturalOrder())));
        fireTableDataChanged();
    }

    List<Patch> getPatches() {
        return new ArrayList<>(patches);
    }

    Patch getPatch(int row) {
        return row >= 0 && row < patches.size() ? patches.get(row) : null;
    }

    void addPatch(Patch patch) {
        patches.add(patch);
        patches.sort(Comparator.comparing(p -> p.address));
        fireTableDataChanged();
    }

    void removePatch(Patch patch) {
        if (patches.remove(patch)) {
            fireTableDataChanged();
        }
    }

    @Override
    public int getRowCount() {
        return patches.size();
    }

    @Override
    public int getColumnCount() {
        return COLUMN_COUNT;
    }

    @Override
    public String getColumnName(int column) {
        return COLUMNS[column];
    }

    @Override
    public Class<?> getColumnClass(int column) {
        return column == ENABLED_COL ? Boolean.class : String.class;
    }

    @Override
    public boolean isCellEditable(int rowIndex, int columnIndex) {
        return false;
    }

    @Override
    public Object getValueAt(int rowIndex, int columnIndex) {
        Patch patch = patches.get(rowIndex);
        PatchState state = patch.getState(plugin);
        return switch (columnIndex) {
            case ENABLED_COL -> state == PatchState.ENABLED;
            case NAME_COL -> patch.name;
            case ADDRESS_COL -> patch.address.toString();
            case ORIGINAL_COL -> HexUtil.format(patch.originalBytes);
            case PATCHED_COL -> HexUtil.format(patch.patchedBytes);
            case STATE_COL -> state.toString();
            default -> "";
        };
    }

    void refresh() {
        fireTableDataChanged();
    }
}
