package com.ghidrapatchmanager;

import java.util.Arrays;

import ghidra.program.model.address.Address;

final class Patch {
    String name;
    Address address;
    byte[] originalBytes;
    byte[] patchedBytes;

    Patch(String name, Address address, byte[] originalBytes, byte[] patchedBytes) {
        this.name = name;
        this.address = address;
        this.originalBytes = originalBytes.clone();
        this.patchedBytes = patchedBytes.clone();
    }

    PatchState getState(PatchManagerPlugin plugin) {
        if (plugin == null || plugin.getCurrentProgram() == null) {
            return PatchState.MISSING;
        }
        try {
            byte[] current = plugin.readBytes(address, patchedBytes.length);
            if (Arrays.equals(current, patchedBytes)) {
                return PatchState.ENABLED;
            }
            if (Arrays.equals(current, originalBytes)) {
                return PatchState.DISABLED;
            }
            return PatchState.CONFLICT;
        }
        catch (Exception e) {
            return PatchState.MISSING;
        }
    }

    Address getEndAddress() {
        return address.add(patchedBytes.length - 1L);
    }
}
