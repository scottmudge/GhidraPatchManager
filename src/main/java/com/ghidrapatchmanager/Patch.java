package com.ghidrapatchmanager;

import java.util.Arrays;

import ghidra.program.model.address.Address;

final class Patch {
    String name;
    Address address;
    byte[] originalBytes;
    byte[] patchedBytes;
    String originalDisassembly;

    Patch(String name, Address address, byte[] originalBytes, byte[] patchedBytes) {
        this.name = name;
        this.address = address;
        this.originalBytes = originalBytes.clone();
        this.patchedBytes = patchedBytes.clone();
    }

    PatchState getState(PatchManagerPlugin plugin) {
        return plugin == null ? PatchState.MISSING : getState(plugin.getCurrentProgram());
    }

    PatchState getState(ghidra.program.model.listing.Program program) {
        if (program == null) {
            return PatchState.MISSING;
        }
        try {
            byte[] current = new byte[patchedBytes.length];
            int count = program.getMemory().getBytes(address, current);
            if (count != patchedBytes.length) {
                return PatchState.MISSING;
            }
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
