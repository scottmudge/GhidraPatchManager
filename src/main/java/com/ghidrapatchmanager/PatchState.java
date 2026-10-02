package com.ghidrapatchmanager;

enum PatchState {
    ENABLED("Enabled"),
    DISABLED("Disabled"),
    CONFLICT("Conflict"),
    MISSING("Missing");

    private final String display;

    PatchState(String display) {
        this.display = display;
    }

    @Override
    public String toString() {
        return display;
    }
}
