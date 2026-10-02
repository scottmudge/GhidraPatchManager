package com.ghidrapatchmanager;

import java.util.HexFormat;

final class HexUtil {
    private HexUtil() {
    }

    static byte[] parse(String text) throws IllegalArgumentException {
        if (text == null) {
            throw new IllegalArgumentException("Byte string is null.");
        }

        String s = text.trim().replace("0x", "").replace("0X", "")
                .replace(" ", "").replace("\t", "")
                .replace(",", "").replace("_", "");
        if (s.isEmpty()) {
            throw new IllegalArgumentException("Byte string is empty.");
        }
        if ((s.length() & 1) != 0) {
            throw new IllegalArgumentException("Byte string must contain an even number of hex digits.");
        }
        if (!s.matches("[0-9A-Fa-f]+")) {
            throw new IllegalArgumentException("Invalid hexadecimal byte string.");
        }
        return HexFormat.of().parseHex(s);
    }

    static String format(byte[] bytes) {
        return HexFormat.of().formatHex(bytes).replaceAll("(..)(?=.)", "$1 ").toUpperCase();
    }
}
