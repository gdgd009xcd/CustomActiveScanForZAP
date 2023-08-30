package org.zaproxy.zap.extension.customactivescan;

import java.util.UUID;

public class UUIDGenerator {
    public static synchronized UUID getUUID() {
        return UUID.randomUUID();
    }
}
