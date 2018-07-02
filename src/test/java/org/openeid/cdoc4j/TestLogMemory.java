package org.openeid.cdoc4j;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class TestLogMemory {

    private static final Logger LOGGER = LoggerFactory.getLogger(TestLogMemory.class);

    public static void logMemoryUsage(String message) {
        LOGGER.info(message + ". Memory used: " + (Runtime.getRuntime().totalMemory() - Runtime.getRuntime().freeMemory()) / (1024 * 1024));
    }
}
