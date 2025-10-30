package dev.ua.ikeepcalm.vynce.tests.impl;

import dev.ua.ikeepcalm.vynce.core.model.ScanContext;
import dev.ua.ikeepcalm.vynce.core.model.source.TestType;
import dev.ua.ikeepcalm.vynce.tests.BaseVulnerabilityTest;
import dev.ua.ikeepcalm.vynce.ui.ConsoleUI;

public class CommandInjectionTest extends BaseVulnerabilityTest {

    @Override
    public TestType getTestType() {
        return TestType.COMMAND_INJECTION;
    }

    @Override
    protected void runTests(ScanContext context) throws Exception {
        // TODO: Implement command injection detection
        ConsoleUI.error("Command injection test not yet implemented");
    }
}
