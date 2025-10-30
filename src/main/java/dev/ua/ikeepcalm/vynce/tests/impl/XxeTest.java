package dev.ua.ikeepcalm.vynce.tests.impl;

import dev.ua.ikeepcalm.vynce.core.model.ScanContext;
import dev.ua.ikeepcalm.vynce.core.model.source.TestType;
import dev.ua.ikeepcalm.vynce.tests.BaseVulnerabilityTest;
import dev.ua.ikeepcalm.vynce.ui.ConsoleUI;

public class XxeTest extends BaseVulnerabilityTest {

    @Override
    public TestType getTestType() {
        return TestType.XXE;
    }

    @Override
    protected void runTests(ScanContext context) throws Exception {
        // TODO: Implement XXE detection
        ConsoleUI.error("XXE test not yet implemented");
    }
}
