package dev.ua.ikeepcalm.vynce.tests.impl;

import dev.ua.ikeepcalm.vynce.core.model.ScanContext;
import dev.ua.ikeepcalm.vynce.core.model.source.TestType;
import dev.ua.ikeepcalm.vynce.tests.BaseVulnerabilityTest;
import dev.ua.ikeepcalm.vynce.ui.ConsoleUI;

public class OpenRedirectTest extends BaseVulnerabilityTest {

    @Override
    public TestType getTestType() {
        return TestType.OPEN_REDIRECT;
    }

    @Override
    protected void runTests(ScanContext context) throws Exception {
        // TODO: Implement open redirect detection
        ConsoleUI.error("Open redirect test not yet implemented");
    }
}
