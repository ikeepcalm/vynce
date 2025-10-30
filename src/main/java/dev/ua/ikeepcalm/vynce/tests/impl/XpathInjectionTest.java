package dev.ua.ikeepcalm.vynce.tests.impl;

import dev.ua.ikeepcalm.vynce.core.model.ScanContext;
import dev.ua.ikeepcalm.vynce.core.model.source.TestType;
import dev.ua.ikeepcalm.vynce.tests.BaseVulnerabilityTest;
import dev.ua.ikeepcalm.vynce.ui.ConsoleUI;

public class XpathInjectionTest extends BaseVulnerabilityTest {

    @Override
    public TestType getTestType() {
        return TestType.XPATH;
    }

    @Override
    protected void runTests(ScanContext context) throws Exception {
        // TODO: Implement XPath injection detection
        ConsoleUI.error("XPath injection test not yet implemented");
    }
}
