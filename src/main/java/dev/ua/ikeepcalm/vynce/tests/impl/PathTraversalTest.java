package dev.ua.ikeepcalm.vynce.tests.impl;

import dev.ua.ikeepcalm.vynce.core.model.ScanContext;
import dev.ua.ikeepcalm.vynce.core.model.source.TestType;
import dev.ua.ikeepcalm.vynce.tests.BaseVulnerabilityTest;
import dev.ua.ikeepcalm.vynce.ui.ConsoleUI;

public class PathTraversalTest extends BaseVulnerabilityTest {

    @Override
    public TestType getTestType() {
        return TestType.PATH_TRAVERSAL;
    }

    @Override
    protected void runTests(ScanContext context) throws Exception {
        // TODO: Implement path traversal detection
        ConsoleUI.error("Path traversal test not yet implemented");
    }
}
