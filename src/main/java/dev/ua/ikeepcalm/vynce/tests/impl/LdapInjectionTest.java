package dev.ua.ikeepcalm.vynce.tests.impl;

import dev.ua.ikeepcalm.vynce.core.model.ScanContext;
import dev.ua.ikeepcalm.vynce.core.model.source.TestType;
import dev.ua.ikeepcalm.vynce.tests.BaseVulnerabilityTest;
import dev.ua.ikeepcalm.vynce.ui.ConsoleUI;

public class LdapInjectionTest extends BaseVulnerabilityTest {

    @Override
    public TestType getTestType() {
        return TestType.LDAP;
    }

    @Override
    protected void runTests(ScanContext context) throws Exception {
        // TODO: Implement LDAP injection detection
        ConsoleUI.error("LDAP injection test not yet implemented");
    }
}
