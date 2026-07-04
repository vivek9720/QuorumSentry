package io.quorumsentry.detect;

import io.quorumsentry.model.Severity;

public final class ContainerEscapeDetector extends ProfiledDetector {
    public ContainerEscapeDetector() {
        super(new DetectorProfile(
                "ContainerEscapeDetector",
                Severity.CRITICAL,
                "Container boundary markers appeared with escape language.",
                DetectorProfile.tokens("cgroup", "namespace", "escape", "privileged"),
                DetectorProfile.tokens("https"),
                DetectorProfile.tokens("container", "escape"),
                0L,
                0L,
                false,
                false));
    }
}
