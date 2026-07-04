package io.quorumsentry.detect;

public final class DefaultDetectorRegistryFactory {
    private DefaultDetectorRegistryFactory() {}

    public static DetectorRegistry create() {
        return new DetectorRegistry()
                .add(new CredentialSprayDetector())
                .add(new BeaconingDetector())
                .add(new DnsTunnelDetector())
                .add(new PrivilegeEscalationDetector())
                .add(new DataExfiltrationDetector())
                .add(new LateralMovementDetector())
                .add(new SuspiciousArchiveDetector())
                .add(new ImpossibleTravelDetector())
                .add(new ServiceDiscoveryDetector())
                .add(new RansomwarePrepDetector())
                .add(new CloudKeyLeakDetector())
                .add(new TorExitDetector())
                .add(new MalwareHashDetector())
                .add(new AdminProtocolDetector())
                .add(new RareProcessDetector())
                .add(new HoneytokenDetector())
                .add(new PayloadEntropyDetector())
                .add(new PolicyBypassDetector())
                .add(new PersistenceDetector())
                .add(new ContainerEscapeDetector())
                .add(new IdentityGraphDetector())
                .add(new DatabaseDumpDetector())
                .add(new PacketStormDetector())
                .add(new LongSessionDetector())
                .add(new IndicatorExpiryDetector())
                .add(new SinkholeDetector())
                .add(new WafBypassDetector())
                .add(new SuspiciousUserAgentDetector())
                .add(new BackupTamperDetector())
                .add(new KernelExploitDetector());
    }
}
