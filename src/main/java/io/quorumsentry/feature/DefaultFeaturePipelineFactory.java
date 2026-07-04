package io.quorumsentry.feature;

public final class DefaultFeaturePipelineFactory {
    private DefaultFeaturePipelineFactory() {}

    public static FeaturePipeline create() {
        FeaturePipeline pipeline = new FeaturePipeline();
        pipeline.add(new TemporalBurstFeature());
        pipeline.add(new HostIdentityFeature());
        pipeline.add(new NetworkExposureFeature());
        pipeline.add(new CredentialSignalFeature());
        pipeline.add(new PayloadShapeFeature());
        pipeline.add(new ProcessLineageFeature());
        pipeline.add(new CloudControlFeature());
        pipeline.add(new DataGravityFeature());
        pipeline.add(new AdminSurfaceFeature());
        pipeline.add(new DnsLexicalFeature());
        pipeline.add(new GeoVarianceFeature());
        pipeline.add(new PersistenceSurfaceFeature());
        pipeline.add(new EndpointPostureFeature());
        pipeline.add(new ArchiveLineageFeature());
        pipeline.add(new PolicyIntentFeature());
        pipeline.add(new MalwareFamilyFeature());
        pipeline.add(new ExploitMaturityFeature());
        pipeline.add(new SessionCadenceFeature());
        pipeline.add(new AssetCriticalityFeature());
        pipeline.add(new SecretMaterialFeature());
        pipeline.add(new HttpSurfaceFeature());
        pipeline.add(new LdapAbuseFeature());
        pipeline.add(new MailAbuseFeature());
        pipeline.add(new RepositoryLeakFeature());
        pipeline.add(new BuildSystemFeature());
        pipeline.add(new ContainerRuntimeFeature());
        pipeline.add(new KubernetesAuditFeature());
        pipeline.add(new SaasAuditFeature());
        pipeline.add(new VpnAnomalyFeature());
        pipeline.add(new BackupIntegrityFeature());
        pipeline.add(new MemoryForensicsFeature());
        pipeline.add(new RegistryDriftFeature());
        pipeline.add(new CertificateFeature());
        pipeline.add(new SshBehaviorFeature());
        pipeline.add(new DatabaseAccessFeature());
        pipeline.add(new ObjectStorageFeature());
        pipeline.add(new AnomalyEnvelopeFeature());
        pipeline.add(new IncidentGraphFeature());
        pipeline.add(new ThreatIntelFeature());
        pipeline.add(new QuarantineReadinessFeature());
        pipeline.add(new TriageCostFeature());
        pipeline.add(new BusinessImpactFeature());
        pipeline.add(new UserBehaviorFeature());
        pipeline.add(new IdentityProviderFeature());
        pipeline.add(new ZeroTrustFeature());
        pipeline.add(new EastWestFlowFeature());
        pipeline.add(new IngressFlowFeature());
        pipeline.add(new EgressFlowFeature());
        pipeline.add(new RiskNarrativeFeature());
        pipeline.add(new SuppressionFeature());
        return pipeline;
    }
}
