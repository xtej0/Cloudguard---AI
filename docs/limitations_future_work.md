# Limitations and Future Improvements

## Current Limitations

### Synthetic Dataset

The ML dataset is synthetic and generated for academic demonstration. It contains realistic feature categories, but it does not represent production telemetry from a real cloud estate.

Impact:

- Model metrics are useful for validating pipeline behavior.
- Model metrics should not be presented as real-world predictive performance.

### Seeded Demo Graph

The Neo4j graph is a compact demo topology. It is suitable for showing attack-path, risk, prediction, and mitigation workflows, but it is not a complete cloud asset inventory.

Impact:

- Path results depend on the seeded graph.
- Reviewers should interpret graph behavior as a proof of concept.

### Rule-Based Risk Scoring

Risk scoring is deterministic and weighted. This makes it explainable, but it is not a calibrated enterprise risk model.

Impact:

- Scores are consistent and inspectable.
- Scores do not account for every cloud control, vulnerability detail, compensating control, or business context.

### ML Label Source

The `risk_level` target is generated from engineered rules and controlled uncertainty. The model learns synthetic labeling behavior rather than labels from incident outcomes.

Impact:

- The classifier demonstrates ML integration.
- Future work should use validated labels from audits, incidents, or expert review.

### Local Static Frontend

The dashboard is a static local frontend. It does not include authentication, authorization, user management, multi-tenant isolation, or persistent workspace state.

Impact:

- It is easy to run and review.
- It is not production SaaS infrastructure.

### Local Runtime Assumptions

The system assumes local Neo4j and local FastAPI availability. Production deployment concerns such as secrets management, TLS termination, container orchestration, logging pipelines, and access control are outside the current scope.

## Future Improvements

### Cloud Provider Integration

Add ingestion from AWS, Azure, or GCP APIs:

- compute inventory
- IAM policies and trust relationships
- security groups and firewall rules
- storage exposure
- vulnerability scanner output
- cloud configuration findings

### Production Graph Model

Expand graph schema to include:

- accounts, subscriptions, and projects
- regions and networks
- security groups and routes
- identities, groups, roles, policies, and trust edges
- vulnerability findings
- data sensitivity labels
- detection and monitoring coverage

### Model Improvements

Future ML upgrades:

- train on real-world or expert-labeled data
- calibrate probabilities
- add model cards and dataset cards
- track train/test splits and experiment metadata
- add drift monitoring
- compare graph neural networks or learning-to-rank methods for next-target prediction

### Mitigation Enhancements

Improve recommendations with:

- asset-specific remediation playbooks
- cloud-provider-specific commands
- compliance mappings such as CIS, NIST, ISO 27001, or SOC 2
- estimated effort and impact
- remediation dependency ordering

### Frontend Enhancements

Potential dashboard improvements:

- authentication and user roles
- saved investigations
- graph filters by asset type, relationship type, and risk level
- historical comparison
- export to PDF
- richer model explainability views

### Deployment Enhancements

Production hardening could include:

- Docker Compose with Neo4j and backend services
- CI test workflow
- environment-specific configuration
- structured logging
- API authentication
- TLS
- secret management
- observability dashboards

## Academic Positioning

CloudGuard AI is best framed as a security analytics prototype demonstrating how graph analysis, explainable risk scoring, ML inference, and mitigation guidance can be integrated into one analyst-facing workflow.
