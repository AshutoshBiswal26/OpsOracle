"""OpsOracle — evidence-first, AI-assisted AWS incident investigation.

The package is organized as a deterministic pipeline: collectors gather raw AWS
evidence, normalizers convert it into a common ``EvidenceEvent`` model, the timeline
builder orders it, the correlation engine relates it, the context builder ranks it, and
only then does the Bedrock reasoner produce an evidence-grounded incident report.
"""

__version__ = "0.1.0"
