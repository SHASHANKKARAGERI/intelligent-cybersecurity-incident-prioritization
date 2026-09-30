# Architecture

```text
Synthetic/External Events
          |
          v
    FastAPI ingestion
          |
          v
   Normalization layer
          |
          +----> Risk scoring
          |
          +----> Correlation
          |
          +----> Optional ML model
          |
          v
    Priority + explanation
          |
          v
       SQLite
          |
          v
     SOC Dashboard
```

## Risk model

The MVP uses transparent weighted contextual scoring:

- Threat severity: 20%
- Asset criticality: 20%
- User privilege: 15%
- Attack confidence: 20%
- Exploitability: 10%
- Business impact: 15%

Network exposure is blended into the final score as a contextual modifier.

These weights are demonstration values, not industry-standard risk formulas. In a production system they should be calibrated against an organization's incident history and risk policy.
