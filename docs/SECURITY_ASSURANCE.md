# Security assurance

SessionArmor uses layered evidence: deterministic unit/adversarial tests,
consumer integration tests, static/type analysis, dependency scanning, PyPI
Trusted Publishing, artifact inspection, and a documented threat model. CodeQL
and OpenSSF Scorecard workflows are included and run when the maintainer starts
them. These controls reduce regression and supply-chain risk; they do not
establish that every deployment is secure.

The assurance case is strongest when consumers test their exact middleware
ordering, proxy path, session backend, identity claims, AccessGate policy set,
audit sink, and failure/recovery paths. Independent design review and targeted
penetration testing remain appropriate before high-impact deployment.
