# Detection Rules (demo defaults)

R001: >=20 distinct modified files in any rolling 10-second window; medium starting signal (+20).

R002: >=15 distinct renamed/moved files in any rolling 10-second window (+25).

R003: >=10 distinct deleted files in any rolling 10-second window (+25; review required).

R004: baseline mismatch, new file, missing file, or unverifiable file; informational by default.

R005: a simulated backup job failure/unavailability (+20) or unexpected disablement (+30). It is never live backup telemetry.

R006: R001, R002, or R003 plus an eligible R005 event for the same monitored root inside 60 seconds. Generate/update one incident and explain the actual rule hits.

R007: fictional approved maintenance windows annotate matching file activity and lower operational priority according to the configured policy; do not erase raw events, hide evidence, or override a separate backup warning.

Score is clamped 0–100; rule-hit IDs prevent repeat counting. Bands: informational 0–29, low 30–49, medium 50–69, high 70–84, critical 85–100. These demo values are not universal thresholds or probabilities.

