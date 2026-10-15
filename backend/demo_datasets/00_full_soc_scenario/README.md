# Full SOC scenario

One coherent 10-event intrusion chain used to exercise the whole data plane in a single run: authentication abuse, a multi-rule process execution, a YARA-detected script drop, C2/DNS/SMB egress and a firewall block.

## Inputs

- `attack_chain.jsonl (10 records, JSON Lines)`

## Observed / expected behaviour

14 real detections and 1 real multi-member correlation (7 members, 1 distinct event, risk 0.628571 = high).

## Run

```bash
python scripts/run_demo_dataset.py full_soc
```
