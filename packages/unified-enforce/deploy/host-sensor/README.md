# Host runtime sensor — the facts that mean "an agent runs here"

Part of detecting rogue agents on customer hardware (build-14, S-3). The
sensor asks osquery three questions and ships **names**: processes and their
parents, listening ports and the process behind them, Python packages. The
control plane classifies them against `agent-runtimes.v1` and raises when an
agent runtime shows up on a host no declared agent runs on. A sensor that
reported and then went quiet is a finding too — a killed or blinded sensor
looks exactly like a quiet host, and the two must not.

## What never leaves the host

No command lines, no environments, no file contents, no arguments. The
runner copies named columns from osquery and nothing else; the control plane
refuses a `cmdline`, `argv`, `env` or `contents` field by name; and
`--dry-run` prints exactly what would be sent:

```sh
pip install unified-enforce   # or vendor the single file host_sensor.py
python -m unified_enforce.host_sensor --dry-run
```

## Running it

Enrol a sidecar credential for the fleet (`unified-control issue-join-token`,
then the enrolment call) and put it in the environment:

```sh
export UNIFIED_CREDENTIAL=uai_sc_...
python -m unified_enforce.host_sensor \
  --control-plane https://control-plane.example \
  --host $(hostname) \
  --interval 300
```

`--host` should be the name the fleet's inventory declares for this machine
(`inventory declare --hosts`); that is what a fact is attributed against. The
Coverage Report lists declared hosts with and without a sensor, by name.

## osqueryd instead

If osquery results already flow to a collector, load
`unified-agent-facts.conf` as a pack and have the collector post each
snapshot to `POST /api/v1/evidence/hosts` in the `host.v1` shape
(`{host, sensor_version, observed_at, facts: [{kind, name, detail, user, port}]}`).
The pack's queries are the runner's, verbatim.

## Stated limits

- A host without the sensor is invisible to S-3 by definition; the Coverage
  Report names them.
- A container the sensor's osquery cannot see is a blind spot; run the sensor
  in the pod or on the node with container-aware tables.
- A kernel-level attacker can blind the sensor. Then it goes quiet, and quiet
  is a finding.
