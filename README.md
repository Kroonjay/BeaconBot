# BeaconBot Staking Monitoring Service

## Function Overview
### BeaconTimer
- Uses a Cron Trigger that runs every 5 minutes
- Finds all validators for a given address, then all attestations & proposals for all validators
- Finds Consensus & Execution Nodes that missed a healthcheck
- Reviews all Policy Violations and posts alerts to PagerDuty
  
### BeaconHook
- Uses an HTTP trigger to receive incoming webhook notification from Beaconcha.in
- Tracks all attestations, proposals, and slashing events for all validators
- Maintained for legacy reasons, beaconcha.in only offers this service for a max of 287 validators

### NodeTrigger
- Uses an HTTP Trigger to Receive Consensus & Execution Node HealthCheck data from NodeWatch script
- NodeWatch script must be deployed on all consensus/execution node pairs for best results
- Reviews all Policy Violations and posts alerts to PagerDuty

## Policy Overview
### Attestations Missed
- Fired whenever validators miss attestations beyond a given threshold within a given number of epochs
- Policy Type
  - `MISSED_ATTESTATIONS`
- Environment Variables
  - `MISSED_ATTESTATION_INTERVAL_EPOCHS`
  - `MISSED_ATTESTATION_THRESHOLD`
- Suggested Defaults
  - Interval: 7 (epochs or ~49 minutes)
  - Threshold: 20 (missed attestations)
    - Dependant on the total number of validators
- Suggested Remediation
  1.  Confirm validator node server is up and running
  2.  Confirm validator node container is up and running
  3. Review validator logs for error messages
  4. Confirm Consensus & Execution nodes are accessible from validator and in sync
  5. Restart Validator node container

### Proposals Missed
- Fired whenever validators miss proposals beyond a given threshold within a given number of epochs
- Policy Type
  - `MISSED_PROPOSALS`
- Environment Variables
  - `MISSED_BLOCK_INTERVAL_EPOCHS`
  - `MISSED_BLOCK_THRESHOLD`
- Suggested Defaults
  - Interval: 7 (epochs or ~49 minutes)
  - Threshold: 2 (missed proposals)
    - Dependant on the total number of validators
- Suggested Remediation
  1.  Confirm validator node server is up and running
  2.  Confirm validator node container is up and running
  3. Review validator logs for error messages
  4. Confirm Consensus & Execution nodes are accessible from validator and in sync
  5. Restart Validator node container

### Beacon or Execution Node Offline
- Policy Types
  - `BEACON_OFFLINE`
  - `EXECUTION_OFFLINE`
- Environment Variables
  - `NODEWATCH_HEALTHCHECK_INTERVAL`

### Beacon or Execution Node Out of Sync
- Policy Types
  - `BEACON_NOT_SYNCED`
  - `EXECUTION_NOT_SYNCED`
  - `BEHIND_ON_BLOCKS`
- Environment Variables
  - `BLOCK_HEIGHT_MISMATCH_TOLERANCE`
- Suggested Defaults
  - Tolerance: 10 (blocks)
- Suggested Remediation
  1. Review PagerDuty alert to determine which nodes are offline
  2. Review validator logs to confirm validator node has failed over to another working consensus/execution pair
  3. Review CPU, Memory, and Disk usage on affected server to confirm we're not running out of resources
  4. Find current block height on etherscan, monitor node block height to determine if it's catching up to the chain
  5. Confirm node software is up to date and that we didn't miss a hard-fork
  6. Restart affected nodes and monitor logs to ensure it's catching up to chain

### Beacon Node Peer Count too Low
- Policy Type
  - `NOT_ENOUGH_PEERS`
- Environment Variables
  - `MINIMUM_BEACON_PEERS`
- Suggested Defaults
  - Minimum Peers: 80 (peers)
- Suggested Remediation
  1. Review PagerDuty alert to determine which beacon node is affected
  2.  Review consensus node logs to determine if node is actively losing peers
      1.  If so, restart beacon node and monitor logs
  3.  If node is not actively losing peers, monitor node logs for 10-15 minutes to determine if peer count is increasing
  4.  