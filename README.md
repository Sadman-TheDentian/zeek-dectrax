# zeek-dectrax

Zeek Network Security Monitor package for **DECTRAX Cyber Deception & Telemetry Platform**.

## Overview

`zeek-dectrax` passively monitors enterprise network traffic via Zeek to detect adversaries, unauthorized scanners, and lateral movement attempts targeting DECTRAX deception decoys and canary honeypots.

When interaction is detected against configured decoy IP addresses, subnets, or trap ports, Zeek automatically generates structured alerts (`Notice::Type` `DECTRAX::Decoy_Access_Attempt`) with zero false positives.

## Installation

Install using the Zeek Package Manager (`zkg`):

```bash
zkg install dectrax
```

Or directly via git:

```bash
zkg install https://github.com/Sadman-TheDentian/zeek-dectrax
```

## Configuration

In your `local.zeek`:

```zeek
@load packages/zeek-dectrax

redef DECTRAX::decoy_ips += {
    10.0.50.25,
    10.0.50.26
};

redef DECTRAX::decoy_subnets += {
    10.0.50.0/24
};
```

## Notice Types

- `DECTRAX::Decoy_Access_Attempt`: Connection established to a DECTRAX decoy sensor or trap port.
- `DECTRAX::Decoy_Port_Scan`: Port scanning or service enumeration against decoy endpoints.
- `DECTRAX::Honeytoken_Interaction`: Decoy credential or canary interaction detected in flight.

## License

Apache License 2.0.
