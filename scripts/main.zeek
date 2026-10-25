##! DECTRAX Deception and Decoy Monitoring Package for Zeek.
##! Automatically monitors network traffic for connections attempting to access
##! configured DECTRAX deception endpoints, decoy IP ranges, or honeypot ports.

module DECTRAX;

export {
    redef enum Notice::Type += {
        ## Raised when an unauthorized internal or external host attempts to access a DECTRAX decoy service.
        Decoy_Access_Attempt,
        ## Raised when an adversary attempts scanning or enumeration across multiple DECTRAX decoy ports.
        Decoy_Port_Scan,
        ## Raised when interaction is observed against sensitive decoy honeytokens or canary credentials.
        Honeytoken_Interaction
    };

    ## Set of IP addresses designated as DECTRAX decoy sensors.
    const decoy_ips: set[addr] = {} &redef;

    ## Set of subnets designated as DECTRAX decoy network zones.
    const decoy_subnets: set[subnet] = {} &redef;

    ## Designated decoy trap ports monitored by DECTRAX.
    const decoy_ports: set[port] = {
        21/tcp,   # Decoy FTP
        22/tcp,   # Decoy SSH
        23/tcp,   # Decoy Telnet
        80/tcp,   # Decoy Web Server
        443/tcp,  # Decoy HTTPS Portal
        445/tcp,  # Decoy SMB
        1433/tcp, # Decoy MSSQL
        3306/tcp, # Decoy MySQL
        3389/tcp, # Decoy RDP
        5000/tcp, # Decoy REST API
        8080/tcp, # Decoy Admin Portal
        9200/tcp  # Decoy Elasticsearch
    } &redef;
}

function is_dectrax_decoy(a: addr): bool
    {
    if ( a in decoy_ips )
        return T;
    for ( s in decoy_subnets )
        {
        if ( a in s )
            return T;
        }
    return F;
    }

event connection_established(c: connection)
    {
    local is_orig_decoy = is_dectrax_decoy(c$id$orig_h);
    local is_resp_decoy = is_dectrax_decoy(c$id$resp_h);

    if ( is_resp_decoy || (c$id$resp_p in decoy_ports && is_resp_decoy) )
        {
        NOTICE([
            $note=Decoy_Access_Attempt,
            $msg=fmt("Adversary connection established to DECTRAX Decoy Sensor %s:%s from %s:%s",
                     c$id$resp_h, c$id$resp_p, c$id$orig_h, c$id$orig_p),
            $sub=fmt("Protocol: %s, Decoy Service Port: %s", c$orig$proto, c$id$resp_p),
            $conn=c,
            $identifier=cat(c$id$orig_h, c$id$resp_h, c$id$resp_p)
        ]);
        }
    }
