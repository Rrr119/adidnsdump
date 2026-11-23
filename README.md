# Active Directory Integrated DNS dump tool

![Python 3](https://img.shields.io/badge/python-3.x-blue.svg)
![PyPI version](https://img.shields.io/pypi/v/adidnsdump.svg)
![License: MIT](https://img.shields.io/pypi/l/adidnsdump.svg)

By default any user in Active Directory can enumerate all DNS records in the Domain or Forest DNS zones, similar to a zone transfer. This tool enables enumeration and exporting of all DNS records in the zone for recon purposes of internal networks.

For more info, read the [associated blog post](https://dirkjanm.io/getting-in-the-zone-dumping-active-directory-dns-with-adidnsdump/).

# Install and usage
You can either install the tool via pip with `pip install adidnsdump` or install it from git to have the latest version:

```
git clone https://github.com/dirkjanm/adidnsdump
cd adidnsdump
pip install .
```

or

```
pip install git+https://github.com/dirkjanm/adidnsdump#egg=adidnsdump
```

The tool requires `impacket` and `dnspython` to function. 

Installation adds the `adidnsdump` command to your `PATH`. For help, try `adidnsdump -h`.
The tool can be used both directly from the network and via an implant using proxychains. If using proxychains, make sure to specify the `--dns-tcp` option.

# Incremental exports and record type filtering

All output keeps the original CSV format (`type,name,value`, one record per line), so existing tooling that consumes `records.csv` keeps working unchanged.

## Record type filtering

Use `-t` / `--record-types` with a comma-separated list of record type names (case-insensitive) or numeric DNS type ids:

```
adidnsdump dc.corp.local -u CORP\user -t A,AAAA,CNAME
adidnsdump dc.corp.local -u CORP\user -t 1,28
```

Unknown type names make the tool exit with an error instead of silently dropping records.

## Incremental exports

`--incremental` tracks the records written in each run in a state file (default: `<outfile>.state.json`). The first run is a full export that establishes the baseline; every following run writes only records that were added or changed:

```
adidnsdump dc.corp.local -u CORP\user --incremental --outfile records.csv
```

- Added and changed records are written to the normal `--outfile` with the same CSV header and line format.
- Add `--include-deleted` to also write records removed since the previous run to a deleted CSV (default: `<outfile>.deleted.csv`, configurable with `--deleted-file`).
- A custom state location can be set with `--state-file`.
- Changing the zone or the `--record-types` filter automatically resets to a full export, so the state never mixes different views.
- Without `--incremental` the behavior is identical to previous versions: a full export is written and no state file is created.

The state file stores a fingerprint (`type,name,value`) per exported record and uses atomic writes, making repeated dumps safe to automate for large zones.
