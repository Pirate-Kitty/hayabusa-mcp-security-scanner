# Sample EVTX files

`CA_4624_4625_LogonType2_LogonProc_chrome.evtx` is a small (69KB) Windows
Security-channel EVTX export used for local testing (`test_scan_evtx.py`). It
contains a single low-severity "Logon Failure (Wrong Password)" event.

## Provenance

The embedded `Computer` (`MSEDGEWIN10`) and target account (`IEUser`) match the
well-known defaults from Microsoft's public "Microsoft Edge on Windows 10"
browser-testing VM images — a hostname/account pair that shows up widely across
public EVTX/Sigma test-data corpora used in security research. No real IP
address, domain, or organization name is present in the event.

The exact upstream source of this specific file was not recorded at the time
it was added to this repo. If you can confirm its origin, please open an issue
or PR with attribution. If in doubt, replace it with a self-generated sample
(e.g. `hayabusa` itself, Windows Event Viewer, or `wevtutil`) before
redistributing.
