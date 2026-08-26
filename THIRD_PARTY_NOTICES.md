# Third-party Notices

## Pithus Bazaar

Project: Pithus Bazaar  
Source: https://github.com/Pithus/bazaar  
License: GNU Affero General Public License version 3

DeceptiScope includes adapter code and analysis concepts derived from Pithus Bazaar's multi-engine Android malware-analysis architecture, including APKiD classification, Quark behavior rules, fuzzy fingerprints, MobSF integration, VirusTotal hash reputation and MalwareBazaar hash reputation.

The Pithus Django application, Elasticsearch persistence layer, templates and user interface are not embedded. DeceptiScope's adapter implementation is in `fraudshield/deceptiscope/engines.py`; source is included in this distribution. Public sample-upload behavior is not part of DeceptiScope. MalwareBazaar and VirusTotal integrations are hash lookup only, disabled by default, and never upload APK bytes.

This combined source distribution is licensed under AGPL-3.0-only. The complete license text is in [LICENSE](LICENSE). Pithus names and trademarks remain the property of their respective owners. No endorsement is implied.

## Analysis Tools

Optional tools retain their own licenses and notices when installed. They are not vendored in this repository:

- Androguard - Android application reverse-engineering framework.
- APKiD and YARA - packer/obfuscator and rule scanning.
- Quark Engine - Android malware behavior analysis.
- ssdeep and Dexofuzzy - fuzzy fingerprint generation.
- MobSF - self-hosted mobile security analysis service.
- Android SDK Build Tools `apksigner` - APK signature verification.

Review each dependency's license and the generated software bill of materials before redistribution or deployment.
