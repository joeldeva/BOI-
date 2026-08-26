# Third-party Notices

## Historical Architecture Inspiration: Pithus Bazaar

Project: Pithus Bazaar  
Source: https://github.com/Pithus/bazaar  
License: GNU Affero General Public License version 3  

Historical context: Early versions of DeceptiScope's multi-engine analysis concept drew inspiration from Pithus Bazaar's approach to orchestrating multiple Android analysis tools. In Pass 6, `fraudshield/deceptiscope/engines.py` was independently redesigned and clean-room reimplemented from FraudShield's own domain requirements, public contracts, and official tool documentation. No Pithus source code is embedded or derived in the current implementation.

The Pithus Django application, Elasticsearch persistence layer, templates, and UI are not and have never been part of this codebase. Public sample-upload behavior is not part of DeceptiScope. MalwareBazaar and VirusTotal integrations are hash lookup only, disabled by default, and never upload APK bytes.

Pithus names and trademarks remain the property of their respective owners. No endorsement is implied.

## Analysis Tools

Optional external analysis tools retain their own licenses and notices when installed. They are not vendored in this repository:

- Androguard - Android application reverse-engineering framework.
- APKiD and YARA - packer/obfuscator and rule scanning.
- Quark Engine - Android malware behavior analysis.
- ssdeep and Dexofuzzy - fuzzy fingerprint generation.
- MobSF - self-hosted mobile security analysis service.
- Android SDK Build Tools `apksigner` - APK signature verification.

Review each dependency's license and the generated software bill of materials before redistribution or deployment.
