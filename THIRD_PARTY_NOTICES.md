# Third-party notices

## Pithus Bazaar

Project: Pithus Bazaar  
Source: https://github.com/Pithus/bazaar  
Reference branch: `2026_release`, reviewed on 2026-08-21  
License: GNU Affero General Public License version 3

DeceptiScope 3.0 incorporates and adapts the Pithus multi-engine analysis architecture: APKiD classification, Quark behavior rules, fuzzy fingerprints, MobSF integration, VirusTotal hash reputation and MalwareBazaar hash reputation. The implementation was modified on 2026-08-21 for a FastAPI worker model, bounded execution, normalized deterministic evidence and explicit privacy policy.

The Pithus Django application, Elasticsearch persistence layer, templates and user interface are not embedded. DeceptiScope's adapter implementation is in `fraudshield/deceptiscope/engines.py`; source is included in this distribution. Public sample-upload behavior was deliberately removed. MalwareBazaar and VirusTotal integrations are hash lookup only, disabled by default, and never upload APK bytes.

This combined source distribution is licensed under AGPL-3.0-only. The complete license text is in [LICENSE](LICENSE). Pithus names and trademarks remain the property of their respective owners. No endorsement is implied.

## Analysis tools

Optional tools retain their own licenses and notices when installed. They are not vendored in this ZIP:

- Androguard — Android application reverse-engineering framework.
- APKiD and YARA — packer/obfuscator and rule scanning.
- Quark Engine — Android malware behavior analysis.
- ssdeep and Dexofuzzy — fuzzy fingerprint generation.
- MobSF — self-hosted mobile security analysis service.
- Android SDK Build Tools `apksigner` — APK signature verification.

Review each dependency's license and the generated software bill of materials before redistribution or deployment.
