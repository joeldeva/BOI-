# FraudShield DeceptiScope frontend

React/Vite analyst interface for the FraudShield DeceptiScope 3.0 APK API.

```bash
npm ci --ignore-scripts --no-audit --no-fund
npm run dev
```

Configuration is in `.env.example`. The production frontend uses same-origin API routing and contains no API, reputation, MobSF or LLM credentials.

Checks:

```bash
npm run test
npm run lint
npm run build
```

The result view intentionally distinguishes risk from legitimacy: no response is presented as a safe-to-install guarantee.
