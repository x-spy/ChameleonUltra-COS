# ChameleonUltra-COS

ChameleonUltra-COS is an unofficial, third-party fork of the Chameleon Ultra firmware and CLI. It keeps the original Chameleon Ultra project history and GPL-3.0 licensing, while adding an experimental COS-style ISO14443-A CPU card emulation layer.

[中文说明](README.zh-CN.md)

This repository is not the official Chameleon Ultra project and is not affiliated with, endorsed by, sponsored by, or supported by RfidResearchGroup, Proxgrind, official distributors, payment networks, transit operators, access-control vendors, or any card issuer.

## What This Fork Adds

The COS extension is intended for authorized research, interoperability testing, and development on hardware you own or are allowed to test.

Implemented additions include:

- COS emulation as a mutually exclusive HF14A mode alongside the original EMV/HF14A-4 behavior.
- Per-slot COS storage with isolated MF/DF/EF file trees.
- Binary EF and linear fixed record EF support.
- APDU selection, `READ BINARY`, `UPDATE BINARY`, `READ RECORD`, `UPDATE RECORD`, and configurable `APPEND RECORD` behavior.
- Simple `GET CHALLENGE` support and placeholder authentication response behavior.
- Custom UID/ATQA/SAK/ATS handling coupled to COS slot data.
- CLI commands for COS configuration, file creation, file listing, file read/write, record management, storage inspection, and direct APDU testing.

## Important Use Restrictions

Use this project only with cards, readers, systems, and data that you own or are explicitly authorized to test.

Do not use this project to:

- Bypass fare, payment, access-control, identity, attendance, loyalty, or entitlement systems.
- Emulate third-party credentials without permission.
- Store, share, or distribute real production card dumps, keys, secrets, or personal data.
- Circumvent technical protection measures or violate local law, contracts, terms of service, or radio regulations.

This repository does not provide keys, protected card data, commercial card dumps, or instructions for unauthorized access.

## Relationship to Upstream

This fork is based on the original Chameleon Ultra project:

- Upstream project: https://github.com/RfidResearchGroup/ChameleonUltra
- Upstream documentation: https://github.com/RfidResearchGroup/ChameleonUltra/wiki
- Upstream documentation repository: https://github.com/RfidResearchGroup/ChameleonUltraDocs

For official hardware support, official documentation, official releases, distributors, and upstream community channels, refer to the upstream project. Issues caused by this fork should be reported here, not to upstream maintainers.

## License

This project is distributed under the GNU General Public License version 3. See [LICENSE](LICENSE).

The original Chameleon Ultra codebase and this fork's modifications remain under the same GPL-3.0 terms unless a file states otherwise. Copyright for individual contributions is tracked by Git history.

Additional notices are in [NOTICE.md](NOTICE.md).

## Warranty and Risk

This software is provided without warranty of any kind. Flashing unofficial firmware can make a device temporarily unusable, require recovery procedures, or cause data loss. You are responsible for backing up device data and understanding the recovery path before flashing.

The COS implementation is experimental. It is designed for development and interoperability testing, not for production security, payment, ticketing, identity, or access-control use.

See [DISCLAIMER.md](DISCLAIMER.md) for the full project disclaimer.

## Security

If you find a vulnerability in this fork, follow [SECURITY.md](SECURITY.md). Do not publicly disclose exploitable details before the maintainers have had a reasonable opportunity to respond.

## Repository Layout

- `firmware/` - Chameleon Ultra firmware, including COS emulation changes.
- `software/` - CLI and supporting scripts.
- `docs/` - Local documentation entry points and images retained from upstream.
- `resource/` - Build, DFU, and support resources.
- `hardware/` - Hardware reference files retained from upstream.

## Building and Flashing

This fork follows the upstream build and DFU flow. Read upstream documentation first, then review this fork's COS-specific commits and CLI commands before flashing.

Typical application firmware build commands used during development:

```bash
make -C firmware/application -j4 APP_FW_VER_MAJOR=0 APP_FW_VER_MINOR=0 GNU_INSTALL_ROOT=/opt/homebrew/bin/
cd firmware/objects
nrfutil nrf5sdk-tools pkg generate \
  --hw-version 0 \
  --key-file ../../resource/dfu_key/chameleon.pem \
  --application application.hex \
  --application-version 1 \
  --sd-req 0x0100 \
  ultra-dfu-app.zip
```

Do not flash bootloader or hardware-layer changes unless you know exactly what you are doing. This fork's COS work is intended to stay in the application and business-logic layers.

## Contributing

Contributions should preserve GPL-3.0 compatibility, keep upstream attribution intact, and avoid committing real card data, secrets, keys, or other sensitive material.

See [CONTRIBUTING.md](CONTRIBUTING.md).
