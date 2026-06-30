# Contributing to ChameleonUltra-COS

Contributions are welcome when they fit the scope and legal boundaries of this third-party fork.

This repository is an unofficial fork of Chameleon Ultra. Do not present contributions, releases, builds, or support responses from this repository as official upstream Chameleon Ultra work.

## Scope

Good contributions include:

- COS emulation fixes and tests.
- CLI support for COS management.
- Documentation that clearly distinguishes this fork from upstream.
- Build, test, and reliability improvements.
- Synthetic fixtures and reproducible tests that do not contain sensitive data.

Out-of-scope contributions include:

- Real production card dumps, protected data, keys, secrets, or personal data.
- Instructions or code intended to bypass payment, fare, identity, access-control, or entitlement systems.
- Requests to emulate third-party credentials without authorization.
- Changes that remove license notices, upstream attribution, safety warnings, or third-party notices.

## Legal and Attribution Requirements

- Keep the GPL-3.0 license intact.
- Preserve upstream copyright and attribution.
- Mark fork-specific behavior clearly in documentation and user-facing text.
- Do not add dependencies or assets with incompatible licenses.
- Do not commit generated firmware packages, private keys, dumps, or local device data unless there is a clear project reason and the data is safe to publish.

## Development Guidelines

- Prefer small, focused commits.
- Avoid force pushes on shared branches.
- Keep changes scoped to the affected layer.
- Do not touch bootloader or hardware-layer code for COS behavior unless the change is explicitly justified and reviewed.
- Include focused tests for APDU parsing, file-system behavior, storage behavior, and CLI protocol changes.
- Run relevant local checks before submitting changes.

Useful checks:

```bash
cc -std=c11 -fshort-enums \
  -DPROJECT_CHAMELEON_ULTRA \
  -DAPP_FW_VER_MAJOR=0 \
  -DAPP_FW_VER_MINOR=0 \
  -Wall -Wextra \
  -Ifirmware/application/tests/cos_host/stubs \
  -Ifirmware/application/src \
  -Ifirmware/application/src/utils \
  -Ifirmware/application/src/rfid \
  -Ifirmware/application/src/rfid/nfctag \
  -Ifirmware/application/src/rfid/nfctag/hf \
  -Ifirmware/common \
  firmware/application/tests/cos_host/cos_host_test.c \
  firmware/application/src/rfid/nfctag/hf/nfc_cos.c \
  firmware/application/src/rfid/crc_utils.c \
  -o /tmp/cos_host_test && /tmp/cos_host_test

make -C firmware/application -j4 APP_FW_VER_MAJOR=0 APP_FW_VER_MINOR=0 GNU_INSTALL_ROOT=/opt/homebrew/bin/
python3 -m py_compile software/script/chameleon_cmd.py software/script/chameleon_cli_unit.py
```

## Reporting Issues

Report issues caused by this fork in this repository. Do not send COS-specific bug reports to upstream maintainers unless the issue is independently reproduced in upstream Chameleon Ultra.

Security-sensitive reports should follow [SECURITY.md](SECURITY.md).
