# privatale-cli

Open-source Linux command-line client for [Privatale](https://github.com/NC-Software-Engineering/privatale), together with the shared core that all Privatale clients build on: end-to-end encryption, sync, conflict resolution and file operations.

The goal of this repository is auditability: the code that encrypts and decrypts your journal is public, so anyone can review it. The web, Android, iOS and future desktop apps use this same core.

> Status: early development. Linux is the first supported platform.

## License

Copyright (C) 2026 NC Software Engineering

This project is licensed under the **GNU Affero General Public License v3.0 only** (AGPL-3.0-only). See [LICENSE](LICENSE) for the full text, also available at <https://www.gnu.org/licenses/agpl-3.0.html>.

Every source file starts with this header:

```
// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 NC Software Engineering
//
// This file is part of privatale-cli.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.
```
