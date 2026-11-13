# Third-party notices

This project is a clean payload extracted from the author's CivSwitchFS
research. It builds on techniques and prior work from the following projects.
No third-party source tree is vendored in this repository.

## CivSwitch

- Project: CivSwitch (Switch 1/2 Civilization VII userland exploit and Remote
  JS Loader)
- Author: Gezine
- License: MIT
- Copyright: Copyright (c) 2026 Gezine

The payload runs inside the CivSwitch Remote JS Loader and relies on the loader
core it initializes (`sdk_base`, `call_rop`, memory helpers, logging, and the
remote JavaScript transport). The core helpers in `src/core/` were written for
this research, but their execution environment and several low-level patterns
come from CivSwitch.

## CivSwitch ns2jb port

- Project: CivSwitch ns2jb → FS-acquisition port (fork of CivSwitch)
- Author: Slapah
- License: MIT
- Copyright: Copyright (c) 2026 Gezine

This project reuses the ns2jb reserved-gap acquisition idea and reference
shape checks documented by that port. The implementation in `src/core/` is an
independent adaptation for this payload; no third-party source tree is
vendored here.

## ns2jb

- Project: ns2jb
- Author: Kurumuz
- License: no license file was present in the reference checkout used during
  the research

Only the documented technique (reserved-gap allocator race) and publicly
described behavior were used. No ns2jb source code is included. If you believe
a specific implementation detail is derived from unlicensed code, open an
issue so it can be reviewed or reimplemented.

## CivSwitch MIT license text

The CivSwitch projects are distributed under the MIT license:

```text
MIT License

Copyright (c) 2026 Gezine

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

The copyright holders above retain their rights; the license in this
repository covers the original code in this repository.
