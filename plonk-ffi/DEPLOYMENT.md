# Deploying `plonk_ffi` into VerifiedX-Core

The workflow **“Build Native Libraries (plonk_ffi)”** (manual `workflow_dispatch`) builds **Windows, Linux, and macOS** in parallel. Download the three artifacts and copy into VerifiedX-Core.

| Platform | GitHub artifact | VerifiedX-Core path |
|----------|-----------------|---------------------|
| **Windows** | `plonk_ffi-windows` → `plonk_ffi.dll` | `ReserveBlockCore/Plonk/win/plonk_ffi.dll` |
| **Linux** | `libplonk_ffi-linux` → `libplonk_ffi.so` | `ReserveBlockCore/Plonk/linux/libplonk_ffi.so` |
| **macOS** | `libplonk_ffi-macos` → `libplonk_ffi.dylib` | `ReserveBlockCore/Plonk/mac/libplonk_ffi.dylib` |

## Steps

1. Push this `plonk` repo to GitHub (or your fork).
2. **Actions** → **Build Native Libraries (plonk_ffi)** → **Run workflow**.
3. When all three jobs finish, download each artifact and place the file as in the table above.

The `.csproj` uses `Condition="Exists(...)"` for optional linux/mac (same idea as FROST).

## Optional: build Windows locally

If you prefer not to use the artifact:

```powershell
cd <plonk-repo-root>
rustup run 1.83.0 cargo build -p plonk_ffi --release
Copy-Item target\release\plonk_ffi.dll <path-to-VX-Core>\ReserveBlockCore\Plonk\win\
```

## Reference: FROST equivalent

FROST’s `build-native-libs.yml` only builds macOS/Linux; **plonk** also runs **`windows-latest`** so you get a signed MSVC-built DLL from GitHub. `plonk_ffi` is a **workspace member**, so CI uses `cargo build -p plonk_ffi --release` from the repo root (FROST uses `working-directory: frost-ffi`).
