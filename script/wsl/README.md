# Remote server in WSL

On Windows, Warp runs its remote server inside each WSL session's distribution, the way VS Code's
Remote-WSL runs its server in the guest. The Project Explorer, global search and code review then
read files and run git natively in Linux and refresh on file changes, instead of going through
the slow `\\wsl$` share that Windows can't watch for changes.

## How it works

1. When a WSL session finishes bootstrapping, Warp runs
   `wsl.exe --distribution <distro> --exec /bin/sh -c '<binary> --version'` to check for the
   server binary.
2. If the binary is missing, Warp installs it without asking, like VS Code installs its WSL
   server, unless **Settings → Warpify → Install SSH extension** is set to never install. It
   downloads the Linux build on Windows, where the tarball is cached for every distribution,
   and streams it into the distribution; if Windows can't download it, the distribution
   downloads it itself.
3. Warp starts `<binary> remote-server-proxy` through `wsl.exe` and talks to it over stdio. The
   proxy starts a daemon that stays up for 10 minutes after the last connection closes.
4. The shell itself never waits for the server. Until the server connects, or if it can't start,
   the session keeps using the `\\wsl$` path.

## Installing the server for a source build

Builds of this repository (the `oss` channel) have no server artifact of their own. They install
Warp's dev build of the server, or its public stable build when the dev one can't be downloaded,
and accept whatever version they get. That server can lag behind or run ahead of your checkout,
and it isn't updated once installed. For a server built from the same revision as your Windows
build, build and install it from inside the distribution you use with Warp:

```bash
./script/linux/install_build_deps   # once, if the distribution can't build Warp yet
./script/wsl/deploy_remote_server   # --channel local for builds with internal channel config
```

The binary is installed to `~/.warp-dev/remote-server/warp-oss` (`~/.warp-local/remote-server/oz-local`
for the `local` channel), and any daemon still running an old build is stopped. Open a new WSL tab
in Warp to connect.
