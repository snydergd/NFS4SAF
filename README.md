# NFS4SAF SAF provider — writable development checkpoint

A pure-Java Android management activity and Storage Access Framework provider
for Kerberos-authenticated NFSv4.1/4.2 exports. No JNI, NDK, root requirement or
server-side gateway. This checkpoint implements directory browsing and regular
file reads; it needs interoperability testing against your actual NFS server.

## Vibe-Code Warning
Take with a grain of salt.  I did not originally intend to publish this project.  I wanted to use NFS from android and couldn't find an option I liked, so I decided to see what AI could do.  It still took a day to be usable, but it served my needs.  If you are in a similar situation of wanting a hacked-together solution, perhaps this could save you the time of walking AI through creation of the project.

I am hoping to clean it up and fully review all aspects of it, but for now I wanted to publish.

## Build, install and use

Use JDK 17, Gradle 8.9 and Android SDK platform 35. Open this project in Android
Studio or run:

```sh
gradle :app:assembleDebug
adb install -r app/build/outputs/apk/debug/app-debug.apk
```

Minimum Android version: 8.0 (API 26). A Gradle wrapper is not included. Preserve
your own `local.properties`, Gradle wrapper, and local SDK configuration when
updating from the previous checkpoint.

1. Add or edit an export in **NFS4SAF**. Configure the NFS hostname/port,
   NFSv4 pseudofilesystem path, realm, KDC/TCP port, user principal and explicit
   service principal, such as `nfs/files.example.com@EXAMPLE.COM`.
2. Keep `krb5p` selected for confidentiality. Enable **Show export in SAF**.
3. Enter your password and choose **Sign in and test NFS**. Success means a
   service ticket was acquired, the NFS service authenticated, and the export
   root directory was read. A ticket alone is no longer reported as NFS success.
4. Open the Android file picker, select the export in its side navigation,
   browse folders, and select a regular file. Other apps can access it through
   `ACTION_OPEN_DOCUMENT` or an `ACTION_OPEN_DOCUMENT_TREE` grant.

Configurations persist. Tickets remain in memory; optionally saved encrypted
passwords allow ticket reacquisition after process death, reboot, or expiry.
Without a saved password, sign in again. Saving an export clears its ticket;
sign-out and configuration changes revoke its active NFS connections. Disabling
an export removes SAF access. Existing file descriptors can fail after sign-out.

## Implemented

- Kerby 2.1.2 TCP-only TGT/service-ticket acquisition with explicit per-client
  configuration and a corrected 15-second socket timeout.
- A wire-oriented RFC 4121 Kerberos GSS initiator using Kerby's ASN.1 and crypto:
  mutual AP-REQ/AP-REP authentication, acceptor subkeys, MICs, privacy wraps,
  direction checks, tamper/replay rejection and service-ticket expiry checks.
- AES128/AES256 CTS-HMAC-SHA1-96. Other enctypes fail explicitly.
- RPCSEC_GSS context initialization, sequence-window verification, protected
  request headers and authenticated responses. Explicit `krb5p`, `krb5i`, and
  `krb5` modes; no automatic fallback to AUTH_SYS or a weaker mode.
- NFSv4.2 negotiation with 4.1 fallback on MINOR_VERS_MISMATCH; EXCHANGE_ID,
  CREATE_SESSION, RECLAIM_COMPLETE, single-slot SEQUENCE validation, export path
  lookup, GETATTR, paged READDIR, OPEN, READ, CLOSE, delegation return and lease
  renewal while a file is open. Reads use chunks up to 512 KiB, bounded by server maxread and session limits.
- SAF roots, metadata, directory listings and random-access proxy
  descriptors. Directories and regular files are exposed; symlinks and special
  files are omitted. Writable exports advertise create, write, rename and delete actions.
- Generated NFS4J XDR operations, ONCRPC4J XDR interfaces, and an Android-safe
  byte-array adapter. See `THIRD_PARTY.md` and `licenses/` for source provenance.
- Bounded RPC records, socket timeouts, directory pagination limits, cancellation
  of file reads and a maximum of 32 tracked NFS connections.

## Validation

```sh
mvn test
mvn -Pandroid-api-check test
mvn -DargLine=-Dsun.security.krb5.acceptor.subkey=true test
```

Validation completed for this checkpoint: **44 JVM tests passed** with
the default JDK acceptor. The Android API
source compilation check passed.
No APK was built in this environment.

The JVM suite includes a local Kerby KDC and an independent JDK Kerberos GSS
acceptor. It checks mutual authentication, bidirectional MIC/privacy tokens,
tampering, replay, rotated tokens, XDR/record limits and RPC framing. A socket
fixture exercises protected NFS compounds, directory pagination, session
negotiation, sequence validation, lease renewal, random reads, wrong-security rejection and CLOSE with all three security flavors.

The optional Android profile compiles application Java against API 27. It is a
source/API check, not an APK/dex build or a device runtime test. JDK GSS/JAAS APIs
are used only in JVM tests; they are not included in the Android protocol path.

This checkpoint has not been tested against Linux NFS, a MIT KDC, or Android's
live proxy-descriptor/file-picker path. The socket fixture tests our operation
flow, not full NFS server conformance. Test with a small export before relying
on it for daily access.

## Current limits

- NFSv4.1/4.2 file operations using one serialized session slot. No 4.0
  fallback or optional 4.2 features (COPY, SEEK, sparse reads, pNFS).
- No byte-range locking, recursive deletion, cross-directory moves or callback server.
- No in-flight GSS refresh, reconnect, NFS server-reboot recovery, or state
  reclaim. Reopen/sign in after a network, lease, ticket or server failure.
- Document IDs contain export-relative paths. Remote renames can invalidate
  persisted document grants; symlinks are not followed.
- Listings collect up to 50,000 entries and 4,096 pages. RPC records are limited
  to 4 MiB. One TCP/GSS connection is used per query or open descriptor.
- The management activity performs a ticket acquisition and root listing on
  sign-in. Opening a file can still fail because of server permissions/state.
- Opt-in passwords are encrypted with Android Keystore. Kerby's password API
  requires a temporary immutable `String`; Java cannot
  reliably erase that copy. Caller character buffers and held session keys are
  cleared when practical.

## Troubleshooting on your server/device

The path is relative to the NFSv4 pseudofilesystem, not necessarily the server's
local filesystem path. Confirm the server supports NFSv4.1 or 4.2 and the selected
`sec=` flavor, the explicit service principal matches its keytab, device/server
clocks agree, and the device can reach the configured KDC and NFS TCP ports.
Errors retain NFS status names where supplied by the server. An
`NFS4ERR_WRONGSEC` response is not retried with weaker authentication.

If the emulator cannot reach the KDC while a physical device can, check emulator
routing and DNS separately. The KDC probe uses TCP; no UDP fallback is enabled.

For a standalone KDC-only probe:

```sh
./ticket-probe.sh EXAMPLE.COM kdc.example.com 88 \
  george@EXAMPLE.COM nfs/files.example.com@EXAMPLE.COM
```

It prompts for a password in the terminal. Do not put passwords on command lines.

## Layout

- `protocol/`: Android-independent Java protocol/client code and JVM tests.
- `app/`: Java management activity, export store, ticket vault and SAF provider.
- `THIRD_PARTY.md` and `licenses/`: redistributed source provenance/licenses.

## Session update validation

Socket fixtures exercise 4.2 and 4.1-only negotiation with an independent JDK
GSS acceptor. Live Linux NFS interoperability and Android SAF behavior still
require device testing. Rebuild, install, and sign in again to establish a new
session. Transport failures close the connection; uncertain calls are not replayed.

## Read throughput update

RPC sockets use TCP_NODELAY and buffered record writes/reads. Each open SAF
descriptor has a 512 KiB read-ahead cache; small reads are served from it, while
seeks refill it. NFS reads respect both maxread and negotiated response limits.
Short NFS responses are filled to satisfy SAF requests; unexpected early EOF
is reported as an error. Cached data is cleared on release. Concurrent remote
file changes are not refreshed within a cached block; reopen for fresh data.

After rebuilding and reinstalling, sign in again and repeat the same local copy.
Capture aggregate diagnostics with `adb logcat -s NFS4SAFPerf:D`. Logs show
SAF read calls/bytes, cache hits, NFS READ calls/bytes, and cumulative NFS read
time every five seconds of callbacks and on release. They contain no credentials,
paths, or file contents. Actual throughput improvement requires device measurement.

## Writable SAF update

Exports default to Read only. Edit the export, turn off Read only, save, and
sign in again. The server export and Kerberos user's filesystem permissions
must also permit writes. SAF supports creating regular files and directories,
random writes, truncating opens (w/wt/rwt), append (wa), read-write (rw), fsync,
rename within a directory, and deleting files or empty directories. File creation
uses guarded OPEN to avoid overwriting existing files. New files use mode 0600
and directories 0700. Rename rejects destinations observed in a directory
listing; a concurrent remote creation can still race the NFS RENAME operation.
Append uses the size observed by this descriptor and is not atomic against
other writers. Reopen descriptors after remote changes.

WRITE requests FILE_SYNC and handles short writes. If the server returns
UNSTABLE/DATA_SYNC, each acknowledged range is committed and its write verifier
checked before success is reported. Transport or durability failures are reported
as errors and are not automatically replayed. A failed multi-chunk write may
have already changed part of the file; this is not an atomic file replacement.

Validation includes short writes, stable/unstable replies, changed-verifier
rejection, truncate, guarded file creation, folder creation, rename, remove and
read-only open rejection in encrypted socket fixtures. Android sources compile.
Live Linux write interoperability and device SAF UI behavior remain unverified.
Test with disposable files first: create a folder, copy a file into it, read it
back and compare a checksum, rename it, and delete the file and empty folder.

## Buffered writes

Each writable descriptor coalesces sequential SAF writes into 512 KiB blocks.
Full buffers, nonsequential writes, reads, fsync and release flush pending bytes
using the durable NFS write path. Writes returned by onWrite may still be buffered
in app memory; call fsync for reported durable completion. A process/device crash
before flushing can lose the pending tail.

Android ProxyFileDescriptorCallback.onRelease cannot report errors to the copying
app. A release flush failure is logged under NFS4SAF, and pending bytes are
retained under the app-private files/failed-writes directory. The management
activity shows a warning on its next refresh. These files are not automatically
replayed or cleared on sign-out. Recovery data is sensitive file content; do not
share it publicly. A .txt companion identifies export, path and failure; each
.bin contains big-endian magic 0x4e465357, offset (int64), byte count (int32), then
the retained bytes. Some bytes may already have reached the server: inspect the
remote file before any manual recovery. For a debug build, extract with adb
exec-out run-as info.gdsnyder.nfs.android tar -C files -cf - failed-writes.

Performance logs include safWrites, safWriteBytes, writeFlushes, pendingWriteBytes.
The speed improvement still requires device measurement. New tests cover small
write coalescing, final tail flush, seeks, partial writes, sticky flush failures
and retention of pending data.

## Concurrent access, ticket refresh and saved passwords

Enable Save password encrypted on this device in the export editor and sign in
successfully to store a password. AES-256-GCM uses a key generated in Android
Keystore, with fresh IVs and authentication-settings binding. App backup is
disabled. Keys are not guaranteed hardware-backed on every device. Automatic
access means the key does not require biometric confirmation per use. Passwords
are never included in export JSON, archives or performance logs.

New connections reuse a valid service ticket; when expired or absent after app
restart, they acquire a fresh TGT/service ticket using the saved password. This
is password-based reacquisition, not renewal of a renewable TGT. Concurrent
refresh requests share one acquisition. Sign-out fences an ongoing refresh and
also removes the saved password. Forget saved password removes it while keeping
the current ticket. Changed authentication settings invalidate saved credentials.
No password is stored by default. Existing GSS connections retain their original
ticket lifetime and must be reopened after expiry. Network/credential errors are
reported rather than replaying writes.

Concurrent encrypted socket tests cover independent files, disjoint ranges of
a shared file, overlapping writes with mixed results permitted, coordinated
truncation and an aborted concurrent reader. Credential tests cover single-flight
refresh, sign-out during acquisition, invalid tickets and refresh failure. These
are socket fixtures, not Linux or Android multi-app interoperability tests.
Read caches may remain stale across descriptors; append is not atomic, and
overlapping writes have no transaction or whole-write atomicity guarantee.

Android Keystore device tests are included under app/src/androidTest. Run
`gradle :app:connectedDebugAndroidTest` with a device/emulator to check encryption
round-trip, randomized ciphertext, principal binding, tamper rejection and
removal. They were not run in this environment. Test automatic reacquisition
by restarting the app and opening an export with saved credentials, then test
expiry with a short-lived test principal. Live KDC refresh on Android remains
to be verified on your device.

## Playback diagnostics and launcher icon

The supplied Cerberus shield/key image is used for density-specific launcher
icons and a padded adaptive icon. Original supplied artwork is retained visually.
Android resource XML was checked separately; no APK/resource build is available
in this environment.

Capture playback diagnostics from before opening the video until it stops:

```sh
adb logcat -v threadtime NFS4SAFTrace:D NFS4SAFPerf:D NFS4SAF:E '*:S' > playback.log
```

Each open descriptor has a short correlation ID. Trace events include open
start/connection/ready, file size, read offset/requested/returned bytes and duration,
RPC operation numbers/duration, lease duration/renewal, cancellation, release and
full read-error exception stacks. No passwords, ticket bytes, or file contents
are logged. Traces are verbose and expose offsets, sizes and timing; use them
for diagnosis rather than throughput benchmarking.

The diagnostics-only checkpoint did not resolve playback. Subsequent full logs
identified Android destroying the provider UID's socket; see the optional
connection protection below.


## Optional connection protection for media players (0.4.0)

Device logs on Android 17/API 37 show the provider connection disappearing during
VLC playback, followed by Android explicitly destroying the provider UID's TCP
socket. The process was not frozen at that failure. Current VLC source converts
the ParcelFileDescriptor to an fd:// URL without retaining that wrapper in the
conversion function; mpvEx's descriptor fallback explicitly calls detachFd().
These are source observations, not proof of the exact installed player versions.
CIFS Documents Provider also offers an optional foreground worker for open files.

To test the workaround:

1. Install this build, open NFS4SAF, and sign in if necessary.
2. Tap **Enable connection protection**. Allow notifications to see its status.
3. Open the video through SAF within two minutes, then play it full screen.
4. Close the video when finished. Protection stops five seconds after the last
   descriptor releases, or after two minutes if no descriptor opens.

Protection must be enabled before opening the file; it does not reconnect a
failed descriptor. It is started from the visible management activity to comply
with foreground-service start restrictions, never silently from the provider.
Normal browsing/file access does not start a foreground service. Notification
permission denial does not prevent the service from running, although Android
may only show it in the active-apps interface. **Stop connection protection**
ends protection without closing descriptors and may expose playback to the same
background socket destruction. Protection is not automatically restored after
process death or reboot.

The service uses dataSync and follows Android's six-hour background budget and
onTimeout callback. A timeout ends protection and is logged; it does not replay
writes. All open descriptors (including concurrent readers/writers and opening
requests) are counted; failed opens and releases relinquish their count.
Generation checks prevent stale delayed shutdowns from stopping protection
while a new file is already open. JVM tests cover concurrent/idempotent releases
and stale idle generations. Android source compilation is checked, but the
foreground service, notification, permissions and Android 17 playback still
require device verification. No automatic NFS reconnect is added in this build;
reopening by pathname alone could resume against a replaced file.

Source references examined:
- https://github.com/videolan/vlc-android (FileUtils.kt, getFileDescriptorFromUri)
- https://github.com/marlboro-advance/mpvEx (PlayerUtils.kt, tryFileDescriptorFallback)
- https://github.com/wa2c/cifs-documents-provider (ProviderWorker.kt)
- https://developer.android.com/develop/background-work/services/fgs/timeout


## Background access setup (0.5.0)

The management screen shows whether battery optimization is exempted and offers
**Allow reliable background file access**. A one-time, dismissible explanation
appears after an export is configured. The button opens Android's app-specific
battery exemption request; settings-list and app-info fallbacks handle devices
without that action. Status refreshes on return. Approval remains the user's
choice. An exemption does not enable the optional connection protection service.

No idle connection pool is maintained. Metadata, browsing and mutation requests
close their clients in finally blocks; descriptor release flushes writes before
closing its client. Lease renewal is stopped before graceful connection close.
The next SAF request establishes a fresh authenticated NFS session, reusing a
valid ticket (or acquiring one with a saved password). Root queries need no
network. An open descriptor counts as in use even between callbacks; closing it
on a timer would disrupt paused playback or pending writes. JVM socket tests now
also assert the server sees EOF after explicit close and subsequent reads fail.
The battery prompt and settings navigation still need Android device validation.


## Automatic protection (0.6.0)

**Automatically protect open files** is enabled by default and configurable on
the management screen. Each openDocument request acquires a descriptor lease and
requests the dataSync foreground service before connecting to NFS. Successful
opens retain protection until release; failed opens relinquish their lease too.
Automatic starts with no remaining files stop after five seconds, including
fast thumbnail probes and failed opens. Concurrent descriptors share the service.
Browsing/metadata queries do not start it. Open-file accounting and stale delayed
shutdown fencing use the existing tested OpenFiles tracker.

This supersedes 0.4.0's requirement to manually enable protection before access.
The manual start button remains a fallback and retains its two-minute window if
no file opens. Stop current protection stops the running service; the next file
open starts it again unless automatic protection is disabled. Disabling the
checkbox stops the service but does not terminate open file connections.

Android may reject a background foreground-service start. A battery optimization
exemption is an official exemption from that restriction and should be enabled
using the setup button. Rejection is logged as connection.service.auto.rejected;
file access proceeds so clients that retain their provider reference can still
work. There is no unsafe background retry loop. Notification permission is
optional for service operation; the manual-start button requests it to make the
notification visible. The service still observes Android's six-hour background
budget and stops on onTimeout. It does not guarantee that this new, later VLC
freeze is fixed; a fresh log is needed if playback still freezes with protection
active. No automatic reconnect or write replay is introduced.


## Management screen layout (0.7.0)

The activity explicitly uses dark status/navigation icons over a white background
and pads the outer scroll view with system window insets. This handles Android
15+ enforced edge-to-edge layout, cutouts and navigation bars without placing
text underneath them; each page replacement installs the same inset handler.
Export buttons, Add export and the file picker appear before background-access
controls. Manual protection start/stop buttons are removed from the screen;
automatic protection remains configurable with its checkbox. Battery settings
and exemption status remain below it. Notification permission can be requested
when the checkbox is enabled. This supersedes the earlier manual-button flow.
The Java source check does not validate visual layout on an Android device.


## NFS4SAF branding (0.8.0)

App labels, management text, diagnostic tags, project name and Maven parent
artifact use NFS4SAF. Logcat filters are NFS4SAFTrace, NFS4SAFPerf and NFS4SAF.
The application ID, document authority, Java package names and legacy Keystore
alias stay stable to preserve upgrades, SAF grants and encrypted credentials.
Kerberos remains the protocol name in technical documentation.


## Licensing

See the top-level LICENSE for the scope of Apache-2.0 original code and the
vendored LGPL components, NOTICE for attribution, and THIRD_PARTY.md for source
provenance. This is a mixed-license repository. Some generated upstream files
have provenance-only headers; confirm their precise upstream LGPL version
before assigning a release-wide SPDX expression.
