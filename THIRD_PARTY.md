# Third-party source and dependency provenance

## Vendored NFS4J source

Source artifact: `org.dcache:nfs4j-core:0.28.5:sources`
https://repo.maven.apache.org/maven2/org/dcache/nfs4j-core/0.28.5/nfs4j-core-0.28.5-sources.jar
SHA-256: `7145d7d5ed94404bf6621b24bf41b6298055474ea65097db97bc5bd958273736`

Included: `org.dcache.nfs.v4.xdr` wire types, supporting NFS status/exception types.
Excluded: generated server dispatch stub and desktop server implementation.
Original copyright/license headers are retained. Files use GNU Library/Lesser GPL
terms as specified in their headers; the applicable LGPL texts and GPLv3 are
included under `licenses/`.

Changes made October 2, 2026:
- Replaced Java 17 `HexFormat` references in diagnostic formatting with the small
  Android-safe `info.gdsnyder.nfs.Hex` utility.
- Added bounds (0..65536) to generated variable-array lengths named `$size`.
  This is basic hardening, not a full audit of every generated decoder or linked
  READDIR entry allocations. Further resource-limit review is required before use
  with untrusted servers.

## Vendored ONCRPC4J source

Source artifact: `org.dcache:oncrpc4j-core:3.4.3:sources`
https://repo.maven.apache.org/maven2/org/dcache/oncrpc4j-core/3.4.3/oncrpc4j-core-3.4.3-sources.jar
SHA-256: `289f31434482dff247646912083ecddef17a0f06736eb3a485b363eafaed01a7`

Included unmodified: XDR interfaces (`XdrAble`, `XdrEncodingStream`,
`XdrDecodingStream`), `BadXdrOncRpcException`, `OncRpcException`, `Bytes`,
`InetSocketAddresses`. Original LGPL headers are retained.

The full Grizzly transport and desktop GSS/Unix authentication implementations
are not included. `ByteArrayXdr` is a new stream adapter; `RpcTcp` and `RpcSecGss`
are new transport/message code. This avoids pulling desktop `sun.*` and
`org.ietf.jgss` APIs into the Android application's protocol path.

## External dependencies

- Apache Kerby `kerb-client:2.1.2`: Apache License 2.0.
- Guava `33.4.0-android`: Apache License 2.0.
- Kerby `kerb-simplekdc:2.1.2`: test only, Apache License 2.0.
- JUnit Jupiter `5.11.4`: test only, EPL 2.0.
- Robolectric `android-all:8.1.0-robolectric-4611349`: optional API compilation
  check only; not an APK runtime dependency.

Dependencies are fetched by Maven/Gradle and are not bundled in this archive.
New authored source in `info.gdsnyder.*` and `ByteArrayXdr` is provided under
Apache License 2.0, without changing the licenses of vendored dCache files.
