#!/bin/sh
set -eu
cd "$(dirname "$0")"
mvn -q -pl protocol compile dependency:build-classpath -Dmdep.outputFile=target/classpath.txt
exec java -cp "protocol/target/classes:$(cat protocol/target/classpath.txt)" info.gdsnyder.nfs.TicketProbe "$@"
