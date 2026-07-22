#!/bin/sh
# JVM arguments (e.g. truststore flags) come from JAVA_OPTS; any Spring Boot
# properties passed after the image name on `docker run` are forwarded via "$@".
# The container runs with --network=host so `localhost` resolves to the host
# (Docker Desktop "Enable host networking" setting, or natively on Linux CI),
# letting the RP reach the CAS instances at https://localhost:8443/8444.
exec java $JAVA_OPTS -jar /app/app.jar "$@"
