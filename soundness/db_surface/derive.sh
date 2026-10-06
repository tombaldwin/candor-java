#!/usr/bin/env bash
# SOUNDNESS R920 — regenerate src/main/java/io/poly/candor/DbClientSurface.java from the client jars' bytecode.
#
#   bash soundness/db_surface/derive.sh build/libs/candor-java-<ver>-all.jar
#
# Per client: unpack the jar, run DbReach (a CHA call graph over the jar; for every public member of every
# public API type, does some implementation reach the client's WIRE CHOKE POINT, named below), then gen.py
# (the handle types: reachable from the ENTRY types through member return types and in-family supertypes, with
# at least one wire member; on each, the members measured local) and emit.py (the Java table).
# An interface call with no implementer in the jar, and a reflective invoke, count as reaching the wire, so the
# derived PURE set cannot inherit the instrument's blind spots. Read the generated diff before committing it:
# a new pure name is a narrowing.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"; ROOT="$(cd "$HERE/../.." && pwd)"; LIB="${CANDOR_SOUNDNESS_LIB:-$ROOT/soundness/lib}"   # populated by soundness/run.sh
JAR="${1:?usage: derive.sh <candor-java-all.jar>}"
J="${JAVA_HOME:-/opt/homebrew/opt/openjdk@21}/bin"
WORK="$(mktemp -d)"; trap 'rm -rf "$WORK"' EXIT
"$J/javac" -nowarn -cp "$JAR" -d "$WORK/tool" "$HERE/DbReach.java"
fam() {   # name jar sinks apiPrefix
  mkdir -p "$WORK/$1/cls"; (cd "$WORK/$1/cls" && unzip -q -o "$LIB/$2" -x 'META-INF/*')
  (cd "$WORK/$1" && "$J/java" -cp "$WORK/tool:$JAR" io.poly.candor.DbReach cls "$3" "$4" > reach.tsv 2> super.tsv)
}
for j in mongodb-driver-sync-5.1.1.jar mongodb-driver-core-5.1.1.jar bson-5.1.1.jar; do
  mkdir -p "$WORK/mongo/cls"; (cd "$WORK/mongo/cls" && unzip -q -o "$LIB/$j" -x 'META-INF/*'); done
(cd "$WORK/mongo" && "$J/java" -cp "$WORK/tool:$JAR" io.poly.candor.DbReach cls \
  'com/mongodb/client/internal/OperationExecutor.execute,com/mongodb/client/internal/MongoClientDelegate$DelegateOperationExecutor.execute' \
  com/mongodb/client/ > reach.tsv 2> super.tsv)
RS=""; for o in CommandAsyncExecutor CommandAsyncService CommandBatchService CommandReactiveExecutor CommandRxExecutor; do
  for n in async evalReadAsync evalReadBatchedAsync evalWriteAsync evalWriteBatchedAsync evalWriteNoRetryAsync executeAllAsync \
           pollFromAnyAsync readAllAsync readAsync readBatchedAsync readRandomAsync writeAllAsync writeAllVoidAsync writeAsync \
           writeBatchedAsync syncedEval syncedEvalWithRetry; do RS="$RS,org/redisson/command/$o.$n"; done; done
fam redisson redisson-3.31.0.jar "${RS#,}" org/redisson/api/
fam jedis jedis-5.1.3.jar 'redis/clients/jedis/Protocol.sendCommand,redis/clients/jedis/Protocol.read,redis/clients/jedis/util/RedisOutputStream.flush,redis/clients/jedis/util/RedisInputStream.read' redis/clients/jedis/
fam sdr spring-data-redis-3.3.1.jar 'io/lettuce/core/,redis/clients/jedis/' org/springframework/data/redis/
cd "$WORK"
python3 "$HERE/gen.py" mongo/reach.tsv com/mongodb/client/ com/mongodb/client/MongoClient,com/mongodb/client/gridfs/GridFSBucket,com/mongodb/client/vault/ClientEncryption > mongo/handles.tsv
python3 "$HERE/gen.py" redisson/reach.tsv org/redisson/api/ org/redisson/api/RedissonClient,org/redisson/api/RedissonReactiveClient,org/redisson/api/RedissonRxClient > redisson/handles.tsv
python3 "$HERE/gen.py" jedis/reach.tsv redis/clients/jedis/ redis/clients/jedis/Jedis,redis/clients/jedis/JedisPooled,redis/clients/jedis/UnifiedJedis,redis/clients/jedis/JedisCluster,redis/clients/jedis/JedisSharding,redis/clients/jedis/JedisSentineled,redis/clients/jedis/JedisPool,redis/clients/jedis/JedisSentinelPool > jedis/handles.tsv
python3 "$HERE/gen.py" sdr/reach.tsv org/springframework/data/redis/connection/ org/springframework/data/redis/connection/RedisConnection,org/springframework/data/redis/connection/StringRedisConnection,org/springframework/data/redis/connection/RedisClusterConnection,org/springframework/data/redis/connection/ReactiveRedisConnection,org/springframework/data/redis/connection/ReactiveRedisClusterConnection,org/springframework/data/redis/connection/RedisConnectionFactory > sdr/handles.tsv
python3 "$HERE/emit.py" > "$ROOT/src/main/java/io/poly/candor/DbClientSurface.java"
echo "derive: wrote src/main/java/io/poly/candor/DbClientSurface.java — read its diff before committing"
