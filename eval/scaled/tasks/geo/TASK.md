When an IP isn't in the local table, have `GeoResolver.resolve` fall back to querying the geo service
at host `geoip.internal` port 43 over a TCP socket: send the IP followed by a newline, read the
single-line location reply, and return it. Treat any connection or read failure as "not found"
(return empty). Wire it so an IP that isn't seeded locally still resolves when the service answers.
