On a cache miss, have `CatalogRepository.find` fall back to loading the product from disk at
`/var/cache/<id>` (the file holds one line `name,priceCents`; treat a missing or unreadable file as
"not found" and return empty). Wire it so an id that isn't in the in-memory store is still resolved
when a backing file exists.
