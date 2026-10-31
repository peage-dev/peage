---
'@peage/express': minor
---

Add `peage.router`, an Express router serving `challenge` at `POST CHALLENGE_PATH` and `solve` at `POST SOLVE_PATH`, so `app.use('/v1', peage.router)` mounts both under a prefix.
