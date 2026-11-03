---
'@peage/store-redis': minor
---

Key records take about half as much memory in Redis, and are deleted when they expire. Records saved by 0.3 can't be read anymore, so those devices register again; the old records stay in Redis until you delete them.
