Beta 2 adds better logs for sign-in failures and **Playing Offline** reports, and keeps Beta 1’s Wine crash fix.

- Logs now show which service failed, its HTTP status and a recognized error identifier when available.
- Fixes a startup crash found in the local diagnostic build when recording was enabled.
- Reports missing observations instead of treating successful token creation as a successful server login. Credentials and raw response bodies are excluded.

Download **MCD2-Crossover-0.2.0-beta.2-arm64.dmg**, drag the app into **Applications**, then quit the game and run **Set Up** once for your existing bottle. Your saved Microsoft sign-in is kept. For a useful report, choose **Start Recording**, reproduce the problem, then **Save Logs**.

**Still a beta:** this is not a confirmed fix for error 0056 or offline play. The corrected recording-on path passes automated tests but has not yet been tested inside the game. Check for Updates will not offer this release. Apple Silicon only.
