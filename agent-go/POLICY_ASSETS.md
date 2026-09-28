# Go agent policy assets

`PUSH_LOCAL_POLICY` may require Microsoft's `LGPO.exe` and the reviewed
`.pol` files named by `policy.go`. Keep those files beside the deployed agent
under its `policy` directory. Never accept policy binaries from a job payload.

The AppLocker Warden rule is useful only after `warden-agent.exe` is
Authenticode signed. Author it at publisher-name granularity so normal
certificate renewal under the same organization does not strand endpoints.
Changing publisher identity still requires a staged policy migration.
