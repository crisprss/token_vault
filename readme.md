# Token Vault
Used to be familiar with and understand the related mechanism of Token in Windows

**based on Rust**

Referring to [cs-token-vault](https://github.com/Henkru/cs-token-vault)

# Usage
```
Available Commands:
    Steal and store tokens:             steal <comma separated list of PIDs>
    Use the stored token:               use <token-index>
    Show the stored tokens:             show
    Remove the stored token:            remove <token-index>
    Use the specific token to execute:  cmd
```

# To be solved
when use `cmd` command, it truns out the following message sometimes,need to `cmd` for a few times and then `CreateProcessWithToken` Success, maybe you can pull your answer in issue
![](https://md.buptmerak.cn/uploads/upload_1c90b8c7c6fa195d83db90b5f9c6a77b.png)
