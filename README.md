# tokeich

**Hate latency ?  Using Exec authentication with your kubernetes clusters ?**

**Save tons of time on your `kubectl` calls with token caching !** ⏱️

#### 😭 Without tokeich, or After running `tokeich off` :

```
> $ hyperfine -w 2 -N -r 30 --prepare 'tokeich off' 'kubectl -n le-namespace get pods'
Benchmark 1: kubectl -n le-namespace get pods
  Time (mean ± σ):      1.841 s ±  0.044 s    [User: 0.354 s, System: 0.195 s]
  Range (min … max):    1.766 s …  1.994 s    30 runs
```

#### 🏎️ With tokeich, After running `tokeich on` :

```
> $ hyperfine -w 2 -N -r 30 --prepare 'tokeich on' 'kubectl -n le-namespace get pods'
Benchmark 1: kubectl -n le-namespace get pods
  Time (mean ± σ):     425.0 ms ±  13.4 ms    [User: 115.9 ms, System: 65.9 ms]
  Range (min … max):   401.2 ms … 456.7 ms    30 runs
```

---

### 📝 Disclaimer

This is a toy project for me to practice -- I have next to zero experience developing in Rust, please be kind :)  
Also, one does not need Rust to accomplish the aim of this project, see [alternatives](#alternatives).

This includes copies of code from [kube-rs](https://github.com/kube-rs/kube),
due to some of the functionality not being exposed as public.

### 🏁 Get Started - Install and Onboard

Assuming you have a Rust toolchain installed (see https://rustup.rs/), simply run:

```bash
cargo install --git https://github.com/hileef/tokeich --tag v0.1.0
```

```bash
tokeich on
```

### ⚙️ Details - It's just a Caching layer

At the time of writing, for kube users authenticating with 
[client-go / the Exec authentication method](https://kubernetes.io/docs/reference/access-authn-authz/authentication/#client-go-credential-plugins), 
**`kubectl` will _NOT_ cache authentication tokens** it gets from calling the underlying program.

For example, say you work with an EKS cluster,
with authentication configuration which might be something along the lines of `aws eks get-token ...`,
then you have to pay for that cost (python init, imports, authentication bootstrap and api calls, etc...)
at every kubectl invocation, even though the returned token is valid for quite some time.

`tokeich` makes it easy to inject a very basic caching mechanism to shave off that time.
You can always revert back to an earlier configuration with `tokeich off`.

### 🔐 On Security

`tokeich` will cache authentication tokens on your filesystem
(exact path depends on the platform, check with `tokeich info`),
this isn't uncommon (ssh keys, aws credentials, etc...)
but might not work for your constraints.

### 🔀 Alternatives

##### can't we make this more lightweight ?!

here is one alternative I found : https://gist.github.com/tyzbit/c9947809cc5146d36ae4ae6c312ce538

##### why not propose a contribution to `kubectl` instead ?

Honestly, because I wanted to have a micro-project to try to develop in Rust :)

It would make more sense (and shave off even more resources) for kubectl to implement this caching directly,
and someone/I might attempt to open such a contribution in the near future.

### 🧑‍🤝‍🧑 Contributions

If you encounter issues, and/or would like to suggest improvements, you're welcome to open PRs and Issues :)
(this goes for features, code style, CI, anything really).

Kindly do note that open-source is not my $dayJob,
so please consider that I might not be able to always respond very fast. 
