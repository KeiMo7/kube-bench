## Commands 
Command | Description
--- | ---
help | Prints help about any command
run | List of components to run 
version | Print kube-bench version

## Flags
Flag | Description
--- | ---
--alsologtostderr | log to standard error as well as files
--asff | Send findings to AWS Security Hub for any benchmark tests that fail or that generate a warning. See [this page][kube-bench-aws-security-hub] for more information on how to enable the kube-bench integration with AWS Security Hub.
--benchmark | Manually specify CIS benchmark version 
-c, --check | A comma-delimited list of checks to run as specified in Benchmark document.
--config | config file (default is ./cfg/config.yaml)
--exit-code | Specify the exit code for when checks fail
--group | Run all the checks under this comma-delimited list of groups.
--include-test-output | Prints the actual result when test fails.
--json | Prints the results as JSON
--junit | Prints the results as JUnit
--log_backtrace_at traceLocation | when logging hits line file:N, emit a stack trace (default :0)
--logtostderr | log to standard error instead of files
--noremediations | Disable printing of remediations section to stdout.
--noresults | Disable printing of results section to stdout.
--nototals | Disable calculating and printing of totals for failed, passed, ... checks across all sections 
--outputfile | Writes the results to output file when run with --json or --junit
--pgsql | Save the results to PostgreSQL
--scored | Run the scored CIS checks (default true)
--skip string | List of comma separated values of checks to be skipped
--stderrthreshold severity | logs at or above this threshold go to stderr (default 2)
-v, --v Level | log level for V logs (default 0)
--unscored | Run the unscored CIS checks (default true)
--version string | Manually specify Kubernetes version, automatically detected if unset
--vmodule moduleSpec | comma-separated list of pattern=N settings for file-filtered logging

### Examples 

#### Report kube-bench findings to AWS Security Hub

You can configure kube-bench with the `--asff` option to send findings to AWS Security Hub for any benchmark tests that fail or that generate a warning. See [this page](asff.md) for more information on how to enable the kube-bench integration with AWS Security Hub.

#### Specifying the benchmark or Kubernetes version

`kube-bench` uses the Kubernetes API, or access to the `kubectl` or `kubelet` executables to try to determine the Kubernetes version, and hence which benchmark to run. If you wish to override this, or if none of these methods are available, you can specify either the Kubernetes version or CIS Benchmark as a command line parameter.  

You can specify a particular version of Kubernetes by setting the `--version` flag or with the `KUBE_BENCH_VERSION` environment variable. The value of `--version` takes precedence over the value of `KUBE_BENCH_VERSION`.

For example, run kube-bench using the tests for Kubernetes version 1.13:

```
kube-bench --version 1.13
```


You can specify `--benchmark` to run a specific CIS Benchmark version:

```
kube-bench --benchmark cis-1.5
```

**Note:**  It is an error to specify both `--version` and `--benchmark` flags together

#### Specifying Benchmark sections

If you want to run specific CIS Benchmark sections (i.e master, node, etcd, etc...)
you can use the `run --targets` subcommand.

```
kube-bench run --targets master,node
```

or

```
kube-bench run --targets master,node,etcd,policies
```


If no targets are specified, `kube-bench` will determine the appropriate targets based on the CIS Benchmark version and the components detected on the node. The detection is done by verifying which components are running, as defined in the config files (see [Configuration](controls.md#configuration-and-variables).

#### Run specific check or group

`kube-bench` supports running individual checks by specifying the check's `id`
as a comma-delimited list on the command line with the `--check` | `-c` flag.
`kube-bench --check="1.1.1,1.1.2,1.2.1,1.3.3"`

`kube-bench` supports running all checks under group by specifying the group's `id`
as a comma-delimited list on the command line with the `--group` | `-g` flag.
`kube-bench --check="1.1,2.2"`
Will run all checks 1.1.X and 2.2.X. 

#### Skip specific check or group

`kube-bench` supports skipping checks or groups by specifying the `id`
as a comma-delimited list on the command line with the `--skip` flag.
`kube-bench --skip="1.1,1.2.1,1.3.3"`
Will skip 1.1.X group and individual checks 1.2.1, 1.3.3.
Skipped checks returns [INFO] output. 

#### Exit code

`kube-bench` supports using uniqe exit code when failing a check or more. 
`kube-bench --exit-code 42` 
Will return 42 if one check or more failed, and 0 incase none failed. 
**Note:** [WARN] is not [FAIL].

#### Output manipulation flags

There are five output states:
- [PASS] indicates that the test was run successfully, and passed.
- [FAIL] indicates that the test was run successfully, and failed. The remediation output describes how to correct the configuration, or includes an error message describing why the test could not be run.
- [WARN] means this test needs further attention, for example it is a test that needs to be run manually. Check the remediation output for further information.
- [INFO] is informational output that needs no further action.
- [NOT_APPLICABLE] means the check belongs to a role that is not present on this machine, so it was not run. It is counted in its own `total_not_applicable` total, is never added to `total_fail`, and never affects the exit code.

#### Machine roles and coverage

`kube-bench` determines what a machine does from observable facts only: which
configured components are running on it (probed with `ps`) and which targets
were explicitly named on the command line. It never infers a role from the
hostname, an environment variable or a directory layout.

- A machine running only `kubelet`/`kube-proxy` is a **workload** machine. Its
  control-plane and etcd checks are reported as `NOT_APPLICABLE`.
- A machine running only `kube-apiserver`, `kube-scheduler` and
  `kube-controller-manager` is a **control-plane** machine. Its worker checks
  are reported as `NOT_APPLICABLE`.
- A machine running both is **mixed**. Both check sets run and are concluded;
  there is no picking one role over the other. If the same check identifier is
  produced by more than one role's controls, the result is kept once, the more
  severe verdict wins, and the surviving check carries `sources` (and
  `source_states`) so the origin of each result is visible.
- If the role cannot be established (no components observed, or `ps` is missing
  or not executable), `kube-bench` does **not** silently skip anything. Every
  role-dependent target is executed and marked with coverage state `uncovered`
  (JSON `applicability.state`), together with a `reason_code` explaining why.

The determination and its evidence are part of the report: `role.roles`,
`role.determined`, `role.source`, `role.reason_code`, `role.reason` and
`role.evidence` in JSON totals (and on each control when `--nototals` is used).
`coverage` reports how many checks were `covered`, how many were
`not_applicable` and `deduplicated`, and a `reasons` map that breaks the
trimmed checks down by reason code. The same information is printed on stdout
as a `== Coverage ==` block whenever checks were trimmed or a role could not be
established.

An explicitly specified target (for example `kube-bench run --targets master`)
is always covered, exactly as before. Automatic role trimming still applies to
the targets that were not named explicitly.

Trimming only decides whether a check runs. It never changes a check's audit
command, comparison operator or threshold.

Note:
- Some tests with `Automated` in their description must still be run manually
- If the user has to run a test manually, this always generates WARN
- If the test is Scored, and kube-bench was unable to run the test, this generates FAIL (because the test has not been passed, and as a Scored test, if it doesn't pass then it must be considered a failure).
- If the test is Not Scored, and kube-bench was unable to run the test, this generates WARN.
- If the test is Scored, type is empty, and there are no `test_items` present, it generates a WARN. This is to highlight tests that appear to be incompletely defined.
- If a check is out of scope for the machine's role, it is NOT_APPLICABLE. This is not a failure: it is excluded from the fail total, from the JUnit failure count and from the exit code. `--skip`ped checks keep their existing INFO behaviour.

`kube-bench` supports multiple output manipulation flags. 
`kube-bench --include-test-output` will print failing checks output in the results section
```
[INFO] 1 Master Node Security Configuration
[INFO] 1.1 Master Node Configuration Files
[FAIL] 1.1.1 Ensure that the API server pod specification file permissions are set to 644 or more restrictive (Automated)
         **permissions=777**
```

**Note:** `--noresults` `--noremediations` and `--include-test-output` **will not** effect the json output but only stdout. 
Only `--nototals` will effect the json output and thats because it will not call the function to calculate totals. 


#### Troubleshooting

Running `kube-bench` with the `-v 3` parameter will generate debug logs that can be very helpful for debugging problems.

If you are using one of the example `job*.yaml` files, you will need to edit the `command` field, for example `["kube-bench", "-v", "3"]`. Once the job has run, the logs can be retrieved using `kubectl logs` on the job's pod.
