# Updating Golden Tests for `vulnreport`

This guide explains how to add or update golden file test cases for most `vulnreport` commands.

The tests for this command use a "golden file" system. This means the output of the command (including logs and any files it creates) is compared against a pre-recorded, known-good version stored in a `.txtar` file. To generate or update these golden files, you must run the test in a special mode that allows it to contact the real Go module proxy and record the results.

### The Update Command

The primary command used for this process is:

```shell
go test -v -proxy -update-test -run TestCreate/<test_case_name>
```

Here is a breakdown of what each flag does:

*   `-v`: Enables verbose mode, showing detailed log output for each test.
*   `-proxy`: This flag temporarily allows the test to make live network calls to the public Go module proxy (`proxy.golang.org`). The test client will cache the responses as JSON files in the `testdata/proxy/` directory so that subsequent test runs can be performed offline.
*   `-update-test`: This flag puts the test into "update" mode. Instead of comparing the command's output to the existing golden file, it will create or overwrite the golden file with the new output.
*   `-run TestCreate/<test_case_name>`: This specifies which test to run. You should target a specific test case to avoid updating golden files for unrelated tests.

### Workflow for Adding a New Test Case

Follow these steps to add a new test for a `create` command scenario:

1.  **Add a Mock Issue**: Add a new issue entry to `cmd/vulnreport/testdata/issue_tracker.txtar`. Ensure the module path in the issue's title refers to a real, public Go module.
2.  **Add the Test Case**: Add a new `testCase` struct to the `TestCreate` function in `cmd/vulnreport/vulnreport_test.go`. Use a descriptive name for your test case.
3.  **Generate Test Files**: Run the `go test` command with both the `-proxy` and `-update-test` flags, targeting your new test case. This single command creates two essential files:
    *   A JSON file in `testdata/proxy/TestCreate/` containing the cached module data from the Go proxy.
    *   A `.txtar` file in `testdata/TestCreate/` containing the captured output of the command. This is your new golden file.
4.  **Verify the Test**: Run the test again without the flags (`go test -v -run TestCreate/<test_case_name>`). The test should now pass by comparing the command's live output against the files you just generated.
