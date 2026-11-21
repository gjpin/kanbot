# OpenShell gateway API

The gRPC API of the [OpenShell](https://github.com/ai-openshell/openshell)
gateway (`openshell.v1`), generated for kanbot's OpenShell integration
(`src/openshell/`, `docs/openshell.md`).

- `proto/`: the `.proto` files of the supported OpenShell version, unchanged,
  with OpenShell's `LICENSE` (Apache-2.0).
- `src/generated/`: Rust generated from them by `tonic-prost-build`: the
  client, and a server trait whose methods default to `unimplemented`, used
  by kanbot's tests as a fake gateway. **Never edit it by hand.**
- `codegen/`: the generator, a crate with its own workspace.

Generated code does not meet the backend's lints (it carries `allow`
attributes), so it lives in this crate of its own; the backend's code that
calls it is held to every lint.

## Supported versions

| kanbot | OpenShell | Source |
|---|---|---|
| this branch | v0.1.9 | `proto/*.proto` at commit `ce58cf8e9b953281352d98a637e41616295b1318` |

Membership sync uses `GetWorkspace`, `ListWorkspaceMembers`,
`AddWorkspaceMember` and `RemoveWorkspaceMember`. A gateway of another
version works as long as those keep their wire format.

## Updating

1. Copy `openshell.proto`, `datamodel.proto`, `options.proto` and
   `sandbox.proto` from the new OpenShell tag into `proto/`, and update the
   table above.
2. Run `sh backend/openshell-api/regenerate.sh`. It downloads the pinned
   `protoc` (checked by SHA-256) into `codegen/.protoc/`, then regenerates
   `src/generated/`. Building kanbot never needs `protoc`.
3. Run the backend's checks and commit everything. CI regenerates the code
   and fails if it differs from what is committed.

To update `protoc`, change the version and the four SHA-256 sums in
`codegen/fetch-protoc.sh` (the release's assets list them).
