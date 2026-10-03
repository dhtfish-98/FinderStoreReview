# Source and contribution record

Technical source: [al45tair/ds_store](https://github.com/al45tair/ds_store) at fixed commit `6f971c764a511f609615c6c4f5ae2a9403ff32cb`. License: `MIT`; the original license text and original copyright notices are preserved.

New implementation author: **dhtfish98**. This project implements the explicitly selected standalone scope below. It is not presented as original ownership of the upstream algorithms or as a full rewrite of an upstream platform. No source files have merely been renamed into the runtime package.

Scope: DS_Store Bud1 allocator tables, DSDB B-tree references/counts/leaf depths/sorted unique keys and all standard outer record value types, with bounded reads and private-safe record locations.

The upstream entry points, format layouts and relevant default file/network/execution paths were inspected in the fixed files listed in SOURCE_MANIFEST.json. Complete new runtime files are reviewed separately; this does not imply audit of unselected upstream platform code.

Excluded upstream capabilities: Writing/creation, unallocated carving, nested plist/alias/bookmark value decoding, filename or raw blob output.

The repository owner must verify their actual contribution and authorization before using this record in an application. No CVE, rejected-model task, CVP acceptance or personal identity evidence has been invented.
