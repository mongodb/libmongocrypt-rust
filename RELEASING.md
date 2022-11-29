# Publishing new crate versions
New versions of both the `mongocrypt-sys` and `mongocrypt` crates can be released with the `publish.sh` script; they do not have to be released in lockstep, although API changes in `mongocrypt-sys` will probably require changes in `mongocrypt` as well.

1. When publishing the `mongocrypt` crate, push a change updating the `mongocrypt-sys` and `bson` dependencies to the most recent published versions.
1. Create a tag combining the crate name and version to be published, e.g. `mongocrypt-sys-0.1`.  If pushing both crates, create two tags (they can point to the same commit).
1. Push the tag(s) upstream.
1. Run the publish script with the `TAG`, `TOKEN`, and `CRATE` variables:

        TAG=0.1 \
        TOKEN=<crates.io auth token> \
        CRATE=mongocrypt-sys \
        ./publish.sh

1. If `mongocrypt` was published, push another change reverting the dependencies.