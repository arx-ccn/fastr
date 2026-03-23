# run before committing: format and auto-fix lints
precommit:
    cargo +nightly test
    cargo +nightly check
    cargo +nightly fmt
    cargo clippy --fix --allow-dirty --allow-staged
