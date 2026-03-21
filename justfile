# run before committing: format and auto-fix lints
precommit:
    cargo fmt
    cargo clippy --fix --allow-dirty --allow-staged
