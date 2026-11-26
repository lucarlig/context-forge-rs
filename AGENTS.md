# ContextForge RS

- Use the [rust-anything skill](https://github.com/erkamyaman/rust-anything) to capture and replay behavior from the pinned upstream release. Keep the reference checkout outside this repository.
- Keep the runtime, build, and tests Python-free. Use `rmcp` for MCP protocol models and transport support.
- Use `git commit -s` for signed-off commits. Commit and push verified slices to `origin` as they land during long milestones. Commit and push again when a milestone is complete.
- Check off milestones in [the port map](rust/MAP.md) after verifying them through their normal entry points. Update the README progress bar, percentage, and milestone count in the same commit. Each milestone counts equally.
