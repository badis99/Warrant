from warrant.llm import complete

# This hands version-range math to the LLM, which the architectural rule
# forbids. It exists only as the baseline that Phase 1's deterministic
# resolver beats in the before/after table. See docs/.../warrant-design.md.
def naive_is_affected(package, affected_range_text: str) -> str:
    prompt = (
        f"A package version is {package.version}.\n"
        f"The affected version range is: {affected_range_text}\n"
        f"Is version {package.version} inside that affected range?\n"
        f"Answer with exactly one word: affected or not-affected."
    )
    reply = complete(prompt)          
    return _parse_verdict(reply)


def _parse_verdict(reply: str) -> str:
    text = reply.strip().lower()
    if "not-affected" in text or "not affected" in text:
        return "not-affected"
    if "affected" in text:
        return "affected"
    return "unknown"