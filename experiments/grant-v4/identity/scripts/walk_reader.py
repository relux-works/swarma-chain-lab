"""Independent stated-history decisions from LIP-0021 Draft sections 6-7.

This reader works directly on the published fact lists, without Go code,
intermediate Go readings, or the implementation's walk/caching helpers.
"""


def evaluate(row):
    rule, context, history = row["rule"], row["context"], row["history"]
    tip, depth = context["tip_height"], context["depth"]
    recent = context.get("recent_block_height", context.get("checkpoint_height"))
    if rule in ("issuer", "recipient", "notary") and tip >= history[0]["height"] + depth:
        return {"issuer": "ISSUER_NAME_CHANGED", "recipient": "RECIPIENT_NAME_NOT_HELD", "notary": "NOTARY_NAME_CHANGED"}[rule]
    if rule == "recipient":
        out = history[0]
        if not context.get("transaction_index", True) or not out.get("readable", True):
            return "RECIPIENT_NAME_UNAVAILABLE"
        if out["reading"] == "another key":
            return "RECIPIENT_NAME_NOT_HELD"
        return "ok" if out["prefix"] in ("update", "registration") and out["reading"] == "controlled" else "RECIPIENT_NAME_UNAVAILABLE"

    # Enumerate the stated input links, counting an examination before judging it.
    examined, registration = [], None
    if context.get("transaction_index", True):
        for ordinal, out in enumerate(history, start=1):
            if ordinal > context.get("step_bound", len(history)):
                break
            if not out.get("readable", True) or out["prefix"] not in ("update", "registration"):
                break
            examined.append(out)
            if rule == "consent" and out["id"] == context["evidence_output"]:
                if out["height"] > recent or recent >= out["height"] + depth or out["reading"] != "controlled":
                    return "CONSENT_EVIDENCE"
                return "ok" if ordinal == 1 or examined[-2]["height"] > recent else "CONSENT_EVIDENCE"
            if out["prefix"] == "registration":
                registration = out
                break
    if rule == "consent":
        return "CONSENT_EVIDENCE"

    # The first output at/below the reference is included; all older readings
    # are outside the stretch but their prefixes are needed to reach registration.
    boundary = next((i for i, out in enumerate(examined) if out["height"] <= recent), len(examined)-1)
    stretch = examined[:boundary+1]
    owner_change = any(out["reading"] == "another key" for out in stretch)
    member_change = rule == "issuer" and any(out["swarma"] == "none" or out["swarma"] != context["bound_swarma"] for out in stretch)
    registration_change = registration is not None and registration["id"] != context["bound_registration"]
    snapshot = registration is not None and not registration_change and registration["height"] > recent
    missing = registration is None or any(out["reading"] not in ("controlled", "another key") for out in stretch)
    if rule == "issuer":
        # The draft explicitly orders these rows, including compound findings.
        if owner_change or member_change or registration_change:
            return "ISSUER_NAME_CHANGED"
        if snapshot:
            return "ISSUER_SNAPSHOT"
        return "ISSUER_HISTORY_UNAVAILABLE" if missing else "ok"
    if rule != "notary":
        raise ValueError(f"unknown walk rule {rule}")
    findings = set()
    if owner_change or registration_change:
        findings.add("NOTARY_NAME_CHANGED")
    if snapshot:
        findings.add("NOTARY_CHECKPOINT")
    if missing:
        findings.add("NOTARY_HISTORY_UNAVAILABLE")
    if len(findings) > 1:
        # O7.3 defines no priority and its published vectors have no compounds.
        raise ValueError("notary compound has no single normative verdict")
    if findings:
        return next(iter(findings))
    return {"written by the owner": "ok", "written by another": "NOTARY_VALUE_UNAUTHORIZED", "unsupported": "NOTARY_HISTORY_UNAVAILABLE"}[history[0]["writer"]]


def calculate_walks(rows):
    counts = {rule: sum(row["rule"] == rule for row in rows) for rule in ("issuer", "recipient", "consent", "notary")}
    if counts != {"issuer": 29, "recipient": 5, "consent": 12, "notary": 10} or len(rows) != 56:
        raise ValueError(f"wrong walk vector counts: {counts}")
    decisions, index = {}, {row["id"]: row for row in rows}
    for row in rows:
        key = row["id"]
        if not key or key in decisions:
            raise ValueError(f"duplicate or empty walk vector {key}")
        actual = evaluate(row)
        decisions[key] = actual
        # Expected outcomes are not inputs to evaluate().
        if actual != row["expect"]:
            raise ValueError(f"VECTOR_DISAGREEMENT {key}: independent={actual!r}, vector={row['expect']!r}")
        if neighbour := row.get("valid_neighbour"):
            if neighbour not in index or index[neighbour].get("valid_neighbour") or evaluate(index[neighbour]) != "ok":
                raise ValueError(f"invalid walk neighbour for {key}")
    return decisions
