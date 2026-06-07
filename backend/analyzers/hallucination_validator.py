from typing import Dict, List


ABSTRACT_NODE_TYPES = {"cascade-effect", "final-impact"}

# Paths with more than this fraction of unanchored nodes are flagged unreliable.
# 0.30 chosen empirically: allows for abstract/compound nodes while
# still catching wholesale AI fabrication.
_HALLUCINATION_THRESHOLD = 0.30


def validate_hallucination(
    causal_paths: List[Dict],
    slither_findings: List[Dict],
) -> Dict:
    slither_types = set()
    for _f in slither_findings:
        _t = _f.get("type", "")
        if _t:
            slither_types.add(_t)                   # "tx-origin"
            slither_types.add(_t.replace("-", " "))  # "tx origin"
            slither_types.add(_t.replace("-", "."))  # "tx.origin"
    slither_funcs = {f.get("function", "").lower() for f in slither_findings if f.get("function")}
    slither_lines = {f.get("lineNumber") for f in slither_findings if f.get("lineNumber")}

    hallucination_count = 0
    total_checkable_nodes = 0
    validated_paths = []

    for path in causal_paths:
        nodes = path.get("nodes", [])
        if not nodes:
            validated_paths.append(path)
            continue

        validated_nodes = []
        path_has_hallucination = False

        for node in nodes:
            node_label = node.get("label", "").lower()
            node_desc = node.get("description", "").lower()
            node_line = node.get("lineNumber")
            node_type = node.get("type", "")

            # Abstract nodes are never flagged
            if node_type in ABSTRACT_NODE_TYPES:
                validated_nodes.append({**node, "hallucination_risk": False, "anchored_to_slither": False})
                continue

            total_checkable_nodes += 1
            anchored = False

            # Anchor check 1: vuln type keyword in label or description
            for s_type in slither_types:
                if s_type and (s_type in node_label or s_type in node_desc):
                    anchored = True
                    break

            # Anchor check 2: function name in label or description
            if not anchored:
                for func in slither_funcs:
                    if func and (func in node_label or func in node_desc):
                        anchored = True
                        break

            # Anchor check 3: line number matches a finding
            if not anchored and node_line and node_line in slither_lines:
                anchored = True

            hallucinated = not anchored
            if hallucinated:
                hallucination_count += 1
                path_has_hallucination = True

            validated_nodes.append({
                **node,
                "hallucination_risk": hallucinated,
                "anchored_to_slither": anchored,
            })

        validated_paths.append({
            **path,
            "nodes": validated_nodes,
            "has_hallucination": path_has_hallucination,
        })

    hallucination_rate = (
        hallucination_count / total_checkable_nodes if total_checkable_nodes > 0 else 0.0
    )
    validation_passed = hallucination_rate < _HALLUCINATION_THRESHOLD

    return {
        "validation_passed": validation_passed,
        "hallucination_count": hallucination_count,
        "hallucination_rate": round(hallucination_rate, 3),
        "validated_paths": validated_paths,
    }
