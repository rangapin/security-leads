"""Risk score calculation logic."""

from ..config import SCORE_THRESHOLDS, TEMPERATURE_MAP


def calculate_score(scan_results: dict) -> dict:
    """
    Aggregate all findings into a single lead score.

    Args:
        scan_results: Dict containing 'checks' with individual scanner results

    Returns:
        Dict with total_score, raw_score, grade, lead_temperature,
        category_scores, top_issues, issue_count
    """
    checks = scan_results.get("checks", {})

    # Calculate category scores
    category_scores = {}
    all_issues = []
    issue_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}

    for check_name, check_data in checks.items():
        score = check_data.get("score", 0)
        category_scores[check_name] = score

        # Collect issues with severity
        severity = check_data.get("severity", "low")
        for issue in check_data.get("issues", []):
            all_issues.append({"text": issue, "severity": severity, "category": check_name})

        # Count by severity
        if severity in issue_counts:
            issue_counts[severity] += 1

    # Calculate total score
    raw_score = sum(category_scores.values())
    total_score = min(100, raw_score)  # Cap at 100

    # Get grade and temperature
    grade = get_grade(total_score)
    temperature = get_temperature(grade)

    # Sort issues by severity (critical first)
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    sorted_issues = sorted(all_issues, key=lambda x: severity_order.get(x["severity"], 4))
    top_issues = [f"[{i['severity'].upper()}] {i['text']}" for i in sorted_issues[:5]]

    return {
        "total_score": total_score,
        "raw_score": raw_score,
        "grade": grade,
        "lead_temperature": temperature,
        "category_scores": category_scores,
        "top_issues": top_issues,
        "issue_count": issue_counts,
    }


def get_grade(score: int) -> str:
    """Get letter grade from score."""
    for grade, (min_score, max_score) in SCORE_THRESHOLDS.items():
        if min_score <= score <= max_score:
            return grade
    return "F"  # Default for scores > 100


def get_temperature(grade: str) -> str:
    """Get lead temperature from grade."""
    return TEMPERATURE_MAP.get(grade, "unknown")
