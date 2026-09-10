from vulnweaver_proof import validate_generated_script


def test_generated_script_policy_accepts_local_bounded_script() -> None:
    result = validate_generated_script("print('proof')\n")
    assert result.allowed is True


def test_generated_script_policy_rejects_red_lines() -> None:
    result = validate_generated_script("import requests\nrequests.get('https://example.test')\n")
    assert result.allowed is False
    assert "external_network" in result.reason_codes
