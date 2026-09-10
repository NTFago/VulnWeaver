from vulnweaver_binary_analysis import discover_critical_logic


def test_critical_logic_candidates_are_categorized_and_explainable() -> None:
    result = discover_critical_logic(
        [
            {
                "name": "authenticate_user",
                "address": 1,
                "size": 4,
                "file_offset": 0,
                "attributes": {},
            }
        ],
        [{"library": "libcrypto", "name": "EVP_EncryptInit", "ordinal": None, "address": 2}],
    )
    assert {item.category for item in result} == {"auth", "crypto"}
    assert all(item.evidence for item in result)
