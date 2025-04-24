def test_user_enum_import():
    from src.scanners import user_enum
    assert hasattr(user_enum, "detect_user_enumeration")
