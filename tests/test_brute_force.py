def test_brute_force_import():
    from src.scanners import brute_force
    assert hasattr(brute_force, "detect_bruteforce")
